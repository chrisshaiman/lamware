#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Localhost forwarder to the Claude API with Workload Identity Federation (ADR-033).

This path holds no API key. The host's own ES256 signing key (root-only; its public
half is registered as an inline-JWKS federation issuer) signs a fresh, short-lived JWT
for each exchange. ``POST /v1/oauth/token`` (RFC 7523 jwt-bearer) trades it for an
access token of a few minutes, kept in memory only and sent as
``Authorization: Bearer``.

Each *route* is its own loopback port bound to one workspace, with its own model
allowlist and its own token (a token is scoped to one workspace). Production and eval
are separate routes, so production traffic cannot bill the eval workspace: the
workspace comes from the port the caller connected to, never from the request.

It forwards ONLY ``POST /v1/messages`` and ``POST /v1/messages/count_tokens``, for the
route's allowlisted models, from allowlisted local uids. Request headers pass through an
allowlist, so an ``x-api-key`` or ``authorization`` from the caller never leaves the
host. Response bodies are streamed through unchanged, which keeps SSE and the
``usage`` block (CLAUDE.md section 10, read by LiteLLM) intact.

Subcommands:

  serve  the forwarder (systemd ``anthropic-wif.service``)
  check  the daily health check (``anthropic-wif-check.timer``): for each route,
         mints a JWT, exchanges it, and counts tokens on the route's first model
         (not billed)
  jwks   print the public key set to register with the federation issuer

Needs python3-cryptography (ES256). Never logged: the signing key, the JWT, the access
token, request or response bodies.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import ipaddress
import json
import logging
import os
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.parse
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger("anthropic-wif")

DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
FORWARDED_PATHS = frozenset({"/v1/messages", "/v1/messages/count_tokens"})
TOKEN_PATH = "/v1/oauth/token"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"

# Request headers copied from the caller. An allowlist, not a strip-list: anything a
# future LiteLLM release starts sending (a new auth header, a cookie) is dropped by
# default instead of forwarded by default.
FORWARDED_REQUEST_HEADERS = ("content-type", "accept", "anthropic-version", "anthropic-beta")

# RFC 7230 section 6.1 hop-by-hop headers, never copied from the upstream response.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
})

# Exit status for configuration errors. The unit sets RestartPreventExitStatus=2, so a
# missing id stops the service with one clear message instead of a restart loop.
EXIT_CONFIG = 2

REQUIRED_STRINGS = ("organization_id", "federation_rule_id", "signing_key_file",
                    "key_id", "issuer", "subject", "audience")


class ConfigError(Exception):
    """The configuration cannot run safely; the message says which field and why."""


class CredentialError(Exception):
    """Getting an access token failed. The message never holds a credential."""


# --------------------------------------------------------------------------- config


@dataclass(frozen=True)
class Route:
    """One loopback port, one workspace, its own model allowlist and token."""

    name: str
    listen_port: int
    workspace_id: str
    allowed_models: tuple[str, ...]


@dataclass(frozen=True)
class Config:
    """Validated runtime configuration (``/etc/anthropic-wif/config.json``)."""

    organization_id: str
    federation_rule_id: str
    signing_key_file: str
    key_id: str
    issuer: str
    subject: str
    audience: str
    routes: tuple[Route, ...] = ()
    service_account_id: str = ""
    listen_host: str = "127.0.0.1"
    allowed_peer_uids: tuple[int, ...] = (0,)
    # Each JWT lives this long (the issuer's maximum is 1 hour); the minted token is
    # the lesser of the rule's lifetime and twice this JWT's remaining life.
    jwt_lifetime_seconds: int = 900
    # Refresh 120 s before the token expires, keep serving the cached one if that
    # fails, and fail 30 s before expiry rather than send a token that can die
    # mid-stream (the SDK's own schedule, from the WIF docs).
    advisory_refresh_seconds: int = 120
    mandatory_refresh_seconds: int = 30
    max_body_bytes: int = 32 * 1024 * 1024
    upstream_timeout_seconds: int = 900
    # Tests point this at a local fake. Empty means the public API.
    upstream_base_url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return self.upstream_base_url or "https://api.anthropic.com"


def load_config(path: str, environ: dict[str, str] | None = None) -> Config:
    """Read and validate the config. Raises ConfigError naming every problem at once."""
    environ = os.environ if environ is None else environ
    try:
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError(f"config {path} is not a JSON object")

    missing = [k for k in REQUIRED_STRINGS if not str(raw.get(k) or "").strip()]
    if missing:
        raise ConfigError("empty or missing: " + ", ".join(missing)
                          + " (set the anthropic_wif_* variables; ADR-033 lists them)")

    known = {f for f in Config.__dataclass_fields__ if f != "extra"}
    kwargs: dict[str, Any] = {k: raw[k] for k in known if k in raw}
    if "allowed_peer_uids" in kwargs:
        kwargs["allowed_peer_uids"] = tuple(kwargs["allowed_peer_uids"] or ())
    problems: list[str] = []
    routes: list[Route] = []
    for i, r in enumerate(raw.get("routes") or []):
        try:
            routes.append(Route(str(r["name"]), int(r["listen_port"]), str(r["workspace_id"]),
                                tuple(r.get("allowed_models") or ())))
        except (KeyError, TypeError, ValueError) as exc:
            problems.append(f"routes[{i}] needs name, listen_port, workspace_id "
                            f"({type(exc).__name__})")
    kwargs["routes"] = tuple(routes)
    kwargs["extra"] = {k: v for k, v in raw.items() if k not in known}
    cfg = Config(**kwargs)

    try:
        if not ipaddress.ip_address(cfg.listen_host).is_loopback:
            problems.append(f"listen_host {cfg.listen_host} is not a loopback address")
    except ValueError:
        problems.append(f"listen_host {cfg.listen_host!r} is not an IP address")
    if not cfg.federation_rule_id.startswith("fdrl_"):
        problems.append("federation_rule_id must start with fdrl_")
    if not cfg.routes:
        problems.append("routes is empty: nothing could be forwarded")
    for r in cfg.routes:
        if not r.workspace_id.startswith("wrkspc_"):
            problems.append(f"route {r.name}: workspace_id must start with wrkspc_")
        if not r.allowed_models:
            problems.append(f"route {r.name}: allowed_models is empty")
        if not 1024 <= r.listen_port <= 65535:
            problems.append(f"route {r.name}: listen_port {r.listen_port} out of range")
    for attr in ("name", "listen_port"):
        values = [getattr(r, attr) for r in cfg.routes]
        if len(values) != len(set(values)):
            problems.append(f"two routes share a {attr}")
    # A model on two workspaces' routes would make the bill depend on which port a
    # caller picked; each model belongs to exactly one route.
    seen: dict[str, str] = {}
    for r in cfg.routes:
        for m in r.allowed_models:
            # A repeat within one route is harmless (haiku-fallback is often the
            # summary model); only a model on two routes is the error.
            if seen.get(m, r.name) != r.name:
                problems.append(f"model {m} is on routes {seen[m]} and {r.name}")
            seen.setdefault(m, r.name)
    if cfg.service_account_id and not cfg.service_account_id.startswith("svac_"):
        problems.append("service_account_id must start with svac_")
    try:
        uuid.UUID(cfg.organization_id)
    except ValueError:
        problems.append("organization_id must be the organization's UUID")
    if not cfg.allowed_peer_uids:
        problems.append("allowed_peer_uids is empty: no local caller could connect")
    if not 60 <= cfg.jwt_lifetime_seconds <= 3600:
        problems.append("jwt_lifetime_seconds must be 60..3600 (the issuer's maximum is 1 hour)")
    if not 0 < cfg.mandatory_refresh_seconds < cfg.advisory_refresh_seconds:
        problems.append("need 0 < mandatory_refresh_seconds < advisory_refresh_seconds")
    if cfg.upstream_base_url and not cfg.upstream_base_url.startswith(("https://", "http://127.")):
        problems.append("upstream_base_url must be https (or a loopback test server)")
    # A static key in this process's environment means someone tried to configure one
    # into this path. Nothing here reads them; their presence is the error.
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        if environ.get(var):
            problems.append(f"{var} is set in the environment; this path carries no "
                            "static key (ADR-033)")
    if problems:
        raise ConfigError("; ".join(problems))
    return cfg


def signing_key_path(cfg: Config, environ: dict[str, str] | None = None) -> str:
    """The signing key, via systemd LoadCredential when available.

    The key file stays root-owned 0600; systemd hands this unit a private copy under
    $CREDENTIALS_DIRECTORY that only the service user can read.
    """
    environ = os.environ if environ is None else environ
    cred_dir = environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        path = os.path.join(cred_dir, "signing-key.pem")
        if os.path.exists(path):
            return path
    return cfg.signing_key_file


# ------------------------------------------------------------------ credentials


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def load_signing_key(path: str):
    """The host's EC P-256 private key (PEM)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    try:
        with open(path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
    except (OSError, ValueError) as exc:
        raise CredentialError(f"cannot load the signing key ({type(exc).__name__})") from exc
    if not isinstance(key, ec.EllipticCurvePrivateKey) or key.curve.name != "secp256r1":
        raise CredentialError("the signing key is not an EC P-256 key (ES256)")
    return key


def mint_assertion(cfg: Config, key, now: float, jti: str | None = None) -> str:
    """A fresh ES256 JWT: unique jti (the issuer enforces single use), iat now, short exp."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    header = {"alg": "ES256", "typ": "JWT", "kid": cfg.key_id}
    claims = {"iss": cfg.issuer, "sub": cfg.subject, "aud": cfg.audience,
              "iat": int(now), "nbf": int(now), "exp": int(now) + cfg.jwt_lifetime_seconds,
              "jti": jti or str(uuid.uuid4())}
    signing_input = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "."
                     + _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)  # JWS wants raw r||s, 32 bytes each (RFC 7518 3.4)
    return signing_input + "." + _b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


@dataclass(frozen=True)
class AccessToken:
    """A short-lived access token. repr=False on the secret: never printed by accident."""

    token: str = field(repr=False)
    expiry: float = 0.0


def _connection(cfg: Config) -> tuple[http.client.HTTPConnection, str]:
    base = urllib.parse.urlsplit(cfg.base_url)
    if base.scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            base.netloc, timeout=cfg.upstream_timeout_seconds,
            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(base.netloc, timeout=cfg.upstream_timeout_seconds)
    return conn, base.netloc


def exchange(cfg: Config, route: Route, assertion: str,
             clock: Callable[[], float] = time.time) -> AccessToken:
    """Trade the JWT for an access token scoped to the route's workspace (RFC 7523)."""
    body = {"grant_type": JWT_BEARER, "assertion": assertion,
            "federation_rule_id": cfg.federation_rule_id,
            "organization_id": cfg.organization_id, "workspace_id": route.workspace_id}
    if cfg.service_account_id:
        body["service_account_id"] = cfg.service_account_id
    raw = json.dumps(body).encode()
    conn, _ = _connection(cfg)
    try:
        conn.request("POST", TOKEN_PATH, body=raw,
                     headers={"content-type": "application/json", "Content-Length": str(len(raw))})
        resp = conn.getresponse()
        payload = resp.read()
    except (OSError, http.client.HTTPException) as exc:
        raise CredentialError(f"token exchange did not complete: {exc}") from exc
    finally:
        conn.close()
    if resp.status != 200:
        # Denials are an opaque 401 by design; the Console's authentication history
        # names the failed check. The body holds no credential.
        raise CredentialError(f"token exchange returned {resp.status} "
                              f"(request_id={_request_id(resp)}): {_error_summary(payload)}")
    try:
        doc = json.loads(payload)
        token, ttl = doc["access_token"], int(doc["expires_in"])
    except (ValueError, KeyError, TypeError) as exc:
        raise CredentialError(f"token exchange response is not a token document "
                              f"({type(exc).__name__})") from exc
    if not isinstance(token, str) or not token:
        raise CredentialError("token exchange returned an empty access token")
    return AccessToken(token, clock() + ttl)


def fetch_token(cfg: Config, route: Route, key_path: str,
                clock: Callable[[], float] = time.time) -> AccessToken:
    """Load the key, mint a fresh JWT, exchange it for the route's workspace."""
    key = load_signing_key(key_path)
    return exchange(cfg, route, mint_assertion(cfg, key, clock()), clock)


class TokenCache:
    """An in-memory access token with two refresh thresholds.

    advisory  (expiry - advisory_s): try to refresh; on failure keep serving the
              cached token, which is still valid.
    mandatory (expiry - mandatory_s): must refresh; on failure raise, because a
              token this close to expiry can die mid-stream.
    Every refresh mints a new JWT, so a retry never replays a jti.
    """

    def __init__(self, fetch: Callable[[], AccessToken], advisory_s: int,
                 mandatory_s: int, clock: Callable[[], float] = time.time):
        self._fetch = fetch
        self._advisory = advisory_s
        self._mandatory = mandatory_s
        self._clock = clock
        self._lock = threading.Lock()
        self._token: AccessToken | None = None

    def get(self) -> AccessToken:
        with self._lock:
            now = self._clock()
            t = self._token
            if t is not None and now < t.expiry - self._advisory:
                return t
            if t is not None and now < t.expiry - self._mandatory:
                try:
                    self._refresh()
                except CredentialError as exc:
                    log.warning("event=advisory_refresh_failed serving_cached_until=%d "
                                "error=%s", int(t.expiry - self._mandatory), exc)
                return self._token  # type: ignore[return-value]
            reason = "initial" if t is None else "mandatory"
            try:
                self._refresh()
            except CredentialError as exc:
                log.error("event=%s_refresh_failed error=%s", reason, exc)
                raise
            return self._token  # type: ignore[return-value]

    def _refresh(self) -> None:
        token = self._fetch()
        self._token = token
        log.info("event=token_refreshed expires_in=%d", int(token.expiry - self._clock()))


# ------------------------------------------------------------------------ peer uid


def _proc_addr(text: str) -> tuple[str, int]:
    ip_hex, port_hex = text.split(":")
    ip = socket.inet_ntoa(struct.pack("<I", int(ip_hex, 16)))
    return ip, int(port_hex, 16)


def peer_uid(client: tuple[str, int], server: tuple[str, int],
             proc_net_tcp: str = "/proc/net/tcp") -> int | None:
    """uid owning the client end of a loopback IPv4 TCP connection, from the kernel table.

    The client socket is the row whose local address is the client's and whose remote
    address is ours. The kernel fills its uid; a caller cannot choose it.
    """
    try:
        with open(proc_net_tcp, encoding="ascii") as fh:
            next(fh)
            for line in fh:
                cols = line.split()
                if len(cols) < 8:
                    continue
                if _proc_addr(cols[1]) == client and _proc_addr(cols[2]) == server:
                    return int(cols[7])
    except (OSError, ValueError, StopIteration):
        return None
    return None


# --------------------------------------------------------------------------- upstream


def upstream_request(cfg: Config, token: AccessToken, path: str, query: str, raw: bytes,
                     caller_headers: dict[str, str]
                     ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    """Open the upstream connection and send one POST with the bearer token. Caller
    closes ``conn``."""
    conn, _ = _connection(cfg)
    headers = {h: v for h, v in caller_headers.items() if v}
    headers.setdefault("anthropic-version", DEFAULT_ANTHROPIC_VERSION)
    headers.setdefault("content-type", "application/json")
    headers["Authorization"] = f"Bearer {token.token}"
    headers["Content-Length"] = str(len(raw))
    target = path + (f"?{query}" if query else "")
    try:
        conn.request("POST", target, body=raw, headers=headers)
        return conn, conn.getresponse()
    except BaseException:
        conn.close()
        raise


# --------------------------------------------------------------------------- server


class ForwarderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: Config, route: Route, cache: TokenCache,
                 uid_lookup: Callable[[tuple[str, int], tuple[str, int]], int | None] = peer_uid):
        self.cfg = cfg
        self.route = route
        self.cache = cache
        self.uid_lookup = uid_lookup
        super().__init__((cfg.listen_host, route.listen_port), ForwarderHandler)


def _request_id(resp: http.client.HTTPResponse) -> str:
    """Anthropic's per-request id (``request-id``), logged for every forwarded call.

    Not a secret, and what a support or false-positive report needs. Header characters
    are limited so a hostile value cannot forge extra log fields.
    """
    rid = resp.getheader("request-id") or "-"
    return "".join(c for c in rid if c.isalnum() or c in "_-")[:80] or "-"


def _error_json(kind: str, message: str) -> bytes:
    return json.dumps({"type": "error", "error": {"type": kind, "message": message}}).encode()


class ForwarderHandler(BaseHTTPRequestHandler):
    server: ForwarderServer
    # HTTP/1.0 responses: a streamed body is delimited by connection close, so no
    # re-chunking is needed and nothing is buffered.
    protocol_version = "HTTP/1.0"
    server_version = "anthropic-wif"
    sys_version = ""

    def version_string(self) -> str:
        # The default is server_version + " " + sys_version. With sys_version empty
        # that leaves a trailing space, and LiteLLM's h11 refuses to relay it (measured
        # on the existing loopback forwarder: every call failed with "Connection error").
        return self.server_version

    def log_message(self, format: str, *args: Any) -> None:
        log.info("event=http %s", format % args)

    def _reply(self, status: int, kind: str, message: str) -> None:
        body = _error_json(kind, message)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self) -> None:
        self._reply(404, "not_found_error", "anthropic-wif forwards only POST "
                    "/v1/messages and POST /v1/messages/count_tokens")

    do_GET = do_PUT = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _not_found

    def do_POST(self) -> None:
        cfg = self.server.cfg
        path = urllib.parse.urlsplit(self.path)
        if path.path not in FORWARDED_PATHS:
            self._not_found()
            return

        uid = self.server.uid_lookup(self.client_address[:2], self.server.server_address[:2])
        if uid is None or uid not in cfg.allowed_peer_uids:
            log.warning("event=peer_rejected uid=%s allowed=%s", uid, list(cfg.allowed_peer_uids))
            self._reply(403, "permission_error", f"anthropic-wif: local uid {uid} is "
                        "not in allowed_peer_uids")
            return

        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None or not length_hdr.isdigit():
            self._reply(411, "invalid_request_error", "anthropic-wif: Content-Length "
                        "required")
            return
        length = int(length_hdr)
        if length > cfg.max_body_bytes:
            self._reply(413, "request_too_large", "anthropic-wif: request body too large")
            return
        raw = self.rfile.read(length)
        try:
            model = json.loads(raw).get("model")
        except (ValueError, AttributeError):
            self._reply(400, "invalid_request_error", "anthropic-wif: body is not a "
                        "JSON object")
            return
        route = self.server.route
        if not isinstance(model, str) or model not in route.allowed_models:
            log.warning("event=model_rejected route=%s model=%r", route.name, model)
            self._reply(403, "permission_error", f"anthropic-wif: model {model!r} is "
                        f"not in route {route.name}'s allowed_models")
            return

        try:
            token = self.server.cache.get()
        except CredentialError as exc:
            self._reply(503, "api_error", f"anthropic-wif: no access token: {exc}")
            return
        self._forward(path, raw, token, model)

    def _forward(self, path: urllib.parse.SplitResult, raw: bytes, token: AccessToken,
                 model: str) -> None:
        cfg = self.server.cfg
        caller = {h: self.headers[h] for h in FORWARDED_REQUEST_HEADERS if self.headers.get(h)}
        try:
            conn, resp = upstream_request(cfg, token, path.path, path.query, raw, caller)
        except (OSError, http.client.HTTPException) as exc:
            log.error("event=upstream_failed error=%s", exc)
            self._reply(502, "api_error", f"anthropic-wif: upstream request failed: {exc}")
            return
        try:
            self.send_response(resp.status, resp.reason)
            for name, value in resp.getheaders():
                if name.lower() not in HOP_BY_HOP:
                    self.send_header(name, value)
            self.end_headers()
            while chunk := resp.read1(65536):
                self.wfile.write(chunk)
                self.wfile.flush()
            log.info("event=forwarded route=%s path=%s model=%s status=%d request_id=%s",
                     self.server.route.name, path.path, model, resp.status, _request_id(resp))
        except OSError as exc:
            log.warning("event=client_or_upstream_dropped path=%s model=%s request_id=%s error=%s",
                        path.path, model, _request_id(resp), exc)
        finally:
            conn.close()


# ------------------------------------------------------------------------------ check


def check(cfg: Config, key_path: str,
          fetch: Callable[[Route], AccessToken] | None = None) -> list[str]:
    """Problems that would stop the next call. Empty means healthy.

    For each route:
    1. A fresh JWT exchanges for a token in its workspace (key, issuer, rule, and the
       service account's membership of that workspace intact).
    2. That token can count tokens on the route's first model (scope intact).
       Counting tokens is not billed.
    """
    problems: list[str] = []
    for route in cfg.routes:
        try:
            token = (fetch or (lambda r: fetch_token(cfg, r, key_path)))(route)
        except CredentialError as exc:
            problems.append(f"route {route.name}: {exc}")
            continue
        body = json.dumps({"model": route.allowed_models[0],
                           "messages": [{"role": "user", "content": "health check"}]}).encode()
        try:
            conn, resp = upstream_request(cfg, token, "/v1/messages/count_tokens", "", body, {})
        except (OSError, http.client.HTTPException) as exc:
            problems.append(f"route {route.name}: count_tokens did not complete: {exc}")
            continue
        try:
            payload = resp.read()
        finally:
            conn.close()
        if resp.status != 200:
            problems.append(f"route {route.name}: count_tokens returned {resp.status} "
                            f"(request_id={_request_id(resp)}): {_error_summary(payload)}")
        else:
            log.info("event=route_ok route=%s workspace=%s", route.name, route.workspace_id)
    return problems


def public_jwks(key, kid: str) -> dict[str, Any]:
    """The public half as a JWKS, in the shape the federation issuer's inline mode takes."""
    n = key.public_key().public_numbers()
    return {"keys": [{"kty": "EC", "crv": "P-256", "kid": kid, "alg": "ES256", "use": "sig",
                      "x": _b64url(n.x.to_bytes(32, "big")),
                      "y": _b64url(n.y.to_bytes(32, "big"))}]}


def _error_summary(body: bytes) -> str:
    """The error type and message from an API error body, never the whole body."""
    try:
        err = json.loads(body).get("error", {})
        return f"{err.get('type')}: {str(err.get('message', ''))[:300]}"
    except (ValueError, AttributeError):
        return f"non-JSON body ({len(body)} bytes)"


# ----------------------------------------------------------------------------- main


def _setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)s %(name)s %(message)s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("serve", "check", "jwks"))
    parser.add_argument("--config", default="/etc/anthropic-wif/config.json")
    parser.add_argument("--key", default="/etc/anthropic-wif/signing-key.pem",
                        help="jwks only: the private key whose public half to print")
    parser.add_argument("--kid", default="lamware-wif-1", help="jwks only: the key id")
    args = parser.parse_args(argv)
    _setup_logging()
    if args.command == "jwks":
        # Needs no config, so the deploy can publish the key set before the ids exist.
        try:
            print(json.dumps(public_jwks(load_signing_key(args.key), args.kid), indent=2))
        except CredentialError as exc:
            log.error("event=jwks_failed %s", exc)
            return 1
        return 0
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        log.error("event=config_error refusing to start: %s", exc)
        return EXIT_CONFIG
    key_path = signing_key_path(cfg)

    if args.command == "check":
        problems = check(cfg, key_path)
        for p in problems:
            log.error("event=check_failed %s", p)
        if problems:
            return 1
        log.info("event=check_ok")
        return 0

    servers = []
    for route in cfg.routes:
        cache = TokenCache(lambda r=route: fetch_token(cfg, r, key_path),
                           cfg.advisory_refresh_seconds, cfg.mandatory_refresh_seconds)
        servers.append(ForwarderServer(cfg, route, cache))
        log.info("event=listening route=%s host=%s port=%d workspace=%s models=%s peer_uids=%s",
                 route.name, cfg.listen_host, route.listen_port, route.workspace_id,
                 ",".join(route.allowed_models), ",".join(str(u) for u in cfg.allowed_peer_uids))
    threads = [threading.Thread(target=s.serve_forever, name=s.route.name, daemon=True)
               for s in servers]
    for t in threads:
        t.start()
    try:
        # If any route's server dies, exit so systemd restarts the whole service
        # rather than leave a route silently gone.
        while all(t.is_alive() for t in threads):
            time.sleep(5)
        log.error("event=route_server_died")
        return 1
    finally:
        # Not shutdown(): it waits for serve_forever, which never returns on a dead
        # thread. The serving threads are daemons and end with the process.
        for s in servers:
            s.server_close()


if __name__ == "__main__":
    sys.exit(main())
