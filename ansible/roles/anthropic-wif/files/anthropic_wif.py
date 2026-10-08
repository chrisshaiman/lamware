#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Localhost token forwarder for Anthropic Workload Identity Federation (ADR-022).

The CVP Defense Access grant forbids static API keys. This service holds no Anthropic
credential at rest. For each exchange it:

  1. signs a short RFC 7523 client assertion with the host-generated client key and
     asks Keycloak for a client_credentials token (``private_key_jwt`` client auth);
  2. checks the token Keycloak returned BEFORE spending it: ``iss`` must equal the
     configured canonical issuer, ``aud`` must contain the configured audience,
     ``azp`` must be the client id, and the signature must verify against the JWKS
     that was uploaded inline to Anthropic (so a Keycloak key rotation fails here,
     by name, rather than as an opaque 4xx from the token endpoint);
  3. exchanges it at Anthropic's ``/v1/oauth/token`` (jwt-bearer grant) for a
     short-lived access token, cached in memory only.

It forwards ONLY ``POST /v1/messages`` and ``POST /v1/messages/count_tokens``, for
allowlisted models, from allowlisted local uids, with ``Authorization: Bearer``. Every
other incoming header is dropped, so an ``x-api-key`` or ``authorization`` from the
caller never reaches Anthropic. Response bodies are streamed through unchanged, which
is what keeps SSE (the interpret loop streams) and the ``usage`` block (CLAUDE.md §10,
read by LiteLLM) intact.

Two subcommands share the code:

  serve      the forwarder (systemd ``anthropic-wif.service``)
  check-kid  the daily key check (``anthropic-wif-kidcheck.timer``): mints a token,
             and fails unless its ``kid`` is in the uploaded JWKS, the live realm JWKS
             publishes the same key under that kid, and the signature verifies.

Stdlib plus ``cryptography`` only (apt ``python3-cryptography`` on the host): the
smallest dependency surface for a process that holds a signing key.

Never logged: the client assertion, the Keycloak token, the Anthropic token.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import logging
import os
import socket
import struct
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

log = logging.getLogger("anthropic-wif")

FORWARDED_PATHS = frozenset({"/v1/messages", "/v1/messages/count_tokens"})

# Request headers copied from the caller. An allowlist, not a strip-list: anything a
# future LiteLLM release starts sending (a new auth header, a cookie) is dropped by
# default instead of forwarded by default.
FORWARDED_REQUEST_HEADERS = ("content-type", "accept", "anthropic-version", "anthropic-beta")

# RFC 7230 §6.1 hop-by-hop headers, never copied from the upstream response.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "trailers", "transfer-encoding", "upgrade",
})

JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Exit status for configuration errors. The unit sets RestartPreventExitStatus=2, so a
# missing id stops the service with one clear message instead of a 5-second restart
# loop that buries it.
EXIT_CONFIG = 2

REQUIRED_STRINGS = (
    "keycloak_token_url", "keycloak_jwks_url", "client_id", "client_key_file",
    "expected_issuer", "audience", "uploaded_jwks_file",
    "anthropic_token_url", "anthropic_base_url",
    "organization_id", "workspace_id", "service_account_id", "federation_rule_id",
)


class ConfigError(Exception):
    """The configuration cannot run safely; the message says which field and why."""


class TokenError(Exception):
    """Minting, checking or exchanging a token failed. The message never holds a token."""


# --------------------------------------------------------------------------- config


@dataclass(frozen=True)
class Config:
    """Validated runtime configuration (``/etc/anthropic-wif/config.json``)."""

    keycloak_token_url: str
    keycloak_jwks_url: str
    client_id: str
    client_key_file: str
    expected_issuer: str
    audience: str
    uploaded_jwks_file: str
    anthropic_token_url: str
    anthropic_base_url: str
    organization_id: str
    workspace_id: str
    service_account_id: str
    federation_rule_id: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 4010
    allowed_models: tuple[str, ...] = ("claude-mythos-5-1",)
    allowed_peer_uids: tuple[int, ...] = (0,)
    advisory_refresh_seconds: int = 120
    mandatory_refresh_seconds: int = 30
    max_body_bytes: int = 32 * 1024 * 1024
    upstream_timeout_seconds: int = 900
    http_timeout_seconds: int = 30
    extra: dict[str, Any] = field(default_factory=dict)


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

    problems: list[str] = []
    missing = [k for k in REQUIRED_STRINGS if not str(raw.get(k) or "").strip()]
    if missing:
        problems.append(
            "empty or missing: " + ", ".join(missing)
            + " (set the anthropic_wif_* variables in ansible/vars/main.yml;"
            " the Console steps that produce the ids are in ADR-022)")

    known = {f for f in Config.__dataclass_fields__ if f != "extra"}
    kwargs: dict[str, Any] = {k: raw[k] for k in known if k in raw}
    for key in ("allowed_models", "allowed_peer_uids"):
        if key in kwargs:
            kwargs[key] = tuple(kwargs[key] or ())
    kwargs["extra"] = {k: v for k, v in raw.items() if k not in known}

    if problems:
        raise ConfigError("; ".join(problems))
    cfg = Config(**kwargs)

    try:
        if not ipaddress.ip_address(cfg.listen_host).is_loopback:
            problems.append(f"listen_host {cfg.listen_host} is not a loopback address")
    except ValueError:
        problems.append(f"listen_host {cfg.listen_host!r} is not an IP address")
    if not cfg.allowed_models:
        problems.append("allowed_models is empty: nothing could be forwarded")
    if not cfg.allowed_peer_uids:
        problems.append("allowed_peer_uids is empty: no local caller could connect")
    if not cfg.expected_issuer.startswith("https://"):
        problems.append(f"expected_issuer {cfg.expected_issuer} is not https")
    if not 0 < cfg.mandatory_refresh_seconds < cfg.advisory_refresh_seconds:
        problems.append("need 0 < mandatory_refresh_seconds < advisory_refresh_seconds")
    # An SDK-style key in this process's environment is the failure the WIF docs warn
    # about (it shadows federation). Nothing here reads it, so its presence means
    # someone tried to configure a static key into this path.
    if environ.get("ANTHROPIC_API_KEY"):
        problems.append("ANTHROPIC_API_KEY is set in the environment; this path must "
                        "carry no static key (ADR-022)")
    if problems:
        raise ConfigError("; ".join(problems))
    return cfg


def read_client_key(cfg: Config, environ: dict[str, str] | None = None) -> bytes:
    """The client private key, via systemd LoadCredential when available.

    The unit loads the root-owned 0400 key file as credential ``client-key.pem``;
    systemd exposes it to this unit's user only, under $CREDENTIALS_DIRECTORY. Outside
    systemd (tests) the configured path is read directly.
    """
    environ = os.environ if environ is None else environ
    cred_dir = environ.get("CREDENTIALS_DIRECTORY")
    candidate = os.path.join(cred_dir, "client-key.pem") if cred_dir else cfg.client_key_file
    if cred_dir and not os.path.exists(candidate):
        candidate = cfg.client_key_file
    try:
        with open(candidate, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise ConfigError(f"cannot read client key ({exc.strerror})") from exc


# ------------------------------------------------------------------------------ JWT


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def keycloak_key_id(public_key: rsa.RSAPublicKey | ec.EllipticCurvePublicKey) -> str:
    """The kid Keycloak assigns an imported key: base64url(SHA-256(SubjectPublicKeyInfo)).

    Sent in the assertion header so Keycloak can select the client key by id.
    """
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return b64url(hashlib.sha256(der).digest())


def sign_rs256(header: dict[str, Any], claims: dict[str, Any], key: rsa.RSAPrivateKey) -> str:
    signing_input = (b64url(json.dumps(header, separators=(",", ":")).encode())
                     + "." + b64url(json.dumps(claims, separators=(",", ":")).encode()))
    sig = key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + b64url(sig)


def decode_unverified(token: str) -> tuple[dict[str, Any], dict[str, Any]]:
    """Header and claims of a compact JWS, WITHOUT verifying it (see verify_with_jwks)."""
    try:
        h, c, _s = token.split(".")
        return json.loads(b64url_decode(h)), json.loads(b64url_decode(c))
    except (ValueError, json.JSONDecodeError) as exc:
        raise TokenError(f"token is not a compact JWS ({type(exc).__name__})") from exc


def _jwk_public_key(jwk: dict[str, Any]) -> rsa.RSAPublicKey | ec.EllipticCurvePublicKey:
    kty = jwk.get("kty")
    if kty == "RSA":
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        return rsa.RSAPublicNumbers(e, n).public_key()
    if kty == "EC":
        curve = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                 "P-521": ec.SECP521R1()}[jwk["crv"]]
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, curve).public_key()
    raise TokenError(f"unsupported JWK kty {kty!r}")


def _jwk_material(jwk: dict[str, Any]) -> tuple:
    """The fields that identify a public key, so two JWKS entries can be compared."""
    if jwk.get("kty") == "RSA":
        return ("RSA", jwk.get("n"), jwk.get("e"))
    return (jwk.get("kty"), jwk.get("crv"), jwk.get("x"), jwk.get("y"))


def find_jwk(jwks: dict[str, Any], kid: str | None) -> dict[str, Any] | None:
    for jwk in jwks.get("keys", []) if isinstance(jwks, dict) else []:
        if kid is not None and jwk.get("kid") == kid:
            return jwk
    return None


_HASHES = {"256": hashes.SHA256, "384": hashes.SHA384, "512": hashes.SHA512}


def verify_with_jwks(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    """Verify the JWS signature against the key in ``jwks`` named by its kid.

    Returns the header. Raises TokenError naming the kid when no such key exists or the
    signature does not verify: either way Anthropic would reject the token too.
    """
    header, _claims = decode_unverified(token)
    kid, alg = header.get("kid"), str(header.get("alg", ""))
    jwk = find_jwk(jwks, kid)
    if jwk is None:
        raise TokenError(f"token kid {kid!r} is not in the uploaded JWKS; Keycloak's signing "
                         "key has changed since the JWKS was uploaded to Anthropic")
    signing_input, _, sig_b64 = token.rpartition(".")
    sig = b64url_decode(sig_b64)
    digest = _HASHES.get(alg[2:])
    if digest is None:
        raise TokenError(f"unsupported token alg {alg!r}")
    key = _jwk_public_key(jwk)
    try:
        if alg.startswith("RS") and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, signing_input.encode("ascii"), padding.PKCS1v15(), digest())
        elif alg.startswith("PS") and isinstance(key, rsa.RSAPublicKey):
            key.verify(sig, signing_input.encode("ascii"),
                       padding.PSS(padding.MGF1(digest()), digest.digest_size), digest())
        elif alg.startswith("ES") and isinstance(key, ec.EllipticCurvePublicKey):
            half = len(sig) // 2
            der = encode_dss_signature(int.from_bytes(sig[:half], "big"),
                                       int.from_bytes(sig[half:], "big"))
            key.verify(der, signing_input.encode("ascii"), ec.ECDSA(digest()))
        else:
            raise TokenError(f"alg {alg!r} does not match JWK kty {jwk.get('kty')!r}")
    except InvalidSignature as exc:
        raise TokenError(f"token signature does not verify against uploaded key {kid!r}") from exc
    return header


# ------------------------------------------------------------------------ minting


def forwarded_headers_for(issuer: str) -> dict[str, str]:
    """X-Forwarded-* headers that make Keycloak issue ``issuer`` as ``iss``.

    Keycloak runs with KC_HOSTNAME=<host> (hostname only) and KC_PROXY_HEADERS=
    xforwarded, so the scheme and port in ``iss`` come from the request. Asked from
    127.0.0.1:8080 without these it reports ``http://<host>:8080/auth/...`` (measured
    by the lead), which matches no federation issuer. Deriving the headers from the
    configured issuer means the two cannot disagree; ``iss`` is still checked after.
    """
    parts = urllib.parse.urlsplit(issuer)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    return {
        "X-Forwarded-Proto": parts.scheme,
        "X-Forwarded-Host": parts.hostname or "",
        "X-Forwarded-Port": str(port),
    }


def _post(url: str, body: bytes, headers: dict[str, str], timeout: int) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - configured https/loopback URLs
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except (urllib.error.URLError, OSError) as exc:
        raise TokenError(f"POST {url} failed: {exc}") from exc


def _error_summary(body: bytes) -> str:
    """error / error_description from an OAuth error body, never the whole body."""
    try:
        doc = json.loads(body)
    except ValueError:
        return f"non-JSON body ({len(body)} bytes)"
    if isinstance(doc, dict):
        err = doc.get("error")
        if isinstance(err, dict):  # Anthropic API error envelope
            return f"{err.get('type')}: {str(err.get('message', ''))[:300]}"
        return f"{err}: {str(doc.get('error_description', ''))[:300]}"
    return "unexpected JSON"


class Minter:
    """Mints Keycloak tokens and exchanges them at Anthropic. Holds no token state."""

    def __init__(self, cfg: Config, key_pem: bytes, clock: Callable[[], float] = time.time):
        self.cfg = cfg
        self.clock = clock
        key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ConfigError("client key must be RSA (Keycloak Signed JWT, RS256)")
        self._key = key
        self.client_kid = str(cfg.extra.get("client_key_id") or keycloak_key_id(key.public_key()))
        try:
            with open(cfg.uploaded_jwks_file, encoding="utf-8") as fh:
                self.uploaded_jwks = json.load(fh)
        except (OSError, ValueError) as exc:
            raise ConfigError(f"cannot read uploaded JWKS {cfg.uploaded_jwks_file}: {exc}") from exc
        if not self.uploaded_jwks.get("keys"):
            raise ConfigError(f"uploaded JWKS {cfg.uploaded_jwks_file} has no keys; export the "
                              "realm JWKS that was uploaded to Anthropic into it")

    def client_assertion(self) -> str:
        """A fresh RFC 7523 assertion: new jti every call, 60 s lifetime."""
        now = int(self.clock())
        claims = {
            "iss": self.cfg.client_id,
            "sub": self.cfg.client_id,
            "aud": self.cfg.expected_issuer,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + 60,
        }
        return sign_rs256({"alg": "RS256", "typ": "JWT", "kid": self.client_kid}, claims,
                          self._key)

    def keycloak_token(self) -> str:
        """A new Keycloak access token for the service account (a fresh jti each time)."""
        form = urllib.parse.urlencode({
            "grant_type": "client_credentials",
            "client_id": self.cfg.client_id,
            "client_assertion_type": CLIENT_ASSERTION_TYPE,
            "client_assertion": self.client_assertion(),
        }).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "application/json",
                   **forwarded_headers_for(self.cfg.expected_issuer)}
        status, body = _post(self.cfg.keycloak_token_url, form, headers,
                             self.cfg.http_timeout_seconds)
        if status != 200:
            raise TokenError(f"Keycloak token request: HTTP {status} {_error_summary(body)}")
        try:
            token = json.loads(body)["access_token"]
        except (ValueError, KeyError, TypeError) as exc:
            raise TokenError("Keycloak token response has no access_token") from exc
        return token

    def check_claims(self, token: str) -> dict[str, Any]:
        """Refuse a token Anthropic would reject, before spending it. Returns its claims."""
        header, claims = decode_unverified(token)
        iss = claims.get("iss")
        if iss != self.cfg.expected_issuer:
            raise TokenError(f"Keycloak issued iss={iss!r}, expected "
                             f"{self.cfg.expected_issuer!r}; refusing to exchange (check "
                             "KC_HOSTNAME / proxy headers, ADR-022)")
        aud = claims.get("aud")
        auds = aud if isinstance(aud, list) else [aud]
        if self.cfg.audience not in auds:
            raise TokenError(f"token aud={aud!r} lacks {self.cfg.audience!r} (Keycloak "
                             "audience mapper on client anthropic-wif)")
        if claims.get("azp") != self.cfg.client_id:
            raise TokenError(f"token azp={claims.get('azp')!r}, expected {self.cfg.client_id!r}")
        if len(auds) > 1:
            log.warning("event=keycloak_token_extra_aud aud=%s", json.dumps(auds))
        verify_with_jwks(token, self.uploaded_jwks)
        log.info("event=keycloak_token_ok iss=%s sub=%s kid=%s exp=%s",
                 iss, claims.get("sub"), header.get("kid"), claims.get("exp"))
        return claims

    def exchange(self) -> tuple[str, float]:
        """Mint, check and exchange. Returns (access_token, absolute expiry epoch)."""
        assertion = self.keycloak_token()
        self.check_claims(assertion)
        body = json.dumps({
            "grant_type": JWT_BEARER_GRANT,
            "assertion": assertion,
            "federation_rule_id": self.cfg.federation_rule_id,
            "organization_id": self.cfg.organization_id,
            "service_account_id": self.cfg.service_account_id,
            "workspace_id": self.cfg.workspace_id,
        }).encode()
        status, resp = _post(self.cfg.anthropic_token_url, body,
                             {"Content-Type": "application/json", "Accept": "application/json"},
                             self.cfg.http_timeout_seconds)
        if status != 200:
            raise TokenError(f"Anthropic token exchange: HTTP {status} {_error_summary(resp)}")
        try:
            doc = json.loads(resp)
            token, expires_in = str(doc["access_token"]), int(doc["expires_in"])
        except (ValueError, KeyError, TypeError) as exc:
            raise TokenError("Anthropic token response lacks access_token/expires_in") from exc
        expiry = self.clock() + expires_in
        log.info("event=exchange_ok expires_in=%d expires_at=%s", expires_in,
                 time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expiry)))
        return token, expiry


# ---------------------------------------------------------------------------- cache


class TokenCache:
    """In-memory access token with the SDK's two refresh thresholds.

    advisory  (expiry - advisory_s): try to refresh; on failure keep serving the
              cached token, which is still valid.
    mandatory (expiry - mandatory_s): must refresh; on failure raise, because a
              token this close to expiry can die mid-stream.
    """

    def __init__(self, exchange: Callable[[], tuple[str, float]], advisory_s: int,
                 mandatory_s: int, clock: Callable[[], float] = time.time):
        self._exchange = exchange
        self._advisory = advisory_s
        self._mandatory = mandatory_s
        self._clock = clock
        self._lock = threading.Lock()
        self._token: str | None = None
        self._expiry = 0.0

    def get(self) -> str:
        with self._lock:
            now = self._clock()
            if self._token is not None and now < self._expiry - self._advisory:
                return self._token
            if self._token is not None and now < self._expiry - self._mandatory:
                try:
                    self._refresh()
                except TokenError as exc:
                    log.warning("event=advisory_refresh_failed serving_cached_until=%d "
                                "error=%s", int(self._expiry - self._mandatory), exc)
                return self._token
            reason = "initial" if self._token is None else "mandatory"
            try:
                self._refresh()
            except TokenError as exc:
                log.error("event=%s_refresh_failed error=%s", reason, exc)
                raise
            return self._token  # type: ignore[return-value]

    def _refresh(self) -> None:
        token, expiry = self._exchange()
        self._token, self._expiry = token, expiry
        log.info("event=token_refreshed expires_in=%d", int(expiry - self._clock()))


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


# --------------------------------------------------------------------------- server


class ForwarderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: Config, cache: TokenCache,
                 uid_lookup: Callable[[tuple[str, int], tuple[str, int]], int | None] = peer_uid):
        self.cfg = cfg
        self.cache = cache
        self.uid_lookup = uid_lookup
        super().__init__((cfg.listen_host, cfg.listen_port), ForwarderHandler)


def _error_json(kind: str, message: str) -> bytes:
    return json.dumps({"type": "error", "error": {"type": kind, "message": message}}).encode()


class ForwarderHandler(BaseHTTPRequestHandler):
    server: ForwarderServer
    # HTTP/1.0 responses: a streamed body is delimited by connection close, so no
    # re-chunking is needed and nothing is buffered.
    protocol_version = "HTTP/1.0"
    server_version = "anthropic-wif"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # The default writes the request line to stderr; paths here carry no secrets,
        # but route it through logging so the journal sees one format.
        log.info("event=http %s", format % args)

    def _reply(self, status: int, kind: str, message: str) -> None:
        body = _error_json(kind, message)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self) -> None:
        self._reply(404, "not_found_error", "anthropic-wif forwards only POST /v1/messages "
                    "and POST /v1/messages/count_tokens")

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
            self._reply(403, "permission_error", f"anthropic-wif: local uid {uid} is not "
                        "in allowed_peer_uids")
            return

        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None or not length_hdr.isdigit():
            self._reply(411, "invalid_request_error", "anthropic-wif: Content-Length required")
            return
        length = int(length_hdr)
        if length > cfg.max_body_bytes:
            self._reply(413, "request_too_large", "anthropic-wif: request body too large")
            return
        raw = self.rfile.read(length)
        try:
            model = json.loads(raw).get("model")
        except (ValueError, AttributeError):
            self._reply(400, "invalid_request_error", "anthropic-wif: body is not a JSON object")
            return
        if not isinstance(model, str) or model not in cfg.allowed_models:
            log.warning("event=model_rejected model=%r", model)
            self._reply(403, "permission_error", f"anthropic-wif: model {model!r} is not in "
                        "allowed_models")
            return

        try:
            token = self.server.cache.get()
        except TokenError as exc:
            self._reply(503, "api_error", f"anthropic-wif: no access token: {exc}")
            return

        self._forward(path, raw, token)

    def _forward(self, path: urllib.parse.SplitResult, raw: bytes, token: str) -> None:
        cfg = self.server.cfg
        base = urllib.parse.urlsplit(cfg.anthropic_base_url)
        conn_cls = (http.client.HTTPSConnection if base.scheme == "https"
                    else http.client.HTTPConnection)
        conn = conn_cls(base.netloc, timeout=cfg.upstream_timeout_seconds)
        headers = {h: self.headers[h] for h in FORWARDED_REQUEST_HEADERS if self.headers.get(h)}
        headers["Authorization"] = f"Bearer {token}"
        headers["Content-Length"] = str(len(raw))
        target = path.path + (f"?{path.query}" if path.query else "")
        try:
            conn.request("POST", target, body=raw, headers=headers)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as exc:
            conn.close()
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
            log.info("event=forwarded path=%s status=%d", path.path, resp.status)
        except OSError as exc:
            log.warning("event=client_or_upstream_dropped path=%s error=%s", path.path, exc)
        finally:
            conn.close()


# ------------------------------------------------------------------------ kid check


def fetch_json(url: str, timeout: int, headers: dict[str, str] | None = None) -> Any:
    req = urllib.request.Request(url, headers={"Accept": "application/json", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - configured loopback URL
            return json.loads(resp.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise TokenError(f"GET {url} failed: {exc}") from exc


def check_kid(cfg: Config, minter: Minter) -> list[str]:
    """Problems that would make Anthropic reject the next exchange. Empty means healthy.

    1. A freshly minted anthropic-wif token's kid must be in the uploaded JWKS, and its
       signature must verify against that key (checked by Minter.check_claims).
    2. The live realm JWKS must publish the same key material under that kid; if it
       does not, Keycloak is about to stop signing with it or already has.
    """
    problems: list[str] = []
    try:
        token = minter.keycloak_token()
        header, _ = decode_unverified(token)
        kid = header.get("kid")
        minter.check_claims(token)
    except TokenError as exc:
        return [str(exc)]
    try:
        live = fetch_json(cfg.keycloak_jwks_url, cfg.http_timeout_seconds,
                          forwarded_headers_for(cfg.expected_issuer))
    except TokenError as exc:
        return [str(exc)]
    live_jwk = find_jwk(live, kid)
    uploaded_jwk = find_jwk(minter.uploaded_jwks, kid)
    if live_jwk is None:
        problems.append(f"kid {kid!r} is no longer published in the realm JWKS")
    elif uploaded_jwk is None or _jwk_material(live_jwk) != _jwk_material(uploaded_jwk):
        problems.append(f"kid {kid!r}: realm key material differs from the uploaded JWKS")
    return problems


# ----------------------------------------------------------------------------- main


def _setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(levelname)s %(name)s %(message)s")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("serve", "check-kid"))
    parser.add_argument("--config", default="/etc/anthropic-wif/config.json")
    args = parser.parse_args(argv)
    _setup_logging()
    try:
        cfg = load_config(args.config)
        minter = Minter(cfg, read_client_key(cfg))
    except ConfigError as exc:
        log.error("event=config_error refusing to start: %s", exc)
        return EXIT_CONFIG

    if args.command == "check-kid":
        problems = check_kid(cfg, minter)
        for p in problems:
            log.error("event=kid_check_failed %s", p)
        if problems:
            return 1
        log.info("event=kid_check_ok")
        return 0

    cache = TokenCache(minter.exchange, cfg.advisory_refresh_seconds,
                       cfg.mandatory_refresh_seconds)
    server = ForwarderServer(cfg, cache)
    log.info("event=listening host=%s port=%d models=%s peer_uids=%s", cfg.listen_host,
             cfg.listen_port, ",".join(cfg.allowed_models),
             ",".join(str(u) for u in cfg.allowed_peer_uids))
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
