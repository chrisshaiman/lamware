#!/usr/bin/env python3
# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""Localhost SigV4 forwarder for Claude Platform on AWS (ADR-026).

CVP access forbids static or long-lived keys. This service holds none: the host's
private key and its short-lived certificate (issued by the owner's own CA, kept off
the host) are exchanged by AWS's ``aws_signing_helper`` for IAM Roles Anywhere
credentials that last about an hour, kept in memory only. Each forwarded request is
signed with SigV4 for the ``aws-external-anthropic`` service.

It forwards ONLY ``POST /v1/messages`` and ``POST /v1/messages/count_tokens``, for
allowlisted models, from allowlisted local uids. The workspace id comes from this
service's config, never from the caller. Request headers pass through an allowlist,
so an ``x-api-key`` or ``authorization`` from the caller never leaves the host.
Response bodies are streamed through unchanged, which keeps SSE and the ``usage``
block (CLAUDE.md section 10, read by LiteLLM) intact.

Subcommands:

  serve  the forwarder (systemd ``claude-platform-aws.service``)
  check  the daily health check (``claude-platform-aws-check.timer``): gets
         credentials, counts tokens on the first allowlisted model (free), and fails
         when the host certificate has fewer than ``cert_warn_days`` left

Stdlib only. Never logged: the credentials, the signature, request or response bodies.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

log = logging.getLogger("claude-platform-aws")

SERVICE = "aws-external-anthropic"
DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
FORWARDED_PATHS = frozenset({"/v1/messages", "/v1/messages/count_tokens"})

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

REQUIRED_STRINGS = (
    "region", "workspace_id", "signing_helper", "certificate_file", "private_key_file",
    "trust_anchor_arn", "profile_arn", "role_arn",
)
_REGION = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+\Z")


class ConfigError(Exception):
    """The configuration cannot run safely; the message says which field and why."""


class CredentialError(Exception):
    """Getting credentials failed. The message never holds a credential."""


# --------------------------------------------------------------------------- config


@dataclass(frozen=True)
class Config:
    """Validated runtime configuration (``/etc/claude-platform-aws/config.json``)."""

    region: str
    workspace_id: str
    signing_helper: str
    certificate_file: str
    private_key_file: str
    trust_anchor_arn: str
    profile_arn: str
    role_arn: str
    listen_host: str = "127.0.0.1"
    listen_port: int = 4010
    allowed_models: tuple[str, ...] = ("claude-mythos-5-1",)
    allowed_peer_uids: tuple[int, ...] = (0,)
    # Credentials last about an hour: refresh 5 minutes early, keep serving the cached
    # ones if that fails, and fail 60 s before expiry rather than sign with
    # credentials that can die mid-stream.
    advisory_refresh_seconds: int = 300
    mandatory_refresh_seconds: int = 60
    max_body_bytes: int = 32 * 1024 * 1024
    upstream_timeout_seconds: int = 900
    helper_timeout_seconds: int = 30
    cert_warn_days: int = 4
    # Tests point this at a local fake. Empty means the regional endpoint.
    upstream_base_url: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def base_url(self) -> str:
        return self.upstream_base_url or f"https://{SERVICE}.{self.region}.api.aws"


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
        raise ConfigError(
            "empty or missing: " + ", ".join(missing)
            + " (set the claude_platform_aws_* variables in ansible/vars/main.yml; "
            "ADR-026 lists the AWS resources they name)")

    known = {f for f in Config.__dataclass_fields__ if f != "extra"}
    kwargs: dict[str, Any] = {k: raw[k] for k in known if k in raw}
    for key in ("allowed_models", "allowed_peer_uids"):
        if key in kwargs:
            kwargs[key] = tuple(kwargs[key] or ())
    kwargs["extra"] = {k: v for k, v in raw.items() if k not in known}
    cfg = Config(**kwargs)

    problems: list[str] = []
    try:
        if not ipaddress.ip_address(cfg.listen_host).is_loopback:
            problems.append(f"listen_host {cfg.listen_host} is not a loopback address")
    except ValueError:
        problems.append(f"listen_host {cfg.listen_host!r} is not an IP address")
    if not _REGION.match(cfg.region):
        problems.append(f"region {cfg.region!r} is not an AWS region name")
    if not cfg.workspace_id.startswith("wrkspc_"):
        problems.append("workspace_id must be a Claude workspace id (wrkspc_...)")
    for name, prefix in (("trust_anchor_arn", "arn:aws:rolesanywhere:"),
                         ("profile_arn", "arn:aws:rolesanywhere:"),
                         ("role_arn", "arn:aws:iam::")):
        if not getattr(cfg, name).startswith(prefix):
            problems.append(f"{name} must start with {prefix}")
    if not cfg.allowed_models:
        problems.append("allowed_models is empty: nothing could be forwarded")
    if not cfg.allowed_peer_uids:
        problems.append("allowed_peer_uids is empty: no local caller could connect")
    if not 0 < cfg.mandatory_refresh_seconds < cfg.advisory_refresh_seconds:
        problems.append("need 0 < mandatory_refresh_seconds < advisory_refresh_seconds")
    if cfg.upstream_base_url and not cfg.upstream_base_url.startswith(("https://", "http://127.")):
        problems.append("upstream_base_url must be https (or a loopback test server)")
    # A static key in this process's environment means someone tried to configure one
    # into this path. Nothing here reads them; their presence is the error.
    for var in ("ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        if environ.get(var):
            problems.append(f"{var} is set in the environment; this path carries no "
                            "static key (ADR-026)")
    if problems:
        raise ConfigError("; ".join(problems))
    return cfg


def credential_paths(cfg: Config, environ: dict[str, str] | None = None) -> tuple[str, str]:
    """Certificate and key paths, via systemd LoadCredential when available.

    The key file stays root-owned 0400; systemd hands this unit a private copy under
    $CREDENTIALS_DIRECTORY that only the service user can read.
    """
    environ = os.environ if environ is None else environ
    cred_dir = environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        cert, key = os.path.join(cred_dir, "host.pem"), os.path.join(cred_dir, "host.key")
        if os.path.exists(cert) and os.path.exists(key):
            return cert, key
    return cfg.certificate_file, cfg.private_key_file


# ------------------------------------------------------------------ credentials


@dataclass(frozen=True)
class AwsCredentials:
    """Temporary credentials. repr=False on the secrets: never printed by accident."""

    access_key_id: str = field(repr=False)
    secret_access_key: str = field(repr=False)
    session_token: str = field(repr=False)
    expiry: float = 0.0


def _parse_expiration(text: str) -> float:
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()


def fetch_credentials(cfg: Config, cert: str, key: str,
                      run: Callable[..., subprocess.CompletedProcess] = subprocess.run
                      ) -> AwsCredentials:
    """Exchange the host certificate for temporary credentials (aws_signing_helper)."""
    cmd = [cfg.signing_helper, "credential-process",
           "--certificate", cert, "--private-key", key,
           "--trust-anchor-arn", cfg.trust_anchor_arn,
           "--profile-arn", cfg.profile_arn, "--role-arn", cfg.role_arn]
    try:
        proc = run(cmd, capture_output=True, text=True, timeout=cfg.helper_timeout_seconds)
    except (OSError, subprocess.SubprocessError) as exc:
        raise CredentialError(f"aws_signing_helper did not run: {exc}") from exc
    if proc.returncode != 0:
        # The helper's stderr names the AWS error (AccessDenied, expired certificate);
        # it never contains credentials. stdout may, so it is never quoted.
        raise CredentialError(f"aws_signing_helper exited {proc.returncode}: "
                              f"{(proc.stderr or '').strip()[-400:]}")
    try:
        doc = json.loads(proc.stdout)
        return AwsCredentials(doc["AccessKeyId"], doc["SecretAccessKey"],
                              doc["SessionToken"], _parse_expiration(doc["Expiration"]))
    except (ValueError, KeyError, TypeError) as exc:
        raise CredentialError(f"aws_signing_helper output is not a credential document "
                              f"({type(exc).__name__})") from exc


class CredentialCache:
    """In-memory credentials with two refresh thresholds.

    advisory  (expiry - advisory_s): try to refresh; on failure keep serving the
              cached credentials, which are still valid.
    mandatory (expiry - mandatory_s): must refresh; on failure raise, because
              credentials this close to expiry can die mid-stream.
    """

    def __init__(self, fetch: Callable[[], AwsCredentials], advisory_s: int,
                 mandatory_s: int, clock: Callable[[], float] = time.time):
        self._fetch = fetch
        self._advisory = advisory_s
        self._mandatory = mandatory_s
        self._clock = clock
        self._lock = threading.Lock()
        self._creds: AwsCredentials | None = None

    def get(self) -> AwsCredentials:
        with self._lock:
            now = self._clock()
            c = self._creds
            if c is not None and now < c.expiry - self._advisory:
                return c
            if c is not None and now < c.expiry - self._mandatory:
                try:
                    self._refresh()
                except CredentialError as exc:
                    log.warning("event=advisory_refresh_failed serving_cached_until=%d "
                                "error=%s", int(c.expiry - self._mandatory), exc)
                return self._creds  # type: ignore[return-value]
            reason = "initial" if c is None else "mandatory"
            try:
                self._refresh()
            except CredentialError as exc:
                log.error("event=%s_refresh_failed error=%s", reason, exc)
                raise
            return self._creds  # type: ignore[return-value]

    def _refresh(self) -> None:
        creds = self._fetch()
        self._creds = creds
        log.info("event=credentials_refreshed expires_in=%d", int(creds.expiry - self._clock()))


# ------------------------------------------------------------------------- SigV4


def _uri_encode(text: str, keep_slash: bool) -> str:
    return urllib.parse.quote(text, safe="/~" if keep_slash else "~")


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4_headers(method: str, host: str, path: str, query: str, headers: dict[str, str],
                  body: bytes, creds: AwsCredentials, region: str, service: str,
                  now: dt.datetime) -> dict[str, str]:
    """Headers to send: ``headers`` plus host, X-Amz-Date, the session token and the
    Authorization header (AWS Signature Version 4, every given header signed)."""
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    scope_date = amz_date[:8]
    out = {**headers, "Host": host, "X-Amz-Date": amz_date}
    if creds.session_token:
        out["X-Amz-Security-Token"] = creds.session_token

    canon = {k.lower(): " ".join(str(v).strip().split()) for k, v in out.items()}
    signed = ";".join(sorted(canon))
    canonical_headers = "".join(f"{k}:{canon[k]}\n" for k in sorted(canon))
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    canonical_query = "&".join(f"{_uri_encode(k, False)}={_uri_encode(v, False)}"
                               for k, v in sorted(pairs))
    canonical_request = "\n".join([
        method, _uri_encode(path or "/", True), canonical_query,
        canonical_headers, signed, hashlib.sha256(body).hexdigest()])

    scope = f"{scope_date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope,
                         hashlib.sha256(canonical_request.encode()).hexdigest()])
    key = _hmac(("AWS4" + creds.secret_access_key).encode(), scope_date)
    for part in (region, service, "aws4_request"):
        key = _hmac(key, part)
    signature = hmac.new(key, to_sign.encode(), hashlib.sha256).hexdigest()
    out["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={creds.access_key_id}/{scope}, "
                            f"SignedHeaders={signed}, Signature={signature}")
    return out


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


def _connection(cfg: Config) -> tuple[http.client.HTTPConnection, str]:
    base = urllib.parse.urlsplit(cfg.base_url)
    if base.scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            base.netloc, timeout=cfg.upstream_timeout_seconds,
            context=ssl.create_default_context())
    else:
        conn = http.client.HTTPConnection(base.netloc, timeout=cfg.upstream_timeout_seconds)
    return conn, base.netloc


def signed_request(cfg: Config, creds: AwsCredentials, path: str, query: str, raw: bytes,
                   caller_headers: dict[str, str],
                   now: Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC)
                   ) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    """Open the upstream connection and send one signed POST. Caller closes ``conn``."""
    conn, host = _connection(cfg)
    headers = {h: v for h, v in caller_headers.items() if v}
    headers.setdefault("anthropic-version", DEFAULT_ANTHROPIC_VERSION)
    headers.setdefault("content-type", "application/json")
    # From config, never from the caller: the workspace is what the IAM policy scopes.
    headers["anthropic-workspace-id"] = cfg.workspace_id
    headers["Content-Length"] = str(len(raw))
    signed = sigv4_headers("POST", host, path, query, headers, raw, creds,
                           cfg.region, SERVICE, now())
    target = path + (f"?{query}" if query else "")
    try:
        conn.request("POST", target, body=raw, headers=signed)
        return conn, conn.getresponse()
    except BaseException:
        conn.close()
        raise


# --------------------------------------------------------------------------- server


class ForwarderServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, cfg: Config, cache: CredentialCache,
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
    server_version = "claude-platform-aws"
    sys_version = ""

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
        self._reply(404, "not_found_error", "claude-platform-aws forwards only POST "
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
            self._reply(403, "permission_error", f"claude-platform-aws: local uid {uid} is "
                        "not in allowed_peer_uids")
            return

        length_hdr = self.headers.get("Content-Length")
        if length_hdr is None or not length_hdr.isdigit():
            self._reply(411, "invalid_request_error", "claude-platform-aws: Content-Length "
                        "required")
            return
        length = int(length_hdr)
        if length > cfg.max_body_bytes:
            self._reply(413, "request_too_large", "claude-platform-aws: request body too large")
            return
        raw = self.rfile.read(length)
        try:
            model = json.loads(raw).get("model")
        except (ValueError, AttributeError):
            self._reply(400, "invalid_request_error", "claude-platform-aws: body is not a "
                        "JSON object")
            return
        if not isinstance(model, str) or model not in cfg.allowed_models:
            log.warning("event=model_rejected model=%r", model)
            self._reply(403, "permission_error", f"claude-platform-aws: model {model!r} is "
                        "not in allowed_models")
            return

        try:
            creds = self.server.cache.get()
        except CredentialError as exc:
            self._reply(503, "api_error", f"claude-platform-aws: no credentials: {exc}")
            return
        self._forward(path, raw, creds)

    def _forward(self, path: urllib.parse.SplitResult, raw: bytes, creds: AwsCredentials) -> None:
        cfg = self.server.cfg
        caller = {h: self.headers[h] for h in FORWARDED_REQUEST_HEADERS if self.headers.get(h)}
        try:
            conn, resp = signed_request(cfg, creds, path.path, path.query, raw, caller)
        except (OSError, http.client.HTTPException) as exc:
            log.error("event=upstream_failed error=%s", exc)
            self._reply(502, "api_error", f"claude-platform-aws: upstream request failed: {exc}")
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


# ------------------------------------------------------------------------------ check


def cert_days_left(cert_path: str,
                   run: Callable[..., subprocess.CompletedProcess] = subprocess.run,
                   now: Callable[[], float] = time.time) -> float:
    """Days until the host certificate expires (openssl; no crypto library needed)."""
    proc = run(["openssl", "x509", "-noout", "-enddate", "-in", cert_path],
               capture_output=True, text=True, timeout=10)
    if proc.returncode != 0 or "notAfter=" not in proc.stdout:
        raise CredentialError(f"cannot read the host certificate: {proc.stderr.strip()[:200]}")
    end = dt.datetime.strptime(proc.stdout.strip().split("=", 1)[1], "%b %d %H:%M:%S %Y %Z")
    return (end.replace(tzinfo=dt.UTC).timestamp() - now()) / 86400


def check(cfg: Config, cert: str, key: str,
          fetch: Callable[[], AwsCredentials] | None = None) -> list[str]:
    """Problems that would stop the next eval call. Empty means healthy.

    1. The certificate has more than cert_warn_days left (a deploy renews it).
    2. It still yields credentials (trust anchor, profile and role intact).
    3. Those credentials can count tokens on the first allowlisted model in the
       workspace (IAM policy and workspace intact). Counting tokens is not billed.
    """
    problems: list[str] = []
    try:
        days = cert_days_left(cert)
        log.info("event=cert_days_left days=%.1f", days)
        if days < cfg.cert_warn_days:
            problems.append(f"the host certificate expires in {days:.1f} days; "
                            "deploy the claude-platform-aws role to renew it")
    except (CredentialError, OSError, subprocess.SubprocessError, ValueError) as exc:
        problems.append(f"certificate: {exc}")
    try:
        creds = (fetch or (lambda: fetch_credentials(cfg, cert, key)))()
    except CredentialError as exc:
        return problems + [str(exc)]
    body = json.dumps({"model": cfg.allowed_models[0],
                       "messages": [{"role": "user", "content": "health check"}]}).encode()
    try:
        conn, resp = signed_request(cfg, creds, "/v1/messages/count_tokens", "", body, {})
    except (OSError, http.client.HTTPException) as exc:
        return problems + [f"count_tokens did not complete: {exc}"]
    try:
        payload = resp.read()
    finally:
        conn.close()
    if resp.status != 200:
        problems.append(f"count_tokens returned {resp.status}: {_error_summary(payload)}")
    return problems


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
    parser.add_argument("command", choices=("serve", "check"))
    parser.add_argument("--config", default="/etc/claude-platform-aws/config.json")
    args = parser.parse_args(argv)
    _setup_logging()
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        log.error("event=config_error refusing to start: %s", exc)
        return EXIT_CONFIG
    cert, key = credential_paths(cfg)

    if args.command == "check":
        problems = check(cfg, cert, key)
        for p in problems:
            log.error("event=check_failed %s", p)
        if problems:
            return 1
        log.info("event=check_ok")
        return 0

    cache = CredentialCache(lambda: fetch_credentials(cfg, cert, key),
                            cfg.advisory_refresh_seconds, cfg.mandatory_refresh_seconds)
    server = ForwarderServer(cfg, cache)
    log.info("event=listening host=%s port=%d region=%s models=%s peer_uids=%s",
             cfg.listen_host, cfg.listen_port, cfg.region, ",".join(cfg.allowed_models),
             ",".join(str(u) for u in cfg.allowed_peer_uids))
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
