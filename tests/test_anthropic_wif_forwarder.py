# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The anthropic-wif forwarder (ADR-022), run against a fake Keycloak and a fake Anthropic.

Behavioural: the real module is imported and served on a loopback port; real HTTP goes
through it to two in-process fakes.

  fake Keycloak   verifies the RS256 client assertion against the client's PUBLIC key
                  (so private_key_jwt is exercised, not assumed), then issues an RS256
                  access token signed with a "realm" key. Like Keycloak with
                  KC_HOSTNAME=<host> and KC_PROXY_HEADERS=xforwarded, it builds `iss`
                  from the X-Forwarded-* headers, falling back to http://<host>:8080,
                  which is what the lead measured from 127.0.0.1.
  fake Anthropic  /v1/oauth/token records each assertion and returns a token with a
                  configurable expires_in; /v1/messages records headers and streams SSE
                  in two halves gated on an Event, so a buffering proxy deadlocks
                  (times out) instead of passing.

What this cannot observe: the real Keycloak 26.1, the real token endpoint, LiteLLM, the
systemd sandbox. Those are listed under Not verified in the PR.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import os
import sys
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

pytest.importorskip("cryptography")
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ansible/roles/anthropic-wif/files"))
import anthropic_wif as wif  # noqa: E402

ISSUER = "https://lamware.example.test/auth/realms/lamware"
AUDIENCE = "https://api.anthropic.com"
CLIENT_ID = "anthropic-wif"
SUB = "6f1c0d3e-0000-4000-8000-000000000001"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwk(pub: rsa.RSAPublicKey, kid: str) -> dict:
    nums = pub.public_numbers()
    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": _b64(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": _b64(nums.e.to_bytes(3, "big"))}


def _sign(header: dict, claims: dict, key: rsa.RSAPrivateKey) -> str:
    si = _b64(json.dumps(header).encode()) + "." + _b64(json.dumps(claims).encode())
    return si + "." + _b64(key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256()))


def _verify(token: str, pub: rsa.RSAPublicKey) -> dict:
    si, _, sig = token.rpartition(".")
    pub.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), si.encode(),
               padding.PKCS1v15(), hashes.SHA256())
    return json.loads(base64.urlsafe_b64decode(si.split(".")[1] + "=="))


class _Server:
    """Run a handler class on a loopback port in a thread."""

    def __init__(self, handler):
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, args=(0.05,), daemon=True).start()

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class FakeKeycloak:
    def __init__(self, client_pub: rsa.RSAPublicKey):
        self.realm_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "realm-rs256-1"
        self.client_pub = client_pub
        self.iss_override: str | None = None
        self.aud: object = AUDIENCE
        self.azp = CLIENT_ID
        self.assertion_jtis: list[str] = []
        self.issued: list[str] = []
        self.forwarded: list[dict] = []
        self.published_jwks: dict | None = None  # None -> publish the signing key
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path.endswith("/certs"):
                    body = json.dumps(outer.published_jwks if outer.published_jwks is not None
                                      else outer.jwks()).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    self.send_error(404)

            def do_POST(self):
                form = urllib.parse.parse_qs(
                    self.rfile.read(int(self.headers["Content-Length"])).decode())
                assertion = form["client_assertion"][0]
                try:
                    claims = _verify(assertion, outer.client_pub)
                except Exception:  # invalid_client, as Keycloak would say
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"error":"invalid_client"}')
                    return
                outer.assertion_jtis.append(claims["jti"])
                fh = {k: self.headers.get(k) for k in
                      ("X-Forwarded-Proto", "X-Forwarded-Host", "X-Forwarded-Port")}
                outer.forwarded.append(fh)
                if fh["X-Forwarded-Proto"]:
                    port = fh["X-Forwarded-Port"]
                    default = {"https": "443", "http": "80"}[fh["X-Forwarded-Proto"]]
                    host = fh["X-Forwarded-Host"] + ("" if port == default else f":{port}")
                    iss = f"{fh['X-Forwarded-Proto']}://{host}/auth/realms/lamware"
                else:
                    iss = "http://lamware.example.test:8080/auth/realms/lamware"
                now = int(time.time())
                token = _sign({"alg": "RS256", "typ": "JWT", "kid": outer.kid},
                              {"iss": outer.iss_override or iss, "aud": outer.aud,
                               "azp": outer.azp, "sub": SUB, "jti": str(uuid.uuid4()),
                               "iat": now, "exp": now + 300}, outer.realm_key)
                outer.issued.append(token)
                body = json.dumps({"access_token": token, "expires_in": 300,
                                   "token_type": "Bearer"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = _Server(H)

    def jwks(self) -> dict:
        return {"keys": [_jwk(self.realm_key.public_key(), self.kid)]}


SSE_FIRST = (b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":"
             b"{\"usage\":{\"input_tokens\":7,\"output_tokens\":1}}}\n\n")
SSE_REST = (b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\","
            b"\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n"
            b"event: message_delta\ndata: {\"type\":\"message_delta\","
            b"\"usage\":{\"output_tokens\":2}}\n\n"
            b"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")


class FakeAnthropic:
    def __init__(self):
        self.exchanges: list[dict] = []
        self.minted: list[str] = []
        self.requests: list[dict] = []
        self.expires_in = 600
        self.exchange_status = 200
        self.release_stream = threading.Event()
        outer = self

        class H(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):
                pass

            def do_POST(self):
                raw = self.rfile.read(int(self.headers["Content-Length"]))
                if self.path == "/v1/oauth/token":
                    doc = json.loads(raw)
                    outer.exchanges.append(doc)
                    if outer.exchange_status != 200:
                        body = b'{"error":"invalid_grant","error_description":"nope"}'
                        self.send_response(outer.exchange_status)
                    else:
                        tok = f"sk-ant-oat01-fake-{uuid.uuid4().hex}"
                        outer.minted.append(tok)
                        body = json.dumps({"access_token": tok, "token_type": "Bearer",
                                           "expires_in": outer.expires_in}).encode()
                        self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                outer.requests.append({"path": self.path, "headers": dict(self.headers.items()),
                                       "body": json.loads(raw)})
                if json.loads(raw).get("stream"):
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Transfer-Encoding", "chunked")
                    self.send_header("request-id", "req_fake")
                    self.end_headers()
                    for part, wait in ((SSE_FIRST, True), (SSE_REST, False)):
                        self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                        self.wfile.flush()
                        if wait:
                            outer.release_stream.wait(10)
                    self.wfile.write(b"0\r\n\r\n")
                    return
                body = json.dumps({"input_tokens": 12} if self.path.startswith(
                    "/v1/messages/count_tokens") else
                    {"type": "message", "usage": {"input_tokens": 5, "output_tokens": 3}}
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = _Server(H)


class _Collect(logging.Handler):
    """Every record the forwarder logs for the fixture's whole life.

    Not caplog: in fixture teardown caplog.text holds only TEARDOWN-phase records, so a
    leak check there read an empty string and passed while the token was being logged
    (found by mutation).
    """

    def __init__(self):
        super().__init__(logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record):
        self.lines.append(record.getMessage())

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@pytest.fixture
def env(tmp_path, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    collected = _Collect()
    wif.log.addHandler(collected)
    # main() reads the real environment; a developer's own key must not fail it.
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("CREDENTIALS_DIRECTORY", raising=False)
    client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = tmp_path / "client-key.pem"
    key_path.write_bytes(client_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    kc = FakeKeycloak(client_key.public_key())
    an = FakeAnthropic()
    jwks_path = tmp_path / "uploaded-jwks.json"
    jwks_path.write_text(json.dumps(kc.jwks()))
    cfg_dict = {
        "listen_host": "127.0.0.1", "listen_port": 0,
        "allowed_peer_uids": [os.getuid()], "allowed_models": ["claude-mythos-5-1"],
        "keycloak_token_url": kc.server.base + "/auth/realms/lamware/protocol/openid-connect/token",
        "keycloak_jwks_url": kc.server.base + "/auth/realms/lamware/protocol/openid-connect/certs",
        "client_id": CLIENT_ID, "client_key_file": str(key_path),
        "expected_issuer": ISSUER, "audience": AUDIENCE, "uploaded_jwks_file": str(jwks_path),
        "anthropic_token_url": an.server.base + "/v1/oauth/token",
        "anthropic_base_url": an.server.base,
        "organization_id": "org-test", "workspace_id": "wrkspc-test",
        "service_account_id": "svac-test", "federation_rule_id": "fdrl-test",
    }
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps(cfg_dict))
    cfg = wif.load_config(str(cfg_path), environ={})
    clock = {"now": time.time()}
    minter = wif.Minter(cfg, wif.read_client_key(cfg, environ={}),
                        clock=lambda: clock["now"])
    cache = wif.TokenCache(minter.exchange, cfg.advisory_refresh_seconds,
                           cfg.mandatory_refresh_seconds, clock=lambda: clock["now"])
    server = wif.ForwarderServer(cfg, cache)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()

    class E:
        pass

    e = E()
    e.kc, e.an, e.cfg, e.cfg_dict, e.cfg_path, e.minter = kc, an, cfg, cfg_dict, cfg_path, minter
    e.cache, e.server, e.clock, e.caplog, e.tmp = cache, server, clock, caplog, tmp_path
    e.port = server.server_address[1]
    yield e
    an.release_stream.set()
    server.shutdown()
    server.server_close()
    kc.server.stop()
    an.server.stop()
    # Never logged: any assertion, Keycloak token or Anthropic token from this test.
    secrets_seen = kc.issued + an.minted + [x["assertion"] for x in an.exchanges]
    wif.log.removeHandler(collected)
    if secrets_seen:  # tokens were minted, so the forwarder logged the exchange
        assert collected.lines, "nothing was collected; the leak check would be vacuous"
    leaked = [s[:16] for s in secrets_seen if s in collected.text]
    assert not leaked, f"token text reached the log: {leaked}"
    assert "sk-ant-oat01" not in collected.text


def _post(e, path: str, body: dict, headers: dict | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", e.port, timeout=15)
    raw = json.dumps(body).encode()
    conn.request("POST", path, body=raw, headers={"Content-Type": "application/json",
                                                  "anthropic-version": "2023-06-01",
                                                  **(headers or {})})
    resp = conn.getresponse()
    return resp, resp.read(), conn


MSG = {"model": "claude-mythos-5-1", "max_tokens": 8,
       "messages": [{"role": "user", "content": "hi"}]}


# ------------------------------------------------------------------ exchange + headers


def test_forwards_with_bearer_and_strips_caller_credentials(env):
    resp, body, _ = _post(env, "/v1/messages", MSG, {
        "x-api-key": "sk-anthropic-wif-placeholder", "Authorization": "Bearer caller-sent",
        "Cookie": "a=b", "anthropic-beta": "some-beta"})
    assert resp.status == 200, body
    assert json.loads(body)["usage"] == {"input_tokens": 5, "output_tokens": 3}
    (req,) = env.an.requests
    hdrs = {k.lower(): v for k, v in req["headers"].items()}
    assert "x-api-key" not in hdrs
    assert "cookie" not in hdrs
    assert hdrs["authorization"] == f"Bearer {env.an.minted[0]}"
    assert hdrs["anthropic-version"] == "2023-06-01"
    assert hdrs["anthropic-beta"] == "some-beta"
    # The exchange carried every id and the jwt-bearer grant.
    (ex,) = env.an.exchanges
    assert ex["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assert (ex["organization_id"], ex["workspace_id"], ex["service_account_id"],
            ex["federation_rule_id"]) == ("org-test", "wrkspc-test", "svac-test", "fdrl-test")
    assert ex["assertion"] == env.kc.issued[0]


def test_keycloak_is_asked_for_the_canonical_https_issuer(env):
    _post(env, "/v1/messages", MSG)
    assert env.kc.forwarded[0] == {"X-Forwarded-Proto": "https",
                                   "X-Forwarded-Host": "lamware.example.test",
                                   "X-Forwarded-Port": "443"}
    claims = json.loads(base64.urlsafe_b64decode(env.kc.issued[0].split(".")[1] + "=="))
    assert claims["iss"] == ISSUER


def test_count_tokens_forwarded_with_query(env):
    resp, body, _ = _post(env, "/v1/messages/count_tokens?beta=true", MSG)
    assert resp.status == 200 and json.loads(body) == {"input_tokens": 12}
    assert env.an.requests[0]["path"] == "/v1/messages/count_tokens?beta=true"


def test_each_exchange_uses_a_fresh_jwt(env):
    """jti-bearing JWTs are single-use at Anthropic: every exchange mints a new one."""
    _post(env, "/v1/messages", MSG)
    env.clock["now"] += 600  # past expiry: mandatory refresh
    _post(env, "/v1/messages", MSG)
    env.clock["now"] += 600
    _post(env, "/v1/messages", MSG)
    assertions = [x["assertion"] for x in env.an.exchanges]
    assert len(assertions) == 3 and len(set(assertions)) == 3
    jtis = [json.loads(base64.urlsafe_b64decode(a.split(".")[1] + "=="))["jti"]
            for a in assertions]
    assert len(set(jtis)) == 3
    assert len(set(env.kc.assertion_jtis)) == 3  # client assertions fresh too


def test_cached_token_reused_inside_its_lifetime(env):
    for _ in range(3):
        _post(env, "/v1/messages", MSG)
    assert len(env.an.exchanges) == 1
    assert len({r["headers"]["Authorization"] for r in env.an.requests}) == 1


# ---------------------------------------------------------------------- refusals


def test_wrong_issuer_is_refused_before_exchange(env):
    env.kc.iss_override = "http://lamware.example.test:8080/auth/realms/lamware"
    resp, body, _ = _post(env, "/v1/messages", MSG)
    assert resp.status == 503
    assert "iss=" in json.loads(body)["error"]["message"]
    assert env.an.exchanges == [] and env.an.requests == []


def test_wrong_audience_or_azp_is_refused(env):
    env.kc.aud = "account"
    assert _post(env, "/v1/messages", MSG)[0].status == 503
    env.kc.aud, env.kc.azp = AUDIENCE, "lamware-web"
    assert _post(env, "/v1/messages", MSG)[0].status == 503
    assert env.an.exchanges == []


def test_rotated_realm_key_is_refused_before_exchange(env):
    """Keycloak signing with a key that was never uploaded: Anthropic would reject it."""
    env.kc.realm_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    resp, body, _ = _post(env, "/v1/messages", MSG)
    assert resp.status == 503 and "signature" in json.loads(body)["error"]["message"]
    env.kc.kid = "realm-rs256-2"
    resp, body, _ = _post(env, "/v1/messages", MSG)
    assert resp.status == 503 and "kid" in json.loads(body)["error"]["message"]
    assert env.an.exchanges == []


@pytest.mark.parametrize("model", ["claude-opus-5", "eval-mythos", None, 7])
def test_non_allowlisted_model_is_rejected_without_minting(env, model):
    body = dict(MSG, model=model)
    resp, raw, _ = _post(env, "/v1/messages", body)
    assert resp.status == 403 and "allowed_models" in json.loads(raw)["error"]["message"]
    assert env.kc.issued == [] and env.an.requests == []


@pytest.mark.parametrize("path", ["/v1/complete", "/v1/models", "/v1/messages/batches",
                                  "/v1/oauth/token", "/", "/v1/messages/"])
def test_other_paths_404(env, path):
    assert _post(env, path, MSG)[0].status == 404
    assert env.kc.issued == []


def test_get_on_messages_404(env):
    conn = http.client.HTTPConnection("127.0.0.1", env.port, timeout=5)
    conn.request("GET", "/v1/messages")
    assert conn.getresponse().status == 404


def test_peer_uid_outside_allowlist_is_rejected(env):
    object.__setattr__(env.cfg, "allowed_peer_uids", (os.getuid() + 1,))
    resp, raw, _ = _post(env, "/v1/messages", MSG)
    assert resp.status == 403 and "uid" in json.loads(raw)["error"]["message"]
    assert env.kc.issued == []


def test_peer_uid_reads_the_kernel_table(env):
    """The real /proc/net/tcp lookup, not a stub: our own connection maps to our uid."""
    import socket
    s = socket.create_connection(("127.0.0.1", env.port))
    try:
        assert wif.peer_uid(s.getsockname(), ("127.0.0.1", env.port)) == os.getuid()
        assert wif.peer_uid(s.getsockname(), ("127.0.0.1", 1)) is None
    finally:
        s.close()


# ------------------------------------------------------------------------ streaming


def test_sse_streams_through_unbuffered_and_intact(env):
    conn = http.client.HTTPConnection("127.0.0.1", env.port, timeout=15)
    conn.request("POST", "/v1/messages", body=json.dumps(dict(MSG, stream=True)),
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 200
    assert resp.getheader("Content-Type") == "text/event-stream"
    assert resp.getheader("request-id") == "req_fake"
    # The fake holds the rest of the stream until we have seen the first event. A
    # forwarder that buffered the response would never deliver it: this read times out.
    first = b""
    while len(first) < len(SSE_FIRST):
        chunk = resp.read1(65536)
        assert chunk, "stream ended before the first event"
        first += chunk
    assert first == SSE_FIRST
    env.an.release_stream.set()
    rest = resp.read()
    assert first + rest == SSE_FIRST + SSE_REST


# ------------------------------------------------------------------- refresh schedule


class _Exchange:
    def __init__(self, clock, lifetime=600):
        self.clock, self.lifetime, self.calls, self.fail = clock, lifetime, 0, False

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise wif.TokenError("exchange down")
        return f"tok{self.calls}", self.clock["now"] + self.lifetime


def _cache():
    clock = {"now": 1000.0}
    ex = _Exchange(clock)
    return wif.TokenCache(ex, 120, 30, clock=lambda: clock["now"]), ex, clock


def test_no_refresh_before_advisory_threshold():
    cache, ex, clock = _cache()
    assert cache.get() == "tok1"
    clock["now"] += 600 - 120 - 1
    assert cache.get() == "tok1" and ex.calls == 1


def test_refresh_at_advisory_threshold():
    cache, ex, clock = _cache()
    cache.get()
    clock["now"] += 600 - 120
    assert cache.get() == "tok2" and ex.calls == 2


def test_advisory_failure_serves_cached_token():
    cache, ex, clock = _cache()
    cache.get()
    clock["now"] += 600 - 100  # inside advisory, outside mandatory
    ex.fail = True
    assert cache.get() == "tok1"
    assert ex.calls == 2  # it did try


def test_mandatory_failure_raises():
    cache, ex, clock = _cache()
    cache.get()
    clock["now"] += 600 - 30
    ex.fail = True
    with pytest.raises(wif.TokenError):
        cache.get()


def test_just_before_mandatory_still_serves_cached_on_failure():
    cache, ex, clock = _cache()
    cache.get()
    clock["now"] += 600 - 31
    ex.fail = True
    assert cache.get() == "tok1"


def test_initial_failure_raises():
    cache, ex, _ = _cache()
    ex.fail = True
    with pytest.raises(wif.TokenError):
        cache.get()


def test_mandatory_failure_is_a_503_end_to_end(env):
    _post(env, "/v1/messages", MSG)
    env.clock["now"] += 600 - 20
    env.an.exchange_status = 400
    resp, raw, _ = _post(env, "/v1/messages", MSG)
    assert resp.status == 503 and "invalid_grant" in json.loads(raw)["error"]["message"]
    assert len(env.an.requests) == 1


def test_advisory_failure_end_to_end_keeps_serving(env):
    _post(env, "/v1/messages", MSG)
    env.clock["now"] += 600 - 60
    env.an.exchange_status = 500
    resp, _, _ = _post(env, "/v1/messages", MSG)
    assert resp.status == 200
    assert len(env.an.exchanges) == 2 and len(env.an.minted) == 1
    assert env.an.requests[1]["headers"]["Authorization"] == f"Bearer {env.an.minted[0]}"


# ----------------------------------------------------------------------------- config


def test_empty_ids_refuse_to_start(env):
    d = dict(env.cfg_dict, organization_id="", federation_rule_id="")
    p = env.tmp / "empty.json"
    p.write_text(json.dumps(d))
    with pytest.raises(wif.ConfigError, match="organization_id, .*federation_rule_id"):
        wif.load_config(str(p), environ={})
    assert wif.main(["serve", "--config", str(p)]) == wif.EXIT_CONFIG


@pytest.mark.parametrize("override,needle", [
    ({"listen_host": "0.0.0.0"}, "loopback"),
    ({"allowed_models": []}, "allowed_models"),
    ({"allowed_peer_uids": []}, "allowed_peer_uids"),
    ({"expected_issuer": "http://x/auth/realms/lamware"}, "https"),
    ({"advisory_refresh_seconds": 30, "mandatory_refresh_seconds": 30}, "mandatory"),
])
def test_unsafe_config_refused(env, override, needle):
    p = env.tmp / "bad.json"
    p.write_text(json.dumps(dict(env.cfg_dict, **override)))
    with pytest.raises(wif.ConfigError, match=needle):
        wif.load_config(str(p), environ={})


def test_static_key_in_environment_refused(env):
    with pytest.raises(wif.ConfigError, match="ANTHROPIC_API_KEY"):
        wif.load_config(str(env.cfg_path), environ={"ANTHROPIC_API_KEY": "sk-ant-x"})


def test_client_key_read_from_systemd_credentials(env, tmp_path):
    creds = tmp_path / "creds"
    creds.mkdir()
    (creds / "client-key.pem").write_bytes(b"from-credentials")
    assert wif.read_client_key(env.cfg, environ={"CREDENTIALS_DIRECTORY": str(creds)}) \
        == b"from-credentials"


def test_client_assertion_kid_is_keycloaks_key_id(env):
    """Keycloak's KeyUtils.createKeyId: base64url(SHA-256(SubjectPublicKeyInfo DER))."""
    pub = env.kc.client_pub.public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
    header, _ = wif.decode_unverified(env.minter.client_assertion())
    assert header["kid"] == _b64(hashlib.sha256(pub).digest())


# ---------------------------------------------------------------------------- kid check


def test_kid_check_passes_when_keys_agree(env):
    assert wif.check_kid(env.cfg, env.minter) == []
    assert wif.main(["check-kid", "--config", str(env.cfg_path)]) == 0


def test_kid_check_fails_when_realm_rotated(env):
    env.kc.realm_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    env.kc.kid = "realm-rs256-2"
    problems = wif.check_kid(env.cfg, env.minter)
    assert problems and "realm-rs256-2" in problems[0]
    assert wif.main(["check-kid", "--config", str(env.cfg_path)]) == 1
    assert "kid_check_failed" in env.caplog.text


def test_kid_check_fails_when_live_jwks_drops_the_kid(env):
    env.kc.published_jwks = {"keys": []}
    problems = wif.check_kid(env.cfg, env.minter)
    assert problems == ["kid 'realm-rs256-1' is no longer published in the realm JWKS"]


def test_kid_check_fails_when_live_material_differs_under_same_kid(env):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    env.kc.published_jwks = {"keys": [_jwk(other.public_key(), env.kc.kid)]}
    problems = wif.check_kid(env.cfg, env.minter)
    assert problems and "differs" in problems[0]
