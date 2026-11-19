# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The Workload Identity Federation forwarder (ADR-033), exercised end to end.

The forwarder runs on real loopback sockets in front of a fake upstream that serves
both ``/v1/oauth/token`` and the Messages API and records what it receives, so the
assertions are on the bytes that would leave the host: the exchange body, the bearer
token, the dropped caller headers, the streamed body. The JWT is verified with the
public key and decoded, not pattern-matched.
"""

import base64
import http.client
import importlib.util
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "ansible/roles/anthropic-wif/files/anthropic_wif.py"
spec = importlib.util.spec_from_file_location("anthropic_wif", SRC)
wif = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = wif      # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(wif)

ORG = "00000000-0000-4000-8000-000000000001"
PROD_WS, EVAL_WS = "wrkspc_PROD", "wrkspc_EVAL"
PROD_MODEL, EVAL_MODEL = "claude-sonnet-4-6", "claude-opus-5-5"


@pytest.fixture(scope="module")
def key_file(tmp_path_factory):
    key = ec.generate_private_key(ec.SECP256R1())
    p = tmp_path_factory.mktemp("key") / "signing-key.pem"
    p.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption()))
    return p


def _base(key_file, **over):
    return {"organization_id": ORG, "federation_rule_id": "fdrl_TEST",
            "service_account_id": "svac_TEST", "signing_key_file": str(key_file),
            "key_id": "kid-1", "issuer": "https://wif.example.internal",
            "subject": "test-forwarder", "audience": "https://api.anthropic.com",
            "routes": [{"name": "production", "listen_port": 4011, "workspace_id": PROD_WS,
                        "allowed_models": [PROD_MODEL]},
                       {"name": "eval", "listen_port": 4012, "workspace_id": EVAL_WS,
                        "allowed_models": [EVAL_MODEL]}],
            **over}


def _config(tmp_path, key_file, **over):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_base(key_file, **over)))
    return wif.load_config(str(p), environ={})


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _verify(jwt: str, public_key) -> tuple[dict, dict]:
    """Verify an ES256 JWS with the public key; return (header, claims)."""
    h, c, sig = jwt.split(".")
    raw = _b64d(sig)
    assert len(raw) == 64, "ES256 signatures are raw r||s, 64 bytes"
    der = encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    public_key.verify(der, f"{h}.{c}".encode(), ec.ECDSA(hashes.SHA256()))
    return json.loads(_b64d(h)), json.loads(_b64d(c))


# ---------------------------------------------------------------------------- config

def test_a_complete_config_loads(tmp_path, key_file):
    cfg = _config(tmp_path, key_file)
    assert cfg.base_url == "https://api.anthropic.com"
    assert [(r.name, r.listen_port, r.workspace_id) for r in cfg.routes] == [
        ("production", 4011, PROD_WS), ("eval", 4012, EVAL_WS)]


@pytest.mark.parametrize("over,needle", [
    ({"federation_rule_id": ""}, "federation_rule_id"),
    ({"federation_rule_id": "rule-1"}, "fdrl_"),
    ({"organization_id": "not-a-uuid"}, "UUID"),
    ({"service_account_id": "sa-1"}, "svac_"),
    ({"issuer": ""}, "issuer"),
    ({"listen_host": "0.0.0.0"}, "not a loopback"),
    ({"routes": []}, "routes is empty"),
    ({"routes": [{"name": "p", "listen_port": 4011}]}, r"routes\[0\]"),
    ({"routes": [{"name": "p", "listen_port": 4011, "workspace_id": "ws", "allowed_models": ["m"]}]},
     "wrkspc_"),
    ({"routes": [{"name": "p", "listen_port": 4011, "workspace_id": PROD_WS, "allowed_models": []}]},
     "allowed_models is empty"),
    ({"routes": [{"name": "a", "listen_port": 4011, "workspace_id": PROD_WS, "allowed_models": ["m"]},
                 {"name": "b", "listen_port": 4011, "workspace_id": EVAL_WS, "allowed_models": ["n"]}]},
     "share a listen_port"),
    ({"routes": [{"name": "a", "listen_port": 4011, "workspace_id": PROD_WS, "allowed_models": ["m"]},
                 {"name": "b", "listen_port": 4012, "workspace_id": EVAL_WS, "allowed_models": ["m"]}]},
     "model m is on routes a and b"),
    ({"allowed_peer_uids": []}, "allowed_peer_uids is empty"),
    ({"jwt_lifetime_seconds": 7200}, "jwt_lifetime_seconds"),
    ({"upstream_base_url": "http://example.com"}, "upstream_base_url"),
])
def test_an_unsafe_config_is_refused_by_name(tmp_path, key_file, over, needle):
    with pytest.raises(wif.ConfigError, match=needle):
        _config(tmp_path, key_file, **over)


@pytest.mark.parametrize("var", ["ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"])
def test_a_static_key_in_the_environment_is_refused(tmp_path, key_file, var):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(_base(key_file)))
    with pytest.raises(wif.ConfigError, match=var):
        wif.load_config(str(p), environ={var: "x"})


def test_the_loadcredential_copy_wins_when_present(tmp_path, key_file):
    cfg = _config(tmp_path, key_file)
    (tmp_path / "signing-key.pem").write_text("k")
    assert wif.signing_key_path(cfg, {"CREDENTIALS_DIRECTORY": str(tmp_path)}) == str(
        tmp_path / "signing-key.pem")
    assert wif.signing_key_path(cfg, {}) == str(key_file)


# ---------------------------------------------------------------------------- the JWT

def test_the_assertion_verifies_with_the_public_key_and_carries_what_the_rule_matches(
        tmp_path, key_file):
    cfg = _config(tmp_path, key_file)
    key = wif.load_signing_key(str(key_file))
    header, claims = _verify(wif.mint_assertion(cfg, key, 1_800_000_000), key.public_key())
    assert header == {"alg": "ES256", "typ": "JWT", "kid": "kid-1"}
    assert {k: claims[k] for k in ("iss", "sub", "aud")} == {
        "iss": "https://wif.example.internal", "sub": "test-forwarder",
        "aud": "https://api.anthropic.com"}
    assert claims["iat"] == claims["nbf"] == 1_800_000_000
    assert claims["exp"] - claims["iat"] == 900 <= 3600   # under the issuer's 1 h maximum


def test_a_tampered_assertion_does_not_verify(tmp_path, key_file):
    """Guards the guard: _verify must reject, or the test above proves nothing."""
    cfg = _config(tmp_path, key_file)
    key = wif.load_signing_key(str(key_file))
    h, c, s = wif.mint_assertion(cfg, key, 1_800_000_000).split(".")
    forged = json.loads(_b64d(c)) | {"sub": "someone-else"}
    c2 = base64.urlsafe_b64encode(json.dumps(forged).encode()).rstrip(b"=").decode()
    with pytest.raises(InvalidSignature):
        _verify(f"{h}.{c2}.{s}", key.public_key())


def test_every_assertion_has_a_fresh_jti(tmp_path, key_file):
    """The issuer enforces single use; a reused jti is an opaque 401."""
    cfg = _config(tmp_path, key_file)
    key = wif.load_signing_key(str(key_file))
    jtis = {json.loads(_b64d(wif.mint_assertion(cfg, key, 1_800_000_000).split(".")[1]))["jti"]
            for _ in range(50)}
    assert len(jtis) == 50


def test_a_non_p256_key_is_refused(tmp_path):
    p = tmp_path / "k.pem"
    p.write_bytes(ec.generate_private_key(ec.SECP384R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    with pytest.raises(wif.CredentialError, match="P-256"):
        wif.load_signing_key(str(p))


def test_the_published_jwks_is_the_public_half_of_the_signing_key(key_file, capsys):
    assert wif.main(["jwks", "--key", str(key_file), "--kid", "kid-1"]) == 0
    (jwk,) = json.loads(capsys.readouterr().out)["keys"]
    assert {k: jwk[k] for k in ("kty", "crv", "kid", "alg", "use")} == {
        "kty": "EC", "crv": "P-256", "kid": "kid-1", "alg": "ES256", "use": "sig"}
    assert "d" not in jwk                                   # never the private scalar
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(_b64d(jwk["x"]), "big"),
                                        int.from_bytes(_b64d(jwk["y"]), "big"),
                                        ec.SECP256R1()).public_key()
    cfg_like = type("C", (), {"key_id": "kid-1", "issuer": "i", "subject": "s",
                              "audience": "a", "jwt_lifetime_seconds": 900})
    _verify(wif.mint_assertion(cfg_like, wif.load_signing_key(str(key_file)), 1), pub)


# ---------------------------------------------------------------------------- cache

def test_the_cache_refreshes_early_and_falls_back_until_the_hard_limit():
    t = [0.0]
    calls = []

    def fetch():
        calls.append(t[0])
        if len(calls) == 2:
            raise wif.CredentialError("transient")
        return wif.AccessToken("tok", t[0] + 600)

    cache = wif.TokenCache(fetch, advisory_s=120, mandatory_s=30, clock=lambda: t[0])
    first = cache.get()
    t[0] = 500             # inside the advisory window: refresh fails, cached returned
    assert cache.get() is first and len(calls) == 2
    t[0] = 575             # inside the mandatory window: refresh succeeds
    assert cache.get() is not first and len(calls) == 3
    assert "tok" not in repr(first)


# ---------------------------------------------------------------------------- end to end

class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    received: list = []
    exchange_status = 200
    pub = None

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        cls = type(self)
        cls.received.append((self.path, dict(self.headers), body))
        if self.path == "/v1/oauth/token":
            doc = json.loads(body)
            _verify(doc["assertion"], cls.pub)
            out = json.dumps({"access_token": f"sk-ant-oat01-{doc['workspace_id']}",
                              "token_type": "Bearer", "expires_in": 600,
                              "scope": "workspace:inference"}).encode()
            if cls.exchange_status != 200:
                out = json.dumps({"type": "error", "error": {
                    "type": "authentication_error", "message": "Authentication failed"}}).encode()
            self.send_response(cls.exchange_status)
            self.send_header("Content-Type", "application/json")
            self.send_header("request-id", "req_EXCHANGE")
            self.end_headers()
            self.wfile.write(out)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("request-id", "req_011TEST\tforged=1")
        self.end_headers()
        for i in range(3):
            self.wfile.write(f"data: chunk{i}\n\n".encode())
            self.wfile.flush()
        self.wfile.write(b'data: {"usage": {"output_tokens": 4}}\n\n')


@pytest.fixture
def stack(tmp_path, key_file):
    _Upstream.received = []
    _Upstream.exchange_status = 200
    _Upstream.pub = wif.load_signing_key(str(key_file)).public_key()
    up = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{up.server_address[1]}"
    cfg = _config(tmp_path, key_file, upstream_base_url=base, allowed_peer_uids=[4242])
    uids = {"value": 4242}
    ports, servers = {}, []
    for route in cfg.routes:
        r0 = wif.Route(route.name, 0, route.workspace_id, route.allowed_models)
        cache = wif.TokenCache(lambda r=r0: wif.fetch_token(cfg, r, str(key_file)), 120, 30)
        srv = wif.ForwarderServer(cfg, r0, cache, uid_lookup=lambda c, s: uids["value"])
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        ports[route.name] = srv.server_address[1]
        servers.append(srv)
    yield ports, uids, cfg
    for s in servers:
        s.shutdown()
    up.shutdown()


def _post(port, path, body, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    raw = json.dumps(body).encode()
    conn.request("POST", path, body=raw, headers={"Content-Type": "application/json",
                                                  **(headers or {})})
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, data


def _msg(model):
    return {"model": model, "max_tokens": 8, "messages": []}


def test_a_request_is_sent_with_the_routes_bearer_token_and_streamed_through(stack):
    ports, _, _ = stack
    status, data = _post(ports["production"], "/v1/messages?beta=true", _msg(PROD_MODEL), {
        "x-api-key": "sk-placeholder", "Authorization": "Bearer caller",
        "anthropic-workspace-id": "wrkspc_CALLER", "anthropic-version": "2023-06-01",
        "Cookie": "c=1"})
    assert status == 200
    assert data.count(b"data: chunk") == 3 and b'"usage"' in data
    (ex_path, ex_headers, ex_body), (path, headers, body) = _Upstream.received
    exchange = json.loads(ex_body)
    assert ex_path == "/v1/oauth/token"
    assert {k: exchange[k] for k in ("grant_type", "federation_rule_id", "organization_id",
                                     "workspace_id", "service_account_id")} == {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "federation_rule_id": "fdrl_TEST", "organization_id": ORG,
        "workspace_id": PROD_WS, "service_account_id": "svac_TEST"}
    lower = {k.lower(): v for k, v in headers.items()}
    assert path == "/v1/messages?beta=true" and json.loads(body) == _msg(PROD_MODEL)
    assert lower["authorization"] == f"Bearer sk-ant-oat01-{PROD_WS}"
    for dropped in ("x-api-key", "cookie", "anthropic-workspace-id"):
        assert dropped not in lower, dropped


def test_the_eval_route_gets_a_token_for_the_eval_workspace(stack):
    ports, _, _ = stack
    assert _post(ports["eval"], "/v1/messages", _msg(EVAL_MODEL))[0] == 200
    (_, _, ex_body), (_, headers, _) = _Upstream.received
    assert json.loads(ex_body)["workspace_id"] == EVAL_WS
    assert {k.lower(): v for k, v in headers.items()}["authorization"] == (
        f"Bearer sk-ant-oat01-{EVAL_WS}")


def test_the_token_is_reused_until_refresh_and_every_exchange_mints_a_new_jwt(stack):
    ports, _, _ = stack
    for _ in range(3):
        assert _post(ports["production"], "/v1/messages", _msg(PROD_MODEL))[0] == 200
    exchanges = [b for p, _, b in _Upstream.received if p == "/v1/oauth/token"]
    assert len(exchanges) == 1


@pytest.mark.parametrize("route,model", [("production", EVAL_MODEL), ("eval", PROD_MODEL)])
def test_a_model_is_refused_on_the_other_workspaces_route(stack, route, model):
    """Production traffic cannot bill the eval workspace, nor the reverse."""
    ports, _, _ = stack
    status, data = _post(ports[route], "/v1/messages", _msg(model))
    assert status == 403 and b"allowed_models" in data
    assert _Upstream.received == []


@pytest.mark.parametrize("path,uid,status,needle", [
    ("/v1/models", 4242, 404, b"forwards only"),
    ("/v1/messages", 1000, 403, b"allowed_peer_uids"),
    ("/v1/messages", None, 403, b"allowed_peer_uids"),
])
def test_refusals_happen_before_any_exchange(stack, path, uid, status, needle):
    ports, uids, _ = stack
    uids["value"] = uid
    got, data = _post(ports["production"], path, _msg(PROD_MODEL))
    assert got == status and needle in data
    assert _Upstream.received == []


def test_a_failed_exchange_is_a_503_that_names_the_request_not_the_token(stack, caplog):
    ports, _, _ = stack
    _Upstream.exchange_status = 401
    with caplog.at_level("INFO", logger="anthropic-wif"):
        status, data = _post(ports["production"], "/v1/messages", _msg(PROD_MODEL))
    assert status == 503 and b"401" in data and b"req_EXCHANGE" in data
    assert b"eyJ" not in data                               # no JWT echoed
    assert not any("eyJ" in r.getMessage() or "sk-ant-oat01" in r.getMessage()
                   for r in caplog.records)
    assert [p for p, _, _ in _Upstream.received] == ["/v1/oauth/token"]


def test_each_forwarded_call_logs_route_model_and_request_id_never_the_token(stack, caplog):
    ports, _, _ = stack
    with caplog.at_level("INFO", logger="anthropic-wif"):
        assert _post(ports["production"], "/v1/messages", _msg(PROD_MODEL))[0] == 200
    msgs = [r.getMessage() for r in caplog.records]
    fwd = [m for m in msgs if "event=forwarded" in m]
    assert fwd and "route=production" in fwd[0] and "request_id=req_011TESTforged1" in fwd[0]
    assert not any("sk-ant-oat01" in m or "eyJ" in m for m in msgs)


def test_the_check_exchanges_and_counts_tokens_per_route(stack, key_file):
    _, _, cfg = stack
    assert wif.check(cfg, str(key_file)) == []
    calls = [(p, json.loads(b).get("workspace_id") or json.loads(b)["model"])
             for p, _, b in _Upstream.received]
    assert calls == [("/v1/oauth/token", PROD_WS), ("/v1/messages/count_tokens", PROD_MODEL),
                     ("/v1/oauth/token", EVAL_WS), ("/v1/messages/count_tokens", EVAL_MODEL)]


def test_the_check_names_the_failing_route(stack, key_file):
    _, _, cfg = stack
    _Upstream.exchange_status = 401
    problems = wif.check(cfg, str(key_file))
    assert len(problems) == 2 and problems[0].startswith("route production: token exchange returned 401")


def test_main_refuses_an_incomplete_config_with_the_config_exit_code(tmp_path):
    p = tmp_path / "config.json"
    p.write_text("{}")
    assert wif.main(["check", "--config", str(p)]) == wif.EXIT_CONFIG




def test_a_model_repeated_within_one_route_is_allowed(tmp_path, key_file):
    """haiku-fallback is usually also the summary model: the same route, twice."""
    routes = [{"name": "production", "listen_port": 4011, "workspace_id": PROD_WS,
               "allowed_models": [PROD_MODEL, PROD_MODEL]}]
    assert _config(tmp_path, key_file, routes=routes).routes[0].allowed_models == (
        PROD_MODEL, PROD_MODEL)
