# Copyright 2026 Christopher Shaiman
# SPDX-License-Identifier: Apache-2.0
"""The Claude Platform on AWS forwarder (ADR-026), exercised end to end.

The forwarder runs on a real loopback socket in front of a fake upstream that records
what it receives, so the assertions are on the bytes that would leave the host:
the signature, the workspace header, the dropped caller headers, the streamed body.
SigV4 itself is checked against AWS's published test-suite vector (get-vanilla); the
same code was also accepted by the live endpoint on 2026-11-09 (count_tokens 200).
"""

import datetime as dt
import http.client
import importlib.util
import json
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "ansible/roles/claude-platform-aws/files/claude_platform_aws.py"
spec = importlib.util.spec_from_file_location("claude_platform_aws", SRC)
cpa = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = cpa      # dataclasses resolve annotations through sys.modules
spec.loader.exec_module(cpa)

WS = "wrkspc_TESTWORKSPACE"
BASE_CFG = {
    "region": "us-west-2", "workspace_id": WS, "signing_helper": "/bin/false",
    "certificate_file": "/nonexistent/host.pem", "private_key_file": "/nonexistent/host.key",
    "trust_anchor_arn": "arn:aws:rolesanywhere:us-west-2:111122223333:trust-anchor/ta",
    "profile_arn": "arn:aws:rolesanywhere:us-west-2:111122223333:profile/p",
    "role_arn": "arn:aws:iam::111122223333:role/r",
}
CREDS = cpa.AwsCredentials("ASIATESTKEYID", "testsecret", "testsessiontoken",
                           dt.datetime(2099, 1, 1, tzinfo=dt.UTC).timestamp())


def _config(tmp_path, **over):
    p = tmp_path / "config.json"
    p.write_text(json.dumps({**BASE_CFG, **over}))
    return cpa.load_config(str(p), environ={})


# ---------------------------------------------------------------------------- config

def test_a_complete_config_loads(tmp_path):
    cfg = _config(tmp_path)
    assert cfg.base_url == "https://aws-external-anthropic.us-west-2.api.aws"
    assert cfg.allowed_models == ("claude-mythos-5-1",)


@pytest.mark.parametrize("over,needle", [
    ({"workspace_id": ""}, "workspace_id"),
    ({"role_arn": ""}, "role_arn"),
    ({"listen_host": "0.0.0.0"}, "not a loopback"),
    ({"region": "uswest2"}, "region"),
    ({"workspace_id": "ws-123"}, "wrkspc_"),
    ({"trust_anchor_arn": "arn:aws:iam::1:role/x"}, "trust_anchor_arn"),
    ({"allowed_models": []}, "allowed_models is empty"),
    ({"allowed_peer_uids": []}, "allowed_peer_uids is empty"),
    ({"upstream_base_url": "http://example.com"}, "upstream_base_url"),
])
def test_an_unsafe_config_is_refused_by_name(tmp_path, over, needle):
    with pytest.raises(cpa.ConfigError, match=needle):
        _config(tmp_path, **over)


@pytest.mark.parametrize("var", ["ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"])
def test_a_static_key_in_the_environment_is_refused(tmp_path, var):
    p = tmp_path / "config.json"
    p.write_text(json.dumps(BASE_CFG))
    with pytest.raises(cpa.ConfigError, match=var):
        cpa.load_config(str(p), environ={var: "x"})


def test_loadcredential_paths_win_when_present(tmp_path):
    cfg = _config(tmp_path)
    (tmp_path / "host.pem").write_text("c")
    (tmp_path / "host.key").write_text("k")
    assert cpa.credential_paths(cfg, {"CREDENTIALS_DIRECTORY": str(tmp_path)}) == (
        str(tmp_path / "host.pem"), str(tmp_path / "host.key"))
    assert cpa.credential_paths(cfg, {}) == (cfg.certificate_file, cfg.private_key_file)


# ---------------------------------------------------------------------------- SigV4

def test_sigv4_matches_the_aws_test_suite_get_vanilla():
    creds = cpa.AwsCredentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "", 0)
    h = cpa.sigv4_headers("GET", "example.amazonaws.com", "/", "", {}, b"", creds,
                          "us-east-1", "service", dt.datetime(2015, 8, 30, 12, 36, tzinfo=dt.UTC))
    assert h["Authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31")


def test_sigv4_signs_the_body_and_every_header_sent():
    now = dt.datetime(2026, 11, 9, tzinfo=dt.UTC)
    a = cpa.sigv4_headers("POST", "h", "/v1/messages", "", {"anthropic-workspace-id": WS},
                          b"{}", CREDS, "us-west-2", cpa.SERVICE, now)
    b = cpa.sigv4_headers("POST", "h", "/v1/messages", "", {"anthropic-workspace-id": WS},
                          b"{ }", CREDS, "us-west-2", cpa.SERVICE, now)
    c = cpa.sigv4_headers("POST", "h", "/v1/messages", "", {"anthropic-workspace-id": "wrkspc_x"},
                          b"{}", CREDS, "us-west-2", cpa.SERVICE, now)
    assert len({a["Authorization"], b["Authorization"], c["Authorization"]}) == 3
    assert "anthropic-workspace-id" in a["Authorization"] and "x-amz-security-token" in a["Authorization"]
    assert "testsecret" not in json.dumps(a)


# ---------------------------------------------------------------------------- credentials

def _run_returning(stdout="", returncode=0, stderr=""):
    def run(cmd, **kw):
        run.cmd = cmd
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)
    return run


def test_credentials_come_from_the_signing_helper(tmp_path):
    cfg = _config(tmp_path)
    run = _run_returning(json.dumps({"Version": 1, "AccessKeyId": "ASIA1",
                                     "SecretAccessKey": "SECRETVALUE", "SessionToken": "TOKENVALUE",
                                     "Expiration": "2099-01-01T00:00:00Z"}))
    c = cpa.fetch_credentials(cfg, "/c.pem", "/k.key", run=run)
    assert (c.access_key_id, c.session_token) == ("ASIA1", "TOKENVALUE")
    assert run.cmd[1] == "credential-process" and "--role-arn" in run.cmd
    for secret in ("ASIA1", "SECRETVALUE", "TOKENVALUE"):
        assert secret not in repr(c)


def test_a_helper_failure_is_reported_without_its_stdout(tmp_path):
    cfg = _config(tmp_path)
    run = _run_returning(stdout='{"SecretAccessKey": "leak"}', returncode=1,
                         stderr="AccessDeniedException: Unable to assume role")
    with pytest.raises(cpa.CredentialError) as e:
        cpa.fetch_credentials(cfg, "/c", "/k", run=run)
    assert "AccessDenied" in str(e.value) and "leak" not in str(e.value)


def test_the_cache_refreshes_early_and_falls_back_until_the_hard_limit():
    t = [0.0]
    calls = []

    def fetch():
        calls.append(t[0])
        if len(calls) == 2:
            raise cpa.CredentialError("transient")
        return cpa.AwsCredentials("a", "s", "t", t[0] + 3600)

    cache = cpa.CredentialCache(fetch, advisory_s=300, mandatory_s=60, clock=lambda: t[0])
    first = cache.get()
    t[0] = 3400            # inside the advisory window: refresh fails, cached returned
    assert cache.get() is first and len(calls) == 2
    t[0] = 3560            # inside the mandatory window: refresh succeeds
    assert cache.get() is not first and len(calls) == 3


# ---------------------------------------------------------------------------- end to end

class _Upstream(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    received: list = []

    def log_message(self, *a):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).received.append((self.path, dict(self.headers), body))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("request-id", "req_011TEST\tforged=1")
        self.end_headers()
        for i in range(3):
            self.wfile.write(f"data: chunk{i}\n\n".encode())
            self.wfile.flush()
        self.wfile.write(b'data: {"usage": {"output_tokens": 4}}\n\n')


@pytest.fixture
def stack(tmp_path):
    _Upstream.received = []
    up = ThreadingHTTPServer(("127.0.0.1", 0), _Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    cfg = _config(tmp_path, listen_port=0,
                  upstream_base_url=f"http://127.0.0.1:{up.server_address[1]}",
                  allowed_peer_uids=[4242])
    uids = {"value": 4242}
    cache = cpa.CredentialCache(lambda: CREDS, 300, 60)
    fwd = cpa.ForwarderServer(cfg, cache, uid_lookup=lambda c, s: uids["value"])
    threading.Thread(target=fwd.serve_forever, daemon=True).start()
    yield fwd.server_address[1], uids
    fwd.shutdown()
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


MSG = {"model": "claude-mythos-5-1", "max_tokens": 8, "messages": []}


def test_an_allowed_request_is_signed_and_streamed_through(stack):
    port, _ = stack
    status, data = _post(port, "/v1/messages?beta=true", MSG, {
        "x-api-key": "sk-claude-platform-aws-placeholder", "Authorization": "Bearer caller",
        "anthropic-workspace-id": "wrkspc_CALLER", "anthropic-version": "2023-06-01",
        "Cookie": "c=1"})
    assert status == 200
    assert data.count(b"data: chunk") == 3 and b'"usage"' in data
    path, headers, body = _Upstream.received[0]
    lower = {k.lower(): v for k, v in headers.items()}
    assert path == "/v1/messages?beta=true" and json.loads(body) == MSG
    assert lower["authorization"].startswith("AWS4-HMAC-SHA256 Credential=ASIATESTKEYID/")
    assert lower["anthropic-workspace-id"] == WS          # config, never the caller
    assert lower["x-amz-security-token"] == "testsessiontoken"
    assert "x-api-key" not in lower and "cookie" not in lower
    assert "caller" not in lower["authorization"]


def _header_lines(port, path, body):
    raw = json.dumps(body).encode()
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(f"POST {path} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n"
                  f"Content-Length: {len(raw)}\r\n\r\n".encode() + raw)
        data = b""
        while chunk := s.recv(65536):
            data += chunk
    return data.split(b"\r\n\r\n", 1)[0].split(b"\r\n")[1:]


@pytest.mark.parametrize("body", [MSG, {**MSG, "model": "claude-opus-5-5"}])
def test_every_response_header_value_is_legal_for_h11(stack, body):
    """LiteLLM relays the forwarder's response headers through h11, which rejects a
    value with leading or trailing whitespace. Read off the wire, not via
    http.client (which strips whitespace and would hide it)."""
    port, _ = stack
    lines = _header_lines(port, "/v1/messages", body)
    assert lines, "no headers read"
    for line in lines:
        name, _, value = line.partition(b":")
        value = value[1:] if value.startswith(b" ") else value
        assert value == value.strip(), f"illegal header value {line!r}"


def test_each_forwarded_call_logs_its_request_id_and_model(stack, caplog):
    """The id a false-positive report or support case needs. Characters outside
    [A-Za-z0-9_-] are dropped, so a hostile header cannot add log fields."""
    port, _ = stack
    with caplog.at_level("INFO", logger="claude-platform-aws"):
        assert _post(port, "/v1/messages", MSG)[0] == 200
    lines = [r.getMessage() for r in caplog.records if "event=forwarded" in r.getMessage()]
    assert lines and "request_id=req_011TESTforged1" in lines[0], lines
    assert "model=claude-mythos-5-1" in lines[0] and "\t" not in lines[0]


@pytest.mark.parametrize("path,body,uid,status,needle", [
    ("/v1/models", MSG, 4242, 404, b"forwards only"),
    ("/v1/messages", {**MSG, "model": "claude-opus-5-5"}, 4242, 403, b"allowed_models"),
    ("/v1/messages", MSG, 1000, 403, b"allowed_peer_uids"),
    ("/v1/messages", MSG, None, 403, b"allowed_peer_uids"),
])
def test_refusals_happen_before_anything_is_signed(stack, path, body, uid, status, needle):
    port, uids = stack
    uids["value"] = uid
    got, data = _post(port, path, body)
    assert got == status and needle in data
    assert _Upstream.received == []


# ---------------------------------------------------------------------------- check

def test_the_check_fails_on_a_certificate_close_to_expiry(tmp_path, monkeypatch):
    cfg = _config(tmp_path, cert_warn_days=4)
    monkeypatch.setattr(cpa, "cert_days_left", lambda path: 2.5)
    problems = cpa.check(cfg, "/c", "/k", fetch=lambda: (_ for _ in ()).throw(
        cpa.CredentialError("no network in tests")))
    assert any("expires in 2.5 days" in p for p in problems)


def test_cert_days_left_reads_openssl_enddate():
    out = "notAfter=Nov 23 08:41:18 2026 GMT\n"
    run = _run_returning(out)
    now = dt.datetime(2026, 11, 9, 8, 41, 18, tzinfo=dt.UTC).timestamp()
    assert cpa.cert_days_left("/c.pem", run=run, now=lambda: now) == pytest.approx(14.0)
