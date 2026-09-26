"""
test_http_conform.py — HTTP server conformance (RFC 9110 / RFC 9112).

SUT: demo/http_demo, started once for this module.  The client is the test
host's own TCP stack (Python http.client and raw sockets) talking to the SUT
over the TAP or veth (Linux) or feth (macOS) link, so this also exercises our TCP
against a production peer.  http_demo serves:

    GET  /            HTML status page
    GET  /api/status  JSON (uptime_ms, requests, ip, query)
    POST /api/echo    echoes the body
    GET  /big         8000 bytes: 'a'..'z' cycling, '\\n' every 64th byte

with two connection slots, a 1024-byte request buffer, and a 10 s request
timeout.

Usage (Linux, tap0 up with 10.0.0.100/24):

    sudo python3 -m pytest tests/blackbox/test_http_conform.py \\
        --iface tap0 --sut-ip 10.0.0.2 --http-sut-bin ./build/demo/http_demo -v

Raw-socket driver instead of TAP: set the link up with sut_net.sh up raw,
then --iface veth-test --sut-iface raw:veth-sut.

Skipped when --http-sut-bin is not given.
"""

import http.client
import json
import os
import signal
import socket
import subprocess
import tempfile
import time

import pytest

from helpers import sut_argv

PORT = 80
REQ_BUF = 1024            # http_demo's request buffer per slot
REQUEST_TIMEOUT_S = 10.0  # HTTP_REQUEST_TIMEOUT_MS


# ── SUT management ─────────────────────────────────────────────────────────────

class HttpSut:
    def __init__(self, binary, host, sut_iface=None):
        self.argv = sut_argv(binary, sut_iface)
        self.binary = binary
        self.host = host
        self.proc = None
        self.log_path = None

    def start(self, timeout=8.0):
        fd, self.log_path = tempfile.mkstemp(prefix="http_sut_", suffix=".log")
        self.proc = subprocess.Popen(self.argv, stdout=fd,
                                     stderr=subprocess.STDOUT)
        os.close(fd)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with socket.create_connection((self.host, PORT), timeout=1):
                    return
            except OSError:
                if self.proc.poll() is not None:
                    break
                time.sleep(0.2)
        raise AssertionError(f"http_demo not reachable; output:\n{self.output()}")

    def output(self):
        with open(self.log_path, errors="replace") as f:
            return f.read()

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()


@pytest.fixture(scope="module")
def sut(request):
    binary = request.config.getoption("--http-sut-bin")
    if not binary:
        pytest.skip("--http-sut-bin not given")
    s = HttpSut(binary, request.config.getoption("--sut-ip"),
                request.config.getoption("--sut-iface"))
    s.start()
    yield s
    s.stop()
    tail = s.output().splitlines()[-40:]
    print("\n--- SUT output (tail) ---\n" + "\n".join(tail))
    os.unlink(s.log_path)


@pytest.fixture(autouse=True)
def sut_alive(request):
    yield
    if "sut" in request.fixturenames:
        s = request.getfixturevalue("sut")
        assert s.proc.poll() is None, f"http_demo exited:\n{s.output()}"


# ── Client helpers ─────────────────────────────────────────────────────────────

def request(sut, method, path, body=None, headers=None):
    """One request with http.client (HTTP/1.1 + Host).  Returns
    (status, lower-cased headers, body, raw status line version)."""
    conn = http.client.HTTPConnection(sut.host, PORT, timeout=5)
    try:
        conn.request(method, path, body=body, headers=headers or {})
        r = conn.getresponse()
        data = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, hdrs, data, r.version
    finally:
        conn.close()


def raw(sut, data, pieces=None, delay=0.0, timeout=5.0):
    """Send raw bytes (optionally in pieces), read until the server closes.
    Returns (status code or None, full response bytes)."""
    with socket.create_connection((sut.host, PORT), timeout=timeout) as s:
        for part in (pieces or [data]):
            s.sendall(part)
            if delay:
                time.sleep(delay)
        chunks = []
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                c = s.recv(4096)
            except socket.timeout:
                break
            if not c:
                break
            chunks.append(c)
    resp = b"".join(chunks)
    status = None
    if resp.startswith(b"HTTP/"):
        status = int(resp.split(b" ", 2)[1])
    return status, resp


def split(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    hdrs = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        hdrs[k.strip().lower()] = v.strip()
    return lines[0], hdrs, body


BIG = bytes(ord("\n") if i % 64 == 63 else ord("a") + (i % 64) % 26
            for i in range(8000))


# ══════════════════════════════════════════════════════════════════════════════
# Methods and responses
# ══════════════════════════════════════════════════════════════════════════════

def test_http_001_get_root(sut):
    """REQ-HTTP-002, 016, 019..022, 029, 035: 200 + headers, then close."""
    status, resp = raw(sut, b"GET / HTTP/1.0\r\n\r\n")
    assert status == 200
    line, hdrs, body = split(resp)
    assert line == "HTTP/1.0 200 OK"
    assert hdrs["content-type"] == "text/html"
    assert int(hdrs["content-length"]) == len(body)
    assert hdrs["connection"] == "close"
    assert b"<html>" in body and b"Pyro Unit 1" in body  # and EOF followed


def test_http_002_head(sut):
    """REQ-HTTP-004, 023: HEAD → same headers as GET, no body."""
    _, ghdrs, gbody, _ = request(sut, "GET", "/")
    status, hhdrs, hbody, _ = request(sut, "HEAD", "/")
    assert status == 200
    assert hbody == b""
    assert hhdrs["content-length"] == ghdrs["content-length"] == str(len(gbody))


def test_http_003_http11_client_gets_http10(sut):
    """REQ-HTTP-006, 010: HTTP/1.1 with Host works; the server answers 1.0."""
    status, _, _, version = request(sut, "GET", "/")
    assert status == 200 and version == 10


def test_http_004_absolute_form(sut):
    """RFC 9112 §3.2.2: absolute-form target reduced to its path."""
    status, _ = raw(sut, f"GET http://{sut.host}/ HTTP/1.0\r\n\r\n".encode())
    assert status == 200


def test_http_005_post_echo(sut):
    """REQ-HTTP-003, 032, 036: POST body delivered to the handler."""
    status, hdrs, body, _ = request(sut, "POST", "/api/echo",
                                    body=b"hello pyro",
                                    headers={"Content-Type": "text/plain"})
    assert status == 200
    assert hdrs["content-type"] == "text/plain"
    assert body == b"hello pyro"


def test_http_006_post_body_in_pieces(sut):
    """Headers and body arrive in separate segments with a gap."""
    status, resp = raw(sut, None, pieces=[
        b"POST /api/echo HTTP/1.0\r\nContent-Length: 12\r\n\r\n",
        b"split ", b"body!!"], delay=0.2)
    assert status == 200
    assert split(resp)[2] == b"split body!!"


def test_http_007_json_status(sut):
    """REQ-HTTP-037: generated JSON body; query passed to the handler."""
    status, hdrs, body, _ = request(sut, "GET", "/api/status?x=1")
    assert status == 200
    assert hdrs["content-type"] == "application/json"
    doc = json.loads(body)
    assert doc["ip"] == sut.host
    assert doc["query"] == "x=1"
    assert doc["uptime_ms"] > 0 and doc["requests"] >= 1


def test_http_008_large_response(sut):
    """A body 5x the TX buffer streams intact over many segments."""
    status, hdrs, body, _ = request(sut, "GET", "/big")
    assert status == 200
    assert int(hdrs["content-length"]) == 8000
    assert body == BIG


def test_http_009_trickled_request(sut):
    """A request arriving one byte per segment is still parsed."""
    req = b"GET /api/status HTTP/1.0\r\n\r\n"
    status, _ = raw(sut, None, pieces=[req[i:i + 1] for i in range(len(req))],
                    delay=0.01)
    assert status == 200


# ══════════════════════════════════════════════════════════════════════════════
# Error statuses
# ══════════════════════════════════════════════════════════════════════════════

def test_http_010_not_found(sut):
    """REQ-HTTP-025."""
    assert request(sut, "GET", "/nope")[0] == 404


def test_http_011_method_not_allowed(sut):
    """REQ-HTTP-024: known method, wrong route → 405 with Allow."""
    status, hdrs, _, _ = request(sut, "POST", "/", body=b"")
    assert status == 405
    assert hdrs["allow"] == "GET, HEAD"


def test_http_012_not_implemented(sut):
    """REQ-HTTP-024: methods the server does not implement → 501."""
    assert request(sut, "PUT", "/")[0] == 501
    assert request(sut, "DELETE", "/")[0] == 501


def test_http_013_bad_requests(sut):
    """REQ-HTTP-026, 010: malformed request line; HTTP/1.1 without Host."""
    assert raw(sut, b"GARBAGE\r\n\r\n")[0] == 400
    assert raw(sut, b"GET / HTTP/1.1\r\n\r\n")[0] == 400
    assert raw(sut, b"GET / HTTP/1.0\r\nNo-Colon-Here\r\n\r\n")[0] == 400


def test_http_014_version_not_supported(sut):
    assert raw(sut, b"GET / HTTP/2.0\r\n\r\n")[0] == 505


def test_http_015_uri_too_long(sut):
    """REQ-HTTP-039, 041."""
    status, _ = raw(sut, b"GET /" + b"a" * (2 * REQ_BUF) + b" HTTP/1.0\r\n\r\n")
    assert status == 414


def test_http_016_headers_too_large(sut):
    """REQ-HTTP-040."""
    status, _ = raw(sut, b"GET / HTTP/1.0\r\nX-Pad: " + b"p" * (2 * REQ_BUF) +
                    b"\r\n\r\n")
    assert status == 431


def test_http_017_body_too_large(sut):
    """REQ-HTTP-033, 034."""
    status, _ = raw(sut, b"POST /api/echo HTTP/1.0\r\nContent-Length: 100000"
                    b"\r\n\r\n" + b"x" * 64)
    assert status == 413


def test_http_018_transfer_encoding_not_implemented(sut):
    status, _ = raw(sut, b"POST /api/echo HTTP/1.1\r\nHost: h\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
    assert status == 501


# ══════════════════════════════════════════════════════════════════════════════
# Connection management
# ══════════════════════════════════════════════════════════════════════════════

def test_http_019_back_to_back_requests(sut):
    """REQ-HTTP-028, 029: 30 sequential requests — slots are recycled at
    once, never stuck for 2xMSL in TIME_WAIT."""
    start = time.monotonic()
    for _ in range(30):
        assert request(sut, "GET", "/")[0] == 200
    assert time.monotonic() - start < 15


def test_http_020_two_concurrent_connections(sut):
    """Both slots serve at the same time."""
    a = socket.create_connection((sut.host, PORT), timeout=5)
    b = socket.create_connection((sut.host, PORT), timeout=5)
    try:
        b.sendall(b"GET /api/status?who=b HTTP/1.0\r\n\r\n")
        a.sendall(b"GET /api/status?who=a HTTP/1.0\r\n\r\n")
        for sock, who in ((a, "a"), (b, "b")):
            data = b""
            while True:
                c = sock.recv(4096)
                if not c:
                    break
                data += c
            assert json.loads(split(data)[2])["query"] == f"who={who}"
    finally:
        a.close()
        b.close()


@pytest.mark.sut_specific  # waits for http_demo's 10 s request timeout
def test_http_021_idle_connection_times_out(sut):
    """An idle client must not hold a slot forever: the server resets it."""
    s = socket.create_connection((sut.host, PORT), timeout=REQUEST_TIMEOUT_S + 5)
    try:
        start = time.monotonic()
        try:
            data = s.recv(1)
        except ConnectionResetError:
            data = b""
        elapsed = time.monotonic() - start
        assert data == b""
        assert REQUEST_TIMEOUT_S - 1 <= elapsed <= REQUEST_TIMEOUT_S + 3
    finally:
        s.close()
    assert request(sut, "GET", "/")[0] == 200  # slot usable again


# ── HTTP over IPv6 (dual-stack http_demo) ──────────────────────────────────────

def test_http_022_get_over_ipv6(sut, request):
    """The same server answers over IPv6: the host's TCP stack fetches the
    status page from the demo's link-local address (Linux)."""
    iface = request.config.getoption("--iface")
    mac = request.config.getoption("--mdns-sut-mac")  # the demos' MAC
    b = bytes.fromhex(mac.replace(":", ""))
    iid = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:6]
    ll = socket.inet_ntop(socket.AF_INET6, b"\xfe\x80" + bytes(6) + iid)
    deadline = time.monotonic() + 5
    while " preferred" not in sut.output() and time.monotonic() < deadline:
        time.sleep(0.1)
    if " preferred" not in sut.output():
        pytest.skip("http_demo is not dual-stack")
    try:
        c = socket.create_connection((f"{ll}%{iface}", PORT), timeout=5)
    except OSError as e:
        pytest.skip(f"no IPv6 route to {ll}%{iface}: {e}")
    with c:
        c.sendall(b"GET / HTTP/1.0\r\n\r\n")
        data = b""
        while True:
            chunk = c.recv(4096)
            if not chunk:
                break
            data += chunk
    assert data.startswith(b"HTTP/1.0 200"), data[:80]
    assert b"Pyro Unit 1" in data
