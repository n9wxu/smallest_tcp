"""
test_https_conform.py — HTTPS: HTTP/1.0 over smallest_tcp's TLS 1.3.

SUT: demo/https_demo, started once for this module: port 443, the test
certificate from tests/tls (pyro-dead01.local, localhost, 10.0.0.2).  The
clients are Python's http.client over ssl and curl, through the host's TCP
to ours.

Usage (Linux, tap0 up with 10.0.0.100/24):

    sudo python3 -m pytest tests/blackbox/test_https_conform.py \\
        --iface tap0 --sut-ip 10.0.0.2 \\
        --https-sut-bin ./build/demo/https_demo -v

Skipped when --https-sut-bin is not given; the curl test when there is no
curl.
"""

import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import tempfile
import time

import pytest

from helpers import sut_argv

PORT = 443
HOSTNAME = "pyro-dead01.local"
CA = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tls",
                  "ca.pem")
CURL = shutil.which("curl")


class HttpsSut:
    def __init__(self, binary, host, sut_iface=None):
        self.argv = sut_argv(binary, sut_iface)
        self.host = host
        self.proc = None
        self.log_path = None

    def start(self, timeout=8.0):
        fd, self.log_path = tempfile.mkstemp(prefix="https_sut_",
                                             suffix=".log")
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
        self.stop()
        raise AssertionError(f"https_demo not reachable:\n{self.output()}")

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
    binary = request.config.getoption("--https-sut-bin")
    if not binary:
        pytest.skip("--https-sut-bin not given")
    s = HttpsSut(binary, request.config.getoption("--sut-ip"),
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
        assert s.proc.poll() is None, f"https_demo exited:\n{s.output()}"


def fetch(sut, method, path, host=HOSTNAME, body=None):
    """One HTTP/1.0 request over TLS 1.3, checked against the CA and @host
    (SNI too); the SUT closes after each.  Retries while it re-arms its
    listener.  Returns (status, lower-cased headers, body)."""
    ctx = ssl.create_default_context(cafile=CA)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    deadline = time.monotonic() + 3
    while True:
        try:
            raw = socket.create_connection((sut.host, PORT), timeout=10)
            break
        except ConnectionRefusedError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)
    with ctx.wrap_socket(raw, server_hostname=host) as s:
        req = f"{method} {path} HTTP/1.0\r\nHost: {host}\r\n"
        if body is not None:
            req += f"Content-Length: {len(body)}\r\n"
        s.sendall(req.encode() + b"\r\n" + (body or b""))
        data = b""
        while True:
            try:
                chunk = s.recv(65536)
            except ssl.SSLZeroReturnError:
                break
            if not chunk:
                break
            data += chunk
    head, _, content = data.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    status = int(lines[0].split()[1])
    hdrs = {k.strip().lower(): v.strip()
            for k, _, v in (l.partition(":") for l in lines[1:])}
    return status, hdrs, content


def test_https_001_index(sut):
    status, hdrs, body = fetch(sut, "GET", "/")
    assert status == 200
    assert hdrs["content-type"] == "text/html"
    assert b"Pyro Unit 1" in body
    assert int(hdrs["content-length"]) == len(body)


def test_https_002_status(sut):
    status, hdrs, body = fetch(sut, "GET", "/api/status")
    assert status == 200 and hdrs["content-type"] == "application/json"
    doc = json.loads(body)
    assert doc["tls"] == "TLSv1.3"
    assert doc["cipher"] == "TLS_AES_128_GCM_SHA256"
    assert doc["group"] == "x25519" and doc["auth"] == "certificate"


def test_https_003_big(sut):
    """20000 bytes: many TLS records, many TCP segments."""
    status, _, body = fetch(sut, "GET", "/big")
    assert status == 200
    want = bytes((0x0A if (i & 63) == 63 else 0x61 + i % 26)
                 for i in range(20000))
    assert body == want


def test_https_004_head(sut):
    status, hdrs, body = fetch(sut, "HEAD", "/big")
    assert status == 200 and body == b""
    assert hdrs["content-length"] == "20000"


def test_https_005_not_found(sut):
    status, _, _ = fetch(sut, "GET", "/nope")
    assert status == 404


def test_https_006_post_not_allowed(sut):
    status, hdrs, _ = fetch(sut, "POST", "/", body=b"x=1")
    assert status == 405
    assert "GET" in hdrs.get("allow", "")


def test_https_007_by_address(sut):
    """By address: the certificate's iPAddress name, no SNI."""
    status, _, body = fetch(sut, "GET", "/", host=sut.host)
    assert status == 200 and b"Pyro Unit 1" in body


def test_https_008_curl(sut):
    if not CURL:
        pytest.skip("no curl")
    p = subprocess.run(
        [CURL, "-sS", "--max-time", "20", "--cacert", CA, "--resolve",
         f"{HOSTNAME}:{PORT}:{sut.host}", f"https://{HOSTNAME}/big"],
        capture_output=True, timeout=30)
    assert p.returncode == 0, p.stderr
    assert len(p.stdout) == 20000


def test_https_009_sequential(sut):
    for _ in range(5):
        status, _, _ = fetch(sut, "GET", "/api/status")
        assert status == 200
