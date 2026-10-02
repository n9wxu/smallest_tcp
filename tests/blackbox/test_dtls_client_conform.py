"""
test_dtls_client_conform.py — DTLS 1.3 client conformance and interop
(RFC 9147).

SUT: demo/dtls_client (dtls_client_demo), run once per test: it connects
from 10.0.0.2 to a DTLS 1.3 server on the test host (--our-ip, UDP port
4433), sends a message or a block of bytes in datagrams, reads the echo and
closes with close_notify.  The server is wolfSSL's example server
(examples/server/server -u -v 4 -e) with the credentials in tests/tls.

Usage (Linux, tap0 up with 10.0.0.100/24):

    sudo python3 -m pytest tests/blackbox/test_dtls_client_conform.py \\
        --iface tap0 --our-ip 10.0.0.100 \\
        --dtls-client-bin ./build/demo/dtls_client_demo \\
        --wolfssl-server /path/to/wolfssl/build/examples/server/server -v

Raw-socket driver: sut_net.sh up raw, then --iface veth-test
--sut-iface raw:veth-sut.  Skipped without --dtls-client-bin and
--wolfssl-server.
"""

import os
import signal
import subprocess
import tempfile
import time

import pytest

from helpers import sut_argv, wolfssl_root

PORT = 4433
HERE = os.path.dirname(os.path.abspath(__file__))
TLS_DIR = os.path.join(HERE, "..", "tls")
WOLF_PSK = "0123456789abcdef" * 4  # wolfssl/test.h, (D)TLS 1.3
WOLF_PSK_ID = "Client_identity"
ALERT_BAD_CERTIFICATE, ALERT_UNKNOWN_CA = 42, 48


def cred(name):
    return os.path.join(TLS_DIR, name)


class WolfServer:
    """wolfSSL's example DTLS 1.3 server on the test host: one connection,
    echoing what it receives."""

    def __init__(self, binary, *args):
        fd, self.log_path = tempfile.mkstemp(prefix="wolf_srv_", suffix=".log")
        argv = [binary, "-u", "-v", "4", "-p", str(PORT), "-b", "-d", "-e",
                "-c", cred("server.pem"), "-k", cred("server.key"), *args]
        self.proc = subprocess.Popen(argv, stdout=fd, stderr=subprocess.STDOUT,
                                     cwd=wolfssl_root(binary))
        os.close(fd)
        time.sleep(0.5)  # bound and waiting

    def output(self):
        with open(self.log_path, errors="replace") as f:
            return f.read()

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            try:
                self.proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        os.unlink(self.log_path)


@pytest.fixture
def server(request):
    binary = request.config.getoption("--wolfssl-server")
    if not binary or not request.config.getoption("--dtls-client-bin"):
        pytest.skip("--wolfssl-server and --dtls-client-bin not both given")
    started = []

    def start(*args):
        s = WolfServer(os.path.abspath(binary), *args)  # run in its tree
        started.append(s)
        return s

    yield start
    for s in started:
        s.stop()


@pytest.fixture
def client(request):
    """Run dtls_client_demo: (exit code, output)."""
    argv = sut_argv(request.config.getoption("--dtls-client-bin"),
                    request.config.getoption("--sut-iface"))
    our_ip = request.config.getoption("--our-ip")

    def run(timeout=40, **env):
        full = dict(os.environ, DTLS_SERVER=our_ip, DTLS_PORT=str(PORT),
                    TLS_CA=cred("ca.pem"))
        full.update(env)
        p = subprocess.run(argv, env=full, capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, p.stdout + p.stderr

    return run


def test_dtls_c01_echo(server, client):
    """REQ-DTLS-001..007, 019, 033: a handshake with the certificate
    checked, 3000 bytes in datagrams, echoed intact, close_notify."""
    server()
    rc, out = client(TLS_BYTES="3000")
    assert rc == 0, out
    assert "DTLS 1.3 established (TLS_AES_128_GCM_SHA256, x25519, certificate)" in out
    assert "echo ok (3000 bytes)" in out


def test_dtls_c02_cookie(server, client):
    """REQ-DTLS-042: the server's HelloRetryRequest carries a cookie; the
    second ClientHello returns it."""
    server("-J")
    rc, out = client(TLS_BYTES="100")
    assert rc == 0 and "echo ok" in out, out


def test_dtls_c03_key_update_from_server(server, client):
    """REQ-DTLS-052, 061: the server updates its keys before sending; the
    client acknowledges the KeyUpdate and reads what follows."""
    server("-U")
    rc, out = client(TLS_BYTES="100")
    assert rc == 0 and "echo ok" in out, out


def test_dtls_c04_key_update_from_client(server, client):
    """REQ-DTLS-060: our KeyUpdate (asking the server's too), acknowledged
    before the new keys are used."""
    server()
    rc, out = client(TLS_BYTES="2000", TLS_KEY_UPDATE="1")
    assert rc == 0, out
    assert "KeyUpdate sent" in out and "echo ok" in out, out


def test_dtls_c05_small_datagrams(server, client):
    """REQ-DTLS-020: 300-byte datagrams: the data in many records."""
    server()
    rc, out = client(TLS_BYTES="3000", DTLS_MTU="300")
    assert rc == 0 and "echo ok (3000 bytes)" in out, out


def test_dtls_c06_psk(server, client):
    """A pre-shared key: no certificate."""
    server("-s")
    rc, out = client(TLS_BYTES="100", TLS_PSK=WOLF_PSK, TLS_PSK_ID=WOLF_PSK_ID,
                     TLS_PSK_MODES="both")
    assert rc == 0, out
    assert "PSK)" in out and "echo ok" in out, out


def test_dtls_c07_wrong_name(server, client):
    """The certificate does not name the server we asked for."""
    server()
    rc, out = client(TLS_NAME="other.example")
    assert rc == 2, out
    assert f"DTLS alert {ALERT_BAD_CERTIFICATE}" in out, out


def test_dtls_c08_untrusted(server, client):
    """A chain that does not lead to our trust anchor."""
    server()
    rc, out = client(TLS_CA=cred("rsa.pem"))
    assert rc == 2, out
    assert f"DTLS alert {ALERT_UNKNOWN_CA}" in out, out
