"""
test_tls_client_conform.py — TLS 1.3 client conformance and interop
(RFC 8446).

SUT: demo/tls_client, run once per test: it connects from 10.0.0.2 to a TLS
server on the test host (--our-ip, port 4433), sends a message or a block of
bytes, reads the reply and closes with close_notify.  The servers are
production TLS stacks on the test host — Python's ssl module and openssl
s_server (OpenSSL 3) — with the credentials in tests/tls.

Usage (Linux, tap0 up with 10.0.0.100/24):

    sudo python3 -m pytest tests/blackbox/test_tls_client_conform.py \\
        --iface tap0 --our-ip 10.0.0.100 \\
        --tls-client-bin ./build/demo/tls_client_demo -v

Raw-socket driver instead of TAP: set the link up with sut_net.sh up raw,
then --iface veth-test --sut-iface raw:veth-sut.  macOS (feth):
--iface feth0 --our-ip 10.0.0.1.

Skipped when --tls-client-bin is not given; the s_server test is skipped
when there is no openssl CLI.
"""

import os
import shutil
import socket
import ssl
import subprocess
import threading
import time

import pytest

from helpers import sut_argv

PORT = 4433
PSK = bytes.fromhex("707366b2103254769ba8dcfe0123456789abcdef1122334455667788990aabbc")
PSK_ID = "device-1"
HERE = os.path.dirname(os.path.abspath(__file__))
TLS_DIR = os.path.join(HERE, "..", "tls")
CA = os.path.join(TLS_DIR, "ca.pem")
OPENSSL = shutil.which("openssl")


def cred(name):
    return os.path.join(TLS_DIR, name)


class Server(threading.Thread):
    """One-connection TLS 1.3 echo server (Python ssl) on the test host."""

    def __init__(self, host, cert="server.pem", key="server.key",
                 verify=ssl.CERT_NONE, maximum=None, psk=None):
        super().__init__(daemon=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if maximum:
            ctx.maximum_version = maximum
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        if cert:
            ctx.load_cert_chain(cred(cert), cred(key))
        if psk:
            ctx.set_psk_server_callback(
                lambda identity: psk if identity == PSK_ID else b"")
        if verify != ssl.CERT_NONE:
            ctx.verify_mode = verify
            ctx.load_verify_locations(CA)
        ctx.sni_callback = self._sni
        self.ctx = ctx
        self.sni = None
        self.error = None
        self.info = {}
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, PORT))
        self.sock.listen(1)
        self.sock.settimeout(30)

    def _sni(self, sock, name, ctx):
        self.sni = name

    def run(self):
        try:
            conn, _ = self.sock.accept()
            conn.settimeout(20)
            with self.ctx.wrap_socket(conn, server_side=True) as s:
                self.info = {"version": s.version(), "cipher": s.cipher()[0]}
                while True:
                    data = s.recv(65536)
                    if not data:  # close_notify
                        break
                    s.sendall(data)
                try:
                    s.unwrap()  # answer with close_notify
                except (OSError, ssl.SSLError):
                    pass
        except Exception as e:  # reported by the test
            self.error = e
        finally:
            self.sock.close()


@pytest.fixture
def client(request):
    binary = request.config.getoption("--tls-client-bin")
    if not binary:
        pytest.skip("--tls-client-bin not given")
    argv = sut_argv(binary, request.config.getoption("--sut-iface"))
    our_ip = request.config.getoption("--our-ip")

    def run(**env):
        e = dict(os.environ, TLS_SERVER=our_ip, TLS_PORT=str(PORT))
        e.update({k: str(v) for k, v in env.items()})
        p = subprocess.run(argv, env=e, capture_output=True, timeout=40)
        return p.returncode, (p.stdout + p.stderr).decode(errors="replace")

    run.our_ip = our_ip
    return run


def serve(client, **kw):
    s = Server(client.our_ip, **kw)
    s.start()
    return s


def finish(server):
    server.join(timeout=10)
    return server


# ── Handshake and data (REQ-TLS-010..017) ─────────────────────────────────────

def test_tls_c01_echo(client):
    """Handshake with Python ssl; the certificate checked against the CA and
    the name, which also goes out as server_name."""
    srv = serve(client)
    rc, out = client()
    finish(srv)
    assert rc == 0, out
    assert "TLS 1.3 established" in out
    assert "received: hello from smallest_tcp" in out
    assert srv.error is None, srv.error
    assert srv.info == {"version": "TLSv1.3",
                        "cipher": "TLS_AES_128_GCM_SHA256"}
    assert srv.sni == "pyro-dead01.local"


def test_tls_c02_bulk(client):
    """30 kB each way: many records, full-size ones from the server."""
    srv = serve(client)
    rc, out = client(TLS_BYTES=30000)
    finish(srv)
    assert rc == 0, out
    assert "echo ok (30000 bytes)" in out


def test_tls_c03_rsa_pss(client):
    """An RSA certificate: CertificateVerify with rsa_pss_rsae_sha256."""
    srv = serve(client, cert="rsa.pem", key="rsa.key")
    rc, out = client(TLS_NAME="rsa.example")
    finish(srv)
    assert rc == 0, out
    assert srv.error is None, srv.error


def test_tls_c04_no_name_check(client):
    """No name: no server_name, no name check (the chain still is)."""
    srv = serve(client)
    rc, out = client(TLS_NAME="-")
    finish(srv)
    assert rc == 0, out
    assert srv.sni is None


# ── Refusals ───────────────────────────────────────────────────────────────────

def test_tls_c10_wrong_name(client):
    """REQ-TLS-014: a certificate for another name: bad_certificate."""
    srv = serve(client)
    rc, out = client(TLS_NAME="evil.example")
    finish(srv)
    assert rc == 2, out
    assert "TLS alert 42" in out
    assert "BAD_CERTIFICATE" in str(srv.error).upper()


def test_tls_c11_untrusted(client):
    """A chain that does not lead to the trust anchors: unknown_ca."""
    srv = serve(client)
    rc, out = client(TLS_CA=cred("rsa.pem"))
    finish(srv)
    assert rc == 2, out
    assert "TLS alert 48" in out
    assert "UNKNOWN_CA" in str(srv.error).upper()


def test_tls_c12_tls12_server(client):
    """A TLS 1.2 server cannot serve a TLS 1.3-only client."""
    srv = serve(client, maximum=ssl.TLSVersion.TLSv1_2)
    rc, out = client()
    finish(srv)
    assert rc == 2, out
    assert "TLS alert 70" in out  # protocol_version, from the server


# ── Client certificates ────────────────────────────────────────────────────────

def test_tls_c20_certificate_request_optional(client):
    """The server asks for a certificate: the client has none and says so
    with an empty Certificate; an optional request is satisfied."""
    srv = serve(client, verify=ssl.CERT_OPTIONAL)
    rc, out = client()
    finish(srv)
    assert rc == 0, out
    assert srv.error is None, srv.error


def test_tls_c21_certificate_required(client):
    """.. a mandatory one ends with certificate_required (116)."""
    srv = serve(client, verify=ssl.CERT_REQUIRED)
    rc, out = client()
    finish(srv)
    assert rc == 2, out
    assert "TLS alert 116" in out


# ── openssl s_server ───────────────────────────────────────────────────────────

def test_tls_c30_openssl_s_server(client):
    """OpenSSL's s_server in -rev mode sends each line back reversed (and
    session tickets, which the client ignores)."""
    if not OPENSSL:
        pytest.skip("no openssl CLI")
    p = subprocess.Popen(
        [OPENSSL, "s_server", "-accept", f"{client.our_ip}:{PORT}",
         "-cert", cred("server.pem"), "-key", cred("server.key"),
         "-tls1_3", "-rev", "-naccept", "1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        time.sleep(1.0)
        rc, out = client(TLS_MESSAGE="hello s_server\n")
    finally:
        p.kill()
        srv_out = p.communicate()[0].decode(errors="replace")
    assert rc == 0, out + srv_out
    assert "received: revres_s olleh" in out
    assert "Protocol version: TLSv1.3" in srv_out


def test_tls_c05_max_fragment_length(client):
    """REQ-TLS-031: the client asks for 512-byte records (the server, an
    OpenSSL, grants it); 20 kB echo through them."""
    srv = serve(client)
    rc, out = client(TLS_MFL=512, TLS_BYTES=20000)
    finish(srv)
    assert rc == 0, out
    assert "max_fragment_length 512" in out
    assert "echo ok (20000 bytes)" in out


def test_tls_c06_key_update(client):
    """The client updates its keys and asks the server to; data flows on
    under the new keys both ways."""
    srv = serve(client)
    rc, out = client(TLS_KEY_UPDATE=1, TLS_BYTES=5000)
    finish(srv)
    assert rc == 0, out
    assert "KeyUpdate sent" in out and "echo ok (5000 bytes)" in out
    assert srv.error is None, srv.error


def test_tls_c31_hello_retry(client):
    """A secp256r1-only s_server answers the x25519 share with a
    HelloRetryRequest; the second ClientHello has a secp256r1 share."""
    if not OPENSSL:
        pytest.skip("no openssl CLI")
    p = subprocess.Popen(
        [OPENSSL, "s_server", "-accept", f"{client.our_ip}:{PORT}",
         "-cert", cred("server.pem"), "-key", cred("server.key"),
         "-tls1_3", "-rev", "-groups", "P-256", "-naccept", "1"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    try:
        time.sleep(1.0)
        rc, out = client(TLS_MESSAGE="hrr\n")
    finally:
        p.kill()
        srv_out = p.communicate()[0].decode(errors="replace")
    assert rc == 0, out + srv_out
    assert "secp256r1, certificate" in out
    assert "received: rrh" in out


# ── Pre-shared keys (REQ-TLS-023/024) ──────────────────────────────────────────

PSK_ENV = {"TLS_PSK": PSK.hex(), "TLS_PSK_ID": PSK_ID,
           # trusting nothing the servers could show: the PSK must do
           "TLS_CA": cred("rsa.pem")}


@pytest.mark.skipif(not hasattr(ssl.SSLContext, "set_psk_server_callback"),
                    reason="Python ssl without PSK callbacks (< 3.13)")
def test_tls_c40_psk_python(client):
    """A PSK-only Python server (no certificate at all)."""
    srv = serve(client, cert=None, psk=PSK)
    rc, out = client(**PSK_ENV)
    finish(srv)
    assert rc == 0, out
    assert "PSK" in out and "received: hello from smallest_tcp" in out
    assert srv.error is None, srv.error


def s_server(client, *args):
    if not OPENSSL:
        pytest.skip("no openssl CLI")
    p = subprocess.Popen(
        [OPENSSL, "s_server", "-accept", f"{client.our_ip}:{PORT}", "-nocert",
         "-psk", PSK.hex(), "-psk_identity", PSK_ID, "-tls1_3", "-rev",
         "-naccept", "1", *args],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    time.sleep(1.0)
    return p


def test_tls_c41_psk_openssl(client):
    """PSK with (EC)DHE against OpenSSL's s_server, which has no
    certificate."""
    p = s_server(client)
    try:
        rc, out = client(TLS_MESSAGE="psk\n", **PSK_ENV)
    finally:
        p.kill()
        srv_out = p.communicate()[0].decode(errors="replace")
    assert rc == 0, out + srv_out
    assert "x25519, PSK" in out
    assert "received: ksp" in out


def test_tls_c42_psk_ke_openssl(client):
    """psk_ke: the PSK alone, no (EC)DHE — the cheapest handshake."""
    p = s_server(client, "-allow_no_dhe_kex")
    try:
        rc, out = client(TLS_MESSAGE="ke\n", TLS_PSK_MODES="ke", **PSK_ENV)
    finally:
        p.kill()
        srv_out = p.communicate()[0].decode(errors="replace")
    assert rc == 0, out + srv_out
    assert "no (EC)DHE, PSK" in out
    assert "received: ek" in out


def test_tls_c43_psk_wrong_key(client):
    p = s_server(client)
    try:
        env = dict(PSK_ENV, TLS_PSK="00" * 32)
        rc, out = client(**env)
    finally:
        p.kill()
        p.communicate()
    assert rc == 2, out
    assert "TLS alert 51" in out  # decrypt_error, from s_server
