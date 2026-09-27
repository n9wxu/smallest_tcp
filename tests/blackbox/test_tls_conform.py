"""
test_tls_conform.py — TLS 1.3 server conformance and interop (RFC 8446).

SUT: demo/tls_echo, started once for this module: a TLS 1.3 echo server on
port 4433 with the ECDSA P-256 test certificate from tests/tls (issued by
tests/tls/ca.pem for pyro-dead01.local, localhost and 10.0.0.2).  The
clients are production TLS stacks on the test host — Python's ssl module and
the openssl s_client CLI (OpenSSL 3) — over the TAP or veth (Linux) or feth
(macOS) link, through the host's TCP to ours.

Usage (Linux, tap0 up with 10.0.0.100/24):

    sudo python3 -m pytest tests/blackbox/test_tls_conform.py \\
        --iface tap0 --sut-ip 10.0.0.2 \\
        --tls-sut-bin ./build/demo/tls_echo_demo -v

Raw-socket driver instead of TAP: set the link up with sut_net.sh up raw,
then --iface veth-test --sut-iface raw:veth-sut.

Skipped when --tls-sut-bin is not given; the s_client tests are skipped
when there is no openssl CLI.
"""

import os
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time

import pytest

from helpers import sut_argv

PORT = 4433
HOSTNAME = "pyro-dead01.local"
HERE = os.path.dirname(os.path.abspath(__file__))
CA = os.path.join(HERE, "..", "tls", "ca.pem")
OPENSSL = shutil.which("openssl")

# ── SUT management ─────────────────────────────────────────────────────────────


def connect(host, timeout=5.0):
    """TCP connection to the SUT; retries while it re-arms its listener."""
    deadline = time.monotonic() + 3
    while True:
        try:
            return socket.create_connection((host, PORT), timeout=timeout)
        except ConnectionRefusedError:
            if time.monotonic() > deadline:
                raise
            time.sleep(0.1)


class TlsSut:
    def __init__(self, binary, host, sut_iface=None):
        self.argv = sut_argv(binary, sut_iface)
        self.host = host
        self.proc = None
        self.log_path = None

    def start(self, timeout=8.0):
        fd, self.log_path = tempfile.mkstemp(prefix="tls_sut_", suffix=".log")
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
        self.stop()  # not left holding the interface
        raise AssertionError(f"tls_echo_demo not reachable:\n{self.output()}")

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
    binary = request.config.getoption("--tls-sut-bin")
    if not binary:
        pytest.skip("--tls-sut-bin not given")
    s = TlsSut(binary, request.config.getoption("--sut-ip"),
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
        assert s.proc.poll() is None, f"tls_echo_demo exited:\n{s.output()}"


# ── Client helpers ─────────────────────────────────────────────────────────────

def client_ctx(**kw):
    ctx = ssl.create_default_context(cafile=CA)
    ctx.minimum_version = kw.pop("minimum", ssl.TLSVersion.TLSv1_3)
    if "maximum" in kw:
        ctx.maximum_version = kw.pop("maximum")
    return ctx


def tls_connect(sut, ctx=None, server_hostname=HOSTNAME):
    raw = connect(sut.host)
    return (ctx or client_ctx()).wrap_socket(raw,
                                             server_hostname=server_hostname)


def recv_exact(s, n):
    data = b""
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk:
            break
        data += chunk
    return data


def echo(s, data, chunk=4096):
    """Send @data in pieces, reading each piece back."""
    got = b""
    for i in range(0, len(data), chunk):
        part = data[i:i + chunk]
        s.sendall(part)
        got += recv_exact(s, len(part))
    return got


class MemoryTls:
    """A TLS client whose bytes we carry ourselves (ssl.MemoryBIO), so a
    test can split, delay or corrupt them on the way to the SUT."""

    def __init__(self, sut, ctx=None):
        self.sock = connect(sut.host)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.inc, self.out = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.obj = (ctx or client_ctx()).wrap_bio(
            self.inc, self.out, server_hostname=HOSTNAME)

    def flush(self, send=None):
        data = self.out.read()
        if data:
            (send or self.sock.sendall)(data)

    def feed(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionError("SUT closed the connection")
        self.inc.write(chunk)

    def handshake(self, send=None):
        while True:
            try:
                self.obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                self.flush(send)
                self.feed()
        self.flush(send)  # the client Finished

    def read(self, n):
        while True:
            try:
                return self.obj.read(n)
            except ssl.SSLWantReadError:
                self.feed()

    def close(self):
        self.sock.close()


def s_client(sut, *args, line=b"hello", timeout=10):
    """Run openssl s_client, send @line, and wait until it comes back or
    s_client exits (a failed handshake).  Returns (exit code or None if we
    stopped it, combined output)."""
    if not OPENSSL:
        pytest.skip("no openssl CLI")
    cmd = [OPENSSL, "s_client", "-connect", f"{sut.host}:{PORT}",
           "-CAfile", CA, "-verify_return_error", *args]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    os.set_blocking(p.stdout.fileno(), False)
    p.stdin.write(line + b"\n")
    p.stdin.flush()
    out = b""
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([p.stdout], [], [], 0.1)
            if ready:
                chunk = p.stdout.read() or b""
                out += chunk
                if not chunk and p.poll() is not None:
                    break
            elif p.poll() is not None:
                break
            # the echo: our line again after the connection summary
            if b"\n" + line + b"\n" in out.split(b"Peer Temp Key")[-1]:
                break
    finally:
        rc = p.poll()
        if rc is None:
            p.kill()
        p.wait()
    return rc, out.decode(errors="replace")


# ── Handshake and data (REQ-TLS-001/002/004/005/018..022) ─────────────────────

def test_tls_001_handshake(sut):
    """Python ssl completes a TLS 1.3 handshake: the only suite, the test
    certificate verified against its CA and the host name."""
    with tls_connect(sut) as s:
        assert s.version() == "TLSv1.3"
        assert s.cipher()[0] == "TLS_AES_128_GCM_SHA256"
        cert = s.getpeercert()
        assert ("commonName", HOSTNAME) in [x[0] for x in cert["subject"]]


def test_tls_002_echo(sut):
    with tls_connect(sut) as s:
        s.sendall(b"hello, TLS")
        assert recv_exact(s, 10) == b"hello, TLS"


def test_tls_003_echo_many_records(sut):
    """40 kB in 4 kB records, echoed through a 1460-byte TCP window."""
    data = os.urandom(40000)
    with tls_connect(sut) as s:
        assert echo(s, data) == data


def test_tls_004_full_size_record(sut):
    """One 2^14-byte record — the largest a peer may send."""
    data = os.urandom(16384)
    with tls_connect(sut) as s:
        s.sendall(data)
        assert recv_exact(s, len(data)) == data


def test_tls_005_close_notify(sut):
    """REQ-TLS-035: close_notify is answered with close_notify, then the SUT
    closes TCP."""
    s = tls_connect(sut)
    s.sendall(b"x")
    assert recv_exact(s, 1) == b"x"
    raw = s.unwrap()  # sends close_notify, waits for the SUT's
    raw.settimeout(5)
    assert raw.recv(16) == b""
    raw.close()


def test_tls_006_hostname_by_ip(sut):
    """The certificate's IP SAN matches when connecting by address."""
    with tls_connect(sut, server_hostname=sut.host) as s:
        s.sendall(b"ip")
        assert recv_exact(s, 2) == b"ip"


def test_tls_007_sequential_connections(sut):
    for i in range(5):
        with tls_connect(sut) as s:
            msg = f"connection {i}".encode()
            s.sendall(msg)
            assert recv_exact(s, len(msg)) == msg


# ── Refusals ───────────────────────────────────────────────────────────────────

def test_tls_010_tls12_refused(sut):
    """REQ-TLS-001: a TLS 1.2 client gets protocol_version."""
    ctx = client_ctx(minimum=ssl.TLSVersion.TLSv1_2,
                     maximum=ssl.TLSVersion.TLSv1_2)
    with pytest.raises(ssl.SSLError) as e:
        tls_connect(sut, ctx)
    assert "PROTOCOL_VERSION" in str(e.value).upper()


def test_tls_011_not_tls(sut):
    """Plain HTTP on the TLS port: an unexpected_message alert in the clear,
    then the connection closes."""
    with connect(sut.host) as s:
        s.sendall(b"GET / HTTP/1.0\r\n\r\n")
        s.settimeout(5)
        data = b""
        while True:
            chunk = s.recv(64)
            if not chunk:
                break
            data += chunk
    assert data == b"\x15\x03\x03\x00\x02\x02\x0a"


def test_tls_012_tampered_record(sut):
    """REQ-TLS-030: a record that fails authentication ends the connection
    with bad_record_mac."""
    t = MemoryTls(sut)
    try:
        t.handshake()
        t.obj.write(b"tamper me")
        rec = bytearray(t.out.read())
        rec[-1] ^= 0x01
        t.sock.sendall(bytes(rec))
        with pytest.raises(ssl.SSLError) as e:
            t.read(64)
        assert "BAD_RECORD_MAC" in str(e.value).upper()
    finally:
        t.close()


def test_tls_013_client_gone_mid_handshake(sut):
    """Half a ClientHello, then a reset: the next client is served."""
    t = MemoryTls(sut)
    try:
        t.obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = t.out.read()
    t.sock.sendall(hello[:len(hello) // 2])
    time.sleep(0.2)
    t.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                      struct.pack("ii", 1, 0))  # close = RST
    t.close()
    time.sleep(0.3)
    with tls_connect(sut) as s:
        s.sendall(b"ok")
        assert recv_exact(s, 2) == b"ok"


# ── Record layer ───────────────────────────────────────────────────────────────

def test_tls_020_client_hello_in_pieces(sut):
    """The ClientHello in 7-byte TCP segments: record reassembly."""
    t = MemoryTls(sut)

    def trickle(data):
        for i in range(0, len(data), 7):
            t.sock.sendall(data[i:i + 7])
            time.sleep(0.002)

    try:
        t.handshake(send=trickle)
        t.obj.write(b"reassembled")
        t.flush(trickle)
        assert t.read(64) == b"reassembled"
    finally:
        t.close()


def test_tls_021_records_coalesced(sut):
    """Client Finished and two application records in one TCP segment."""
    t = MemoryTls(sut)
    try:
        while True:
            try:
                t.obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                t.flush()
                t.feed()
        t.obj.write(b"one,")
        t.obj.write(b"two")
        t.sock.sendall(t.out.read())  # Finished + 2 records together
        got = b""
        while len(got) < 7:
            got += t.read(64)
        assert got == b"one,two"
    finally:
        t.close()


# ── openssl s_client interop ───────────────────────────────────────────────────

@pytest.mark.parametrize("group,shown", [("X25519", "X25519"),
                                         ("P-256", "prime256v1")])
def test_tls_030_groups(sut, group, shown):
    """REQ-TLS-004/005: x25519 and secp256r1 key exchange."""
    rc, out = s_client(sut, "-groups", group, "-brief")
    assert rc is None, out  # still connected when the echo came back
    assert "Protocol version: TLSv1.3" in out
    assert f"Peer Temp Key: {'ECDH, ' if group == 'P-256' else ''}{shown}" in out
    assert "\nhello\n" in out.split("Peer Temp Key")[1], out


def test_tls_031_default_client_hello(sut):
    """OpenSSL's default ClientHello (post-quantum X25519MLKEM768 share
    first, x25519 second, compatibility-mode session id)."""
    rc, out = s_client(sut, "-brief")
    assert rc is None, out
    assert "Ciphersuite: TLS_AES_128_GCM_SHA256" in out
    assert "\nhello\n" in out.split("Peer Temp Key")[1], out


def test_tls_032_no_middlebox_compat(sut):
    """No session id: no dummy change_cipher_spec either way."""
    rc, out = s_client(sut, "-no_middlebox", "-brief")
    assert rc is None, out
    assert "\nhello\n" in out.split("Peer Temp Key")[1], out


@pytest.mark.parametrize("args", [
    ("-groups", "P-384"),
    ("-ciphersuites", "TLS_CHACHA20_POLY1305_SHA256"),
    ("-ciphersuites", "TLS_AES_256_GCM_SHA384"),
    ("-sigalgs", "rsa_pss_rsae_sha256"),
], ids=["group", "chacha20", "aes256", "sigalg"])
def test_tls_033_nothing_in_common(sut, args):
    """No shared group, suite or signature scheme: handshake_failure."""
    rc, out = s_client(sut, *args, "-brief")
    assert rc not in (None, 0), out
    assert "alert handshake failure" in out, out


def test_tls_034_key_update(sut):
    """s_client 'K': KeyUpdate(update_requested); the SUT answers with its
    own and data flows under the new keys both ways."""
    if not OPENSSL:
        pytest.skip("no openssl CLI")
    cmd = [OPENSSL, "s_client", "-connect", f"{sut.host}:{PORT}",
           "-CAfile", CA, "-verify_return_error"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    try:
        time.sleep(1.0)
        p.stdin.write(b"K\n")
        p.stdin.flush()
        time.sleep(0.5)
        p.stdin.write(b"after-update\n")
        p.stdin.flush()
        time.sleep(1.0)
        p.stdin.close()
        out = p.stdout.read().decode(errors="replace")
    finally:
        p.kill()
        p.wait()
    assert "KEYUPDATE" in out
    assert "after-update" in out.split("KEYUPDATE")[1], out


# ── IPv6 ───────────────────────────────────────────────────────────────────────

def test_tls_040_over_ipv6(sut, request):
    """The same server over IPv6, at its link-local address (Linux)."""
    iface = request.config.getoption("--iface")
    mac = request.config.getoption("--mdns-sut-mac")  # the demos' MAC
    b = bytes.fromhex(mac.replace(":", ""))
    iid = bytes([b[0] ^ 0x02]) + b[1:3] + b"\xff\xfe" + b[3:6]
    ll = socket.inet_ntop(socket.AF_INET6, b"\xfe\x80" + bytes(6) + iid)
    deadline = time.monotonic() + 5
    while " preferred" not in sut.output() and time.monotonic() < deadline:
        time.sleep(0.1)
    if " preferred" not in sut.output():
        pytest.skip("tls_echo_demo is not dual-stack")
    try:
        raw = socket.create_connection((f"{ll}%{iface}", PORT), timeout=5)
    except OSError as e:
        pytest.skip(f"no IPv6 route to {ll}%{iface}: {e}")
    with client_ctx().wrap_socket(raw, server_hostname=HOSTNAME) as s:
        s.sendall(b"over IPv6")
        assert recv_exact(s, 9) == b"over IPv6"
