"""
test_dtls_conform.py — DTLS 1.3 server conformance and interop (RFC 9147).

SUT: demo/dtls_echo (dtls_echo_demo), a DTLS 1.3 echo server on UDP port
4433 at --sut-ip, started once for the module (restarted for tests that need
other settings).

Peers:
  * wolfSSL's example client (examples/client/client -u -v 4), the only
    widely available DTLS 1.3 implementation (OpenSSL and Mbed TLS have
    none): handshakes with each key-exchange group, HelloRetryRequest, PSK,
    KeyUpdate, several clients at once.
  * Hand-built datagrams over a plain UDP socket for what needs no peer:
    the cookie HelloRetryRequest, refusals, silence towards garbage.

Usage (Linux, tap0 up with 10.0.0.100/24; wolfSSL built with
-DWOLFSSL_DTLS=yes -DWOLFSSL_DTLS13=yes -DWOLFSSL_CURVE25519=yes
-DWOLFSSL_PSK=yes):

    sudo python3 -m pytest tests/blackbox/test_dtls_conform.py \\
        --iface tap0 --sut-ip 10.0.0.2 --our-ip 10.0.0.100 \\
        --dtls-sut-bin ./build/demo/dtls_echo_demo \\
        --wolfssl-client /path/to/wolfssl/build/examples/client/client -v

Raw-socket driver: sut_net.sh up raw, then --iface veth-test
--sut-iface raw:veth-sut.  The wolfSSL tests are skipped without
--wolfssl-client; the hand-built ones need only the SUT.
"""

import os
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time

import pytest

from helpers import sut_argv, wolfssl_root

PORT = 4433
HERE = os.path.dirname(os.path.abspath(__file__))
CA = os.path.join(HERE, "..", "tls", "ca.pem")

# wolfSSL's test pre-shared key for (D)TLS 1.3 (wolfssl/test.h)
WOLF_PSK = bytes.fromhex("0123456789abcdef" * 4)
WOLF_PSK_ID = "Client_identity"

HRR_RANDOM = bytes.fromhex(
    "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
CT_ALERT, CT_HANDSHAKE = 21, 22
HS_CLIENT_HELLO, HS_SERVER_HELLO = 1, 2
EXT_SUPPORTED_GROUPS, EXT_SIGNATURE_ALGORITHMS = 10, 13
EXT_SUPPORTED_VERSIONS, EXT_COOKIE, EXT_KEY_SHARE = 43, 44, 51
X25519, ECDSA_P256_SHA256, AES_128_GCM_SHA256 = 0x001D, 0x0403, 0x1301
DTLS13, DTLS12 = 0xFEFC, 0xFEFD
ALERT_ILLEGAL_PARAMETER, ALERT_PROTOCOL_VERSION = 47, 70


# ── Hand-built datagrams ─────────────────────────────────────────────────────

def ext(ext_type, data):
    return struct.pack("!HH", ext_type, len(data)) + data


def client_hello_body(legacy_cookie=b"", versions=(DTLS13,), cookie=None):
    """A DTLS 1.3 ClientHello (RFC 9147 §5.3) with an x25519 share: enough
    for the server to answer — the share is never used."""
    exts = ext(EXT_SUPPORTED_VERSIONS,
               bytes([2 * len(versions)]) +
               b"".join(struct.pack("!H", v) for v in versions))
    exts += ext(EXT_SUPPORTED_GROUPS, struct.pack("!HH", 2, X25519))
    exts += ext(EXT_SIGNATURE_ALGORITHMS, struct.pack("!HH", 2, ECDSA_P256_SHA256))
    exts += ext(EXT_KEY_SHARE,
                struct.pack("!HHH", 36, X25519, 32) + os.urandom(32))
    if cookie is not None:
        exts += ext(EXT_COOKIE, struct.pack("!H", len(cookie)) + cookie)
    return (struct.pack("!H", DTLS12) + os.urandom(32) + b"\x00" +
            bytes([len(legacy_cookie)]) + legacy_cookie +
            struct.pack("!HH", 2, AES_128_GCM_SHA256) + b"\x01\x00" +
            struct.pack("!H", len(exts)) + exts)


def plaintext_handshake(msg_type, body, msg_seq=0, rec_seq=0):
    """One whole handshake message in a DTLSPlaintext record (RFC 9147 §4)."""
    n = len(body).to_bytes(3, "big")
    hs = (bytes([msg_type]) + n + struct.pack("!H", msg_seq) + b"\x00" * 3 +
          n + body)
    return (bytes([CT_HANDSHAKE]) + struct.pack("!H", DTLS12) + b"\x00\x00" +
            rec_seq.to_bytes(6, "big") + struct.pack("!H", len(hs)) + hs)


def parse_hello(dgram):
    """The first handshake message of a DTLSPlaintext datagram:
    (type, legacy_version, random, session id, {extension: data})."""
    assert dgram[0] == CT_HANDSHAKE, f"not a plaintext handshake: {dgram[:16].hex()}"
    hs = dgram[13:]
    body = hs[12:12 + int.from_bytes(hs[9:12], "big")]
    version, random = struct.unpack("!H", body[:2])[0], body[2:34]
    sid_len = body[34]
    sid = body[35:35 + sid_len]
    off = 35 + sid_len + 3  # cipher suite, compression
    exts_len = struct.unpack("!H", body[off:off + 2])[0]
    exts, off = {}, off + 2
    end = off + exts_len
    while off + 4 <= end:
        t, n = struct.unpack("!HH", body[off:off + 4])
        exts[t] = body[off + 4:off + 4 + n]
        off += 4 + n
    return hs[0], version, random, sid, exts


def alert_of(dgram):
    """A plaintext alert datagram's (level, description), else None."""
    if len(dgram) >= 15 and dgram[0] == CT_ALERT:
        return dgram[13], dgram[14]
    return None


class Udp:
    """A UDP socket on the test host, talking to the SUT's port."""

    def __init__(self, our_ip, sut_ip, timeout=2.0):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.bind((our_ip, 0))
        self.s.settimeout(timeout)
        self.dst = (sut_ip, PORT)

    def send(self, data):
        self.s.sendto(data, self.dst)

    def recv(self):
        try:
            return self.s.recvfrom(65536)[0]
        except socket.timeout:
            return None

    def close(self):
        self.s.close()


# ── The SUT ──────────────────────────────────────────────────────────────────

class DtlsSut:
    def __init__(self, binary, host, our_ip, sut_iface=None):
        self.argv = sut_argv(binary, sut_iface)
        self.host, self.our_ip = host, our_ip
        self.proc = None
        self.log_path = None

    def start(self, timeout=8.0, **env):
        fd, self.log_path = tempfile.mkstemp(prefix="dtls_sut_", suffix=".log")
        full = dict(os.environ, TLS_PSK=WOLF_PSK.hex(), TLS_PSK_ID=WOLF_PSK_ID,
                    TLS_PSK_MODES="both", **env)
        self.proc = subprocess.Popen(self.argv, stdout=fd, env=full,
                                     stderr=subprocess.STDOUT)
        os.close(fd)
        # ready once a ClientHello is answered
        u = Udp(self.our_ip, self.host, timeout=0.5)
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline and self.proc.poll() is None:
                u.send(plaintext_handshake(HS_CLIENT_HELLO, client_hello_body()))
                if u.recv():
                    return
        finally:
            u.close()
        self.stop()  # not left holding the interface
        raise AssertionError(f"dtls_echo_demo not answering:\n{self.output()}")

    def restart(self, **env):
        self.stop()
        self.start(**env)

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
    binary = request.config.getoption("--dtls-sut-bin")
    if not binary:
        pytest.skip("--dtls-sut-bin not given")
    s = DtlsSut(binary, request.config.getoption("--sut-ip"),
                request.config.getoption("--our-ip"),
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
        assert s.proc.poll() is None, f"dtls_echo_demo exited:\n{s.output()}"


@pytest.fixture
def udp(sut):
    u = Udp(sut.our_ip, sut.host)
    yield u
    u.close()


@pytest.fixture
def wolfssl(request, sut):
    """Run wolfSSL's DTLS 1.3 client against the SUT: (exit code, output)."""
    binary = request.config.getoption("--wolfssl-client")
    if not binary:
        pytest.skip("--wolfssl-client not given")
    binary = os.path.abspath(binary)  # it runs in its own source tree

    def run(*args, timeout=30):
        argv = [binary, "-u", "-v", "4", "-h", sut.host, "-p", str(PORT),
                "-A", CA, "-x", *args]
        p = subprocess.run(argv, capture_output=True, text=True,
                           timeout=timeout, cwd=wolfssl_root(binary))
        return p.returncode, p.stdout + p.stderr

    return run


def established(sut, count=1):
    return sut.output().count("DTLS 1.3 established") >= count


# ── Interop: wolfSSL's client ────────────────────────────────────────────────

class TestInterop:
    """REQ-DTLS-001..007, 042, 052, 060: a whole handshake, the echo of
    the client's message, and close_notify, for each way a client may
    start."""

    def _ok(self, sut, rc, out, group):
        assert rc == 0, out
        assert "DTLSv1.3" in out, out
        assert "hello wolfssl!" in out, out
        assert f"SSL curve name is {group}" in out, out

    def test_dtls_001_handshake_p256(self, sut, wolfssl):
        """wolfSSL's default share is P-256; the cookie exchange first."""
        before = sut.output().count("DTLS 1.3 established")
        rc, out = wolfssl()
        self._ok(sut, rc, out, "SECP256R1")
        assert established(sut, before + 1)

    def test_dtls_002_handshake_x25519(self, sut, wolfssl):
        rc, out = wolfssl("-t")
        self._ok(sut, rc, out, "X25519")

    def test_dtls_003_hello_retry_for_a_group(self, sut, wolfssl):
        """-J: no share at first; the HelloRetryRequest asks for one, with
        the cookie."""
        rc, out = wolfssl("-J")
        self._ok(sut, rc, out, "X25519")

    def test_dtls_004_key_update_from_client(self, sut, wolfssl):
        """-I: the client updates its keys before sending; the SUT
        acknowledges the KeyUpdate and follows it (REQ-DTLS-060, 061)."""
        rc, out = wolfssl("-I")
        self._ok(sut, rc, out, "SECP256R1")

    def test_dtls_005_psk_dhe(self, sut, wolfssl):
        rc, out = wolfssl("-s", "--openssl-psk", "-l", "TLS13-AES128-GCM-SHA256")
        self._ok(sut, rc, out, "SECP256R1")
        assert "secp256r1, PSK)" in sut.output()

    def test_dtls_006_psk_ke(self, sut, wolfssl):
        rc, out = wolfssl("-s", "-K", "--openssl-psk", "-l",
                          "TLS13-AES128-GCM-SHA256")
        assert rc == 0 and "hello wolfssl!" in out, out
        assert "no (EC)DHE, PSK" in sut.output()

    def test_dtls_007_clients_at_once(self, sut, wolfssl):
        """Three clients in parallel, each its own connection."""
        results = []

        def one():
            results.append(wolfssl("-t"))

        threads = [threading.Thread(target=one) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 3
        for rc, out in results:
            assert rc == 0 and "hello wolfssl!" in out, out

    def test_dtls_008_fragmented_flight(self, sut, wolfssl):
        """REQ-DTLS-033: with 300-byte datagrams the server's flight goes in
        fragments, which wolfSSL reassembles."""
        sut.restart(DTLS_MTU="300")
        try:
            rc, out = wolfssl()
            self._ok(sut, rc, out, "SECP256R1")
        finally:
            sut.restart()

    def test_dtls_009_no_cookie(self, sut, wolfssl):
        """REQ-DTLS-043: configured not to, the server answers the first
        ClientHello with its ServerHello."""
        sut.restart(DTLS_NO_COOKIE="1")
        try:
            u = Udp(sut.our_ip, sut.host)
            u.send(plaintext_handshake(HS_CLIENT_HELLO, client_hello_body()))
            reply = u.recv()
            u.close()
            assert reply and parse_hello(reply)[2] != HRR_RANDOM
            rc, out = wolfssl()
            self._ok(sut, rc, out, "SECP256R1")
        finally:
            sut.restart()


# ── Hand-built datagrams ─────────────────────────────────────────────────────

class TestCookie:
    def test_dtls_020_cookie(self, sut, udp):
        """REQ-DTLS-004, 043: a HelloRetryRequest with a cookie, DTLS's
        versions, no session id echoed."""
        udp.send(plaintext_handshake(HS_CLIENT_HELLO, client_hello_body()))
        reply = udp.recv()
        assert reply, "no answer to a ClientHello"
        msg, version, random, sid, exts = parse_hello(reply)
        assert msg == HS_SERVER_HELLO and random == HRR_RANDOM
        assert version == DTLS12 and sid == b""
        assert exts[EXT_SUPPORTED_VERSIONS] == struct.pack("!H", DTLS13)
        cookie = exts[EXT_COOKIE]
        assert len(cookie) >= 3 and struct.unpack("!H", cookie[:2])[0] == len(cookie) - 2
        assert EXT_KEY_SHARE not in exts  # the share was fine

    def test_dtls_021_same_hello_same_cookie(self, sut, udp):
        """REQ-DTLS-038: the ClientHello again (its HelloRetryRequest lost)
        is answered with the same HelloRetryRequest."""
        ch = plaintext_handshake(HS_CLIENT_HELLO, client_hello_body())
        udp.send(ch)
        first = udp.recv()
        udp.send(ch[:5] + (1).to_bytes(6, "big") + ch[11:])  # a new record
        again = udp.recv()
        assert first and again
        assert parse_hello(first)[4][EXT_COOKIE] == parse_hello(again)[4][EXT_COOKIE]

    def test_dtls_022_wrong_cookie_refused(self, sut, udp):
        """REQ-DTLS-044: a second ClientHello with a cookie not the one
        sent: illegal_parameter."""
        udp.send(plaintext_handshake(HS_CLIENT_HELLO, client_hello_body()))
        cookie = parse_hello(udp.recv())[4][EXT_COOKIE][2:]
        wrong = bytes([cookie[0] ^ 1]) + cookie[1:]
        udp.send(plaintext_handshake(HS_CLIENT_HELLO,
                                     client_hello_body(cookie=wrong),
                                     msg_seq=1, rec_seq=1))
        assert alert_of(udp.recv() or b"") == (2, ALERT_ILLEGAL_PARAMETER)

    def test_dtls_023_legacy_cookie_refused(self, sut, udp):
        """REQ-DTLS-003: a DTLS 1.3 ClientHello with a legacy_cookie."""
        udp.send(plaintext_handshake(HS_CLIENT_HELLO,
                                     client_hello_body(legacy_cookie=b"\xaa")))
        assert alert_of(udp.recv() or b"") == (2, ALERT_ILLEGAL_PARAMETER)

    def test_dtls_024_dtls12_refused(self, sut, udp):
        """REQ-DTLS-001: DTLS 1.2 only."""
        udp.send(plaintext_handshake(HS_CLIENT_HELLO,
                                     client_hello_body(versions=(DTLS12,))))
        assert alert_of(udp.recv() or b"") == (2, ALERT_PROTOCOL_VERSION)


class TestSilence:
    """REQ-DTLS-014, 022: what is not DTLS 1.3 gets no answer at all."""

    @pytest.mark.parametrize("junk", [
        b"\x40" + b"\x00" * 40,                        # no content type
        b"\x17\xfe\xfd" + b"\x00" * 30,               # DTLS 1.2 application data
        b"\x2f\x00\x00\x00\x20" + b"\x55" * 32,        # a forged protected record
        b"\x16\xfe\xfd\x00\x00",                       # truncated
    ], ids=["type", "dtls12", "forged", "truncated"])
    def test_dtls_030_ignored(self, sut, udp, junk):
        """REQ-DTLS-014, 022: no record of DTLS 1.3, no answer."""
        udp.send(junk)
        assert udp.recv() is None

    def test_dtls_031_still_serving(self, sut, wolfssl):
        rc, out = wolfssl()
        assert rc == 0 and "hello wolfssl!" in out, out
