#!/usr/bin/env python3
"""gen_rfc8448.py — C header of RFC 8448 trace values: §3 (simple 1-RTT),
§4 (resumed, PSK with (EC)DHE) and §5 (HelloRetryRequest).

Writes tests/unit/tls_rfc8448.h for the key-schedule, record and handshake
tests.  Every value is checked against the length the RFC states.

    curl -o rfc8448.txt https://www.rfc-editor.org/rfc/rfc8448.txt
    python3 tests/tls/gen_rfc8448.py rfc8448.txt
"""
import os
import sys

from rfc8448 import steps

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "unit", "tls_rfc8448.h")

# (actor, step title, occurrence of that title, field) -> C name
S3 = [
    ("client", "create an ephemeral x25519 key pair", 0, "private key", "c_x25519_priv"),
    ("client", "create an ephemeral x25519 key pair", 0, "public key", "c_x25519_pub"),
    ("client", "construct a ClientHello handshake message", 0, "ClientHello", "client_hello"),
    ("client", "send handshake record", 0, "complete record", "ch_record"),
    ("server", 'extract secret "early"', 0, "secret", "early_secret"),
    ("server", "create an ephemeral x25519 key pair", 0, "private key", "s_x25519_priv"),
    ("server", "create an ephemeral x25519 key pair", 0, "public key", "s_x25519_pub"),
    ("server", "construct a ServerHello handshake message", 0, "ServerHello", "server_hello"),
    ("server", 'derive secret for handshake "tls13 derived"', 0, "expanded", "derived_hs"),
    ("server", 'extract secret "handshake"', 0, "IKM", "ecdhe_shared"),
    ("server", 'extract secret "handshake"', 0, "secret", "handshake_secret"),
    ("server", 'derive secret "tls13 c hs traffic"', 0, "hash", "hash_ch_sh"),
    ("server", 'derive secret "tls13 c hs traffic"', 0, "expanded", "c_hs_traffic"),
    ("server", 'derive secret "tls13 s hs traffic"', 0, "expanded", "s_hs_traffic"),
    ("server", 'derive secret for master "tls13 derived"', 0, "expanded", "derived_ms"),
    ("server", 'extract secret "master"', 0, "secret", "master_secret"),
    ("server", "send handshake record", 0, "complete record", "sh_record"),
    ("server", "derive write traffic keys for handshake data", 0, "key expanded", "s_hs_key"),
    ("server", "derive write traffic keys for handshake data", 0, "iv expanded", "s_hs_iv"),
    ("server", "construct an EncryptedExtensions handshake message", 0,
     "EncryptedExtensions", "encrypted_extensions"),
    ("server", "construct a Certificate handshake message", 0, "Certificate", "certificate"),
    ("server", "construct a CertificateVerify handshake message", 0,
     "CertificateVerify", "certificate_verify"),
    ("server", 'calculate finished "tls13 finished"', 0, "expanded", "s_finished_key"),
    ("server", "construct a Finished handshake message", 0, "Finished", "s_finished"),
    ("server", "send handshake record", 1, "payload", "s_hs_payload"),
    ("server", "send handshake record", 1, "complete record", "s_hs_record"),
    ("server", 'derive secret "tls13 c ap traffic"', 0, "hash", "hash_ch_sfin"),
    ("server", 'derive secret "tls13 c ap traffic"', 0, "expanded", "c_ap_traffic"),
    ("server", 'derive secret "tls13 s ap traffic"', 0, "expanded", "s_ap_traffic"),
    ("server", 'derive secret "tls13 exp master"', 0, "expanded", "exp_master"),
    ("server", "derive write traffic keys for application data", 0, "key expanded", "s_ap_key"),
    ("server", "derive write traffic keys for application data", 0, "iv expanded", "s_ap_iv"),
    ("server", "derive read traffic keys for handshake data", 0, "key expanded", "c_hs_key"),
    ("server", "derive read traffic keys for handshake data", 0, "iv expanded", "c_hs_iv"),
    ("client", 'calculate finished "tls13 finished"', 0, "expanded", "c_finished_key"),
    ("client", "construct a Finished handshake message", 0, "Finished", "c_finished"),
    ("client", "send handshake record", 1, "complete record", "c_fin_record"),
    ("client", "derive write traffic keys for application data", 0, "key expanded", "c_ap_key"),
    ("client", "derive write traffic keys for application data", 0, "iv expanded", "c_ap_iv"),
    ("client", 'derive secret "tls13 res master"', 0, "hash", "hash_ch_cfin"),
    ("client", 'derive secret "tls13 res master"', 0, "expanded", "res_master"),
    ("server", 'generate resumption secret "tls13 resumption"', 0, "hash", "ticket_nonce"),
    ("server", 'generate resumption secret "tls13 resumption"', 0, "expanded", "resumption_psk"),
    ("server", "construct a NewSessionTicket handshake message", 0,
     "NewSessionTicket", "new_session_ticket"),
    ("server", "send handshake record", 2, "complete record", "nst_record"),
    ("client", "send application_data record", 0, "payload", "c_app_payload"),
    ("client", "send application_data record", 0, "complete record", "c_app_record"),
    ("server", "send application_data record", 0, "payload", "s_app_payload"),
    ("server", "send application_data record", 0, "complete record", "s_app_record"),
    ("client", "send alert record", 0, "payload", "c_alert_payload"),
    ("client", "send alert record", 0, "complete record", "c_alert_record"),
    ("server", "send alert record", 0, "payload", "s_alert_payload"),
    ("server", "send alert record", 0, "complete record", "s_alert_record"),
]


# §4: a PSK from §3's ticket, a binder, PSK + (EC)DHE
S4 = [
    ("client", "create an ephemeral x25519 key pair", 0, "private key", "c_x25519_priv"),
    ("client", "create an ephemeral x25519 key pair", 0, "public key", "c_x25519_pub"),
    ("client", 'extract secret "early"', 0, "IKM", "psk"),
    ("client", 'extract secret "early"', 0, "secret", "early_secret"),
    ("client", "calculate PSK binder", 0, "ClientHello prefix", "ch_prefix"),
    ("client", "calculate PSK binder", 0, "binder hash", "binder_hash"),
    ("client", "calculate PSK binder", 0, "PRK", "binder_key"),
    ("client", "calculate PSK binder", 0, "finished", "binder"),
    ("client", "send handshake record", 0, "payload", "client_hello"),
    ("client", "send handshake record", 0, "complete record", "ch_record"),
    ("server", "create an ephemeral x25519 key pair", 0, "private key", "s_x25519_priv"),
    ("server", "create an ephemeral x25519 key pair", 0, "public key", "s_x25519_pub"),
    ("server", "construct a ServerHello handshake message", 0, "ServerHello", "server_hello"),
    ("server", 'extract secret "handshake"', 0, "IKM", "ecdhe_shared"),
    ("server", 'extract secret "handshake"', 0, "secret", "handshake_secret"),
    ("server", 'derive secret "tls13 c hs traffic"', 0, "expanded", "c_hs_traffic"),
    ("server", 'derive secret "tls13 s hs traffic"', 0, "expanded", "s_hs_traffic"),
    ("server", "send handshake record", 0, "complete record", "sh_record"),
    ("server", "derive write traffic keys for handshake data", 0, "key expanded", "s_hs_key"),
    ("server", "derive write traffic keys for handshake data", 0, "iv expanded", "s_hs_iv"),
    ("server", 'extract secret "master"', 0, "secret", "master_secret"),
]


# §5: a HelloRetryRequest for secp256r1, then a full handshake
S5 = [
    ("client", "construct a ClientHello handshake message", 0, "ClientHello", "client_hello1"),
    ("server", "construct a ServerHello handshake message", 0, "ServerHello", "hrr"),
    ("client", "create an ephemeral P-256 key pair", 0, "private key", "c_p256_priv"),
    ("client", "create an ephemeral P-256 key pair", 0, "public key", "c_p256_pub"),
    ("client", "construct a ClientHello handshake message", 1, "ClientHello", "client_hello2"),
    ("server", "create an ephemeral P-256 key pair", 0, "private key", "s_p256_priv"),
    ("server", "create an ephemeral P-256 key pair", 0, "public key", "s_p256_pub"),
    ("server", "construct a ServerHello handshake message", 1, "ServerHello", "server_hello"),
    ("server", 'extract secret "handshake"', 0, "IKM", "ecdhe_shared"),
    ("server", 'extract secret "handshake"', 0, "secret", "handshake_secret"),
    ("server", 'derive secret "tls13 c hs traffic"', 0, "hash", "hash_hs"),
    ("server", 'derive secret "tls13 c hs traffic"', 0, "expanded", "c_hs_traffic"),
    ("server", 'derive secret "tls13 s hs traffic"', 0, "expanded", "s_hs_traffic"),
]


def c_bytes(name, data):
    lines = [f"static const uint8_t {name}[{len(data)}] = {{"]
    for i in range(0, len(data), 12):
        lines.append("    " + ", ".join(f"0x{b:02x}" for b in data[i:i + 12]) + ",")
    lines.append("};")
    return "\n".join(lines)


def pick(trace, table, prefix):
    out = []
    for actor, title, n, field, name in table:
        hits = [f for a, t, f in trace if a == actor and t == title]
        if len(hits) <= n or field not in hits[n]:
            sys.exit(f"missing: {actor} {title} #{n} {field}")
        out.append(c_bytes(prefix + name, hits[n][field]))
    return out


def main():
    text = open(sys.argv[1]).read()
    parts = [
        "/* tls_rfc8448.h — RFC 8448 trace values: §3 (simple 1-RTT handshake),",
        " * §4 (resumed handshake: PSK with (EC)DHE), §5 (HelloRetryRequest).",
        " * Generated by tests/tls/gen_rfc8448.py from the RFC text; do not edit. */",
        "",
        "#ifndef TLS_RFC8448_H",
        "#define TLS_RFC8448_H",
        "",
        "#include <stdint.h>",
        "",
        "/* Each test uses some of these. */",
        "#pragma GCC diagnostic push",
        '#pragma GCC diagnostic ignored "-Wunused-const-variable"',
        "",
    ]
    parts += [p + "\n" for p in pick(steps(text, 3), S3, "r3_")]
    parts += [p + "\n" for p in pick(steps(text, 4), S4, "r4_")]
    parts += [p + "\n" for p in pick(steps(text, 5), S5, "r5_")]
    parts += ["#pragma GCC diagnostic pop", "", "#endif /* TLS_RFC8448_H */", ""]
    with open(OUT, "w") as f:
        f.write("\n".join(parts))
    print(f"wrote {os.path.relpath(OUT)}")


if __name__ == "__main__":
    main()
