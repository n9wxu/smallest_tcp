"""rfc8448.py — parse the RFC 8448 TLS 1.3 example traces.

steps(text, section) -> list of (actor, title, {field: bytes}) in order.
"""
import re

SECTIONS = {3: ("3.  Simple 1-RTT Handshake", "4.  Resumed 0-RTT Handshake"),
            5: ("5.  HelloRetryRequest", "6.  Client Authentication")}


def steps(text, section):
    start, end = SECTIONS[section]
    lines = text.split("\n")
    i0 = [k for k, l in enumerate(lines) if l.startswith(start)][-1]
    i1 = [k for k, l in enumerate(lines) if l.startswith(end)][-1]
    body = [l for l in lines[i0:i1]
            if not re.match(r"^(Thomson\s+Informational|RFC 8448\s+TLS 1\.3 Traces)", l)
            and "\f" not in l]
    out, cur, field = [], None, None
    for l in body:
        m = re.match(r"^   \{(client|server)\}\s+(.*?):?$", l)
        if m:
            cur = (m.group(1), m.group(2).rstrip(":"), {})
            out.append(cur)
            field = None
            continue
        m = re.match(r"^      (.+?) \((\d+) octets?\):\s+(.*)$", l)
        if m and cur:
            field = m.group(1)
            v = m.group(3).split()
            cur[2][field] = (int(m.group(2)), [] if v == ["(empty)"] else v)
            continue
        m = re.match(r"^      (.+?):\s+(.*)$", l)
        if m and cur and not re.match(r"^[0-9a-f]{2}( |$)", m.group(1)):
            field = None
            continue
        if field and cur and re.match(r"^\s+[0-9a-f]{2}( [0-9a-f]{2})*\s*$", l):
            cur[2][field][1].extend(l.split())
            continue
    # Values run across page breaks, so a blank line does not end one; each
    # is checked against the length the trace states.
    res = []
    for a, t, f in out:
        vals = {}
        for k, (n, v) in f.items():
            b = bytes(int(x, 16) for x in v)
            if len(b) != n:
                raise ValueError(f"{a} {t}: {k} has {len(b)} of {n} octets")
            vals[k] = b
        res.append((a, t, vals))
    return res


if __name__ == "__main__":
    import sys
    text = open(sys.argv[1]).read()
    for a, t, f in steps(text, 3):
        print(f"{a:6} {t}")
        for k, v in f.items():
            print(f"         {k} ({len(v)})")
