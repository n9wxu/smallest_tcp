#!/usr/bin/env python3
"""Requirement traceability: which tests verify which requirements.

  trace.py [--strict] [--markdown] [--untested DOC]

Reads the requirement rows in docs/requirements/*.md (| REQ-XXX-NNN | LEVEL
| ...) and the REQ IDs that tests cite: tests/integration/*.c,
tests/unit/*.c and tests/blackbox/*.py.  A citation may list several
numbers of one prefix — "REQ-TCP-046, 047", "REQ-UDP-002/005",
"REQ-TCP-046..049".

Prints, per requirement document, how many MUST rows (MUST, MUST NOT) are
cited by a black-box test (integration or blackbox suite), by any test, or
by none.  --untested DOC lists the MUST rows of one document (e.g. tcp)
that no test cites.

--strict fails (exit 1) if a test cites an ID that no document defines, or
if an integration test (a TEST() in tests/integration/) cites none: every
integration test must trace to the requirements it verifies.
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROW = re.compile(r"^\|\s*(REQ-[A-Za-z0-9]+-\d+)\s*\|\s*([A-Z][A-Z /]*?)\s*\|")
CITE = re.compile(r"REQ-([A-Za-z0-9]+)-(\d{3})((?:\s*(?:,|/|\.\.|–|and)\s*\d{3})*)")
MUST = ("MUST", "MUST NOT", "SHALL", "SHALL NOT", "REQUIRED")


def requirements():
    """{id: (level, doc)}"""
    reqs = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "docs/requirements/*.md"))):
        doc = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = ROW.match(line)
                if m:
                    reqs[m.group(1)] = (m.group(2).strip(), doc)
    return reqs


def cited(text):
    """Every REQ ID @p text cites, ranges expanded"""
    ids = []
    for m in CITE.finditer(text):
        prefix, first, rest = m.group(1), int(m.group(2)), m.group(3)
        ids.append("REQ-%s-%03d" % (prefix, first))
        prev = first
        for sep, num in re.findall(r"(,|/|\.\.|–|and)\s*(\d{3})", rest):
            n = int(num)
            if sep in ("..", "–"):
                ids += ["REQ-%s-%03d" % (prefix, k) for k in range(prev + 1, n + 1)]
            else:
                ids.append("REQ-%s-%03d" % (prefix, n))
            prev = n
    return ids


def tests():
    """[(suite, file, test name, [ids])]: one entry per test where the
    file can be split into tests, else one per file"""
    found = []
    for path in sorted(glob.glob(os.path.join(ROOT, "tests/integration/*.c"))):
        text = open(path, encoding="utf-8").read()
        # A test's text: from the end of the previous function to the end
        # of its own body
        starts = [m.start() for m in re.finditer(r"^TEST\(", text, re.M)]
        prev_end = 0
        for s in starts:
            name = re.match(r"TEST\((\w+)\)", text[s:]).group(1)
            end = text.find("\n}\n", s)
            end = len(text) if end < 0 else end + 3
            found.append(("integration", path, name, cited(text[prev_end:end])))
            prev_end = end
    for suite, pattern in (("unit", "tests/unit/*.c"),
                           ("blackbox", "tests/blackbox/*.py")):
        for path in sorted(glob.glob(os.path.join(ROOT, pattern))):
            text = open(path, encoding="utf-8").read()
            found.append((suite, path, None, cited(text)))
    return found


def main(argv):
    strict = "--strict" in argv
    markdown = "--markdown" in argv
    untested_doc = argv[argv.index("--untested") + 1] if "--untested" in argv else None
    reqs = requirements()
    found = tests()
    problems = []
    by_req = {}
    for suite, path, name, ids in found:
        rel = os.path.relpath(path, ROOT)
        if suite == "integration" and not ids:
            problems.append("%s: %s cites no requirement" % (rel, name))
        for i in ids:
            if i not in reqs:
                problems.append("%s%s cites %s, which no document defines"
                                % (rel, (" (%s)" % name) if name else "", i))
            by_req.setdefault(i, set()).add(suite)

    docs = sorted({doc for _, doc in reqs.values()})
    rows = []
    for doc in docs:
        must = [i for i, (lvl, d) in reqs.items() if d == doc and lvl in MUST]
        black = [i for i in must if by_req.get(i, set()) & {"integration", "blackbox"}]
        anyt = [i for i in must if by_req.get(i)]
        rows.append((doc, len(must), len(black), len(anyt)))
    total = [sum(r[k] for r in rows) for k in (1, 2, 3)]

    if markdown:
        print("| Requirements | MUST rows | Black-box test | Any test | None |")
        print("|---|---:|---:|---:|---:|")
        for doc, n, b, a in rows:
            print("| %s | %d | %d | %d | %d |" % (doc, n, b, a, n - a))
        print("| **Total** | **%d** | **%d** | **%d** | **%d** |"
              % (total[0], total[1], total[2], total[0] - total[2]))
    else:
        print("%-10s %9s %10s %9s %6s" % ("doc", "MUST rows", "black-box", "any test", "none"))
        for doc, n, b, a in rows:
            print("%-10s %9d %10d %9d %6d" % (doc, n, b, a, n - a))
        print("%-10s %9d %10d %9d %6d" % ("total", total[0], total[1], total[2],
                                          total[0] - total[2]))
    if untested_doc:
        for i, (lvl, d) in sorted(reqs.items()):
            if d == untested_doc and lvl in MUST and not by_req.get(i):
                print("untested:", i, lvl)
    for p in problems:
        print("problem:", p, file=sys.stderr)
    if strict and problems:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
