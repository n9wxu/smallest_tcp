#!/usr/bin/env python3
"""Requirement traceability: which tests verify which requirements.

  trace.py [--strict] [--markdown] [--untested DOC]

Reads the requirement rows in docs/requirements/*.md (| REQ-XXX-NNN | LEVEL
| text | RFC | Test ID |) and the REQ IDs that tests cite:
tests/integration/*.c, tests/unit/*.c and tests/blackbox/*.py.  A citation
may list several numbers of one prefix — "REQ-TCP-046, 047",
"REQ-UDP-002/005", "REQ-TCP-046..049".

Prints, per requirement document, how many MUST rows (MUST, MUST NOT) are
cited by a black-box test (integration or blackbox suite) or by any test;
how many no test can verify — the Test ID column says "not observable" or
"not implemented"; and how many are left with none.  --untested DOC lists
the MUST rows of one document (e.g. tcp) that are left.

--strict fails (exit 1) if
- a test cites an ID that no document defines;
- an integration test (a TEST() in tests/integration/) cites none: every
  integration test must trace to the requirements it verifies;
- a row's Test ID column names a test that does not exist, or one that
  does not cite the row (its file, for a blackbox suite).
"""

import glob
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROW = re.compile(r"^\|\s*(REQ-[A-Za-z0-9]+-\d+)\s*\|\s*([A-Z][A-Z /]*?)\s*\|")
NAMED = re.compile(r"\b(?:itest|test)_[A-Za-z0-9_]+\b")
CITE = re.compile(r"REQ-([A-Za-z0-9]+)-(\d{3})((?:\s*(?:,|/|\.\.|–|and)\s*\d{3})*)")
MUST = ("MUST", "MUST NOT", "SHALL", "SHALL NOT", "REQUIRED")


def requirements():
    """{id: (level, doc, the Test ID column)}"""
    reqs = {}
    for path in sorted(glob.glob(os.path.join(ROOT, "docs/requirements/*.md"))):
        doc = os.path.splitext(os.path.basename(path))[0]
        with open(path, encoding="utf-8") as f:
            for line in f:
                m = ROW.match(line)
                if m:
                    cells = line.rstrip().rstrip("|").split("|")
                    reqs[m.group(1)] = (m.group(2).strip(), doc,
                                        cells[-1].strip())
    return reqs


def unverifiable(test_id):
    """'not observable' / 'not implemented' if the Test ID column says no
    test can verify the row, else None"""
    for why in ("not observable", "not implemented"):
        if why in test_id.lower():
            return why
    return None


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


def c_tests(suite, path):
    """One entry per TEST() of a C file: its text runs from the end of the
    previous function to the end of its own body"""
    text = open(path, encoding="utf-8").read()
    found = []
    prev_end = 0
    for m in re.finditer(r"^TEST\((\w+)\)", text, re.M):
        end = text.find("\n}\n", m.start())
        end = len(text) if end < 0 else end + 3
        found.append((suite, path, m.group(1), cited(text[prev_end:end])))
        prev_end = end
    return found


def tests():
    """[(suite, file, test name, [ids])]: one entry per test of a C file;
    for a unit or blackbox file also one for the whole file (name None),
    whose header may cite what all its tests verify"""
    found = []
    for path in sorted(glob.glob(os.path.join(ROOT, "tests/integration/*.c"))):
        found += c_tests("integration", path)
    for path in sorted(glob.glob(os.path.join(ROOT, "tests/unit/*.c"))):
        text = open(path, encoding="utf-8").read()
        found.append(("unit", path, None, cited(text)))
        found += [(s, p, n, []) for s, p, n, _ in c_tests("unit", path)]
    for path in sorted(glob.glob(os.path.join(ROOT, "tests/blackbox/*.py"))):
        text = open(path, encoding="utf-8").read()
        found.append(("blackbox", path, None, cited(text)))
        for name in re.findall(r"^def (test_\w+)\(", text, re.M):
            found.append(("blackbox", path, name, []))
    return found


def main(argv):
    strict = "--strict" in argv
    markdown = "--markdown" in argv
    untested_doc = argv[argv.index("--untested") + 1] if "--untested" in argv else None
    reqs = requirements()
    found = tests()
    problems = []
    by_req = {}
    cites = {}  # test name -> the ids it cites (its file's, where a file
    #             is not split into tests)
    file_ids = {}
    for suite, path, name, ids in found:
        rel = os.path.relpath(path, ROOT)
        if name is None:
            file_ids[path] = set(ids)
        if suite == "integration" and not ids:
            problems.append("%s: %s cites no requirement" % (rel, name))
        for i in ids:
            if i not in reqs:
                problems.append("%s%s cites %s, which no document defines"
                                % (rel, (" (%s)" % name) if name else "", i))
            by_req.setdefault(i, set()).add(suite)
    for suite, path, name, ids in found:
        if name is not None:
            cites.setdefault(name, set()).update(
                ids if suite == "integration" else file_ids[path])

    # The Test ID column names tests that exist and cite the row
    for i, (lvl, doc, test_id) in sorted(reqs.items()):
        for name in NAMED.findall(test_id):
            if name not in cites:
                problems.append("docs/requirements/%s.md: %s names %s, which "
                                "is no test" % (doc, i, name))
            elif i not in cites[name]:
                problems.append("docs/requirements/%s.md: %s names %s, which "
                                "does not cite it" % (doc, i, name))

    docs = sorted({doc for _, doc, _ in reqs.values()})
    rows = []
    left = {}
    for doc in docs:
        must = [i for i, (lvl, d, _) in reqs.items() if d == doc and lvl in MUST]
        black = [i for i in must if by_req.get(i, set()) & {"integration", "blackbox"}]
        anyt = [i for i in must if by_req.get(i)]
        untested = [i for i in must if not by_req.get(i)]
        unobs = [i for i in untested
                 if unverifiable(reqs[i][2]) == "not observable"]
        unimpl = [i for i in untested
                  if unverifiable(reqs[i][2]) == "not implemented"]
        left[doc] = [i for i in untested if i not in unobs and i not in unimpl]
        rows.append((doc, len(must), len(black), len(anyt), len(unobs),
                     len(unimpl), len(left[doc])))
    total = [sum(r[k] for r in rows) for k in range(1, 7)]

    if markdown:
        print("| Requirements | MUST rows | Black-box test | Any test "
              "| Not observable | Not implemented | None |")
        print("|---|---:|---:|---:|---:|---:|---:|")
        for r in rows:
            print("| %s | %d | %d | %d | %d | %d | %d |" % r)
        print("| **Total** | **%d** | **%d** | **%d** | **%d** | **%d** "
              "| **%d** |" % tuple(total))
    else:
        fmt = "%-10s %9s %10s %9s %11s %11s %6s"
        print(fmt % ("doc", "MUST rows", "black-box", "any test",
                     "not observ.", "not implem.", "none"))
        for r in rows:
            print(fmt % r)
        print(fmt % (("total",) + tuple(total)))
    if untested_doc:
        for i in sorted(left.get(untested_doc, [])):
            print("untested:", i, reqs[i][0])
    for p in problems:
        print("problem:", p, file=sys.stderr)
    if strict and problems:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
