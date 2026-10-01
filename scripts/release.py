#!/usr/bin/env python3
"""The release steps, from the source tree (docs/release-process.md).

  release.py version          the version in include/net_version.h
  release.py next             the version the next release takes: that one if
                              it has no tag yet, else its PATCH + 1
  release.py stamp VERSION    write VERSION into net_version.h and close the
                              CHANGELOG's [Unreleased] section as VERSION —
                              with the commit subjects since the last tag
                              when the section is empty
  release.py notes [VERSION]  VERSION's section of CHANGELOG.md
  release.py check            what CI verifies on every push: the version
                              parses, CHANGELOG.md has an [Unreleased]
                              section, and stamping works (on a copy)

release.yml runs next, stamp and notes when CI passes on main, commits the
result as "release: X.Y.Z", tags it vX.Y.Z and publishes the release.
"""

import datetime
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = "https://github.com/n9wxu/smallest_tcp"
HEADER = "include/net_version.h"
CHANGELOG = "CHANGELOG.md"
PARTS = ("MAJOR", "MINOR", "PATCH")


def fail(message):
    sys.stderr.write(message + "\n")
    sys.exit(1)


def read(root, name):
    with open(os.path.join(root, name), encoding="utf-8") as f:
        return f.read()


def write(root, name, text):
    with open(os.path.join(root, name), "w", encoding="utf-8") as f:
        f.write(text)


def version(root=ROOT):
    text = read(root, HEADER)
    numbers = []
    for part in PARTS:
        m = re.search(r"^#define NET_VERSION_%s (\d+)$" % part, text, re.M)
        if not m:
            fail("no NET_VERSION_%s in %s" % (part, HEADER))
        numbers.append(int(m.group(1)))
    return "%d.%d.%d" % tuple(numbers)


def git(root, *args):
    return subprocess.run(["git", "-C", root] + list(args), check=True,
                          capture_output=True, text=True).stdout.strip()


def tagged(root, v):
    return git(root, "tag", "-l", "v" + v) != ""


def next_version(root=ROOT):
    v = version(root)
    if not tagged(root, v):
        return v
    major, minor, patch = (int(x) for x in v.split("."))
    n = "%d.%d.%d" % (major, minor, patch + 1)
    if tagged(root, n):
        fail("v%s is tagged already, but %s says %s" % (n, HEADER, v))
    return n


def last_tag(root):
    try:
        return git(root, "describe", "--tags", "--abbrev=0", "--match",
                   "v[0-9]*.[0-9]*.[0-9]*")
    except subprocess.CalledProcessError:
        return None


def commit_subjects(root, since):
    span = since + "..HEAD" if since else "HEAD"
    subjects = git(root, "log", "--no-merges", "--format=%s", span)
    return [s for s in subjects.splitlines()
            if s and not s.startswith("release: ")]


def section(text, v):
    """The lines of V's section, between its heading and the next '## '
    heading or the link definitions at the end."""
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith("## [%s]" % v):
            body = []
            for line in lines[i + 1:]:
                if line.startswith("## ") or re.match(r"^\[[^]]*\]: ", line):
                    break
                body.append(line)
            while body and not body[0].strip():
                body.pop(0)
            while body and not body[-1].strip():
                body.pop()
            return body
    return None


def stamp(root, v, today=None, git_root=None):
    """git_root: the repository whose tags and log to read (default root)"""
    today = today or datetime.date.today().isoformat()
    git_root = git_root or root
    major, minor, patch = v.split(".")

    header = read(root, HEADER)
    for part, n in zip(PARTS, (major, minor, patch)):
        header = re.sub(r"^#define NET_VERSION_%s \d+$" % part,
                        "#define NET_VERSION_%s %s" % (part, n), header,
                        flags=re.M)
    write(root, HEADER, header)

    text = read(root, CHANGELOG)
    notes = section(text, "Unreleased")
    if notes is None:
        fail("%s has no '## [Unreleased]' section" % CHANGELOG)
    pending = any(line.strip() for line in notes)
    previous = last_tag(git_root)
    lines = text.splitlines()
    if section(text, v) is not None:
        # Written by hand under the version's own heading
        if pending:
            fail("%s has notes under both [Unreleased] and [%s]"
                 % (CHANGELOG, v))
    else:
        if not pending:
            subjects = commit_subjects(git_root, previous)
            notes = ["### Changes", ""] + ["- " + s for s in subjects]
            if not subjects:
                notes = ["No changes since %s." % previous]
        start = next(i for i, line in enumerate(lines)
                     if line.startswith("## [Unreleased]"))
        end = start + 1
        while end < len(lines) and not lines[end].startswith("## ") and \
                not re.match(r"^\[[^]]*\]: ", lines[end]):
            end += 1
        lines[start:end] = ["## [Unreleased]", "", "## [%s] - %s" % (v, today),
                            ""] + notes + [""]

    # The link definitions: Unreleased compares from this release, and the
    # release from the one before
    links = [i for i, line in enumerate(lines)
             if re.match(r"^\[[^]]*\]: ", line)]
    unreleased = "[Unreleased]: %s/compare/v%s...HEAD" % (REPO, v)
    this = "[%s]: %s/%s" % (v, REPO, "compare/%s...v%s" % (previous, v)
                            if previous else "releases/tag/v" + v)
    rest = [lines[i] for i in links
            if not lines[i].startswith(("[Unreleased]:", "[%s]:" % v))]
    body = [line for i, line in enumerate(lines) if i not in links]
    while body and not body[-1].strip():
        body.pop()
    write(root, CHANGELOG,
          "\n".join(body + [""] + [unreleased, this] + rest) + "\n")


def notes(root, v):
    body = section(read(root, CHANGELOG), v)
    if not body or not any(line.strip() for line in body):
        fail("%s has no notes for %s" % (CHANGELOG, v))
    return "\n".join(body) + "\n"


def check(root=ROOT):
    v = version(root)
    if section(read(root, CHANGELOG), "Unreleased") is None:
        fail("%s has no '## [Unreleased]' section" % CHANGELOG)
    # Stamp a copy, as the release would
    with tempfile.TemporaryDirectory() as tmp:
        copy = os.path.join(tmp, "tree")
        os.makedirs(os.path.join(copy, "include"))
        shutil.copy(os.path.join(root, HEADER), os.path.join(copy, HEADER))
        shutil.copy(os.path.join(root, CHANGELOG), os.path.join(copy, CHANGELOG))
        n = next_version(root)
        stamp(copy, n, git_root=root)
        if version(copy) != n:
            fail("stamping %s left %s" % (n, version(copy)))
        notes(copy, n)
    print("smallest_tcp %s; the next release is %s" % (v, n))


def main(argv):
    if len(argv) < 2:
        fail(__doc__)
    command = argv[1]
    if command == "version":
        print(version())
    elif command == "next":
        print(next_version())
    elif command == "stamp" and len(argv) == 3:
        stamp(ROOT, argv[2])
    elif command == "notes":
        sys.stdout.write(notes(ROOT, argv[2] if len(argv) > 2 else version()))
    elif command == "check":
        check()
    else:
        fail(__doc__)


if __name__ == "__main__":
    main(sys.argv)
