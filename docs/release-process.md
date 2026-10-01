# Release Process

**Status:** in use from v0.1.0; every green push to `main` released from v0.1.1
**Files:** `include/net_version.h`, `CHANGELOG.md`, `scripts/release.py`,
`.github/workflows/release.yml`, the `release-check` job of
`.github/workflows/ci.yml`

Every push to `main` that passes CI is released.  A release is a commit
`release: X.Y.Z` on `main` that CI made on top of the tested commit, tagged
`vX.Y.Z`, with a GitHub Release whose notes are its section of
`CHANGELOG.md`.  Nobody tags by hand, and nobody has to remember to release.

---

## 1. Versions

smallest_tcp follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

| Part | Raised by | For |
|---|---|---|
| PATCH | CI, on every release | Whatever the push contained |
| MINOR | You, in `include/net_version.h` | New features; while MAJOR is 0, also API changes, which the CHANGELOG entry spells out under **Changed** |
| MAJOR | You | API changes once 1.0 is released |

The version is written once, in `include/net_version.h`:

```c
#define NET_VERSION_MAJOR 0
#define NET_VERSION_MINOR 1
#define NET_VERSION_PATCH 0
```

Everything else reads it.  `CMakeLists.txt` parses the three numbers into
`project(VERSION)` and prints `-- smallest_tcp X.Y.Z` when it configures.
`scripts/release.py version` prints them for the workflows.  Code gets
`NET_VERSION_STRING` (`"0.1.0"`) and `NET_VERSION` (`0x000100`, for `#if`).
Between releases, `main` states the last released version; the release
commit raises it.

**Which version a release takes** (`scripts/release.py next`): the one in
`net_version.h` if it has no tag yet — the first release after you raise
MINOR or MAJOR (set PATCH to 0 when you do) — else that version's PATCH + 1.

## 2. The changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Changes that a user of the library would notice go under `## [Unreleased]`
as they land, in the sections **Added**, **Changed** (anything a caller
may have to adapt to), **Fixed**, **Removed** and **Known limitations**.

At release, `scripts/release.py stamp X.Y.Z` turns `## [Unreleased]` into
`## [X.Y.Z] - YYYY-MM-DD` under a new empty `## [Unreleased]`, and updates
the link definitions at the end.  If nothing was written under
`[Unreleased]`, the release's notes are the subjects of the commits since
the last tag, so no release goes out without notes.  Notes written by hand
under `## [X.Y.Z]` itself are used as they are.

Links in a version's section must be absolute
(`https://github.com/n9wxu/smallest_tcp/blob/vX.Y.Z/...`): the same text
becomes the release notes on GitHub, where relative links break.

## 3. What happens on a push to `main`

1. **CI** ("CI — Build & Unit Tests") runs every job: the compiler builds,
   the unit and integration tests on Linux and macOS, the IPv4-only and
   IPv6-only builds, the Cortex-M0 size and link checks, the board
   firmware, every blackbox suite over both Linux drivers, FetchContent,
   and `release-check`, which runs `scripts/release.py check` — the version
   parses, `[Unreleased]` exists, and a trial stamp of the next version
   works — and confirms that CMake and the compiled library report the
   version.
2. **Release** (`release.yml`) starts on `workflow_run` when CI completes.
   It goes on only if CI succeeded for a push to this repository's `main`
   (not a pull request, even one from a fork's branch named `main`) and
   `main` still points at the commit CI tested.  If a newer push has
   arrived, that push's own CI run releases both.
3. It stamps the next version, commits `release: X.Y.Z` as
   `github-actions[bot]`, tags the commit `vX.Y.Z`, and pushes both
   atomically: if `main` moved in the meantime, neither lands and the newer
   push's run releases it.  Then `gh release create` publishes the release
   with the notes; GitHub attaches the source archives.
4. A push made with the workflow's own token starts no workflow, so the
   release commit is not tested or released again.  It differs from the
   tested commit only in `net_version.h` and `CHANGELOG.md`.

Releases run one at a time (`concurrency: release`).

**After you push, pull.**  The release commit lands on `main` a few minutes
after your push; `git pull --rebase` before your next push.

## 4. Raising MINOR or MAJOR

1. Raise it in `include/net_version.h` and set PATCH to 0.
2. Make sure `[Unreleased]` says what changed — **Changed** for anything
   callers must adapt to.
3. Push.  The release takes exactly that version.

## 5. When something goes wrong

| Situation | What to do |
|---|---|
| CI fails | Nothing is released.  Fix it and push; the next green push is released, and its notes include everything since the last release |
| The Release job fails (a network error, say) | Re-run it from the Actions tab.  It only acts if `main` is still the tested commit |
| `main` moved before the job pushed | Nothing to do: the newer push's run releases it |
| A release turns out bad | Push the fix; the next release supersedes it.  Never move or delete a published tag: users pin them |

## 6. What CI does not cover

- **macOS blackbox:** `tests/blackbox/run_blackbox_macos.sh` over the feth
  pair, with the mDNSResponder and browser interop
  ([ci-debugging.md](ci-debugging.md) explains the suites).
- **The nightly fuzz workflow** (`fuzz.yml`).
- **Hardware:** the NUCLEO-F429ZI firmware is built in CI but has not been
  run on a board yet.

## 7. Using a release

Pin the tag, not `main`:

```cmake
FetchContent_Declare(
    smallest_tcp
    GIT_REPOSITORY https://github.com/n9wxu/smallest_tcp.git
    GIT_TAG        v0.1.0
)
```

Code that depends on a feature can test the version at compile time:

```c
#include "net_version.h"
#if NET_VERSION < 0x000200
#error "needs smallest_tcp 0.2.0 or later"
#endif
```
