# Release Process

**Status:** in use from v0.1.0
**Files:** `include/net_version.h`, `CHANGELOG.md`, `scripts/release_info.sh`,
`.github/workflows/release.yml`, the `release-check` job of
`.github/workflows/ci.yml`

A release is a commit on `main` that CI has passed, tagged `vX.Y.Z`, with a
GitHub Release whose notes are its section of `CHANGELOG.md`.  Nobody tags
by hand: raising the version on `main` is the decision to release, and the
release follows automatically once CI is green.

---

## 1. Versions

smallest_tcp follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html):

| Part | Raised for |
|---|---|
| PATCH | Fixes that change no API and no documented behaviour callers rely on |
| MINOR | New features; while MAJOR is 0, also API changes, which the CHANGELOG entry spells out under **Changed** |
| MAJOR | API changes once 1.0 is released |

The version is written once, in `include/net_version.h`:

```c
#define NET_VERSION_MAJOR 0
#define NET_VERSION_MINOR 1
#define NET_VERSION_PATCH 0
```

Everything else reads it.  `CMakeLists.txt` parses the three numbers into
`project(VERSION)` and prints `-- smallest_tcp X.Y.Z` when it configures.
`scripts/release_info.sh version` prints them for the workflows.  Code gets
`NET_VERSION_STRING` (`"0.1.0"`) and `NET_VERSION` (`0x000100`, for `#if`).
`test_net` checks that the macros agree.

## 2. The changelog

`CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Changes that a user of the library would notice go under `## [Unreleased]`
as they land, in the sections **Added**, **Changed** (anything a caller
may have to adapt to), **Fixed**, **Removed** and **Known limitations**.
Internal changes such as refactoring, tests and CI don't need an entry.

`scripts/release_info.sh notes X.Y.Z` prints the lines between
`## [X.Y.Z]` and the next `## ` heading (or the link definitions at the end),
and fails if there are none.  Links in a version's section must be absolute
(`https://github.com/n9wxu/smallest_tcp/blob/vX.Y.Z/...`), because the same
text becomes the release notes on GitHub, where relative links break.

## 3. Making a release

1. **Pick the version** by the table in section 1.
2. **Raise it** in `include/net_version.h`.
3. **Close the changelog section.**  Rename `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD` with a sentence on what the release is, open a
   new empty `## [Unreleased]` above it, and update the two link
   definitions at the end of the file:
   ```
   [Unreleased]: https://github.com/n9wxu/smallest_tcp/compare/vX.Y.Z...HEAD
   [X.Y.Z]: https://github.com/n9wxu/smallest_tcp/compare/vPREVIOUS...vX.Y.Z
   ```
4. **Check what CI does not run** (section 5).
5. **Commit and push to `main`** — directly or by merging a pull request —
   as `release: X.Y.Z`.

When the push's CI run passes, **Release** (`release.yml`) runs:

1. It starts on `workflow_run` when "CI — Build & Unit Tests" completes,
   and goes on only if CI succeeded for a push to this repository's
   `main`.  A pull request does not count, even one from a fork's branch
   named `main`.
2. It checks out the commit CI tested and reads its version.
3. If the version already has a GitHub Release, it stops.  This is the
   ordinary case: most green pushes don't change the version.
4. Otherwise it extracts the notes and runs `gh release create vX.Y.Z
   --target <commit>`, which creates the tag on that commit and publishes
   the release.  GitHub attaches the source archives.

The release can only tag a commit that passed every CI job: the compiler
builds, the unit tests on Linux and macOS, the IPv4-only and IPv6-only
builds, the Cortex-M0 size and link checks, the board firmware, every
blackbox suite over both Linux drivers, FetchContent, and the
`release-check` job.  `release-check` confirms the version has its
changelog section and that CMake and the compiled library both report it.
A version raised without notes therefore fails CI, before the release could.

## 4. When something goes wrong

| Situation | What to do |
|---|---|
| CI fails on the release commit | Nothing is released.  Fix it and push; the first green push with the new version releases it |
| The Release job itself fails (a network error, say) | Re-run it from the Actions tab: it starts again from the same CI run and commit |
| A pushed tag `vX.Y.Z` exists without a release | The job publishes the release on that existing tag, wherever the tag points.  Don't push version tags by hand |
| A release turns out bad | Release a new PATCH version with the fix.  Never move or delete a published tag: users pin them |
| Two pushes in quick succession | Releases run one at a time (`concurrency: release`); the second finds the version released and stops |

## 5. Before releasing: what CI does not cover

- **macOS blackbox:** `tests/blackbox/run_blackbox_macos.sh` over the feth
  pair, with the mDNSResponder and browser interop
  ([ci-debugging.md](ci-debugging.md) explains the suites).
- **The nightly fuzz workflow** (`fuzz.yml`) should be green for the commit
  or one close to it.
- **Hardware:** the NUCLEO-F429ZI firmware is built in CI but has not been
  run on a board yet; say so in the release notes until it has.
- **Sizes and counts:** the README's size table, test counts and the
  [size history](design/size-comparison.md) should be current.  Each change
  keeps them so, but check them.

## 6. Using a release

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
