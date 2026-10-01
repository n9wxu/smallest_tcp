#!/bin/sh
# What the release process needs to know, from the source tree:
#
#   scripts/release_info.sh version         the version in include/net_version.h
#   scripts/release_info.sh notes [VERSION] its section of CHANGELOG.md
#                                           (fails if there is none, or it is empty)
#
# CI runs both on every push, so a version without release notes fails
# before the release workflow would (docs/release-process.md).
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)

version() {
  for part in MAJOR MINOR PATCH; do
    n=$(sed -n "s/^#define NET_VERSION_$part \([0-9][0-9]*\)$/\1/p" \
      "$root/include/net_version.h")
    [ -n "$n" ] || { echo "no NET_VERSION_$part in net_version.h" >&2; exit 1; }
    printf '%s' "$n"
    [ "$part" = PATCH ] || printf '.'
  done
  echo
}

# The lines after "## [VERSION]" up to the next "## " heading or the link
# definitions at the end
notes() {
  v=$1
  awk -v v="$v" '
    index($0, "## [" v "]") == 1 { on = 1; next }
    on && (/^## / || /^\[[^]]*\]: /) { exit }
    on { print }
  ' "$root/CHANGELOG.md" | sed -e '/./,$!d' >"${TMPDIR:-/tmp}/notes.$$"
  if ! grep -q '[^[:space:]]' "${TMPDIR:-/tmp}/notes.$$"; then
    rm -f "${TMPDIR:-/tmp}/notes.$$"
    echo "CHANGELOG.md has no notes for $v: add a '## [$v]' section" >&2
    exit 1
  fi
  cat "${TMPDIR:-/tmp}/notes.$$"
  rm -f "${TMPDIR:-/tmp}/notes.$$"
}

case "${1:-}" in
version) version ;;
notes) notes "${2:-$(version)}" ;;
*)
  echo "usage: $0 version | notes [VERSION]" >&2
  exit 2
  ;;
esac
