#!/usr/bin/env bash
# build_wolfssl.sh — the DTLS 1.3 peer for the DTLS blackbox tests: wolfSSL
# (OpenSSL and Mbed TLS have no DTLS 1.3), its example client and server.
#
#   tests/blackbox/build_wolfssl.sh [dir]        (default: ./build/wolfssl)
#
# Downloads the pinned release (GitHub's archive of the tag, checked by
# SHA-256), builds it with CMake — DTLS 1.3, x25519, PSK — and prints the
# two programs' paths for --wolfssl-client and --wolfssl-server.  A second
# run finds them built and only prints the paths.

set -euo pipefail

VERSION=5.9.4
SHA256=7256bfc89b183a75183806c7debfa203443873b0b4a562e1b80d68e01b45ac57
URL=https://github.com/wolfSSL/wolfssl/archive/refs/tags/v${VERSION}-stable.tar.gz

dir=${1:-build/wolfssl}
src=$dir/wolfssl-${VERSION}-stable
client=$src/build/examples/client/client
server=$src/build/examples/server/server

if [[ ! -x $client || ! -x $server ]]; then
  mkdir -p "$dir"
  tarball=$dir/wolfssl-${VERSION}.tar.gz
  [[ -f $tarball ]] || curl -sSfL -o "$tarball" "$URL"
  if command -v sha256sum >/dev/null; then
    echo "$SHA256  $tarball" | sha256sum -c - >&2
  else # macOS
    echo "$SHA256  $tarball" | shasum -a 256 -c - >&2
  fi
  tar -xzf "$tarball" -C "$dir"
  cmake -S "$src" -B "$src/build" \
    -DWOLFSSL_DTLS=yes -DWOLFSSL_DTLS13=yes \
    -DWOLFSSL_CURVE25519=yes -DWOLFSSL_PSK=yes \
    -DWOLFSSL_EXAMPLES=yes -DWOLFSSL_CRYPT_TESTS=no \
    -DBUILD_SHARED_LIBS=no >&2
  cmake --build "$src/build" -j "$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)" >&2
fi

echo "WOLFSSL_CLIENT=$(cd "$(dirname "$client")" && pwd)/client"
echo "WOLFSSL_SERVER=$(cd "$(dirname "$server")" && pwd)/server"
