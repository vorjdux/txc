#!/bin/sh
# Fills the package manifests in packaging/ with a version and the checksums of
# the published archives.
#
# Usage:
#   packaging/render.sh <version> <dist-dir> [output-dir]
#
# <dist-dir> holds the release archives and a SHA256SUMS file. The rendered
# manifests are written to <output-dir>, packaging/rendered by default, and are
# what gets submitted to Homebrew, Scoop, the AUR, winget and Alpine.
set -eu

VERSION="${1:?usage: render.sh <version> <dist-dir> [output-dir]}"
VERSION="${VERSION#v}"
DIST="${2:?usage: render.sh <version> <dist-dir> [output-dir]}"
OUT="${3:-packaging/rendered}"
HERE=$(dirname "$0")

[ -f "${DIST}/SHA256SUMS" ] || {
  echo "error: ${DIST}/SHA256SUMS not found" >&2
  exit 1
}

# The checksum of one archive, or empty when that archive was not built.
sum_for() {
  awk -v name="$1" '$2 == name || $2 == "*" name { print $1 }' "${DIST}/SHA256SUMS" | head -1
}

# Fails loudly rather than rendering a manifest with a placeholder left in it,
# which would install nothing and be found only by whoever tried.
require_sum() {
  value=$(sum_for "$1")
  if [ -z "$value" ]; then
    echo "error: no checksum for $1 in ${DIST}/SHA256SUMS" >&2
    exit 1
  fi
  echo "$value"
}

LINUX_X86_64=$(require_sum "txc-${VERSION}-linux-x86_64.tar.gz")
LINUX_AARCH64=$(require_sum "txc-${VERSION}-linux-aarch64.tar.gz")
MACOS_X86_64=$(require_sum "txc-${VERSION}-macos-x86_64.tar.gz")
MACOS_ARM64=$(require_sum "txc-${VERSION}-macos-arm64.tar.gz")
WINDOWS_X86_64=$(require_sum "txc-${VERSION}-windows-x86_64.zip")
WINDOWS_ARM64=$(require_sum "txc-${VERSION}-windows-arm64.zip")

# winget wants uppercase hex.
upper() { echo "$1" | tr '[:lower:]' '[:upper:]'; }

# Alpine builds from the source tarball, which GitHub generates for the tag.
SOURCE_SHA512=$(sum_for "txc-${VERSION}-source.tar.gz")
[ -n "$SOURCE_SHA512" ] || SOURCE_SHA512="fill-in-with-abuild-checksum"

RELEASE_DATE=$(date -u +%Y-%m-%d)

render() {
  sed \
    -e "s|@VERSION@|${VERSION}|g" \
    -e "s|@SHA256_LINUX_X86_64@|${LINUX_X86_64}|g" \
    -e "s|@SHA256_LINUX_AARCH64@|${LINUX_AARCH64}|g" \
    -e "s|@SHA256_MACOS_X86_64@|${MACOS_X86_64}|g" \
    -e "s|@SHA256_MACOS_ARM64@|${MACOS_ARM64}|g" \
    -e "s|@SHA256_WINDOWS_X86_64_UPPER@|$(upper "${WINDOWS_X86_64}")|g" \
    -e "s|@SHA256_WINDOWS_ARM64_UPPER@|$(upper "${WINDOWS_ARM64}")|g" \
    -e "s|@SHA256_WINDOWS_X86_64@|${WINDOWS_X86_64}|g" \
    -e "s|@SHA256_WINDOWS_ARM64@|${WINDOWS_ARM64}|g" \
    -e "s|@SHA512_SOURCE@|${SOURCE_SHA512}|g" \
    -e "s|@RELEASE_DATE@|${RELEASE_DATE}|g" \
    "$1" > "$2"
}

mkdir -p "${OUT}/homebrew" "${OUT}/scoop" "${OUT}/aur" "${OUT}/alpine" "${OUT}/winget"

render "${HERE}/homebrew/txc.rb"   "${OUT}/homebrew/txc.rb"
render "${HERE}/scoop/txc.json"    "${OUT}/scoop/txc.json"
render "${HERE}/aur/PKGBUILD"      "${OUT}/aur/PKGBUILD"
render "${HERE}/alpine/APKBUILD"   "${OUT}/alpine/APKBUILD"
for manifest in "${HERE}"/winget/*.yaml; do
  render "$manifest" "${OUT}/winget/$(basename "$manifest")"
done

# A placeholder that survived means a manifest would ship pointing at nothing.
if grep -rl '@[A-Z0-9_]*@' "$OUT" 2>/dev/null | grep -q .; then
  echo "error: placeholders left unrendered in:" >&2
  grep -rl '@[A-Z0-9_]*@' "$OUT" >&2
  exit 1
fi

echo "rendered into ${OUT}:"
find "$OUT" -type f | sort | sed 's/^/  /'
