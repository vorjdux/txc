#!/bin/sh
# txc installer for Linux and macOS.
#
# Usage:
#   curl -sSf https://raw.githubusercontent.com/vorjdux/txc/main/install.sh | sh
#
# Environment overrides:
#   VERSION=0.2.0              install a specific version, without the v prefix
#   INSTALL_DIR=/usr/local/bin override where the binary goes
#   NO_COLOR=1                 plain output
#   INSECURE=1                 skip checksum verification, not recommended
set -eu

REPO="vorjdux/txc"
BINARY="txc"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  RED='\033[0;31m';   BOLD='\033[1m';   RESET='\033[0m'
else
  GREEN=''; YELLOW=''; RED=''; BOLD=''; RESET=''
fi

info() { printf "${BOLD}%s${RESET}\n" "$*"; }
ok()   { printf "${GREEN}ok${RESET} %s\n" "$*"; }
warn() { printf "${YELLOW}warning:${RESET} %s\n" "$*" >&2; }
die()  { printf "${RED}error:${RESET} %s\n" "$*" >&2; exit 1; }

DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --help|-h)
      echo "Usage: install.sh [--dry-run]"
      echo
      echo "  VERSION=x.y.z      install a specific version"
      echo "  INSTALL_DIR=PATH   where to put the binary"
      echo "  INSECURE=1         skip checksum verification"
      exit 0 ;;
    *) die "unknown argument: $arg" ;;
  esac
done

# ── What are we running on ─────────────────────────────────────────────────
detect_platform() {
  case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=macos ;;
    *) die "unsupported operating system: $(uname -s). Try: cargo install txc" ;;
  esac

  case "$(uname -m)" in
    x86_64|amd64)  ARCH=x86_64 ;;
    aarch64|arm64) [ "$OS" = macos ] && ARCH=arm64 || ARCH=aarch64 ;;
    *) die "unsupported architecture: $(uname -m). Try: cargo install txc" ;;
  esac
}

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required but not installed"; }

fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  else
    wget -qO "$2" "$1"
  fi
}

fetch_stdout() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1"
  else
    wget -qO- "$1"
  fi
}

# ── Which version ──────────────────────────────────────────────────────────
resolve_version() {
  if [ -n "${VERSION:-}" ]; then
    VERSION="${VERSION#v}"
    return
  fi
  info "Looking up the latest release"
  VERSION=$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name" *: *"v\{0,1\}\([^"]*\)".*/\1/p' | head -1)
  [ -n "$VERSION" ] || die "cannot determine the latest version; set VERSION=x.y.z"
}

# ── Where it goes ──────────────────────────────────────────────────────────
resolve_install_dir() {
  if [ -n "${INSTALL_DIR:-}" ]; then
    return
  fi
  # Prefer a directory the user owns, so no sudo is needed.
  for candidate in "$HOME/.local/bin" "/usr/local/bin"; do
    if [ -d "$candidate" ] && [ -w "$candidate" ]; then
      INSTALL_DIR="$candidate"
      return
    fi
  done
  INSTALL_DIR="$HOME/.local/bin"
}

main() {
  need tar
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
    || die "curl or wget is required"

  detect_platform
  resolve_version
  resolve_install_dir

  ARCHIVE="${BINARY}-${VERSION}-${OS}-${ARCH}.tar.gz"
  BASE="https://github.com/${REPO}/releases/download/v${VERSION}"

  info "txc ${VERSION} for ${OS}/${ARCH}"
  info "Installing into ${INSTALL_DIR}"

  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  would download ${BASE}/${ARCHIVE}"
    ok "dry run complete, nothing was changed"
    exit 0
  fi

  TMP=$(mktemp -d)
  # shellcheck disable=SC2064
  trap "rm -rf '$TMP'" EXIT INT TERM

  info "Downloading ${ARCHIVE}"
  fetch "${BASE}/${ARCHIVE}" "${TMP}/${ARCHIVE}" \
    || die "cannot download ${BASE}/${ARCHIVE}"

  if [ -z "${INSECURE:-}" ]; then
    if fetch "${BASE}/SHA256SUMS" "${TMP}/SHA256SUMS" 2>/dev/null; then
      info "Verifying checksum"
      expected=$(grep " ${ARCHIVE}\$" "${TMP}/SHA256SUMS" | awk '{print $1}')
      [ -n "$expected" ] || die "${ARCHIVE} is not listed in SHA256SUMS"
      if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "${TMP}/${ARCHIVE}" | awk '{print $1}')
      elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "${TMP}/${ARCHIVE}" | awk '{print $1}')
      else
        warn "no sha256 tool found, skipping verification"
        actual="$expected"
      fi
      [ "$actual" = "$expected" ] || die "checksum mismatch for ${ARCHIVE}"
      ok "checksum verified"
    else
      warn "SHA256SUMS is not published for this release, skipping verification"
    fi
  fi

  tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP"
  BIN=$(find "$TMP" -type f -name "$BINARY" -perm -u+x | head -1)
  [ -n "$BIN" ] || die "the archive does not contain a ${BINARY} binary"

  mkdir -p "$INSTALL_DIR"
  if [ -w "$INSTALL_DIR" ]; then
    install -m 755 "$BIN" "${INSTALL_DIR}/${BINARY}"
  else
    info "${INSTALL_DIR} needs elevated permissions"
    sudo install -m 755 "$BIN" "${INSTALL_DIR}/${BINARY}"
  fi
  ok "installed ${INSTALL_DIR}/${BINARY}"

  # ── Shell completions, where the shell will find them ────────────────────
  install_completion() {
    src="$1"; dest_dir="$2"; dest_name="$3"
    [ -f "$src" ] || return 0
    [ -d "$dest_dir" ] || mkdir -p "$dest_dir" 2>/dev/null || return 0
    cp "$src" "${dest_dir}/${dest_name}" 2>/dev/null && ok "completions: ${dest_dir}/${dest_name}"
  }
  COMP=$(dirname "$BIN")/completions
  if [ -d "$COMP" ]; then
    install_completion "$COMP/txc.bash" "${XDG_DATA_HOME:-$HOME/.local/share}/bash-completion/completions" "txc"
    install_completion "$COMP/txc.fish" "${XDG_CONFIG_HOME:-$HOME/.config}/fish/completions" "txc.fish"
    install_completion "$COMP/_txc" "${XDG_DATA_HOME:-$HOME/.local/share}/zsh/site-functions" "_txc"
  fi

  # ── Is it on the PATH ────────────────────────────────────────────────────
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      warn "${INSTALL_DIR} is not on your PATH"
      echo "  add this to your shell profile:"
      echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac

  echo
  "${INSTALL_DIR}/${BINARY}" --version 2>/dev/null || true
  echo
  echo "  txc            open the interactive interface"
  echo "  txc list       every operation"
  echo "  txc --help     usage"
}

main "$@"
