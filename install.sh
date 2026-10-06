#!/bin/sh
# origin-probe bootstrapper for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/lemonhub-io/origin-probe/main/install.sh | sh
#
# Optional environment overrides:
#   ORIGIN_PROBE_VERSION=v0.2.0   pin a release tag (default: latest)
#   ORIGIN_PROBE_DIR=/path        install directory (default: ~/.local/bin)

set -eu

REPO="lemonhub-io/origin-probe"

say()  { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

# --- pick a downloader -------------------------------------------------------
download() {
    if have curl;  then curl -fsSL --retry 3 -o "$2" "$1"
    elif have wget; then wget -q -O "$2" "$1"
    else die "need curl or wget to download files"
    fi
}

fetch() {
    if have curl;  then curl -fsSL --retry 3 "$1"
    elif have wget; then wget -qO- "$1"
    else die "need curl or wget to download files"
    fi
}

# --- detect OS/arch ----------------------------------------------------------
os="$(uname -s)"
arch="$(uname -m)"

case "$os" in
    Linux)
        case "$arch" in
            x86_64|amd64)
                if ldd --version 2>&1 | grep -qi musl; then
                    target="x86_64-unknown-linux-musl"
                else
                    target="x86_64-unknown-linux-gnu"
                fi
                ;;
            aarch64|arm64) target="aarch64-unknown-linux-gnu" ;;
            *) die "unsupported Linux architecture: $arch" ;;
        esac
        ext="tar.gz"
        ;;
    Darwin)
        case "$arch" in
            x86_64)        target="x86_64-apple-darwin" ;;
            arm64|aarch64) target="aarch64-apple-darwin" ;;
            *) die "unsupported macOS architecture: $arch" ;;
        esac
        ext="tar.gz"
        ;;
    MINGW*|MSYS*|CYGWIN*|Windows_NT)
        die "on Windows run install.ps1 from PowerShell instead"
        ;;
    *) die "unsupported OS: $os" ;;
esac

# --- resolve release ---------------------------------------------------------
# Asset filenames embed the tag, so "latest" must be resolved first via the API.
version="${ORIGIN_PROBE_VERSION:-latest}"
if [ "$version" = "latest" ]; then
    version="$(fetch "https://api.github.com/repos/$REPO/releases/latest" \
        | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$version" ] || die "could not resolve latest release tag; set ORIGIN_PROBE_VERSION"
    say "Latest release: $version"
fi
base="https://github.com/$REPO/releases/download/$version"
asset="origin-probe-${version}-${target}.${ext}"

# --- download + verify --------------------------------------------------------
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say "Downloading $asset for $target ..."
download "$base/$asset" "$tmp/$asset"

if download "$base/SHA256SUMS.txt" "$tmp/SHA256SUMS.txt" 2>/dev/null; then
    want="$(grep " $asset\$" "$tmp/SHA256SUMS.txt" | awk '{print $1}')"
    if [ -n "$want" ]; then
        if have sha256sum; then got="$(sha256sum "$tmp/$asset" | awk '{print $1}')"
        elif have shasum;  then got="$(shasum -a 256 "$tmp/$asset" | awk '{print $1}')"
        else got=""; warn "no sha256 tool; skipping checksum verification"
        fi
        if [ -n "$got" ]; then
            [ "$got" = "$want" ] || die "checksum mismatch for $asset"
            say "Checksum verified."
        fi
    fi
else
    warn "SHA256SUMS.txt not found for this release; skipping checksum verification"
fi

# --- unpack + install ---------------------------------------------------------
mkdir -p "$tmp/x"
tar -xzf "$tmp/$asset" -C "$tmp/x"
bin="$(find "$tmp/x" -name origin-probe -type f | head -1)"
[ -n "$bin" ] || die "archive did not contain an origin-probe binary"

dest="${ORIGIN_PROBE_DIR:-$HOME/.local/bin}"
mkdir -p "$dest"
install -m 755 "$bin" "$dest/origin-probe"
say "Installed to $dest/origin-probe"

case ":$PATH:" in
    *":$dest:"*) ;;
    *) warn "$dest is not on PATH; add it with:  export PATH=\"$dest:\$PATH\"" ;;
esac

# --- usage --------------------------------------------------------------------
cat <<EOF

origin-probe is ready. It inspects this device and estimates the
likelihood that its user is Chinese. You must explicitly consent
before any scanning happens.

  origin-probe            interactive scan (prompts for consent)
  origin-probe --offline  local checks only, no network requests
  origin-probe --json     machine-readable report on stdout

One-shot non-interactive use:

  echo yes | origin-probe --offline

Nothing is written to disk and nothing is sent anywhere except a
public-IP geolocation lookup (skipped by --offline).
EOF
