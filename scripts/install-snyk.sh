#!/usr/bin/env bash
# Install the Snyk CLI and verify the published SHA-256.
#
# Env:
#   SNYK_VERSION     "latest"/"stable", or a pin like "1.1305.1"/"v1.1305.1".
#   SNYK_VERIFY_GPG  "true" also verifies the GPG-signed sha256sums.txt.asc and
#                    takes the digest from there. The per-asset .sha256 shares
#                    an origin with the binary, so it proves nothing against a
#                    compromised origin; this is the only step giving
#                    provenance rather than integrity alone.
#
# https://docs.snyk.io/developer-tools/snyk-cli/snyk-cli/install-the-snyk-cli/verifying-cli-standalone-binaries
set -euo pipefail

: "${SNYK_VERSION:=latest}"
: "${SNYK_VERIFY_GPG:=false}"

SNYK_GPG_FINGERPRINT="467717A30B2B4658415975629691DA64D0025194"

# ---------------------------------------------------------------- platform ---
# RUNNER_OS cannot distinguish musl from glibc, so probe the loader. Without
# this an Alpine runner downloads the glibc build and dies at exec time with a
# "not found" that looks like a missing binary.
libc="gnu"
if [ "${RUNNER_OS:-Linux}" = "Linux" ]; then
  if [ -n "$(ls /lib/ld-musl-* 2>/dev/null || true)" ]; then
    libc="musl"
  elif command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
    libc="musl"
  fi
fi

case "${RUNNER_OS:-Linux}-${RUNNER_ARCH:-X64}-${libc}" in
  Linux-X64-musl)    asset="snyk-alpine" ;;
  Linux-ARM64-musl)  asset="snyk-alpine-arm64" ;;
  Linux-X64-gnu)     asset="snyk-linux" ;;
  Linux-ARM64-gnu)   asset="snyk-linux-arm64" ;;
  macOS-X64-*)       asset="snyk-macos" ;;
  macOS-ARM64-*)     asset="snyk-macos-arm64" ;;
  Windows-X64-*)     asset="snyk-win.exe" ;;
  *)                 asset="" ;;
esac

if [ -z "$asset" ]; then
  # npm has no "stable" dist-tag; without this remap the install ETARGETs.
  npm_spec="$SNYK_VERSION"
  case "$npm_spec" in
    stable|"") npm_spec="latest" ;;
    v*)        npm_spec="${npm_spec#v}" ;;
  esac
  echo "::warning::No Snyk standalone binary for ${RUNNER_OS:-?}/${RUNNER_ARCH:-?}/${libc};" \
       "installing via npm (unverified: npm's own integrity check only)."
  npm install -g "snyk@${npm_spec}"
  snyk --version
  exit 0
fi

case "$SNYK_VERSION" in
  latest|stable|"") channel="stable" ;;
  v*)               channel="$SNYK_VERSION" ;;
  *)                channel="v${SNYK_VERSION}" ;;
esac

dest="${RUNNER_TEMP:-/tmp}/snyk-cli"
mkdir -p "$dest"
cd "$dest"
rm -f "$asset" "${asset}.sha256" sha256sums.txt.asc snyk snyk.exe

base="https://downloads.snyk.io/cli/${channel}"

fetch() {  # fetch <url> <output>
  curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-delay 2 \
       --retry-connrefused --max-time 300 "$1" -o "$2"
}

fetch "${base}/${asset}" "$asset"

# ------------------------------------------------------------ verification ---
# `sha256sum -c` needs "<digest>  <filename>" lines; Snyk's per-asset .sha256
# files already carry the filename column.
sumfile=""
if [ "$SNYK_VERIFY_GPG" = "true" ]; then
  if ! command -v gpg >/dev/null 2>&1; then
    echo "::error::SNYK_VERIFY_GPG=true but gpg is not on the runner."
    exit 1
  fi
  fetch "${base}/sha256sums.txt.asc" sha256sums.txt.asc
  export GNUPGHOME="${dest}/gnupg"
  mkdir -p "$GNUPGHOME"
  chmod 700 "$GNUPGHOME"
  gpg --batch --keyserver hkps://keys.openpgp.org \
      --recv-keys "$SNYK_GPG_FINGERPRINT"
  # --status-fd lets us assert on the fingerprint instead of trusting exit 0,
  # which gpg also returns for a good signature from an unrelated key.
  if ! gpg --batch --status-fd 1 --verify sha256sums.txt.asc 2>/dev/null \
       | grep -q "VALIDSIG ${SNYK_GPG_FINGERPRINT}"; then
    echo "::error::GPG signature on sha256sums.txt.asc did not validate against ${SNYK_GPG_FINGERPRINT}."
    exit 1
  fi
  echo "GPG signature verified against ${SNYK_GPG_FINGERPRINT}."
  grep -E "[[:space:]]\*?${asset}\$" sha256sums.txt.asc > "${asset}.sha256"
  sumfile="${asset}.sha256"
else
  fetch "${base}/${asset}.sha256" "${asset}.sha256"
  sumfile="${asset}.sha256"
fi

if [ ! -s "$sumfile" ] || ! grep -q "$asset" "$sumfile"; then
  echo "::error::Checksum file for ${asset} is empty or does not name the asset; refusing to install."
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum -c "$sumfile"
else
  shasum -a 256 -c "$sumfile"
fi
rm -f "$sumfile" sha256sums.txt.asc
rm -rf "${dest}/gnupg"

case "$asset" in
  *.exe) mv "$asset" snyk.exe; bin="snyk.exe" ;;
  *)     mv "$asset" snyk; chmod +x snyk; bin="snyk" ;;
esac

if [ -z "${GITHUB_PATH:-}" ]; then
  echo "::error::GITHUB_PATH is not set; this script must run inside a GitHub Actions step."
  exit 1
fi
echo "$dest" >> "$GITHUB_PATH"
"./${bin}" --version
