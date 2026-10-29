#!/usr/bin/env bash
set -euo pipefail

# usage: install.sh [--install | --reinstall | --install-non-interactive]
# piped: curl -fsSL .../install.sh | bash -s -- --reinstall
#
# Downloads the latest release for this architecture, checks the Ed25519
# signature of the binary against the release public keys, and only then runs
# the binary as root. The keys are the raw 32 byte keys embedded in the binary
# (embedded/signingkeys/public1.bin and public2.bin), fetched at the release tag
# being installed so keys and binary come from the same commit, and wrapped as
# PEM so openssl can read them. The signature covers the raw binary bytes, the
# same check the self update in install/update.go does.
MODE="${1:---install}"
case "$MODE" in
  --install | --reinstall | --install-non-interactive) ;;
  *) echo "[!] Unknown option $MODE (use --install, --reinstall or --install-non-interactive)" >&2; exit 1 ;;
esac

REPO_URL="https://github.com/phishingclub/baitbox"
RAW_URL="https://raw.githubusercontent.com/phishingclub/baitbox"

die() { echo "[!] $*" >&2; exit 1; }

for tool in curl tar openssl mktemp wc; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# root runs the binary directly, anyone else needs sudo
IS_ROOT=0
if [ "$(id -u)" -eq 0 ]; then
  IS_ROOT=1
else
  command -v sudo >/dev/null 2>&1 || die "sudo is required when not running as root"
fi

echo "Getting Bait Box"

# pick the asset for this host architecture
case "$(uname -m)" in
  x86_64 | amd64) ARCH=amd64 ;;
  aarch64 | arm64) ARCH=arm64 ;;
  *) die "Unsupported architecture $(uname -m)" ;;
esac

TMP=$(mktemp -d "${TMPDIR:-/tmp}/baitbox.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

CURL=(curl -fsSL --proto '=https' --tlsv1.2)

# fetch_key downloads a raw Ed25519 public key and writes it as PEM. The DER form
# is the fixed SubjectPublicKeyInfo prefix for Ed25519 followed by the 32 key
# bytes, so no hex tool is needed.
fetch_key() {
  local name="$1" out="$2" size
  "${CURL[@]}" --max-filesize 64 "$KEYS_URL/$name" -o "$TMP/$name" \
    || die "Could not fetch the signing key $name"
  size=$(wc -c < "$TMP/$name") || die "Could not read the signing key $name"
  [ "$((size))" -eq 32 ] || die "Signing key $name is $((size)) bytes, expected 32"
  {
    printf '\060\052\060\005\006\003\053\145\160\003\041\000'
    cat "$TMP/$name"
  } > "$TMP/$name.der"
  openssl pkey -pubin -inform DER -in "$TMP/$name.der" -out "$out" >/dev/null 2>&1 \
    || die "Signing key $name is not a valid Ed25519 key (needs OpenSSL 3)"
}

# the latest release page redirects to .../releases/tag/<tag>; read the tag from
# the final URL instead of parsing the API JSON.
LATEST=$("${CURL[@]}" -o /dev/null -w '%{url_effective}' "$REPO_URL/releases/latest") \
  || die "Could not look up the latest release"
case "$LATEST" in
  "$REPO_URL/releases/tag/"*) TAG="${LATEST#"$REPO_URL/releases/tag/"}" ;;
  *) die "Unexpected latest release URL: $LATEST" ;;
esac
[[ "$TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "Unexpected release tag: $TAG"
VERSION="${TAG#v}"

# keys come from the same tag as the binary
KEYS_URL="$RAW_URL/$TAG/embedded/signingkeys"
fetch_key public1.bin "$TMP/public1.pem"
fetch_key public2.bin "$TMP/public2.pem"

URL="$REPO_URL/releases/download/$TAG/baitbox_${VERSION}_linux_${ARCH}.tar.gz"
echo "Downloading $URL"
"${CURL[@]}" --max-filesize 134217728 "$URL" -o "$TMP/bb.tgz" || die "Download failed"

# extract only the binary and its signature into a fresh directory
mkdir "$TMP/x"
tar -xzf "$TMP/bb.tgz" -C "$TMP/x" --no-same-owner --no-same-permissions baitbox baitbox.sig \
  || die "Release archive is missing baitbox or baitbox.sig"
BIN="$TMP/x/baitbox"
SIG="$TMP/x/baitbox.sig"
[ -f "$BIN" ] && [ ! -L "$BIN" ] || die "Release binary is not a regular file"
[ -f "$SIG" ] && [ ! -L "$SIG" ] || die "Release signature is not a regular file"

VERIFIED=0
for key in "$TMP/public1.pem" "$TMP/public2.pem"; do
  if openssl pkeyutl -verify -pubin -inkey "$key" -rawin -in "$BIN" -sigfile "$SIG" >/dev/null 2>&1; then
    VERIFIED=1
    break
  fi
done
[ "$VERIFIED" = 1 ] || die "Signature verification failed for $TAG, refusing to install (needs OpenSSL 3 for Ed25519)"
echo "Signature verified for $TAG"

chmod 0755 "$BIN"
echo "Installing from $TMP"
cd "$TMP/x"
if [ "$IS_ROOT" = 1 ]; then
  ./baitbox "$MODE"
else
  sudo ./baitbox "$MODE"
fi
