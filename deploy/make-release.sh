#!/usr/bin/env bash
# Prepares an o2ee client release for this platform, to be signed offline.
# Usage: deploy/make-release.sh <address>.onion <minisign.pub>
#
# 1. Builds o2ee with the onion address and release public key built in.
# 2. Writes target/o2ee-release/ with the binary, minisign.pub and manifest.json.
# 3. You copy that folder to the offline machine and sign:
#      minisign -Sm manifest.json <binary> -s <offline secret key>
# 4. Copy it back and publish on the server:
#      o2ee-server publish-release --data-dir ~/.local/share/o2ee-server/data --from <folder>
set -euo pipefail
cd "$(dirname "$0")/.."
ONION="${1:?usage: $0 <address>.onion <minisign.pub>}"
PUBFILE="${2:?usage: $0 <address>.onion <minisign.pub>}"
[[ "$ONION" =~ ^[a-z2-7]{56}\.onion$ ]] || { echo "Not a v3 onion address: $ONION" >&2; exit 1; }
PUBKEY="$(grep -v '^untrusted comment:' "$PUBFILE" | grep -v '^$' | head -1)"
[ -n "$PUBKEY" ] || { echo "Cannot read a public key from $PUBFILE" >&2; exit 1; }

case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) echo "Unsupported CPU: $(uname -m)" >&2; exit 1 ;;
esac
case "$(uname -s)" in
    Linux) OS=linux ;;
    Darwin) OS=macos ;;
    *) echo "Unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac
TARGET="$ARCH-$OS"
NAME="o2ee-$TARGET"
VERSION="$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)"

export O2EE_SERVER_ONION="$ONION"
export O2EE_RELEASE_PUBKEY="$PUBKEY"
export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME/.cargo=~/.cargo"
export SOURCE_DATE_EPOCH=0
cargo build --release --locked -p o2ee

OUT=target/o2ee-release
rm -rf "$OUT"
mkdir -p "$OUT"
cp target/release/o2ee "$OUT/$NAME"
cp "$PUBFILE" "$OUT/minisign.pub"
SIZE="$(stat -c %s "$OUT/$NAME" 2>/dev/null || stat -f %z "$OUT/$NAME")"
SHA="$(sha256sum "$OUT/$NAME" 2>/dev/null | cut -d' ' -f1 || shasum -a 256 "$OUT/$NAME" | cut -d' ' -f1)"
cat > "$OUT/manifest.json" <<JSON
{"product":"o2ee","version":"$VERSION","server":"$ONION","files":[{"target":"$TARGET","name":"$NAME","size":$SIZE,"sha256":"$SHA"}]}
JSON

echo "Release $VERSION for $TARGET in $OUT"
echo "Sign offline:  minisign -Sm manifest.json $NAME -s <secret key>"
echo "Then publish:  o2ee-server publish-release --data-dir <data dir> --from <signed folder>"
