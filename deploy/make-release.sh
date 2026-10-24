#!/usr/bin/env bash
# Builds, signs and publishes an o2ee client release in one go.
#
#   deploy/make-release.sh --onion <address>.onion --pub <minisign.pub> --version <x.y.z>
#                          [--name <file name>] [--key <minisign secret key>]
#                          [--server-data-dir <o2ee-server data dir>]
#
#   --onion            onion address built into the client
#   --pub              release public key (minisign.pub), also built in
#   --version          release version; written to Cargo.toml
#   --name             published file name (default: o2ee-<arch>-<os>)
#   --key              secret key to sign with (e.g. on a USB stick). minisign
#                      asks for its password. Without --key the script stops
#                      after building, so you can sign on an offline machine.
#   --server-data-dir  publish into this o2ee-server data dir. Without it the
#                      script stops after signing.
#
# Output folder: target/o2ee-release
set -euo pipefail
cd "$(dirname "$0")/.."

usage() { sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 1; }
fail() { echo "Error: $*" >&2; exit 1; }

ONION="" PUBFILE="" VERSION="" NAME="" KEY="" DATA=""
while [ $# -gt 0 ]; do
    case "$1" in
        --onion) ONION="${2:-}"; shift 2 ;;
        --pub) PUBFILE="${2:-}"; shift 2 ;;
        --version) VERSION="${2:-}"; shift 2 ;;
        --name) NAME="${2:-}"; shift 2 ;;
        --key) KEY="${2:-}"; shift 2 ;;
        --server-data-dir) DATA="${2:-}"; shift 2 ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1" >&2; usage ;;
    esac
done
[ -n "$ONION" ] && [ -n "$PUBFILE" ] && [ -n "$VERSION" ] || usage

# Check everything before spending minutes on a build.
[[ "$ONION" =~ ^[a-z2-7]{56}\.onion$ ]] || fail "not a v3 onion address: $ONION"
[[ "$VERSION" =~ ^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$ ]] \
    || fail "version must look like 1.2.3: $VERSION"
[ -f "$PUBFILE" ] || fail "public key file not found: $PUBFILE"
PUBKEY="$(grep -v '^untrusted comment:' "$PUBFILE" | grep -v '^$' | head -1)"
[ -n "$PUBKEY" ] || fail "cannot read a public key from $PUBFILE"
if [ -n "$KEY" ]; then
    [ -f "$KEY" ] || fail "secret key not found: $KEY (is the USB stick mounted?)"
    command -v minisign >/dev/null || fail "minisign is not installed (sudo apt install minisign)"
fi

case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) fail "unsupported CPU: $(uname -m)" ;;
esac
case "$(uname -s)" in
    Linux) OS=linux ;;
    Darwin) OS=macos ;;
    *) fail "unsupported OS: $(uname -s)" ;;
esac
TARGET="$ARCH-$OS"
NAME="${NAME:-o2ee-$TARGET}"
[[ "$NAME" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || fail "invalid file name: $NAME"
case "$NAME" in
    manifest.json|minisign.pub|*.minisig) fail "reserved file name: $NAME" ;;
esac

SERVER_BIN=""
if [ -n "$DATA" ]; then
    [ -d "$DATA" ] || fail "server data dir not found: $DATA"
    PUBLISHED="$(sed -n 's/.*"version":"\([0-9.]*\)".*/\1/p' "$DATA/release/manifest.json" 2>/dev/null || true)"
    if [ -n "$PUBLISHED" ]; then
        newer="$(printf '%s\n%s\n' "$PUBLISHED" "$VERSION" | sort -V | tail -1)"
        [ "$newer" = "$VERSION" ] && [ "$VERSION" != "$PUBLISHED" ] \
            || fail "version $VERSION is not newer than the published $PUBLISHED"
    fi
    if [ -x "$HOME/.local/bin/o2ee-server" ]; then
        SERVER_BIN="$HOME/.local/bin/o2ee-server"
    else
        SERVER_BIN="target/release/o2ee-server"
    fi
fi

# 1. Version
CURRENT="$(sed -n '/^\[workspace.package\]/,/^\[/ s/^version = "\(.*\)"/\1/p' Cargo.toml)"
if [ "$CURRENT" != "$VERSION" ]; then
    sed -i.bak '/^\[workspace.package\]/,/^\[/ s/^version = ".*"/version = "'"$VERSION"'"/' Cargo.toml
    rm -f Cargo.toml.bak
    cargo update --workspace --offline --quiet
    echo "Version $CURRENT -> $VERSION (Cargo.toml, Cargo.lock: commit these)"
fi

# 2. Build: same toolchain and lockfile, no local paths in the binary.
export O2EE_SERVER_ONION="$ONION"
export O2EE_RELEASE_PUBKEY="$PUBKEY"
export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME/.cargo=~/.cargo"
export SOURCE_DATE_EPOCH=0
cargo build --release --locked -p o2ee
if [ -n "$SERVER_BIN" ] && [ ! -x "$SERVER_BIN" ]; then
    (unset O2EE_SERVER_ONION O2EE_RELEASE_PUBKEY; cargo build --release --locked -p o2ee-server)
fi

OUT=target/o2ee-release
rm -rf "$OUT"
mkdir -p "$OUT"
cp target/release/o2ee "$OUT/$NAME"
cp "$PUBFILE" "$OUT/minisign.pub"
SIZE="$(stat -c %s "$OUT/$NAME" 2>/dev/null || stat -f %z "$OUT/$NAME")"
SHA="$( (sha256sum "$OUT/$NAME" 2>/dev/null || shasum -a 256 "$OUT/$NAME") | cut -d' ' -f1)"
printf '{"product":"o2ee","version":"%s","server":"%s","files":[{"target":"%s","name":"%s","size":%s,"sha256":"%s"}]}\n' \
    "$VERSION" "$ONION" "$TARGET" "$NAME" "$SIZE" "$SHA" > "$OUT/manifest.json"
echo "Built release $VERSION for $TARGET in $OUT"

if [ -z "$KEY" ]; then
    echo "Sign it (offline):  minisign -Sm manifest.json $NAME -s <secret key>"
    echo "Then publish:       o2ee-server publish-release --data-dir <data dir> --from <folder>"
    exit 0
fi

# 3. Sign, then check the signatures against the public key we built in.
(cd "$OUT" && minisign -Sm manifest.json "$NAME" -s "$KEY")
for f in manifest.json "$NAME"; do
    minisign -Vqm "$OUT/$f" -p "$PUBFILE" >/dev/null \
        || fail "signature of $f does not match $PUBFILE (wrong key?)"
done
echo "Signed with $KEY"

if [ -z "$DATA" ]; then
    echo "Publish:  o2ee-server publish-release --data-dir <data dir> --from $OUT"
    exit 0
fi

# 4. Publish. The guide and o2ee update serve it right away.
"$SERVER_BIN" publish-release --data-dir "$DATA" --from "$OUT"
echo "Done. Users can now run: o2ee update"
