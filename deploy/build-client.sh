#!/usr/bin/env bash
# Builds a release o2ee client with the server's onion address built in.
# Usage: deploy/build-client.sh <address>.onion
# Output: target/release/o2ee and target/release/o2ee.sha256
set -euo pipefail
cd "$(dirname "$0")/.."
ONION="${1:?usage: $0 <address>.onion}"
[[ "$ONION" =~ ^[a-z2-7]{56}\.onion$ ]] || { echo "Not a v3 onion address: $ONION" >&2; exit 1; }

# Same toolchain (rust-toolchain.toml), same lockfile, no local paths in the
# binary: two people building the same commit get the same bytes.
export O2EE_SERVER_ONION="$ONION"
export RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME/.cargo=~/.cargo"
export SOURCE_DATE_EPOCH=0
cargo build --release --locked -p o2ee
(cd target/release && sha256sum o2ee > o2ee.sha256)
cat target/release/o2ee.sha256
echo "Sign it with the offline release key, e.g.:"
echo "  ssh-keygen -Y sign -f /media/offline/o2ee-release-key -n o2ee target/release/o2ee"
