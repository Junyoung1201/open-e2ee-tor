#!/usr/bin/env bash
# Installs o2ee-server and its Tor onion service as systemd user services.
# Needs: tor (sudo apt install tor), Rust toolchain. Changes only files
# under your home directory.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v tor >/dev/null || { echo "Install tor first: sudo apt install tor" >&2; exit 1; }

BASE="$HOME/.local/share/o2ee-server"
CONF="$HOME/.config/o2ee-server"
UNITS="$HOME/.config/systemd/user"

cargo build --release --locked -p o2ee-server
install -d -m 700 "$BASE" "$BASE/run" "$BASE/data" "$CONF"
install -D -m 755 target/release/o2ee-server "$HOME/.local/bin/o2ee-server"
sed "s|@BASE@|$BASE|g" deploy/torrc.template > "$CONF/torrc"
chmod 600 "$CONF/torrc"
install -D -m 644 deploy/o2ee-tor.service "$UNITS/o2ee-tor.service"
install -D -m 644 deploy/o2ee-server.service "$UNITS/o2ee-server.service"

systemctl --user daemon-reload
systemctl --user enable --now o2ee-tor.service o2ee-server.service

for _ in $(seq 120); do [ -s "$BASE/hs/hostname" ] && break; sleep 1; done
echo "Onion address: $(cat "$BASE/hs/hostname")"
if [ ! -s "$BASE/data/admin_password" ]; then
    echo "Set the admin password:"
    echo "  $HOME/.local/bin/o2ee-server set-admin-password --data-dir $BASE/data"
fi
echo "Admin page: http://127.0.0.1:8788/"
echo "Back up $BASE/hs (onion keys) and $BASE/data (accounts) somewhere safe."
