#!/usr/bin/env bash
# Installation pour l'utilisateur courant, sans root : binaire, unit systemd
# --user, fichiers d'activation D-Bus. Le module PAM, lui, s'installe en root
# (README, « Déverrouillage à la connexion ») : ce script ne le touche pas,
# pas plus qu'il n'arrête gnome-keyring.
set -euo pipefail
LINUX=$(cd "$(dirname "$0")/.." && pwd)
BIN=${XDG_BIN_HOME:-$HOME/.local/bin}
UNITS=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
SERVICES=${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services

cargo build --release --manifest-path "$LINUX/Cargo.toml" --workspace
install -Dm0755 "$LINUX/target/release/mymfa" "$BIN/mymfa"
install -Dm0644 "$LINUX/systemd/mymfa.service" "$UNITS/mymfa.service"
mkdir -p "$SERVICES"
for f in today.mindlog.MyMfa1.service org.freedesktop.secrets.service; do
  sed "s|@MYMFA@|$BIN/mymfa|" "$LINUX/dbus/$f" > "$SERVICES/$f"
done
systemctl --user daemon-reload
echo "Installé : $BIN/mymfa, $UNITS/mymfa.service, $SERVICES/{today.mindlog.MyMfa1,org.freedesktop.secrets}.service"
echo "Module PAM construit : $LINUX/target/release/libpam_mymfa.so (installation root : voir README)"
echo "Suite : mymfa init (ou mymfa init --from mymfa-vault.json), puis systemctl --user enable --now mymfa"
