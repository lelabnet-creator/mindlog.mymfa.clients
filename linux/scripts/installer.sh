#!/usr/bin/env bash
# Installation (et mise à jour) pour l'utilisateur courant, sans root :
# binaire, unit systemd --user, fichiers d'activation D-Bus, puis relance du
# démon pour que la nouvelle version serve aussitôt — sans quoi l'ancien
# binaire, toujours chargé, continue de répondre (méthodes absentes :
# « Unknown method »). Rejouable : chaque déploiement passe par ce script.
#
# La relance ne perd rien : le démon verrouille le coffre (il se rouvre au
# besoin) et rend la clé de session en attente au démon suivant.
#
# Le module PAM, lui, s'installe en root (README, « Déverrouillage à la
# connexion ») : ce script le construit et signale s'il est à recopier, sans
# y toucher, pas plus qu'il n'arrête gnome-keyring.
set -euo pipefail
LINUX=$(cd "$(dirname "$0")/.." && pwd)
BIN=${XDG_BIN_HOME:-$HOME/.local/bin}
UNITS=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
SERVICES=${XDG_DATA_HOME:-$HOME/.local/share}/dbus-1/services
PAM_CONSTRUIT="$LINUX/target/release/libpam_mymfa.so"

echo "== construction"
cargo build --release --manifest-path "$LINUX/Cargo.toml" --workspace

echo "== binaire, unit, activation D-Bus"
# Copie puis renommage : le binaire en cours d'exécution n'est jamais réécrit.
mkdir -p "$BIN"
ETAPE=$(mktemp "$BIN/.mymfa-installer.XXXXXX")
trap 'rm -f -- "$ETAPE"' EXIT
install -m0755 "$LINUX/target/release/mymfa" "$ETAPE"
mv -f -- "$ETAPE" "$BIN/mymfa"
trap - EXIT
install -Dm0644 "$LINUX/systemd/mymfa.service" "$UNITS/mymfa.service"
mkdir -p "$SERVICES"
for f in today.mindlog.MyMfa1.service org.freedesktop.secrets.service; do
  sed "s|@MYMFA@|$BIN/mymfa|" "$LINUX/dbus/$f" > "$SERVICES/$f"
done
systemctl --user daemon-reload
echo "   $BIN/mymfa, $UNITS/mymfa.service, $SERVICES/{today.mindlog.MyMfa1,org.freedesktop.secrets}.service"

echo "== démon"
# Qui tient le Secret Service avant la relance : un gnome-keyring encore actif
# peut le prendre pendant la seconde où le démon redémarre.
tenant() { busctl --user status org.freedesktop.secrets 2>/dev/null | sed -n 's/^Comm=//p'; }
AVANT=$(tenant)
if systemctl --user is-active --quiet mymfa.service; then
  systemctl --user restart mymfa.service
  echo "   relancé sur la nouvelle version"
elif pgrep -u "$(id -u)" -x mymfa >/dev/null; then
  # Lancé hors de l'unit : arrêté, l'activation D-Bus relance la nouvelle version.
  pkill -TERM -u "$(id -u)" -x mymfa || true
  echo "   ancien démon arrêté (relancé à la demande, par le bus)"
else
  echo "   pas en service (démarré à la demande, par le bus)"
fi
# Contrôle : le démon répond, et il a démarré après l'installation du binaire
# (/proc/PID/exe est illisible : le démon se déclare non inspectable).
OK=
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if "$BIN/mymfa" status >/dev/null 2>&1; then OK=1; break; fi
  sleep 0.5
done
if [[ -z "$OK" ]]; then
  echo "!! le démon ne répond pas : journalctl --user -u mymfa -n 50" >&2
  exit 1
fi
PID=$(pgrep -u "$(id -u)" -x mymfa | head -1 || true)
if [[ -n "$PID" ]]; then
  DEPART=$(( $(date +%s) - $(ps -o etimes= -p "$PID" | tr -d ' ') ))
  if (( DEPART + 1 < $(stat -c %Y "$BIN/mymfa") )); then
    echo "!! le démon en service (PID $PID) date d'avant le binaire installé : systemctl --user restart mymfa" >&2
    exit 1
  fi
fi
"$BIN/mymfa" status | sed 's/^/   /'
APRES=$(tenant)
if [[ "$AVANT" == mymfa && "$APRES" != mymfa ]]; then
  echo "!! ${APRES:-un autre service} a pris le Secret Service pendant la relance ;" >&2
  echo "   pour que myMFA le garde : hyprdesk, Réglages → Mots de passe →" >&2
  echo "   « Remplacer gnome-keyring par myMFA… » (coffre ouvert)." >&2
fi

echo "== module PAM"
PAM_INSTALLE=
for d in /usr/lib/security /lib/security /usr/lib64/security; do
  if [[ -f "$d/pam_mymfa.so" ]]; then PAM_INSTALLE="$d/pam_mymfa.so"; break; fi
done
if [[ -z "$PAM_INSTALLE" ]]; then
  echo "   non installé (root) : sudo install -Dm0755 $PAM_CONSTRUIT /usr/lib/security/pam_mymfa.so"
elif cmp -s "$PAM_CONSTRUIT" "$PAM_INSTALLE"; then
  echo "   à jour ($PAM_INSTALLE)"
else
  echo "   à mettre à jour (root) : sudo install -Dm0755 $PAM_CONSTRUIT $PAM_INSTALLE"
fi

if [[ "$("$BIN/mymfa" status 2>/dev/null)" == *"absent"* ]]; then
  echo
  echo "Pas encore de coffre : hyprdesk propose de le créer (ou de reprendre la"
  echo "sauvegarde du web) ; sans hyprdesk : mymfa init [--from mymfa-vault.json]."
fi
