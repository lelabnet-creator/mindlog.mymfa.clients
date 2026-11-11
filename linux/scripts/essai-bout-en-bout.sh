#!/usr/bin/env bash
# Essai de bout en bout du client Linux, sur un bus de session PRIVÉ
# (dbus-run-session, config propre : aucun service système activable) et un
# dossier jetable : ni le vrai bus, ni ~/.local/share, ni /etc ne sont touchés.
#
#   1. activation D-Bus du démon, coffre créé par `mymfa init` ;
#   2. secret-tool (libsecret, session DH) : stockage coffre verrouillé →
#      Prompt → déverrouillage par MyMfa1 → stockage effectif ; relecture ;
#   3. session `plain` et GetSecrets à la main (gdbus) ;
#   4. persistance : démon relancé, secret relu ; invite pinentry (factice) ;
#   5. vraie pile PAM (pam_start_confdir) : clé remise → sceau posé au
#      déverrouillage → connexion suivante = coffre ouvert sans saisie ;
#      chauthtok → sceau renouvelé ;
#   6. codes et logins par MyMfa1 (coffre du web, si la fixture d'android/ existe) ;
#   7. reprise de gnome-keyring (si installé) : un gnome-keyring isolé tient le
#      nom, mymfa attend, importe, puis reprend le nom quand il s'arrête.
#
# Usage : linux/scripts/essai-bout-en-bout.sh   (TMPDIR pour le dossier jetable)
set -euo pipefail
LINUX=$(cd "$(dirname "$0")/.." && pwd)

if [[ "${1:-}" != "--dedans" ]]; then
  cargo build --release --manifest-path "$LINUX/Cargo.toml" --workspace
  cargo build --release --manifest-path "$LINUX/Cargo.toml" -p pam_mymfa --examples
  T=$(mktemp -d)
  trap 'rm -rf "$T"' EXIT
  mkdir -p "$T/services"
  cat > "$T/bus.conf" <<EOF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <keep_umask/>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <servicedir>$T/services</servicedir>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
EOF
  T="$T" dbus-run-session --config-file="$T/bus.conf" -- "$0" --dedans
  exit $?
fi

M=$LINUX/target/release/mymfa
SO=$LINUX/target/release/libpam_mymfa.so
PAM=$LINUX/target/release/examples/essai_pam
MDP='correct horse battery'
export MYMFA_DATA_DIR=$T/data MYMFA_RUNTIME_DIR=$T/run MYMFA_PINENTRY=none
mkdir -m 700 -p "$T/run"
unset GNOME_KEYRING_CONTROL SSH_AUTH_SOCK || true

etape() { printf '\n== %s\n' "$*"; }
ok() { printf '  ok — %s\n' "$*"; }
echec() { printf '  ÉCHEC — %s\n' "$*"; echo "--- journal du démon"; cat "$T"/demon*.log 2>/dev/null || true; exit 1; }
nom_tenu() {
  gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.NameHasOwner "$1" | grep -q true
}
attendre() { for _ in $(seq 1 100); do eval "$1" && return 0; sleep 0.1; done; return 1; }
arreter_demon() {
  local pid
  pid=$(gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.GetConnectionUnixProcessID today.mindlog.MyMfa1 | sed 's/[^0-9]*uint32 \([0-9]*\).*/\1/')
  kill "$pid"; attendre '! nom_tenu today.mindlog.MyMfa1' || echec "démon toujours là"
}

# Activation D-Bus : le démon démarre au premier appel (comme en vrai, sans systemd ici).
for nom in today.mindlog.MyMfa1 org.freedesktop.secrets; do
  cat > "$T/services/$nom.service" <<EOF
[D-BUS Service]
Name=$nom
Exec=/bin/sh -c 'exec env MYMFA_DATA_DIR=$T/data MYMFA_RUNTIME_DIR=$T/run MYMFA_PINENTRY=none $M daemon 2>>$T/demon.log'
EOF
done

etape "1. coffre et activation D-Bus"
printf '%s\n%s\n' "$MDP" "$MDP" | "$M" init >/dev/null
[[ $(stat -c %a "$T/data/mymfa-vault.json") == 600 ]] || echec "coffre non 0600"
"$M" status | grep -q "Coffre          : verrouillé" || echec "status"
ok "coffre créé (0600), démon activé par le bus, verrouillé"

etape "2. secret-tool : stockage coffre verrouillé → invite → Unlock"
( printf 'valeur-secrète' | timeout 30 secret-tool store --label='Essai' app essai cle 1 ) & STORE=$!
sleep 1
echo "$MDP" | "$M" unlock >/dev/null
wait $STORE || echec "secret-tool store"
[[ $(secret-tool lookup app essai cle 1) == valeur-secrète ]] || echec "lookup"
ok "stockage par l'invite, relecture (session DH de libsecret)"
"$M" lock >/dev/null
( timeout 30 secret-tool lookup app essai cle 1 > "$T/lu" ) & LU=$!
sleep 1
echo "$MDP" | "$M" unlock >/dev/null
wait $LU || echec "lookup verrouillé"
[[ $(cat "$T/lu") == valeur-secrète ]] || echec "valeur relue après invite"
ok "verrouillé : la recherche répond « verrouillé », l'invite rend la valeur"
grep -q "valeur-secrète" "$T/data/mymfa-keyring.json" && echec "secret en clair dans le trousseau"
grep -q "Essai" "$T/data/mymfa-keyring.json" && echec "libellé en clair dans le trousseau"
[[ $(stat -c %a "$T/data/mymfa-keyring.json") == 600 ]] || echec "trousseau non 0600"
ok "trousseau local chiffré, 0600"

etape "3. session plain et GetSecrets (gdbus)"
S=$(gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
  --method org.freedesktop.Secret.Service.OpenSession plain '<"">' | grep -o "/org/freedesktop/secrets/session/[a-z0-9]*")
I=$(gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
  --method org.freedesktop.Secret.Service.SearchItems "{'app': 'essai'}" | grep -o "/org/freedesktop/secrets/collection/login/[a-f0-9]*" | head -1)
gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
  --method org.freedesktop.Secret.Service.GetSecrets "['$I']" "$S" | grep -q "0x76, 0x61, 0x6c, 0x65, 0x75, 0x72" \
  || echec "GetSecrets plain"
[[ $(gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets \
  --method org.freedesktop.Secret.Service.ReadAlias default) == *collection/login* ]] || echec "alias default"
ok "plain, GetSecrets, alias default → login"

etape "4. persistance"
arreter_demon
"$M" status >/dev/null # réactivation
echo "$MDP" | "$M" unlock >/dev/null
[[ $(secret-tool lookup app essai cle 1) == valeur-secrète ]] || echec "relu après redémarrage"
ok "démon relancé : secret relu"

etape "4 bis. invite de repli (pinentry, protocole Assuan)"
cat > "$T/pinentry" <<EOF
#!/bin/sh
# Faux pinentry : répond au protocole Assuan comme un utilisateur pressé.
echo "OK Pleased to meet you"
while read -r commande reste; do
  case "\$commande" in
    GETPIN) echo "D $MDP"; echo OK ;;
    BYE) echo OK; exit 0 ;;
    *) echo OK ;;
  esac
done
EOF
chmod +x "$T/pinentry"
arreter_demon
MYMFA_PINENTRY="$T/pinentry" "$M" daemon 2>>"$T/demon.log" &
attendre 'nom_tenu org.freedesktop.secrets' || echec "démon relancé"
[[ $(timeout 30 secret-tool lookup app essai cle 1) == valeur-secrète ]] || echec "invite pinentry"
ok "coffre verrouillé : pinentry demande, le secret est rendu"

etape "5. PAM : remise, sceau, connexion sans saisie, chauthtok"
mkdir -p "$T/pam.d"
cat > "$T/pam.d/mymfa-essai" <<EOF
auth     required  pam_permit.so
auth     optional  $SO ask rundir=$T/run
account  required  pam_permit.so
session  required  pam_permit.so
session  optional  $SO rundir=$T/run
password required  pam_permit.so
password optional  $SO ask rundir=$T/run
EOF
"$M" lock >/dev/null
"$PAM" "$T/pam.d" mymfa-essai "$USER" session 'mdp-session' | grep -q "pam_open_session = 0" || echec "pile PAM"
attendre '"$M" status | grep -q "clé de session reçue"' || echec "clé non reçue"
[[ -e "$T/run/mymfa/session-key" ]] && echec "remise non consommée"
ok "clé remise par pam_sm_open_session, consommée et effacée"
echo "$MDP" | "$M" unlock >/dev/null
"$M" status | grep -q "déverrouillage à la connexion actif" || echec "sceau non posé"
grep -q correct "$T/data/session-seal.json" && echec "mot de passe en clair dans le sceau"
ok "premier déverrouillage manuel : sceau posé"
"$M" lock >/dev/null
"$PAM" "$T/pam.d" mymfa-essai "$USER" session 'mdp-session' >/dev/null
attendre '"$M" status | grep -q "Coffre          : déverrouillé"' || echec "pas d'ouverture à la connexion"
ok "connexion suivante : coffre ouvert sans saisie"
"$M" lock >/dev/null
"$PAM" "$T/pam.d" mymfa-essai "$USER" session 'faux-mdp' >/dev/null
sleep 3
"$M" status | grep -q "Coffre          : verrouillé" || echec "mauvais mot de passe de session : ouvert ?!"
ok "autre mot de passe de session : rien n'est ouvert, la connexion n'échoue pas"
"$PAM" "$T/pam.d" mymfa-essai "$USER" chauthtok 'mdp-session' 'nouveau-mdp' >/dev/null
sleep 2
"$PAM" "$T/pam.d" mymfa-essai "$USER" session 'nouveau-mdp' >/dev/null
attendre '"$M" status | grep -q "Coffre          : déverrouillé"' || echec "sceau non renouvelé"
ok "chauthtok : sceau renouvelé, nouveau mot de passe de session accepté"

FIXTURE=$LINUX/../android/crates/mymfa-core/tests/fixtures/vault-web.json
if [[ -f $FIXTURE ]]; then
  etape "6. MyMfa1 : codes et logins d'un coffre chiffré par le web"
  arreter_demon
  python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1]))["records"]["simple"]))' "$FIXTURE" > "$T/data/mymfa-vault.json"
  echo "$MDP" | "$M" unlock >/dev/null || echec "coffre du web"
  "$M" codes | grep -qE '^[0-9]{3} [0-9]{3}' || echec "codes"
  gdbus call --session --dest today.mindlog.MyMfa1 --object-path /today/mindlog/MyMfa1 \
    --method today.mindlog.MyMfa1.Codes | grep -q "uint32" || echec "Codes() D-Bus"
  gdbus call --session --dest today.mindlog.MyMfa1 --object-path /today/mindlog/MyMfa1 \
    --method today.mindlog.MyMfa1.SearchLogins '' >/dev/null || echec "SearchLogins"
  ok "coffre du web ouvert, $("$M" codes | wc -l) code(s) en cours"
fi

if command -v gnome-keyring-daemon >/dev/null; then
  etape "7. reprise de gnome-keyring"
  arreter_demon
  rm -f "$T"/services/org.freedesktop.secrets.service
  G=$T/gk; mkdir -m 700 -p "$G/home" "$G/run"
  ( cd "$G" && echo -n 'mdp-gnome' | env HOME="$G/home" XDG_DATA_HOME="$G/home/.local/share" \
      XDG_CONFIG_HOME="$G/home/.config" XDG_RUNTIME_DIR="$G/run" \
      gnome-keyring-daemon --foreground --unlock --components=secrets --control-directory=ctl \
      >/dev/null 2>"$T/gk.log" ) & GK=$!
  if attendre 'nom_tenu org.freedesktop.secrets'; then
    printf 'mot-de-passe-wifi' | secret-tool store --label='Wi-Fi maison' service wifi ssid maison
    "$M" status | grep -q "tenu par un autre service" || echec "mymfa devait attendre son tour"
    echo "$MDP" | "$M" unlock >/dev/null
    "$M" import-gnome-keyring | tail -1
    "$M" import-gnome-keyring >/dev/null # relançable sans doublon
    pkill -P $GK || true; kill $GK 2>/dev/null || true
    attendre '"$M" status | grep -q "tenu par mymfa"' || echec "nom non repris"
    [[ $(secret-tool lookup service wifi ssid maison) == mot-de-passe-wifi ]] || echec "secret repris"
    [[ $(secret-tool search --all service wifi 2>/dev/null | grep -c '^label') == 1 ]] || echec "doublon à l'import"
    ok "gnome-keyring importé, nom repris à son arrêt, sans doublon"
  else
    kill $GK 2>/dev/null || true
    echo "  sauté — gnome-keyring isolé n'a pas démarré ($(head -c 200 "$T/gk.log"))"
  fi
fi

grep -qiE "valeur-secr|correct horse|mdp-session|wifi" "$T"/demon*.log && echec "secret dans le journal"
ok "aucun secret dans le journal du démon"
arreter_demon
printf '\nTout est vert.\n'
