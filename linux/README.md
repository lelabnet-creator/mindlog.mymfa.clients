# myMFA — Linux

Le trousseau du bureau, **alternative à gnome-keyring**, sur le coffre myMFA :
un démon utilisateur `mymfa` tient l'API Secret Service
(`org.freedesktop.secrets`) pour les applications (Chromium, NetworkManager,
Evolution, tout ce qui passe par libsecret) et une interface D-Bus
`today.mindlog.MyMfa1` pour [hyprdesk](../../mindlog.hyprland_desktop). Le
coffre s'ouvre à la connexion, sans deuxième saisie, grâce au module PAM
`pam_mymfa.so`. Tickets Plane : épique LIN (LIN-02 démon et CLI, LIN-03
déverrouillage à la connexion, LIN-04 interface hyprdesk).

## Ce que contient ce client

- **Même coffre que le web et Android** : le cœur Rust
  [`android/crates/mymfa-core`](../android/crates/mymfa-core) (AES-256-GCM,
  PBKDF2-SHA256 1 000 000 itérations, AAD par rôle), en dépendance de chemin,
  sans ses textes générés (fonction `texts` désactivée : pas besoin de Node).
  Le fichier est `~/.local/share/mymfa/mymfa-vault.json`, même nom et même
  contenu que la sauvegarde Drive du web — et même dossier que l'app Slint
  lancée sur le bureau. Le démon **ne l'écrit jamais** : il en lit les comptes
  2FA et les logins des sites, et le relit s'il est remplacé sur le disque.
- **Secrets des applications dans un trousseau local**
  (`~/.local/share/mymfa/mymfa-keyring.json`, 0600), chiffré par la clé du
  coffre (DEK) avec sa propre AAD (`mymfa:linux:keyring:v1`) : jamais
  synchronisé, jamais dans le coffre, mais ouvert et refermé avec lui.
- **Logins du coffre exposés en lecture** dans une collection Secret Service
  « myMFA » (`/org/freedesktop/secrets/collection/mymfa`), attributs
  `xdg:schema=today.mindlog.MyMfa.Login`, `origin`, `host`, `username`.
- **Déverrouillage à la connexion par clé scellée** : le mot de passe myMFA
  reste distinct de celui de la session. Au premier déverrouillage manuel, le
  démon scelle le mot de passe du coffre (AES-256-GCM) par une clé dérivée du
  mot de passe de session (PBKDF2-SHA256, 1 000 000 itérations, sel propre à
  la machine et à l'utilisateur) ; ensuite, la connexion ouvre le coffre.
- **CLI `mymfa`** : `status`, `unlock`, `lock`, `codes`, `logins`, `copy`,
  `copy-login`, `seal`, `init`, `import-gnome-keyring`, `daemon`.

## Architecture

```
linux/
├── Cargo.toml                 espace de travail (cible : linux/target)
├── crates/mymfa-sceau/        partagé démon ↔ PAM : dérivation de la clé de
│                              session, sceau, remise par /run/user/UID
├── crates/mymfa-linux/        binaire `mymfa` (démon + CLI)
│   └── src/  main, cli, demon (état, sceau, remise), coffre (lecture du
│             coffre, codes), trousseau (fichier local chiffré), session
│             (plain, DH), service (Secret Service), interface (MyMfa1),
│             invite (pinentry de repli), presse_papiers (wl-copy),
│             import_gnome
├── crates/pam_mymfa/          cdylib `libpam_mymfa.so` (FFI PAM écrite à la main)
│   └── examples/essai_pam.rs  banc d'essai : vraie pile libpam, sans root
├── systemd/mymfa.service      unit systemd --user (Type=dbus)
├── dbus/*.service             activation D-Bus (MyMfa1 et org.freedesktop.secrets)
└── scripts/
    ├── installer.sh           installation utilisateur (sans root)
    └── essai-bout-en-bout.sh  essai complet sur un bus privé
```

```
 greetd ─ PAM ─ pam_mymfa ──(clé dérivée, 0600)──▶ /run/user/UID/mymfa/session-key
                                                          │ consommée, effacée
 Chromium, nm… ─ org.freedesktop.secrets ─┐               ▼
                                          ├──▶ mymfa daemon ──▶ mymfa-vault.json   (lecture)
 hyprdesk, CLI ─ today.mindlog.MyMfa1 ────┘        │      ├──▶ mymfa-keyring.json  (DEK + AAD propre)
                                                   │      └──▶ session-seal.json   (clé de session)
                                                   └── invite : signal UnlockRequested (+ pinentry de repli)
```

Un seul verrou : celui du coffre. Déverrouillé, le démon tient en mémoire la
DEK, les comptes et les logins ; verrouillé (`Lock`, arrêt du démon), tout est
effacé (`zeroize`). Les mots de passe en transit (D-Bus, PAM, saisie) sont
dans des tampons effacés à leur libération ; le démon se rend non vidable
(`PR_SET_DUMPABLE`, `LimitCORE=0`) et crée ses fichiers en 0600. Aucun secret
dans les journaux (vérifié par l'essai de bout en bout).

## Construire et tester

```sh
cd linux
cargo build --release        # target/release/mymfa et target/release/libpam_mymfa.so
cargo test                   # sceau, remise, trousseau, sessions DH, coffre, démon
cargo clippy --all-targets   # propre
scripts/essai-bout-en-bout.sh
```

Le test `coffre_du_web_si_fixture` ouvre un coffre chiffré par le vrai
`web/js/vault.js` quand la fixture d'Android existe (`cd android && npm run gen`) ;
sinon il est sauté. L'essai de bout en bout tourne sur un bus de session privé
(`dbus-run-session` avec une configuration sans services système) et un
dossier jetable : il ne touche ni le vrai bus, ni `~/.local/share`, ni `/etc`.
Il couvre secret-tool (libsecret, session DH), l'invite (Prompt) d'un coffre
verrouillé, la session `plain`, la persistance, une vraie pile PAM
(`pam_start_confdir`), le sceau, `chauthtok`, les codes d'un coffre du web,
et la reprise d'un gnome-keyring isolé.

## Installation (utilisateur)

```sh
linux/scripts/installer.sh            # ~/.local/bin/mymfa, unit systemd --user, activation D-Bus
mymfa init                            # nouveau coffre…
mymfa init --from mymfa-vault.json    # …ou la sauvegarde Drive du web
systemctl --user enable --now mymfa
mymfa unlock
```

Le démon lit `WAYLAND_DISPLAY` (presse-papiers, pinentry) dans
l'environnement du gestionnaire systemd de l'utilisateur quand il ne l'a pas
reçu au démarrage : le compositeur doit l'y importer
(`dbus-update-activation-environment --systemd WAYLAND_DISPLAY`, ce que fait
hyprdesk).

## Reprise de gnome-keyring

L'import lit gnome-keyring **par le Secret Service**, pendant qu'il tient
encore le nom : le démon mymfa démarre alors en file d'attente sur
`org.freedesktop.secrets` (MyMfa1 reste disponible) et le reprend
automatiquement dès que gnome-keyring s'arrête.

```sh
systemctl --user start mymfa          # en file derrière gnome-keyring
mymfa unlock
mymfa import-gnome-keyring            # invite de gnome-keyring si son trousseau est verrouillé
# puis, quand tout est repris (relançable, sans doublon) :
systemctl --user mask --now gnome-keyring-daemon.service gnome-keyring-daemon.socket
mymfa status                          # « Secret Service : tenu par mymfa »
```

La collection « login » de gnome-keyring rejoint la nôtre (alias `default`
et `login`) ; les autres collections sont recréées sous leur libellé ; la
collection éphémère « session » est ignorée. Les fichiers de
`~/.local/share/keyrings` ne sont pas touchés. Le fichier
`~/.local/share/dbus-1/services/org.freedesktop.secrets.service` posé par
l'installation passe avant celui de gnome-keyring pour l'activation D-Bus.
Si l'on retire aussi `pam_gnome_keyring` de la pile PAM, gnome-keyring ne
démarre plus du tout à la connexion.

## Déverrouillage à la connexion (pam_mymfa)

Installation (root, non faite par les scripts) :

```sh
install -Dm0755 linux/target/release/libpam_mymfa.so /usr/lib/security/pam_mymfa.so
```

Lignes à poser dans `/etc/pam.d/greetd` (hyprdesk les posera) — **après** les
lignes `include` existantes, toujours en `optional` :

```
auth       include   system-local-login
auth       optional  pam_mymfa.so
account    include   system-local-login
session    include   system-local-login
session    optional  pam_mymfa.so
password   include   system-local-login
password   optional  pam_mymfa.so
```

- `auth` : après `pam_unix` (inclus), le module trouve le mot de passe de
  session dans la pile (`PAM_AUTHTOK`) et le garde (`pam_set_data`, effacé au
  nettoyage). Il ne demande jamais rien.
- `session` : après `pam_systemd` (inclus, il crée `/run/user/UID`), il en
  dérive la clé de session et la dépose — jamais le mot de passe — dans
  `/run/user/UID/mymfa/session-key` (dossier 0700, fichier 0600, propriété de
  l'utilisateur, écriture par descripteurs `openat`/`O_NOFOLLOW`/`O_EXCL`).
  Le démon le lit, l'efface, puis descelle et ouvre le coffre. Sans sceau
  encore, il garde la clé : le premier déverrouillage manuel scelle.
- `password` : au changement du mot de passe de session (`passwd`), il remet
  l'ancienne et la nouvelle clé (`/run/user/UID/mymfa/rekey`) ; le démon
  rescelle. Changé par root (pas d'ancien mot de passe) ou hors connexion : le
  sceau devient périmé, la connexion suivante ne l'ouvre pas, le
  déverrouillage manuel suivant rescelle.
- **Ne bloque jamais une connexion** : `optional`, toutes les fonctions
  rendent `PAM_IGNORE` (ou `PAM_SUCCESS` après une remise réussie), erreurs
  et paniques avalées.
- Options : `debug` (une ligne syslog par étape, sans secret) ; `ask`,
  `rundir=`, `iterations=` servent aux essais.

Côté utilisateur : `mymfa seal` scelle à la demande (avec la clé reçue à la
connexion), `mymfa seal --forget` renonce (sceau effacé, plus de sceau
automatique jusqu'au prochain `mymfa seal`).

Le sel de la clé de session est `SHA-256("mymfa:linux:seal-salt:v1" ‖ 0 ‖
machine-id ‖ 0 ‖ uid ‖ 0 ‖ nom)` : déterministe, pour que le module PAM (root)
n'ait pas à lire le dossier personnel. Changer de `machine-id` périme le sceau
(déverrouillage manuel, puis nouveau sceau).

## Interface D-Bus pour hyprdesk

Bus de session, nom **`today.mindlog.MyMfa1`**, objet
**`/today/mindlog/MyMfa1`**, interface **`today.mindlog.MyMfa1`**. Le démon
est activable par le bus (premier appel = démarrage).

### Méthodes

| Méthode | Signature | Rôle |
|---|---|---|
| `Unlock(s password)` | `s → ()` | Déverrouille avec le mot de passe du coffre. Scelle au passage si une clé de session attend. |
| `Lock()` | `() → ()` | Verrouille : DEK, comptes, logins et trousseau quittent la mémoire. |
| `Codes()` | `() → a(sssssuub)` | Codes en cours : `(id, émetteur, compte, tag, code, secondes_restantes, période, favori)`. HOTP : code du compteur enregistré, `période = 0`, `restantes = 0`. |
| `SearchLogins(s query)` | `s → a(sssss)` | Logins : `(id, titre, hôte, adresse, identifiant)` ; recherche insensible à la casse dans titre, adresse, identifiant ; vide = tous. Jamais de mot de passe. |
| `CopyCode(s id)` | `s → ()` | Copie le code en cours d'un compte (wl-copy). |
| `CopyLogin(s id, s field)` | `ss → ()` | `field` = `password` (marqué sensible, effacé après 30 s s'il est toujours là) ou `username`. |
| `Seal(s password)` | `s → ()` | Scelle le mot de passe du coffre par la clé de session reçue (vérifie le mot de passe, déverrouille au besoin). |
| `ForgetSeal()` | `() → ()` | Efface le sceau et désactive le sceau automatique. |
| `ImportSecret(s collection, s collection_label, s label, a{ss} attributes, ay secret, s content_type)` | `sssa{ss}ays → o` | Écrit un secret dans le trousseau local (reprise de gnome-keyring) ; remplace l'élément aux mêmes attributs. |

### Propriétés (lecture seule, `PropertiesChanged` émis)

| Propriété | Type | Sens |
|---|---|---|
| `Locked` | `b` | Coffre verrouillé. |
| `VaultPresent` | `b` | Un coffre existe (`mymfa init` sinon). |
| `Sealed` | `b` | Déverrouillage à la connexion en place. |
| `SessionKey` | `b` | Une clé de session attend : le prochain déverrouillage scellera. |
| `SecretService` | `b` | Le démon tient `org.freedesktop.secrets` (sinon : autre service, en file). |
| `Version` | `s` | Version du démon. |

### Signaux

| Signal | Signature | Quand |
|---|---|---|
| `StateChanged(b locked)` | `b` | Après chaque verrouillage ou déverrouillage, quelle qu'en soit la voie (Unlock, PAM, pinentry, Lock du Secret Service). |
| `UnlockRequested(s application)` | `s` | Une application a besoin du coffre verrouillé (Prompt du Secret Service). `application` = nom du processus demandeur (`/proc/PID/comm`), vide si inconnu. hyprdesk affiche son invite et répond par `Unlock` ; l'invite se termine d'elle-même au `StateChanged(false)`. |

### Erreurs (`today.mindlog.MyMfa1.Error.*`)

`WrongPassword`, `NoVault`, `Corrupted`, `Locked`, `NotFound`,
`NoSessionKey` (Seal sans connexion par pam_mymfa), `Failed` — chacune avec un
message en français affichable.

### Invite de déverrouillage

Tant que hyprdesk n'a pas la sienne (LIN-04), le démon ouvre en plus un
`pinentry` de repli à chaque `UnlockRequested` (3 essais). Pour que hyprdesk
réponde seul : `MYMFA_PINENTRY=none` (unit systemd, ligne commentée prévue).
`MYMFA_PINENTRY=/chemin/pinentry-xxx` choisit le programme.

## Secret Service : couverture

- `Service` : `OpenSession`, `CreateCollection`, `SearchItems`, `Unlock`,
  `Lock`, `GetSecrets`, `ReadAlias`, `SetAlias`, propriété `Collections`,
  signaux `CollectionCreated/Deleted/Changed`.
- `Collection` : `Delete`, `SearchItems`, `CreateItem` (avec `replace`),
  propriétés `Items`, `Label` (écriture), `Locked`, `Created`, `Modified`,
  signaux `ItemCreated/Deleted/Changed` (émis aussi sur les chemins d'alias).
- `Item` : `Delete`, `GetSecret`, `SetSecret`, propriétés `Locked`,
  `Attributes` et `Label` (écriture), `Created`, `Modified`.
- `Session` : `plain` et `dh-ietf1024-sha256-aes128-cbc-pkcs7` ; `Close`.
- `Prompt` : `Prompt`, `Dismiss`, signal `Completed` — pour `Unlock` et pour
  `CreateCollection` coffre verrouillé.
- Alias `default` et `login` → collection `login` ; chemins
  `/org/freedesktop/secrets/aliases/<alias>` servis.
- Coffre verrouillé, `SearchItems` répond « verrouillé » (pas « rien ») grâce
  à un index d'empreintes salées des attributs, comme gnome-keyring : une
  application ne recrée pas sa clé par erreur.

## Limites et suites

- **Un seul verrou** pour toutes les collections (celui du coffre) : `Lock`
  d'un objet verrouille tout.
- Les sessions Secret Service ne sont pas fermées au départ du client
  (`NameOwnerChanged`) ; elles meurent avec le démon.
- Les logins du coffre sont en lecture seule côté Secret Service (le démon
  n'écrit jamais le coffre) ; les codes HOTP n'avancent pas leur compteur.
- Le coffre n'est pas synchronisé par ce client : il s'installe avec
  `mymfa init --from` (sauvegarde Drive du web) ; une synchronisation Drive
  ou depuis l'app Slint du bureau reste à faire.
- Écran de verrouillage (hyprlock) : la pile `auth` seule n'ouvre pas de
  session, donc ne remet pas de clé ; si hyprdesk verrouille aussi le coffre
  à l'écran de veille, il faudra une remise à l'authentification réussie
  (`pam_sm_setcred`) — à faire avec LIN-04.
- Si le coffre est recréé ailleurs (autre DEK), le trousseau local devient
  illisible : il est mis de côté (`mymfa-keyring.illisible-<date>.json`),
  intact, et un trousseau neuf prend sa place.
- Pas de collection persistante créée par `CreateCollection` avec un mot de
  passe propre (gnome-keyring en demande un) : toutes les collections
  partagent la clé du coffre.
