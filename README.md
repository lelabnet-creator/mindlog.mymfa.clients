# myMFA — clients

Les clients de myMFA, le générateur de codes de double authentification de la
suite mindlog.today. Un sous-dossier par client :

| Dossier | Contenu |
|---|---|
| [`web/`](web/README.md) | L'application web (100 % navigateur). C'est elle que sert `https://app.mymfa.mindlog.today/`. |
| [`extension/`](extension/README.md) | L'extension Chromium, autonome : elle embarque l'app web complète, et propose codes, mots de passe et passkeys sur les sites. |
| [`android/`](android/README.md) | L'application Android native, en Slint (Rust) : cœur partagé compatible octet pour octet avec le web (coffre, fusions v1 et v2), vue Codes, vue Mots de passe (logins et passkeys des sites), ajout manuel, réglages. |
| [`linux/`](linux/README.md) | Le trousseau du bureau Linux, alternative à gnome-keyring (Rust) : démon `mymfa` qui tient le Secret Service sur le même coffre, le modifie comme le web et le synchronise par Google Drive (cycle v2, heure de référence NTS), interface D-Bus pour hyprdesk, CLI, module PAM `pam_mymfa` qui ouvre le coffre à la connexion. |

Chaque client est autonome : ses dépendances, ses scripts et ses tests vivent
dans son dossier, et les commandes s'y lancent (`cd web && npm start`).
Une exception, voulue : l'app web est la seule source des modules communs
(OTP, coffre, fusion, Drive, WebAuthn, langues). L'extension les recopie depuis
`web/` à sa construction, avec l'app elle-même. Deux de ses scénarios de bout en
bout attendent en plus l'app hébergée, servie par `web/`.
De même, le client Linux ne réplique pas le coffre : il réutilise le cœur Rust
d'Android (`android/crates/mymfa-core`, en dépendance de chemin). La synchro v2
du coffre — fusion champ par champ par horloge hybride, registre des appareils,
journal de synchro — vit dans deux cœurs jumeaux : ce cœur Rust (Android et
démon Linux), et son miroir JavaScript côté web (`js/sync2.js`, cycle Drive
commun `js/drivesync.js`) que l'extension recopie avec les autres modules.

## Déploiement

Ce dépôt construit des images ; `LeLab-infra` les déploie. L'image de l'app
web, `mfa-web`, sert aussi l'archive de l'extension. Elle se construit donc
depuis la **racine** du dépôt, avec le `Dockerfile` de `web/`
(`docker build -f web/Dockerfile .`, exclusions dans `.dockerignore`), par la
pile `mymfa.mindlog.today.app` (son `images.tsv`). Voir `INFRA.md`, généré par
LeLab-infra.
