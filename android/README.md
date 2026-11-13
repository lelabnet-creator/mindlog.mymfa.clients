# myMFA — Android

L'application Android native de myMFA : interface [Slint](https://slint.dev) en
Rust, cœur métier répliqué depuis l'app web. Tickets Plane : épique AND
(AND-02 pour ce socle, AND-03 pour la vue Mots de passe).

## Ce que contient ce socle (jalon 1)

- **Cœur Rust (`crates/mymfa-core`)** — compatible octet pour octet avec
  `../web/js/` :
  - OTP : base32 (mêmes tolérances), HOTP/TOTP (RFC 4226/6238), parsing et
    construction des URI `otpauth://` avec les sémantiques JavaScript exactes
    (`parseInt` tolérant, sérialisation `URLSearchParams`, `encodeURIComponent`) ;
  - coffre chiffré : AES-256-GCM, PBKDF2-SHA256 (1 000 000 d'itérations,
    mot de passe normalisé NFC), AAD par rôle, enveloppes passkey (HKDF-SHA256) —
    un coffre écrit par l'app web ou l'extension s'ouvre ici, et inversement ;
  - fusion `sync.js` (tombstones, `updatedAt`, déduplication par identité,
    historique plafonné, réglages `mymfa.settings.v1`) ;
  - synchro v2 (SYN-07) : fusion champ par champ par horloge hybride
    (`sync2.rs`, réplique fidèle de `../web/js/sync2.js`), heure de référence
    T() (`temps.rs`, SYN-08 — la sonde NTS reste derrière la fonctionnalité
    cargo `nts`, que l'app n'active pas encore), écritures du Store
    tamponnées (SYN-12) ;
  - modèle de données `store.js` (comptes, historique, tags, export/import),
    textes FR/EN (fonction cargo `texts`, active par défaut ; le client
    `../linux/` la désactive et se construit sans Node).
- **Application Slint (`crates/mymfa-app`)** — les vues du socle :
  - écran de verrouillage (création du coffre avec jauge de solidité,
    déverrouillage, ralentissement exponentiel après 3 échecs) ;
  - vue **Codes** : cartes avec code en direct, décompte, favoris, copie au
    toucher (toast + presse-papiers), filtres Tous/Favoris/tags, recherche ;
  - **Nouveau compte** : clé base32 ou URI `otpauth://`, vérification et
    aperçu du code actuel, tag, description, options avancées (TOTP/HOTP,
    algorithme, chiffres, période, compteur) ;
  - **Réglages** : thème auto/clair/sombre, langue FR/EN, masquage des codes,
    verrouillage automatique (1/5/15/60 min/jamais), changement de mot de passe.
- **Verrouillage automatique** (défaut 5 min, comme le web) et **persistance**
  (`mymfa-vault.json`, même contenu que la sauvegarde Drive du web) dans le
  stockage interne de l'app.

## Vue Mots de passe (jalon 2, AND-03)

Miroir de `web/js/credentials.js` : mots de passe et passkeys des sites, dans
le coffre chiffré, jamais hors coffre.

- **Cœur** (`mymfa-core`) : modèle `Login` et `SitePasskey` (`mymfa.logins.v1`,
  `mymfa.passkeys.v1`, mêmes clés et champs JSON que le web), CRUD fidèles
  (`addLogin`/`updateLogin`/`removeLogin`, passkey remplacée par compte du
  site, journal sans jamais y écrire un mot de passe), rattachement site↔compte
  (`siteOf`, `accountMatchesHost`, hôtes ignorés et suffixes multi-parties
  repris de `store.js`), générateur sans biais de `credentials.js`
  (`passgen.rs` : caractères ou phrase de syllabes).
- **UI** (`credentials.slint`) : onglets Tout/Mots de passe/Passkeys avec
  compteurs, « Récemment utilisés » (3 derniers, 30 jours), recherche, tuiles
  à initiales et puces 2FA/Passkey ; détail par site (mot de passe masqué puis
  révélé, code 2FA du site en direct, passkeys datées, métadonnées) ;
  éditeur plein écran avec générateur (longueur, familles, phrase) et jauge
  de solidité ; suppression armée en deux pressions.
- **Preuve d'interopérabilité réelle** : un coffre créé par l'APK sur
  l'émulateur (avec un login) se déchiffre avec le `vault.js` du web — clés,
  champs et journal identiques ; `npm test` rejoue l'interop dans les deux
  sens.

## Jalons suivants

Caméra/QR (JNI), Tableau de bord (HIBP), Activité, sauvegarde Drive (OAuth),
Credential Manager/autofill (AND-01, passerelle JNI/Kotlin), déverrouillage
par passkey (PRF). Les onglets concernés affichent « Bientôt ».

## Structure

| Chemin | Rôle |
|---|---|
| `Cargo.toml` | Workspace (`mymfa-core`, `mymfa-app`) |
| `package.json` | Scripts : `gen` (textes + fixtures), `test`, `interop`, `run`, `android` |
| `scripts/sync-locales.mjs` | Convertit `../web/js/locales/{fr,en}.js` en Rust (web/ reste la source unique, les copies ne se versionnent pas — comme l'extension) |
| `scripts/make-fixtures.mjs` | Chiffre des coffres de test **avec le vrai `vault.js`** et calcule des fusions attendues avec le vrai `sync.js` |
| `scripts/interop-check.mjs` | Vérifie qu'un coffre écrit par Rust s'ouvre avec `vault.js` (sens inverse) |
| `crates/mymfa-core/src/` | `otp`, `otpauth`, `vault`, `sync`, `sync2`, `temps`, `store`, `passgen`, `texts` (généré) |
| `crates/mymfa-core/tests/` | Vecteurs RFC 4226/6238, interop coffre et fusion (fixtures générées) |
| `crates/mymfa-app/ui/` | `common.slint` (palette, i18n, icônes, composants), `lock`, `home`, `credentials`, `new`, `settings`, `main` |
| `crates/mymfa-app/src/` | `backend.rs` (état, ticker des codes, auto-lock, vue Mots de passe), `storage.rs` (fichiers, thread d'écriture) |
| `crates/mymfa-app/manifest.yaml` | Identité xbuild : paquet `today.mindlog.mymfa`, label myMFA, icône |
| `crates/mymfa-app/assets/` | Manrope (police du web, OFL) et l'icône |

## Prérequis

- **Rust** via [rustup](https://rustup.rs) avec les cibles
  `rustup target add aarch64-linux-android x86_64-linux-android` ;
- **SDK Android** (`ANDROID_HOME`) et un NDK ;
- **[xbuild](https://github.com/rust-mobile/xbuild)** (le `x` de Slint,
  installé depuis git : `cargo install --git https://github.com/rust-mobile/xbuild.git`) ;
- **Node** (pour générer textes et fixtures depuis `../web/`).

## Commandes

Tout se lance depuis `android/` :

```sh
npm run gen        # textes FR/EN + fixtures d'interopérabilité (requis avant le premier build)
npm test           # gen + cargo test + interop-check.mjs
npm run interop    # sens Rust → web uniquement
npm run run        # application sur le bureau (itération rapide de l'UI)

# APK debug (émulateur x86_64) :
x build --manifest-path crates/mymfa-app/Cargo.toml --platform android --arch x64 --format apk
# APK release (appareil arm64) :
x build --manifest-path crates/mymfa-app/Cargo.toml --platform android --arch arm64 --format apk --release

x run --manifest-path crates/mymfa-app/Cargo.toml --platform android --arch x64 --device adb:<série>
```

Sorties : `target/x/{debug,release}/android/mymfa-app.apk`. Sur l'appareil,
les journaux Slint : `adb logcat -s slint`.

## Interopérabilité, preuve continue

`npm test` rejoue chaque campagne : vecteurs RFC officiels, coffres réellement
chiffrés par `web/js/vault.js` ouverts en Rust, fusions attendues calculées par
`web/js/sync.js` reproduites à l'identique, et coffre écrit par Rust ouvert par
le `vault.js` du web (mot de passe, passkey PRF, re-chiffrement). L'APK embarque
exactement ce cœur.

## Divergences v1 (documentées)

- Le coffre est **obligatoire** dès le premier lancement (le web permet un mode
  « clair » sans coffre) : l'Android est pensé sauvegarde/interop Drive.
- Thème « Auto » = sombre en attendant la lecture du réglage système (pont
  natif AND-01).
- Presse-papiers via le `TextInput` interne de Slint (voie officielle, backend
  Android inclus) ; le toast confirme toujours la copie. Le web vide le
  presse-papiers 30 s après la copie d'un mot de passe : impossible sans pont
  natif, le secret y reste jusqu'à la prochaine copie.
- Les inserts système (barre d'état, clavier) ne sont pas encore lus : hauteur
  fixe raisonnable (`Theme.safe-top`) et champs atteignables — un pont d'inserts
  viendra avec AND-01.
- « Générer » hors éditeur (bloc autonome du web) suit le jalon autofill
  (AND-01) ; le générateur complet est dans l'éditeur.
- `xbuild` épingle un NDK plafonné à l'API 33 (`targetSdkVersion 33`).
