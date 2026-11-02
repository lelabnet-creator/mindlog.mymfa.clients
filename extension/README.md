# myMFA — extension navigateur (Chromium)

> Client « extension » de myMFA (voir le [README du dépôt](../README.md) pour les autres
> clients). Toutes les commandes ci-dessous se lancent depuis ce dossier `extension/`.

Extension Manifest V3, **autonome** : elle embarque l'app myMFA complète (comptes,
scanner, activité, mots de passe, coffre chiffré, passkeys, sauvegarde Google Drive),
ouverte dans un onglet par « Ouvrir myMFA » du popup. Sur les pages web, codes de
double authentification, mots de passe et passkeys des sites sont proposés par des
toasts. Aucune app hébergée n'est nécessaire ; celle de `https://app.mymfa.mindlog.today/`
peut être synchronisée en plus, si on l'utilise dans le même navigateur.

## Construire et charger

```sh
npm install
npm run build        # copie l'app et les modules partagés, génère les icônes, produit dist/mymfa-extension.zip
```

Puis `chrome://extensions` → **Mode développeur** → **Charger l'extension non empaquetée**
→ dossier `src/`. La page `extension.html` de l'app (Réglages › Installer
l'extension) explique la même chose aux utilisateurs et propose le zip.

L'extension n'a pas de modules à elle pour l'OTP, le coffre, la fusion, Drive,
WebAuthn ni les langues : `npm run build` les copie depuis l'app web (`../web/js/`)
dans `src/lib/`, avec la configuration de déploiement (`../web/js/config.js` →
`src/lib/config.js`), et copie l'app elle-même dans `src/app/`. On les modifie donc
dans `../web/`, puis on reconstruit.
Une langue ajoutée à l'app (`../web/js/locales/xx.js`) se déclare aussi ici : dans
la liste `COPIES` de `scripts/build.mjs`, dans les `content_scripts` de
`src/manifest.json` et dans `src/popup.html`.

## Structure

| Fichier | Rôle |
|---|---|
| `src/manifest.json` | Manifeste (MV3) : permissions, scripts de contenu |
| `src/background.js` | Service d'arrière-plan : stockage, coffre, synchronisation app et Drive |
| `src/content.js` | QR codes des pages, code demandé, pont avec l'onglet de l'app |
| `src/passwords.js` | Mots de passe des sites : remplissage, enregistrement |
| `src/webauthn-page.js`, `src/webauthn.js` | Passkeys des sites (monde de la page, puis relais) |
| `src/ui.js` | Toasts (shadow root fermé) |
| `src/popup.*` | Popup : comptes, déverrouillage, réglages, « Ouvrir myMFA » |
| `src/app-host.js` | Fait de l'app embarquée une page de l'extension : synchronisation, verrou partagé, jeton Drive |
| `src/_locales/` | Nom et description de l'extension (Chrome Web Store) |
| `src/app/`, `src/lib/`, `src/fonts/`, `src/icons/` | **Générés** par `npm run build` — ne pas modifier |
| `scripts/build.mjs` | Construction de l'extension et de son archive |
| `test/` | Tests `node --test` (textes de l'extension), scénarios e2e, pages de test |

## L'app embarquée

`src/app/index.html` est l'app web de `../web/`, telle quelle, plus `src/app-host.js`,
chargé avant `lock.js` et `app.js`. Ceux-ci le trouvent dans `window.MYMFA_HOST` ;
sans lui, sur l'app hébergée, ces points d'accroche ne font rien.

- **Mêmes données que le popup et les toasts.** La copie de l'app (son `localStorage`,
  celui de l'extension) et celle du service d'arrière-plan sont fusionnées par le même
  échange que pour une app hébergée (`content:sync`), mais par messages directs
  (`app:sync`) : une page de l'extension n'a pas de script de contenu. Les messages
  `app:*` ne sont acceptés que des pages de l'extension.
- **Un seul verrou.** Déverrouiller l'app (mot de passe ou passkey) déverrouille
  l'extension, et inversement ; verrouiller l'un verrouille l'autre. La clé passe d'un
  côté à l'autre seulement si elle ouvre le même coffre. Le délai de verrouillage
  automatique est celui de l'extension (le choisir dans l'app le change), et l'activité
  dans l'app le repousse : un onglet de l'app oublié ne verrouille donc pas l'extension
  en pleine navigation.
- **Passkeys du coffre** : elles fonctionnent dans la page de l'extension (WebAuthn avec
  PRF), liées à son identifiant (`rpId`). Celles créées sur l'app hébergée ne servent
  pas ici, ni l'inverse : le mot de passe maître reste toujours valable. Une extension
  non empaquetée change d'identifiant si on la charge depuis un autre dossier, et ses
  passkeys de coffre ne servent plus.
- **Google Drive** : pas de script Google distant, interdit en MV3. L'app demande son
  jeton au service d'arrière-plan (`chrome.identity`), et la console Google doit
  autoriser l'URI de redirection de l'extension (affichée dans les réglages de l'app et
  du popup), pas une origine JavaScript.
- **Import** (Proton Pass en CSV, Proton Authenticator en JSON, export myMFA, avec barre de
  progression) : popup → Réglages → Données → Importer ouvre
  l'app embarquée sur sa ligne Importer (`#/settings/import`, mise en évidence). Le choix
  d'un fichier fermerait le popup, d'où l'onglet. L'import passe ensuite par la
  synchronisation : les mots de passe arrivent chiffrés dans l'extension (coffre ouvert
  exigé, voir `../web/README.md`).
- **Onglet de l'app réutilisé** : le popup le retrouve par `chrome.runtime.getContexts`
  (sans la permission `tabs`, `chrome.tabs.query` ne donne pas les adresses).
- La rubrique « Installer l'extension » des réglages est masquée.

## Ce qu'elle fait

- **Sur les pages web** : repère les QR codes `otpauth://` (images, canvas, SVG). Compte
  déjà enregistré → carte avec le code, « Remplir le champ » et « Copier ». Nouveau
  compte → ajout avec tag et description. La carte vit dans un shadow root fermé ; le
  décodeur jsQR n'est injecté que si une image ressemble à un QR code.
- **Popup** : comptes du site ouvert en premier, recherche, copie, remplissage,
  « Scanner l'onglet » (capture de l'onglet visible), « Ouvrir myMFA » (l'app embarquée),
  réglages (repérage, remplissage, génération à l'inscription, import, app hébergée
  facultative, sauvegarde Drive, thème, langue, verrouillage automatique).
- **Vue « Tout » du popup** : un compte par ligne avec ses trois informations — code 2FA
  (copie au clic), mot de passe (copie), passkey (indicateur). Mot de passe, code et passkey
  vont ensemble quand l'identifiant est le même (`alice` ≈ `alice@exemple.fr`), ou quand le
  site n'en a qu'un de chaque. Filtres Tous / Favoris, recherche, et quatre affichages
  (retenus) : **par domaine** (un site, ses comptes par ordre alphabétique ; le site ouvert
  d'abord ; les adresses IP, v4 et v6, réunies dans une entrée « Adresses IP », par adresse), **récents** (dernier usage : mot de passe rempli ou copié, code affiché ou copié,
  passkey utilisée), **A → Z**, **par tag**.
- **Modifier** (crayon sur chaque ligne) : mot de passe (adresse, identifiant, mot de passe
  affiché à la demande ou régénéré, nom, note) et code 2FA (service, compte, description) de
  la ligne, son tag (commun au mot de passe et au code) et son statut de favori. Jamais la
  clé secrète d'un code. Messages `popup:updateLogin` / `popup:updateAccount`, champs filtrés.
- **Inscription** : sur un formulaire de création de compte ou de changement de mot de passe,
  toast « Mot de passe fort », généré selon les règles du site (`../web/js/passgen.js`) ; un
  clic remplit le mot de passe et sa confirmation, proposé ensuite à l'enregistrement.
- **Synchronisation** avec l'app embarquée, et avec une app hébergée si son adresse est
  réglée (vide par défaut) : dans les deux sens, par un pont actif seulement sur cette
  adresse (vérifiée par le service d'arrière-plan). Fusion par compte
  (`../web/js/sync.js`) : ajouts des deux côtés, version la plus récente, suppressions propagées.
- **Coffre chiffré** : l'extension ne stocke que le coffre chiffré et se déverrouille
  dans le popup (mot de passe maître) ou dans l'app embarquée (mot de passe ou passkey),
  **jamais dans une page web**. La clé vit dans `chrome.storage.session` (mémoire,
  inaccessible aux scripts de contenu).
- Les scripts de contenu ne reçoivent jamais de secret : seulement le code du compte
  correspondant au QR que la page affiche elle-même.

### Toasts : codes, mots de passe et passkeys

Tout passe par un toast en bas à droite de la page (`src/ui.js`), un seul à la
fois, du plus urgent au moins urgent : passkey, code demandé, enregistrement d'un mot
de passe, QR code, remplissage.

- **Code demandé** (`content.js`) : un champ « code à usage unique » apparaît et
  myMFA a un compte pour ce site → le code, l'anneau, « Remplir » et « Copier ».
- **Mots de passe** (`passwords.js`) : formulaire de connexion d'un site connu →
  « Se connecter à … », un clic remplit identifiant et mot de passe. Connexion ou
  inscription envoyée → « Enregistrer le mot de passe ? » (ou « Mettre à jour ») sur
  la page suivante, ou quand le formulaire disparaît ; identifiant modifiable,
  « Jamais pour ce site ». Connexions en deux écrans (identifiant puis mot de passe)
  reconnues. Formulaire encore là sur la page suivante : connexion sans doute refusée,
  rien n'est proposé.
- **Passkeys** (`webauthn-page.js` dans le monde de la page, `webauthn.js`) :
  `navigator.credentials.create/get` sont enveloppés. Création → « Créer une passkey
  pour … ? » ; connexion, y compris en saisie automatique (`mediation: 'conditional'`)
  → choix de la passkey myMFA du site. « Utiliser un autre appareil », fermeture du
  toast, aucune passkey myMFA pour le site, ou demande que myMFA ne sait pas traiter
  (PRF, largeBlob, clé de sécurité exigée, app myMFA elle-même) → la demande repart,
  inchangée, vers le navigateur. Clés ES256, attestation « none », compteur à 0 et
  drapeaux BE/BS (passkey synchronisée par l'app et Drive).
- **Coffre fermé ou absent** : le toast propose « Déverrouiller » ou « Créer mon
  coffre », qui ouvre le popup (le mot de passe maître ne se tape jamais dans une
  page) ; l'action demandée (enregistrement, passkey) reprend dès le coffre ouvert.
  Un coffre créé dans l'extension est transmis à l'app à la synchronisation suivante :
  elle le demandera au déverrouillage.

Garde-fous :

- mots de passe et passkeys n'existent que dans un coffre chiffré : l'app refuse de
  désactiver le chiffrement tant qu'il y en a, et la synchronisation ne repasse jamais
  en clair ;
- l'origine d'une demande est celle que donne Chrome (`sender.origin`), jamais celle
  que dit la page ; cadre principal uniquement ; un mot de passe ne part vers la page
  que pour son site (même origine, ou même site sans repasser de https à http) ;
- le code d'un compte « demandé par la page » reste dans le service d'arrière-plan :
  le script de contenu ne le reçoit qu'au clic (afficher, remplir, copier) — rien
  d'avance à une page qui imiterait un champ de vérification ;
- remplir, enregistrer, créer ou utiliser une passkey exige un vrai clic
  (`event.isTrusted`) dans le toast (shadow root fermé) ;
- les mots de passe saisis attendent « Enregistrer » en mémoire
  (`chrome.storage.session`, inaccessible aux scripts de contenu), 5 minutes au plus ;
- coffre fermé, seules des empreintes salées des sites connus restent lisibles, pour
  proposer « Déverrouiller » au bon endroit ; elles ne disent rien des comptes ;
- l'historique note l'ajout, la modification (champs seulement) ou la suppression d'un
  mot de passe ou d'une passkey, jamais leur valeur.
- un « site » est le domaine enregistrable (`Store.siteOf`) : les sous-domaines se
  regroupent (accounts.google.com → google.com), jamais deux voisins sous un suffixe
  public à plusieurs niveaux (impots.gouv.fr ≠ ameli.gouv.fr, alice.github.io ≠
  bob.github.io) ; la liste de ces suffixes est un extrait de la Public Suffix List.

Limites : formulaires et passkeys dans des iframes non pris en charge ; l'export JSON
de l'app ne contient que les comptes OTP (mots de passe et passkeys restent dans le
coffre chiffré et ses sauvegardes Drive).

## Sauvegarde et synchronisation par Drive

L'extension sauvegarde par le fichier Google Drive de l'app
([`../web/README.md`](../web/README.md#sauvegarde-google-drive)), sans que l'app soit ouverte :
Réglages de l'extension › Sauvegarde Google Drive › **Sauvegarder maintenant**. Elle récupère
la sauvegarde, la fusionne avec ses comptes (mêmes règles que la synchronisation avec
l'app) et renvoie le résultat sur Drive s'il apporte quelque chose. Drive vide : elle
y dépose son propre coffre, s'il est chiffré — jamais de données en clair. Verrouillée,
elle ne fusionne rien : elle demande le mot de passe de la sauvegarde.

**Sauvegarde automatique** (`driveEvery`) : désactivée, toutes les heures, 6 h, 12 h, tous
les jours (défaut), 3 jours, 7 jours — réglée dans le popup ou dans l'app embarquée. Après
une première sauvegarde réussie (de l'extension ou de l'app), elle est refaite sans fenêtre
Google quand elle est due : vérifiée toutes les 15 minutes (alarme) et après chaque
modification. Le popup et l'app affichent la dernière et la prochaine. Une sauvegarde faite
depuis l'app compte (`app:driveBackedUp`) ; l'identifiant client Google saisi d'un côté sert
de l'autre.

Configuration : le même identifiant client (`googleClientId` de `../web/js/config.js`, repris
par `npm run build`, ou saisi dans les réglages de l'extension). Dans Google Cloud, ajouter
à ses *URI de redirection autorisés* celle qu'affichent les réglages de l'extension,
`https://<id-de-l-extension>.chromiumapp.org/`. L'identifiant d'une extension non
empaquetée dépend de son dossier : il change si on la charge depuis un autre chemin.

## Tests

```sh
npm test             # chaque texte de l'extension existe dans les langues de l'app
```

De bout en bout :

```sh
(cd ../web && npm start)   # dans un autre terminal, pour les scénarios avec app hébergée
npm run test:e2e           # reconstruit l'extension, puis les trois scénarios
```

`test/e2e/app.e2e.mjs` (extension autonome, sans serveur : app embarquée ouverte depuis
le popup, synchronisation, verrou partagé dans les deux sens, passkey du coffre,
sauvegarde Drive par le jeton de l'extension, délai de verrouillage, rechargement),
`test/e2e/extension.e2e.mjs` (extension chargée dans un Chromium isolé avec une app hébergée :
synchronisation dans les deux sens, cartes QR, popup, coffre chiffré, Drive simulé) et
`test/e2e/credentials.e2e.mjs` (extension seule : mot de passe enregistré, coffre créé
dans le popup, remplissage, mise à jour, code demandé, passkey créée puis utilisée — y
compris en saisie automatique — et vérifiée comme le ferait un serveur, coffre fermé,
coffre transmis à l'app). Les pages de test (`test/fixtures/`) sont servies par le
scénario lui-même, sur leur propre origine : un site quelconque, distinct de l'app.
L'app hébergée est attendue sur `BASE_URL` (défaut `http://localhost:4173`), que ces
deux scénarios déclarent dans les réglages de l'extension ; Chromium est cherché dans le cache Playwright, ou via
`CHROMIUM=/chemin/vers/chrome`.
