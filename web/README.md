# myMFA — application web

> Client web de myMFA (voir le [README du dépôt](../README.md) pour les autres
> clients). Toutes les commandes ci-dessous se lancent depuis ce dossier `web/`.

Générateur de codes OTP (TOTP/HOTP) 100 % navigateur : aucun serveur, aucune
dépendance au runtime, données stockées dans le `localStorage` du navigateur.

## Fonctionnalités

Interface mobile d'abord (navigation du bas Accueil · Scanner · Activité · Réglages),
barre latérale à partir de 900 px. Maquette de référence :
https://claude.ai/artifact/Cq8EHnmZw48Yk7RciHfwjG

- **Scanner** : caméra (détection continue, jsQR), import d'image, collage d'une
  capture (bouton ou Ctrl+V n'importe où), glisser-déposer. Tout est décodé localement.
- **Ajout par clé** : clé base32 (espaces/minuscules tolérés) ou URI `otpauth://`.
- **Nouveau compte** : vérification du service et du compte, tag (existant ou nouveau),
  description, et **code actuel affiché** pour confirmer l'activation sur le site.
- **Accueil** : cartes avec code, anneau de décompte, copie au toucher, favoris (étoile),
  filtres Tous / Favoris / par tag, recherche (touche `/` sur bureau).
- TOTP SHA1/SHA256/SHA512, 6–8 chiffres, période libre ; HOTP avec bouton « code suivant ».
- **Activité** : historique groupé par jour, filtrable — ajouts (source QR / lien / clé),
  modifications (avant → après), suppressions, copies, imports/exports. 500 entrées max.
- **Réglages** : thème Auto / Clair / Sombre, langue, masquage des codes,
  export / import JSON.
- **Import d'autres gestionnaires** (Réglages → Importer) : Proton Pass (CSV), Proton
  Authenticator (JSON), avec barre de progression. Voir plus bas.
- **Coffre chiffré** : mot de passe maître et passkeys, verrouillage automatique.
- **Mots de passe et passkeys des sites** (vue « Mots de passe ») : liste (récemment
  utilisés, puis tous les sites, filtre Tout / Mots de passe / Passkeys) et détail du site
  avec ce qui en dépend — identifiant, mot de passe (affiché ou copié à la demande), code
  du compte 2FA du même site en direct, passkeys. Sur bureau côte à côte, sur mobile un
  écran par site (`#/passwords/<id>`). Éditeur avec générateur (longueur, chiffres,
  symboles ou phrase de syllabes) et jauge de solidité ; tout reste dans le coffre chiffré.
- **Tableau de bord** (`#/dashboard` ; sur mobile, depuis Activité) : chiffres clés, usage sur
  30 jours, santé des mots de passe (hors politique, réutilisés, à renouveler, compromis),
  vérification des fuites et politique de mots de passe. Voir plus bas.
- **Synchronisation Google Drive** du coffre chiffré (synchro v2, fusion champ par champ),
  et restauration.
- **Espace Synchro** (`#/sync` ; sur mobile, depuis Activité) : appareils et types de
  clients, chronologie des ajouts / modifications / suppressions avec leur source, journal
  des synchros. Voir plus bas.
- **i18n** : français et anglais, détection de la langue du navigateur, choix mémorisé.
- Police Manrope hébergée localement (aucune requête vers un tiers).

## Lancer

```sh
npm start            # http://localhost:4173, rechargement à chaud (autre port : PORT=5000 npm start)
```

Le serveur de dev (`scripts/dev-server.mjs`, sans dépendance) surveille les
fichiers : une modification de CSS est appliquée à chaud sans recharger la page,
tout autre changement recharge la page. `npm run serve:static` lance un simple
serveur statique sans rechargement.

Le calcul HMAC utilise Web Crypto, qui exige un contexte sécurisé : `https://`
ou `http://localhost`. Ouvrir `index.html` en `file://` fonctionne aussi dans
Chrome/Firefox.

## Tests

```sh
npm install
npm test
```

Couvre : vecteurs officiels RFC 4226 / RFC 6238 (SHA1/256/512), parsing
`otpauth://`, aller-retour QR (génération → décodage jsQR), store localStorage,
et cohérence i18n (mêmes clés dans toutes les langues, aucune clé utilisée
manquante, chaque code d'erreur traduit).

## Structure

| Fichier | Rôle |
|---|---|
| `index.html` | Page unique à 6 vues (routage par hash `#/scan`…) ; textes via `data-i18n` |
| `css/style.css` | Styles mobile-first, thèmes auto / clair / sombre (variables CSS) |
| `js/otp.js` | base32, HOTP, TOTP, parsing/génération d'URI `otpauth://` |
| `js/store.js` | Comptes, mots de passe, passkeys des sites, historique (sur `Lock.storage`) |
| `js/credentials.js` | Vue « Mots de passe » : liste, ajout, générateur, passkeys |
| `js/importers.js` | Import d'autres gestionnaires (Proton Pass CSV, Proton Authenticator JSON) : analyse, puis ajout sans doublon |
| `js/passgen.js` | Mot de passe généré selon la politique d'un site (`passwordrules`, `minlength` / `maxlength` / `pattern`, texte d'aide), utilisé par l'extension |
| `js/webauthn.js` | Authentificateur WebAuthn logiciel (ES256, attestation « none ») de l'extension |
| `js/audit.js` | Politique de mots de passe, analyse du coffre, statistiques d'usage, Have I Been Pwned (k-anonymat) |
| `js/dashboard.js` | Vue « Tableau de bord » |
| `js/vault.js` | Cryptographie du coffre (AES-GCM, PBKDF2, HKDF/PRF) |
| `js/lock.js` | Verrouillage, mot de passe maître, passkeys, réglages de sécurité |
| `js/drive.js` | Client Google Drive (appDataFolder) et jeton OAuth |
| `js/config.js` | Configuration de déploiement (identifiant client Google) |
| `js/sync.js` | Fusion de deux copies des données (app ↔ extension) |
| `extension.html` | Page d'installation de l'extension |
| `js/i18n.js` | Moteur i18n (interpolation `{x}`, pluriels `Intl.PluralRules`) |
| `js/locales/*.js` | Dictionnaires (`fr`, `en`) |
| `js/app.js` | Contrôleur de l'interface |
| `vendor/jsQR.js` | Décodeur QR (jsQR 1.4, Apache-2.0), copié par `npm run vendor` |
| `vendor/fonts/` | Manrope variable (OFL-1.1), copiée par `npm run vendor` |
| `scripts/dev-server.mjs` | Serveur de dev avec rechargement à chaud |
| `test/` | Tests `node --test`, et le scénario de bout en bout du coffre (`test/e2e/`) |

### Ajouter une langue

1. Copier `js/locales/en.js` en `js/locales/xx.js`, remplacer `'en'` par `'xx'` et traduire.
2. Ajouter `<script src="js/locales/xx.js"></script>` dans `index.html`.
3. `npm test` vérifie qu'aucune clé ne manque.

## Import depuis un autre gestionnaire

Réglages → Importer accepte, à côté des exports myMFA (JSON), les exports d'autres
gestionnaires ; le format se reconnaît à l'en-tête d'un CSV ou à la forme d'un JSON
(`js/importers.js`).

**Proton Pass** (Paramètres → Exporter → CSV) :
`type,name,url,autofillUrls,email,username,password,note,totp,createTime,modifyTime,vault`.

| Colonne Proton | myMFA |
|---|---|
| `type` | seuls les `login` sont repris ; notes, alias, cartes, identités sont ignorés |
| `url`, sinon `autofillUrls` | origine du site (première adresse web ; `exemple.fr` → `https://exemple.fr`) ; sans adresse web, le mot de passe est ignoré |
| `username`, sinon `email` | identifiant |
| `password`, `name`, `note` | mot de passe, titre, note |
| `totp` (URI `otpauth://` ou clé seule) | compte 2FA ; service et compte repris de l'URI, sinon du nom et de l'identifiant |
| `createTime`, `modifyTime`, `vault` | non repris |

- Les mots de passe n'entrent que dans un **coffre chiffré et ouvert**. Coffre en clair : les
  comptes 2FA sont importés, les mots de passe comptés et signalés (activer le mot de passe
  maître, puis réimporter).
- Doublons ignorés : même site et même identifiant pour un mot de passe (l'existant est gardé),
  même clé, service et compte pour un compte 2FA. Réimporter le même fichier n'ajoute rien.
- L'historique trace l'import et chaque ajout (« Via import Proton Pass »), jamais un mot de passe.
- Le CSV est en clair : le message de fin rappelle de le supprimer.

**Proton Authenticator** (export **non chiffré**, JSON) :
`{ "version": 1, "entries": [{ "id", "content": { "uri", "entry_type", "name" }, "note" }] }`.

| Champ | myMFA |
|---|---|
| `content.uri` (`otpauth://`) | compte 2FA : service, compte, clé, algorithme, chiffres, période |
| `content.name` | compte, si l'URI n'en donne pas |
| `note` | description |
| `content.entry_type: "Steam"` | ignoré et signalé : les codes Steam Guard ne sont pas des TOTP standard |

Un export chiffré par mot de passe n'est pas reconnu (« Format non reconnu »).

**Progression** : sous la ligne Importer, une barre suit l'ajout (mise à jour tous les 20
éléments, la page se redessine entre deux), puis le chiffrement du coffre ; la ligne est
inactive pendant l'import. Les écritures du coffre en rafale sont regroupées (`Lock`, un seul
chiffrement en attente) : un import de 300 éléments ne rechiffre pas le coffre 600 fois.

Ajouter un format : une entrée dans `FORMATS` (`headers` exigés pour un CSV, `matches` et
`items` pour un JSON ; conversion d'un élément en `{ login, account, ignored }` ; `passwords`
s'il apporte des mots de passe), un libellé `history.source.<id>` et un test dans
`test/importers.test.js`.

## Tableau de bord

- **Chiffres** : comptes 2FA (et tags), mots de passe (dont ceux dont le site a aussi un compte
  2FA), passkeys, et une **note de santé** : la part des mots de passe sans aucun problème connu.
- **Usage sur 30 jours** : événements de l'historique par jour (survol : le jour et son nombre) et
  par action. L'historique étant dans le coffre, les statistiques suivent ses sauvegardes.
- **Santé** : mots de passe **hors politique**, **réutilisés** (même valeur sur plusieurs entrées),
  **à renouveler** (plus vieux que la durée fixée : date du dernier changement du mot de passe,
  `passwordChangedAt`, sinon de création) et **compromis**. Chaque ligne se déplie sur les sites
  concernés, vers leur fiche.
- **Politique** (`js/audit.js`) : longueur minimale (8 à 32), majuscules et minuscules, chiffres,
  symboles, solidité minimale (la jauge `Vault.passwordStrength`), renouvellement (jamais, 30, 90,
  180 ou 365 jours). Elle sert à l'audit et au **générateur** (longueur et familles garanties) ;
  elle conseille, sans jamais bloquer.
- **Fuites** :
  - **Have I Been Pwned** (Pwned Passwords), sur un clic : pour chaque mot de passe distinct, seuls
    les 5 premiers caractères de son empreinte SHA-1 partent vers `api.pwnedpasswords.com/range/`,
    avec l'en-tête `Add-Padding` ; la réponse (des centaines de suffixes) est comparée ici. Le
    mot de passe ni son empreinte complète ne quittent l'appareil. La CSP (`nginx.conf`) autorise
    ce seul hôte en plus de Google.
  - **Mozilla Monitor** et **Google Password Checkup** n'ont pas d'API publique (le premier vérifie
    des adresses e-mail, le second les mots de passe du compte Google) : de simples liens, myMFA
    ne leur transmet rien.

### Ce que le coffre emporte

Le coffre — donc la sauvegarde Drive, l'export chiffré et la synchronisation avec l'extension —
contient : comptes 2FA, mots de passe, passkeys des sites, suppressions, **historique** (source des
statistiques d'usage) et **réglages** (`mymfa.settings.v1`, `{ nom → { value, at } }`, fusionnés par
nom, le plus récent l'emporte) :

- `policy` : la politique du tableau de bord ;
- `breaches` : le dernier résultat de Have I Been Pwned, par mot de passe et lié à la date de ce
  mot de passe (le changer invalide son résultat) ; jamais de valeur ni d'empreinte ;
- `prefs` : copie des préférences en clair (thème, langue, masquage des codes, délai de
  verrouillage, identifiant client Google). Elles restent en clair, lues avant le déverrouillage ;
  au déverrouillage — après une restauration notamment — la copie du coffre les remplace si elle
  est plus récente que leur dernier changement local (`mymfa.prefsAt`, une date seule).

Seuls restent hors du coffre : la date de dernière modification et de dernière sauvegarde, la
proposition de passkey reportée, et le coffre remplacé gardé pour « Annuler la restauration ».
L'export **JSON** en clair, lui, ne contient que les comptes 2FA et l'historique : il sert à migrer.

## Code 2FA d'un site

Un compte 2FA est rattaché à un site (vue Mots de passe, toasts et popup de l'extension, codes
qu'une page peut proposer) par son **service** seulement : « GitHub » ↔ github.com, « OVH » ↔
ovhcloud.com (`Store.accountMatchesHost`). Jamais par l'identifiant ni la description : une
adresse `jacques@…` ne doit pas rattacher un compte à tous les sites dont l'adresse contient
« jacques ». Les morceaux génériques d'une adresse (`mail`, `cloud`, `web`…) ne comptent pas ;
un compte sans service n'est rattaché à aucun site.

## Sécurité : mot de passe maître et passkeys

Réglages › Sécurité › **Activer** chiffre les comptes et l'historique :

- une **clé de coffre** AES-256-GCM aléatoire chiffre les données (`mymfa.vault.v1`) ;
- elle est elle-même chiffrée par chaque moyen de déverrouillage :
  - **mot de passe maître** → PBKDF2-SHA256, 1 000 000 d'itérations, sel aléatoire
    (au-delà des 600 000 recommandés par OWASP : la sauvegarde Drive est
    brute-forçable hors ligne, et ce coût n'est payé qu'au déverrouillage) ;
  - **passkey** → extension WebAuthn **PRF** → HKDF-SHA256. Un passkey sans PRF
    ne peut pas chiffrer : il est refusé (message explicite) ;
- chaque bloc chiffré est lié à son rôle (données additionnelles AES-GCM) : un bloc
  substitué ou altéré est rejeté ;
- changer de mot de passe ne rechiffre que la clé de coffre : les passkeys restent valides ;
- le mot de passe maître fait au moins **10 caractères** ; une **jauge de solidité**
  (estimation partagée, `Vault.passwordStrength`) conseille la saisie dans l'app
  comme dans l'extension, sans jamais bloquer ;
- verrouillage manuel ou automatique (1 à 60 min d'inactivité) : la clé et les données
  déchiffrées sont effacées de la mémoire ;
- copier un mot de passe vide le presse-papiers 30 s plus tard, si l'onglet a
  encore le focus ;
- **aucune récupération possible** sans le mot de passe ni un passkey : « Mot de passe
  oublié ? » sur l'écran de verrouillage réinitialise le coffre (tout est effacé, après
  confirmation ; une extension encore déverrouillée recopie ses comptes dans l'app).

Les mots de passe et passkeys des sites **n'existent que dans le coffre** : l'app
refuse de les enregistrer hors chiffrement (boutons fermés, écriture refusée au
niveau du stockage) et, au démarrage, toute donnée sensible restée en clair aux
côtés d'un coffre existant est effacée (crash pendant l'activation, par exemple).

Restent en clair dans `localStorage`, car nécessaires avant le déverrouillage et sans
contenu sensible : thème, langue, masquage des codes, délai de verrouillage, date
de dernière modification et de dernière sauvegarde.

Passkeys : uniquement en `https://` ou sur `http://localhost` (pas sur une adresse IP),
avec un authentificateur compatible PRF (Chrome/Edge récents avec gestionnaire de
passkeys ou Windows Hello, Safari 18+, clés de sécurité FIDO2 récentes).

⚠️ L'**export JSON** reste un export en clair (pour migrer vers une autre app) :
préférez **Exporter le coffre chiffré** (Réglages › Données, coffre déverrouillé),
qui télécharge le coffre tel quel — réimportable par le même chemin, ou la
sauvegarde Google Drive, chiffrée elle aussi.

## Sauvegarde Google Drive

Le coffre **chiffré** (jamais de clair) vit dans le dossier caché `appDataFolder` du
Drive, fichier `mymfa-vault.json` : scope `drive.appdata`, l'app ne voit que ses propres
fichiers, et ce dossier n'apparaît pas dans l'interface de Google Drive.

**Synchroniser** (Réglages › Synchronisation Google Drive, ou l'espace Synchro) conduit
le cycle v2 (`js/drivesync.js`, le même que le démon Linux) : lire la copie Drive en
notant sa version, l'ouvrir avec la clé du coffre, fusionner champ par champ
(`js/sync2.js`), écrire en local, envoyer si la fusion apporte quelque chose après avoir
revérifié que Drive n'a pas bougé (sinon relire et refusionner). Une copie d'un **autre
coffre** (autre clé) n'est jamais fusionnée : **Restaurer** permet de l'adopter — elle
remplace le coffre local puis verrouille, il faut son mot de passe ; tant qu'elle n'a pas
été déverrouillée, **Annuler la restauration** rétablit le coffre précédent. Synchro
automatique au déverrouillage et peu après chaque modification, seulement si Drive a déjà
servi et qu'un jeton Google est en mémoire (jamais de fenêtre Google imprévue). Le tout
nécessite le mot de passe maître.

## Espace Synchro

`#/sync` (`js/syncview.js`) montre :

- **l'état** : dernière synchro, changements en attente, fichier Drive, heure de
  référence (vérifiée par la réponse de Drive à un envoi, sinon horloge de l'appareil) ;
- **les appareils** : le registre v2 du coffre — chaque client s'y décrit (`web`,
  `extension`, `linux`, `android`, et un nom : « Chrome · Linux », le nom d'hôte…),
  dernière activité connue, couverture, éléments dont il a fait la dernière
  modification ;
- **la chronologie** : l'historique (ajouts, modifications avec les champs, suppressions)
  avec l'appareil source de chaque entrée, filtrable ;
- **le journal de synchro** : chaque cycle de cet appareil (et de l'arrière-plan de
  l'extension) — reçus et envoyés avec leur auteur et leur date, conflits (valeur gardée
  et écartée), doublons, horloges suspectes. Chiffré par la clé du coffre, jamais
  synchronisé ; mots de passe, clés et notes n'y sont jamais écrits.

Configuration (une fois) :

1. [Google Cloud Console](https://console.cloud.google.com/) → créer un projet →
   *API et services* → activer **Google Drive API**.
2. *Écran de consentement OAuth* : type « Externe », ajouter le scope
   `.../auth/drive.appdata` et votre compte comme utilisateur test.
3. *Identifiants* → **ID client OAuth** → « Application Web » → *Origines JavaScript
   autorisées* : `http://localhost:4173` et l'URL de production.
4. Coller l'identifiant client dans Réglages › Sauvegarde Google Drive (mémorisé dans ce
   navigateur), ou le fixer pour tout le déploiement dans `js/config.js`
   (`googleClientId`, prioritaire). Ce n'est pas un secret.

Le script de connexion Google (`accounts.google.com/gsi/client`) n'est chargé qu'au
premier clic sur un bouton Drive.

### L'extension et la sauvegarde Drive

L'extension sait se synchroniser par ce même fichier, sans que l'app soit ouverte : voir
[`../extension/README.md`](../extension/README.md#synchronisation-par-drive).

Côté app, **Restaurer** remplace toujours le coffre local par la sauvegarde : ce que
l'extension y a fusionné arrive donc dans l'app par une restauration, ou directement
par la synchronisation d'onglet.

## Extension navigateur

L'extension Chromium est un client à part : [`../extension/`](../extension/README.md).
Elle est autonome : elle embarque cette app tout entière (copiée à sa construction,
avec les modules de `js/`), et peut en plus se synchroniser avec l'app hébergée ouverte
dans un onglet. Embarquée, l'app trouve l'extension dans `window.MYMFA_HOST` : verrou
partagé (`lock.js`), jeton Drive par `chrome.identity` au lieu du script Google
(`app.js`). Sans lui, ces points d'accroche ne font rien. L'app hébergée n'en garde que
`extension.html`, la page d'installation, et l'archive qu'elle propose
(`/dist/mymfa-extension.zip`) : le serveur de dev la prend dans `../extension/dist/`,
l'image la construit.

## Tests de bout en bout

```sh
npm start            # dans un autre terminal
npm run test:e2e
```

`test/e2e/vault.e2e.mjs` pilote un Chromium isolé (profil temporaire, via `playwright-core`) avec un
authentificateur WebAuthn virtuel compatible PRF : activation du mot de passe maître,
verrouillage, mauvais mot de passe, passkey, changement de mot de passe, rechargement,
sauvegarde et restauration Drive (API Google simulée), désactivation. Chromium est
cherché dans le cache Playwright, ou via `CHROMIUM=/chemin/vers/chrome`.
`test/e2e/dashboard.e2e.mjs` vérifie le tableau de bord (chiffres, santé, politique, Have I Been
Pwned simulé : préfixes seuls, avec remplissage), puis recopie le coffre sur un « autre appareil » :
politique, résultats de fuite, historique et thème reviennent au déverrouillage.
`test/e2e/import.e2e.mjs` importe un CSV Proton Pass sans puis avec coffre chiffré, un gros CSV
(barre de progression), réimporte, puis importe un JSON Proton Authenticator.

Les scénarios de l'extension (avec l'app) sont dans `../extension/test/e2e/`.
