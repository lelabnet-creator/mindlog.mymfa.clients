# myMFA — Android

L'application Android de myMFA. Dossier réservé, aucun code pour l'instant.

L'application web de référence, et le comportement à reproduire, sont dans
[`../web/`](../web/README.md).

## Choix technique : Slint (Rust)

L'interface native est écrite en [Slint](https://slint.dev), en Rust, sur la
cible Android (`android-activity`). Ticket Plane : AND-02 (épique AND).

Ce que le socle devra tenir :

- **Cœur Rust partagé** : OTP (RFC 4226 / 6238), coffre compatible octet pour
  octet avec `../web/js/vault.js` (AES-256-GCM, PBKDF2-SHA256 à 1 000 000
  d'itérations, données additionnelles par rôle), fusion de `../web/js/sync.js`
  (clés `Sync.KEYS`, y compris les réglages `mymfa.settings.v1`). Vérifié contre
  les mêmes vecteurs que l'app web : un coffre sauvegardé sur Drive par l'app ou
  l'extension doit s'ouvrir ici, et inversement.
- **Interface Slint** : les mêmes vues que l'app web (Codes, Scanner, Mots de
  passe, Tableau de bord, Activité, Réglages), mêmes textes FR/EN.
- **Point à cadrer** : fournir mots de passe et passkeys aux autres applications
  passe par l'API Credential Manager (AND-01), hors de portée de Slint seul — une
  passerelle JNI/Kotlin sera nécessaire.
