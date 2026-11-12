/*
 * Synchro v2 avec Drive (SYN-10) : deux appareils du même coffre (même clé) se
 * synchronisent par un faux Drive — premier envoi, réception, ajouts / modifications /
 * suppressions attribués à leur appareil, conflits (valeurs sensibles masquées), autre
 * coffre refusé, course détectée puis rattrapée.
 */
const test = require('node:test');
const assert = require('node:assert');
const Sync2 = require('../js/sync2.js');
const Vault = require('../js/vault.js');
const Store = require('../js/store.js');
const DriveSync = require('../js/drivesync.js');

const T0 = 1_794_405_900_000;
const MINUT = 60_000;

function fauxDrive() {
  let fichier = null;
  let version = 0;
  const drive = {
    lectures: 0,
    avantRelecture: null, // crochet : modifier Drive entre la lecture et la revérification
    contenu: () => fichier && fichier.content,
    async find() {
      if (drive.avantRelecture && drive.lectures === 1) {
        const crochet = drive.avantRelecture;
        drive.avantRelecture = null;
        await crochet();
      }
      drive.lectures += 1;
      return fichier ? { id: 'f1', name: 'mymfa-vault.json', size: String(fichier.content.length), createdTime: '2026-11-11T14:00:00.000Z', modifiedTime: fichier.modifiedTime, headRevisionId: `r${version}` } : null;
    },
    async download() {
      return { content: fichier.content, modifiedTime: fichier.modifiedTime };
    },
    async upload(content) {
      version += 1;
      fichier = { content, modifiedTime: new Date(T0 + version * 1000).toISOString() };
      return { id: 'f1', name: 'mymfa-vault.json', size: String(content.length), modifiedTime: fichier.modifiedTime, headRevisionId: `r${version}` };
    },
  };
  return drive;
}

function memoire() {
  const carte = new Map();
  return { getItem: (k) => (carte.has(k) ? carte.get(k) : null), setItem: (k, v) => carte.set(k, String(v)), removeItem: (k) => carte.delete(k) };
}

const horloge = { t: T0 };

function appareil(nom, dek, drive) {
  let map = {};
  const journal = [];
  const temps = Sync2.etatPersistant(memoire(), () => horloge.t, { type: 'web', nom });
  map = Sync2.migrer(map, 0, temps.appareil);
  const coffre = {
    donnees: () => ({ ...map }),
    dechiffrerAutre: (record) => Vault.decryptData(dek, record.data),
    remplacerDonnees: async (m) => {
      map = { ...m };
    },
    exporter: async () => JSON.stringify({ v: 2, password: { fictif: true }, passkeys: [], data: await Vault.encryptData(dek, map) }),
    ajouterJournal: async (e) => {
      journal.unshift(e);
    },
  };
  const stockage = { getItem: (k) => (k in map ? map[k] : null), setItem: (k, v) => (map[k] = String(v)), removeItem: (k) => delete map[k] };
  const store = Store.createStore(stockage, temps);
  const sync = DriveSync.creer({ client: drive, coffre, temps, maintenant: () => horloge.t });
  return { temps, store, journal, sync, donnees: () => map };
}

const cle = () => crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
const vivants = (a) => a.store.list().map((c) => c.issuer).sort();

test('premier envoi, puis réception attribuée à son appareil', async () => {
  horloge.t = T0;
  const drive = fauxDrive();
  const dek = await cle();
  const pc = appareil('PC', dek, drive);
  const tel = appareil('Tel', dek, drive);
  pc.store.add({ issuer: 'GitHub', account: 'moi', secret: 'JBSWY3DPEHPK3PXP' });

  const premier = await pc.sync.cycle();
  assert.strictEqual(premier.resultat, 'premier');
  assert.deepStrictEqual(premier.totaux.envoyes, { ajout: 1, modification: 0, suppression: 0 });
  assert.strictEqual(premier.envoyes[0].appareil, pc.temps.appareil);
  assert.ok(drive.contenu(), 'coffre déposé sur Drive');

  horloge.t += MINUT;
  const recu = await tel.sync.cycle();
  assert.deepStrictEqual(vivants(tel), ['GitHub']);
  assert.strictEqual(recu.recus[0].action, 'ajout');
  assert.strictEqual(recu.recus[0].libelle, 'GitHub — moi');
  assert.strictEqual(recu.recus[0].appareil, pc.temps.appareil, 'la source est le PC');
  // Le registre décrit les deux appareils (SYN-09).
  const registre = JSON.parse(tel.donnees()[Sync2.SYNC_KEY]).appareils;
  assert.strictEqual(registre[pc.temps.appareil].nom, 'PC');
  assert.strictEqual(registre[tel.temps.appareil].type, 'web');
  assert.strictEqual(tel.journal.length, 1);
});

test('ajouts, modifications et suppressions croisés, chacun avec son auteur', async () => {
  horloge.t = T0;
  const drive = fauxDrive();
  const dek = await cle();
  const pc = appareil('PC', dek, drive);
  const tel = appareil('Tel', dek, drive);
  const gh = pc.store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  const gl = pc.store.add({ issuer: 'GitLab', secret: 'JBSWY3DPEHPK3PXQ' });
  await pc.sync.cycle();
  horloge.t += MINUT;
  await tel.sync.cycle();

  horloge.t += MINUT;
  tel.store.update(gh.id, { issuer: 'GitHub Pro' });
  tel.store.remove(gl.id);
  tel.store.add({ issuer: 'Proton', secret: 'JBSWY3DPEHPK3PXR' });
  const envoi = await tel.sync.cycle();
  assert.strictEqual(envoi.resultat, 'envoye');
  assert.deepStrictEqual(envoi.totaux.envoyes, { ajout: 1, modification: 1, suppression: 1 });

  horloge.t += MINUT;
  const reception = await pc.sync.cycle();
  assert.deepStrictEqual(vivants(pc), ['GitHub Pro', 'Proton']);
  const par = Object.fromEntries(reception.recus.map((c) => [c.action, c]));
  assert.deepStrictEqual(par.modification.champs, ['issuer']);
  for (const c of reception.recus) assert.strictEqual(c.appareil, tel.temps.appareil, `${c.action} : auteur Tel`);
  assert.strictEqual(par.suppression.libelle, 'GitLab');
  // Rien de nouveau : un cycle de plus ne change rien et n'envoie rien.
  horloge.t += MINUT;
  const calme = await pc.sync.cycle();
  assert.strictEqual(calme.resultat, 'aJour');
});

test('conflit : journalisé avec le gagnant, valeur sensible jamais écrite', async () => {
  horloge.t = T0;
  const drive = fauxDrive();
  const dek = await cle();
  const pc = appareil('PC', dek, drive);
  const tel = appareil('Tel', dek, drive);
  const login = pc.store.addLogin({ origin: 'https://example.net', username: 'moi', password: 'depart-commun' });
  await pc.sync.cycle();
  horloge.t += MINUT;
  await tel.sync.cycle();
  horloge.t += MINUT;
  pc.store.updateLogin(login.id, { title: 'Exemple (PC)', password: 'AAAAAAAAAAAAAAAA' });
  horloge.t += MINUT;
  tel.store.updateLogin(login.id, { title: 'Exemple (Tel)', password: 'BBBBBBBBBBBBBBBB' });
  await tel.sync.cycle();
  horloge.t += MINUT;
  const res = await pc.sync.cycle();
  const parChamp = Object.fromEntries(res.conflits.map((c) => [c.champ, c]));
  assert.strictEqual(parChamp.title.gagnant.valeur, 'Exemple (Tel)');
  assert.strictEqual(parChamp.title.gagnant.appareil, tel.temps.appareil);
  assert.strictEqual(parChamp.title.perdant.valeur, 'Exemple (PC)');
  assert.strictEqual(parChamp.title.collection, 'logins');
  assert.deepStrictEqual(parChamp.password.perdant, { masque: true });
  assert.strictEqual(parChamp.password.gagnant.masque, true);
  const texte = JSON.stringify(pc.journal);
  assert.ok(!texte.includes('AAAAAAAAAAAAAAAA') && !texte.includes('BBBBBBBBBBBBBBBB'), 'aucun mot de passe dans le journal');
});

test('autre coffre sur Drive : pas de fusion, journalisé', async () => {
  horloge.t = T0;
  const drive = fauxDrive();
  const pc = appareil('PC', await cle(), drive);
  const autre = appareil('Autre', await cle(), drive);
  pc.store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  await pc.sync.cycle();
  autre.store.add({ issuer: 'Autre', secret: 'JBSWY3DPEHPK3PXQ' });
  await assert.rejects(autre.sync.cycle(), { code: 'driveOtherVault' });
  assert.deepStrictEqual(vivants(autre), ['Autre'], 'rien fusionné');
  assert.strictEqual(autre.journal[0].resultat, 'autreCoffre');
});

test('Drive modifié pendant le cycle : relu, refusionné, rien de perdu', async () => {
  horloge.t = T0;
  const drive = fauxDrive();
  const dek = await cle();
  const pc = appareil('PC', dek, drive);
  const tel = appareil('Tel', dek, drive);
  pc.store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  await pc.sync.cycle();
  horloge.t += MINUT;
  await tel.sync.cycle();
  horloge.t += MINUT;
  pc.store.add({ issuer: 'Proton', secret: 'JBSWY3DPEHPK3PXR' });
  tel.store.add({ issuer: 'GitLab', secret: 'JBSWY3DPEHPK3PXQ' });
  drive.lectures = 0;
  drive.avantRelecture = () => tel.sync.cycle(); // Tel envoie pendant le cycle du PC
  const res = await pc.sync.cycle();
  assert.strictEqual(res.tour, 2, 'deuxième tour après la course');
  assert.deepStrictEqual(vivants(pc), ['GitHub', 'GitLab', 'Proton']);
  horloge.t += MINUT;
  await tel.sync.cycle();
  assert.deepStrictEqual(vivants(tel), ['GitHub', 'GitLab', 'Proton']);
});

test('changements : ignore les dernières utilisations', () => {
  const temps = { tampon: () => Sync2.encoderTampon(T0, 0, 'pc'), appareil: 'pc' };
  const map = {};
  const stockage = { getItem: (k) => (k in map ? map[k] : null), setItem: (k, v) => (map[k] = String(v)), removeItem: (k) => delete map[k] };
  const store = Store.createStore(stockage, temps);
  const c = store.add({ issuer: 'GitHub', secret: 'JBSWY3DPEHPK3PXP' });
  const avant = { ...map };
  store.touchAccount(c.id);
  assert.deepStrictEqual(DriveSync.changements(avant, map), []);
});
