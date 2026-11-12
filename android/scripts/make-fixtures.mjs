/*
 * Produit les fixtures d'interopérabilité : des coffres réellement chiffrés par
 * web/js/vault.js et des fusions attendues calculées par web/js/sync.js. Les
 * tests Rust (crates/mymfa-core/tests/) les rejouent : un coffre écrit par le
 * web doit s'ouvrir en Rust, et la fusion Rust doit rendre exactement ce que
 * rend la fusion web.
 *
 *   node scripts/make-fixtures.mjs     (depuis android/, itérations PBKDF2 réduites)
 */
import { createRequire } from 'node:module';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const Vault = require(join('..', '..', 'web', 'js', 'vault.js'));
const Sync = require(join('..', '..', 'web', 'js', 'sync.js'));
const Sync2 = require(join('..', '..', 'web', 'js', 'sync2.js'));
const outDir = join(here, '..', 'crates', 'mymfa-core', 'tests', 'fixtures');

const FAST = { iterations: 1000 };
const DATA = {
  'mymfa.accounts.v1': JSON.stringify([
    { id: 'a1', type: 'totp', issuer: 'GitHub', account: 'moi@example.net', secret: 'JBSWY3DPEHPK3PXP', algorithm: 'SHA1', digits: 6, period: 30, counter: 0, tag: 'travail', description: '', favorite: true, createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z' },
  ]),
  'mymfa.history.v1': '[]',
  'mymfa.deleted.v1': '{"accounts":{},"historyClearedAt":null}',
  'mymfa.settings.v1': JSON.stringify({ policy: { value: { minLength: 12 }, at: '2026-02-01T00:00:00.000Z' } }),
};

const prfOutput = Buffer.alloc(32, 7);
const prfSalt = Buffer.alloc(32, 3);

async function vaultFixtures() {
  const simple = await Vault.create('correct horse battery', DATA, FAST);
  // Mot de passe avec accent décomposé (NFD) : la dérivation doit normaliser en NFC.
  const decomposed = 'mot de passe accentue\u0301 suffisamment long';
  const nfc = await Vault.create(decomposed, DATA, FAST);
  const withPasskey = await Vault.addPasskey(simple.record, simple.dek, {
    id: 'cred-fixture', name: 'Clé de test', prfSalt, prfOutput,
  });
  return {
    iterations: FAST.iterations,
    data: DATA,
    decomposedPassword: decomposed,
    prfOutput: prfOutput.toString('base64'),
    records: {
      simple: simple.record,
      decomposed: nfc.record,
      withPasskey,
    },
  };
}

function account(id, secret, issuer, createdAt, updatedAt, extra = {}) {
  return { id, type: 'totp', issuer, account: 'moi@example.net', secret, algorithm: 'SHA1', digits: 6, period: 30, counter: 0, tag: '', description: '', favorite: false, createdAt, updatedAt, ...extra };
}

function history(id, at) {
  return { id, at, action: 'create', accountId: id, label: 'Test — moi@example.net', tag: '', details: { source: 'qr' } };
}

function syncCases() {
  const NOW = '2026-11-05T12:00:00.000Z';
  const wrap = (items) => JSON.stringify(items);
  const cases = [
    {
      name: 'union-simple',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01')]) },
      right: { 'mymfa.accounts.v1': wrap([account('a2', 'JBSWY3DPEHPK3PXPZ', 'OVH', '2026-02-01', '2026-02-01')]) },
    },
    {
      name: 'conflit-updatedAt',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-03-01', { tag: 'vieux-quete' })]) },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01')]) },
    },
    {
      name: 'egalite-updatedAt-premier-vu-gagne',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01', { description: 'côté gauche' })]) },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01', { description: 'côté droit' })]) },
    },
    {
      name: 'tombstone-le-cote-droit-ne-ranimme-pas',
      left: {
        'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01')]),
        'mymfa.deleted.v1': JSON.stringify({ accounts: { a1: '2026-06-01T00:00:00.000Z' }, historyClearedAt: null }),
      },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-07-01')]) },
    },
    {
      name: 'doublon-par-identite',
      left: { 'mymfa.accounts.v1': wrap([account('recent', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-05-01', '2026-05-01')]) },
      right: { 'mymfa.accounts.v1': wrap([account('ancien', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01')]) },
    },
    {
      name: 'usedAt-fusionne-sans-compter',
      left: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-01-01', { usedAt: '2026-06-01T00:00:00.000Z' })]) },
      right: { 'mymfa.accounts.v1': wrap([account('a1', 'JBSWY3DPEHPK3PXP', 'GitHub', '2026-01-01', '2026-02-01', { usedAt: '2026-03-01T00:00:00.000Z' })]) },
    },
    {
      name: 'historique-vidage-et-plafond',
      left: {
        'mymfa.history.v1': wrap(
          Array.from({ length: 20 }, (_, i) => history(`h${i}`, `2026-10-${String(i + 1).padStart(2, '0')}T00:00:00.000Z`)),
        ),
      },
      right: {
        'mymfa.history.v1': wrap([history('gauche-seulement', '2026-09-01T00:00:00.000Z')]),
        'mymfa.deleted.v1': JSON.stringify({ accounts: {}, historyClearedAt: '2026-10-05T00:00:00.000Z' }),
      },
    },
    {
      name: 'reglages-le-plus-recent-gagne',
      left: { 'mymfa.settings.v1': JSON.stringify({ policy: { value: { minLength: 12 }, at: '2026-01-01T00:00:00.000Z' }, prefs: { value: { theme: 'dark' }, at: '2026-05-01T00:00:00.000Z' } }) },
      right: { 'mymfa.settings.v1': JSON.stringify({ policy: { value: { minLength: 16 }, at: '2026-06-01T00:00:00.000Z' }, prefs: { value: { theme: 'light' }, at: '2026-03-01T00:00:00.000Z' } }) },
    },
    {
      name: 'collections-absentes-des-deux-cotes',
      left: { 'mymfa.accounts.v1': '[]' },
      right: {},
    },
    {
      name: 'logins-et-passkeys-fusionnes',
      left: {
        'mymfa.logins.v1': JSON.stringify([
          { id: 'l1', origin: 'https://github.com', username: 'moi', password: 'x', title: '', note: '', tag: '', source: '', createdAt: '2026-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z', passwordChangedAt: '2026-01-01T00:00:00.000Z' },
        ]),
      },
      right: {
        'mymfa.passkeys.v1': JSON.stringify([
          { id: 'p1', credentialId: 'c1', rpId: 'example.com', rpName: 'Example', origin: 'https://example.com', userHandle: 'u1', userName: 'moi', userDisplayName: 'Moi', algorithm: -7, privateKey: 'k', createdAt: '2026-02-01T00:00:00.000Z', updatedAt: '2026-02-01T00:00:00.000Z' },
        ]),
      },
    },
  ];
  return {
    now: NOW,
    cases: cases.map((c) => ({ ...c, expected: Sync.merge(c.left, c.right, NOW) })),
  };
}

/* ───── Synchro v2 (SYN-07) : fusions calculées par web/js/sync2.js, rejouées
 * par crates/mymfa-core/tests/sync2_interop.rs. Chaque cas donne l'état initial
 * de l'appareil (horloge, repère), les deux copies et le résultat attendu (les
 * deux côtés comparent le JSON parsé : l'ordre des clés n'engage pas). Les
 * rapports ne sont comparés que sur les genres d'entrées — leurs textes portent
 * l'heure de la fusion. */
const T2 = 1794405900000; // 2026-11-11T14:05:00.000Z
const MINUT_MS = 60000;

function stamp(l, c, appareil) {
  return Sync2.encoderTampon(l, c, appareil);
}

function compte2(id, issuer, date, extra = {}) {
  return {
    id, type: 'totp', issuer, account: 'moi@example.net', secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA1', digits: 6, period: 30, counter: 0, tag: '', description: '',
    favorite: false, createdAt: date, updatedAt: date, ...extra,
  };
}

/** Éditer un champ d'une copie v2 : tampon = horloge de l'appareil, plafonné au
 * tampon actuel du champ (même règle que l'app). */
function editer(copieLocale, id, champ, valeur, tampon) {
  const items = JSON.parse(copieLocale['mymfa.accounts.v1']);
  const item = items.find((a) => a.id === id);
  item[champ] = valeur;
  item.h = { ...(item.h || {}), [champ]: tampon };
  item.updatedAt = Sync2.isoDepuisTampon(
    Object.values(item.h).reduce((a, b) => (b > a ? b : a), '')
  );
  copieLocale['mymfa.accounts.v1'] = JSON.stringify(items);
}

function sync2Cases() {
  const maintenant = T2;
  const debut = { l: T2 - MINUT_MS, c: 0 };
  const cases = [];
  const ajouter = (nom, locale, distante, etat, construire) => {
    // La fusion JS calcule le résultat attendu ; `construire` peut vérifier des
    // attentes supplémentaires (genres de rapport, traces) sur place.
    const e = { appareil: 'pc', horloge: { ...debut, ...etat?.horloge }, repere: etat?.repere || '' };
    // Description de l'appareil (SYN-09) : facultative, citée dans le cas si posée.
    const description = etat?.type ? { type: etat.type, ...(etat.nom ? { nom: etat.nom } : {}) } : {};
    const { donnees, rapport } = Sync2.fusion(locale, distante, { appareil: e.appareil, horloge: new Sync2.Horloge(e.horloge.l), repere: e.repere, ...description }, maintenant);
    if (e.horloge.c !== undefined) { /* l'horloge d'entrée est citée telle quelle */ }
    const cas = {
      name: nom,
      locale,
      distante,
      etat: { appareil: e.appareil, horloge: e.horloge, repere: e.repere, ...description },
      maintenant,
      attendu: donnees,
      aEnvoyer: rapport.aEnvoyer,
      genres: rapport.entrees.map((x) => x.genre).sort(),
    };
    if (construire) construire(cas, rapport);
    cases.push(cas);
    return cas;
  };

  // Deux copies v1 (avant migration) : union par id, champ le plus récent gagne.
  ajouter(
    'v2-union-simple',
    { 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) },
    { 'mymfa.accounts.v1': JSON.stringify([compte2('a2', 'OVH', '2026-02-01T00:00:00.000Z')]) },
  );

  // Copies déjà migrées : deux champs édités des deux côtés → les deux survivent.
  {
    const locale = Sync2.migrer(
      { 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) },
      maintenant, 'pc'
    );
    const distante = Sync2.migrer(
      { 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) },
      maintenant, 'tel'
    );
    editer(locale, 'a1', 'tag', 'travail', stamp(T2, 1, 'pc'));
    editer(distante, 'a1', 'description', 'perso', stamp(T2, 1, 'tel'));
    ajouter('v2-deux-champs-en-parallele', locale, distante);
  }

  // Le même champ des deux côtés : le plus grand tampon gagne, conflit signalé.
  {
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'pc');
    const distante = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'tel');
    editer(locale, 'a1', 'issuer', 'Côté PC', stamp(T2 + MINUT_MS, 0, 'pc'));
    editer(distante, 'a1', 'issuer', 'Côté téléphone', stamp(T2, 0, 'tel'));
    ajouter('v2-conflit-meme-champ', locale, distante, null, (cas) => {
      if (!cas.genres.includes('conflit')) throw new Error('conflit attendu');
    });
  }

  // Suppression d'un côté, modification plus récente de l'autre : ça revit.
  {
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'pc');
    const distante = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'tel');
    const items = JSON.parse(locale['mymfa.accounts.v1']);
    items[0].t = stamp(T2, 1, 'pc');
    locale['mymfa.accounts.v1'] = JSON.stringify(items);
    editer(distante, 'a1', 'description', 'clé de secours', stamp(T2 + 2 * MINUT_MS, 0, 'tel'));
    ajouter('v2-modifie-apres-suppression', locale, distante, null, (cas) => {
      const item = JSON.parse(cas.attendu['mymfa.accounts.v1'])[0];
      if (!Sync2.estVivant(item)) throw new Error('la modification postérieure fait revivre');
    });
  }

  // HOTP : valeur maximale, quel que soit le tampon.
  {
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([{ ...compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z'), counter: 5 }]) }, maintenant, 'pc');
    const distante = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([{ ...compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z'), counter: 2, updatedAt: '2026-06-01T00:00:00.000Z' }]) }, maintenant, 'tel');
    ajouter('v2-compteur-hotp-max', locale, distante, null, (cas) => {
      const item = JSON.parse(cas.attendu['mymfa.accounts.v1'])[0];
      if (item.counter !== 5) throw new Error('le compteur maximal doit gagner');
    });
  }

  // Doublons de même identité : fusion champ par champ, le plus ancien fait foi,
  // l'autre enterré dans le marqueur.
  {
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([{ ...compte2('nouveau', 'GitHub', '2026-06-01T00:00:00.000Z'), tag: 'travail' }]) }, maintenant, 'pc');
    const distante = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([{ ...compte2('ancien', 'GitHub', '2026-01-01T00:00:00.000Z'), description: 'perso' }]) }, maintenant, 'tel');
    ajouter('v2-doublons-fusionnes', locale, distante, null, (cas) => {
      const ids = JSON.parse(cas.attendu['mymfa.accounts.v1']).map((a) => a.id);
      if (ids.join() !== 'ancien') throw new Error(`doublons : attendu [ancien], eu [${ids}]`);
      const marqueur = Sync2.lireMarqueur(cas.attendu);
      if (!marqueur.v1.nouveau) throw new Error('le doublon doit être enterré dans le marqueur');
    });
  }

  // Tampon reçu dans le futur : contenu accepté, genres de rapport signalés.
  {
    const locale = {};
    const distante = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'tel');
    editer(distante, 'a1', 'issuer', 'Du futur', stamp(T2 + 365 * 24 * 60 * MINUT_MS, 3, 'tel'));
    ajouter('v2-tampon-futur-journalise', locale, distante, null, (cas) => {
      if (!cas.genres.includes('horloge')) throw new Error("l'horloge suspecte doit être journalisée");
    });
  }

  // Élagage : trace vue par tous les appareils enregistrés et rétention écoulée
  // (31 jours > 30) — la trace doit aussi être plus récente que tous les champs.
  {
    const il_y_a_31_jours = T2 - 31 * 24 * 60 * MINUT_MS;
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'pc');
    const items = JSON.parse(locale['mymfa.accounts.v1']);
    items[0].t = stamp(il_y_a_31_jours, 1, 'tel');
    locale['mymfa.accounts.v1'] = JSON.stringify(items);
    locale[Sync2.SYNC_KEY] = JSON.stringify({
      sync: 'v2',
      appareils: { pc: { vu: stamp(T2, 5, 'pc'), actifLe: maintenant }, tel: { vu: stamp(T2, 5, 'tel'), actifLe: maintenant } },
      historiqueVideLe: null,
    });
    const distante = JSON.parse(JSON.stringify(locale));
    ajouter('v2-trace-vue-partout-elaguee', locale, distante, null, (cas) => {
      const items2 = JSON.parse(cas.attendu['mymfa.accounts.v1']);
      if (items2.length !== 0) throw new Error('la trace vue partout doit élaguer');
    });
  }

  // Trace récente : gardée même vue partout (rétention de 30 jours).
  {
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'pc');
    const items = JSON.parse(locale['mymfa.accounts.v1']);
    items[0].t = stamp(T2 - MINUT_MS, 1, 'tel');
    locale['mymfa.accounts.v1'] = JSON.stringify(items);
    locale[Sync2.SYNC_KEY] = JSON.stringify({
      sync: 'v2',
      appareils: { pc: { vu: stamp(T2, 5, 'pc'), actifLe: maintenant }, tel: { vu: stamp(T2, 5, 'tel'), actifLe: maintenant } },
      historiqueVideLe: null,
    });
    const distante = JSON.parse(JSON.stringify(locale));
    ajouter('v2-trace-recente-gardee', locale, distante, null, (cas) => {
      const items2 = JSON.parse(cas.attendu['mymfa.accounts.v1']);
      if (items2.length !== 1) throw new Error('la trace récente doit être gardée pour se propager');
    });
  }

  // Registre décrit (SYN-09) : chaque côté porte une description différente de
  // « tel » (la plus récente activité fait foi), « pc » à l'ancienne forme se
  // décrit à la fusion ; l'historique garde l'appareil auteur de chaque entrée.
  {
    const evenement = (id, at, appareil) => ({
      id, at, action: 'create', accountId: 'a1', label: 'GitHub — moi@example.net', tag: null, details: null, appareil,
    });
    const locale = Sync2.migrer({ 'mymfa.accounts.v1': JSON.stringify([compte2('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]) }, maintenant, 'pc');
    const distante = JSON.parse(JSON.stringify(locale));
    locale[Sync2.SYNC_KEY] = JSON.stringify({
      sync: 'v2',
      appareils: { pc: stamp(T2 - 9 * MINUT_MS, 0, 'pc'), tel: { vu: stamp(T2 - 9 * MINUT_MS, 0, 'tel'), actifLe: T2 - 3 * MINUT_MS, type: 'android', nom: 'ancien nom' } },
      historiqueVideLe: null,
    });
    distante[Sync2.SYNC_KEY] = JSON.stringify({
      sync: 'v2',
      appareils: { tel: { vu: stamp(T2 - 2 * MINUT_MS, 0, 'tel'), actifLe: T2 - 2 * MINUT_MS, type: 'android', nom: 'Pixel' }, lin: { vu: stamp(T2 - 5 * MINUT_MS, 0, 'lin'), actifLe: T2 - 5 * MINUT_MS, type: 'linux' } },
      historiqueVideLe: null,
    });
    locale['mymfa.history.v1'] = JSON.stringify([evenement('h1', '2026-11-11T13:00:00.000Z', 'pc')]);
    distante['mymfa.history.v1'] = JSON.stringify([evenement('h2', '2026-11-11T13:30:00.000Z', 'tel')]);
    ajouter('v2-registre-decrit-et-historique-source', locale, distante, { type: 'web', nom: 'Firefox · Linux' }, (cas) => {
      const appareils = JSON.parse(cas.attendu[Sync2.SYNC_KEY]).appareils;
      if (appareils.tel.nom !== 'Pixel' || appareils.pc.type !== 'web' || appareils.lin.type !== 'linux' || 'nom' in appareils.lin) {
        throw new Error('registre décrit inattendu');
      }
      const historique = JSON.parse(cas.attendu['mymfa.history.v1']);
      if (historique.map((h) => h.appareil).join() !== 'tel,pc') throw new Error("l'historique doit garder l'appareil auteur");
    });
  }

  return { maintenant, cases };
}

mkdirSync(outDir, { recursive: true });
const vault = await vaultFixtures();
writeFileSync(join(outDir, 'vault-web.json'), `${JSON.stringify(vault, null, 2)}\n`);
const sync = syncCases();
writeFileSync(join(outDir, 'sync-web.json'), `${JSON.stringify(sync, null, 2)}\n`);
const sync2 = sync2Cases();
writeFileSync(join(outDir, 'sync2-web.json'), `${JSON.stringify(sync2, null, 2)}\n`);
console.log(
  `fixtures : vault-web.json (3 coffres), sync-web.json (${sync.cases.length} cas de fusion), sync2-web.json (${sync2.cases.length} cas de fusion v2)`
);
