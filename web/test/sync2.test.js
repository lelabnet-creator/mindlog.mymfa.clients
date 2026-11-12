/*
 * Synchro v2 (SYN-07) : mêmes scénarios que crates/mymfa-core/src/sync2.rs —
 * horloge hybride, fusion champ par champ, suppressions datées, migration, les
 * cinq scénarios du simulateur, pas de résurrection, élagage après rétention.
 * L'interopérabilité JS ↔ Rust est couverte par les fixtures sync2-web.json
 * (rejouées en Rust) et sync2-rust.json (générées en Rust, rejouées ici).
 */
const test = require('node:test');
const assert = require('node:assert');
const Sync2 = require('../js/sync2.js');
const Store = require('../js/store.js');

const T0 = 1_794_405_900_000; // 2026-11-11T14:05:00.000Z
const MINUT = 60_000;

const compte = (id, issuer, date) => ({
  id,
  type: 'totp',
  issuer,
  account: 'moi@example.net',
  secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA1',
  digits: 6,
  period: 30,
  counter: 0,
  tag: '',
  description: '',
  favorite: false,
  createdAt: date,
  updatedAt: date,
});

const copie = (items) => ({ [Store.ACCOUNTS_KEY]: JSON.stringify(items) });

const valeur = (map, id, champ) => {
  const item = JSON.parse(map[Store.ACCOUNTS_KEY] || '[]').find((a) => a.id === id);
  return item ? (item[champ] ?? null) : null;
};

const ids = (map) => JSON.parse(map[Store.ACCOUNTS_KEY] || '[]').map((a) => a.id);

/* ─── Tampons : ordre, encodage, ISO ─── */

test("l'ordre des tampons est (l, c, D)", () => {
  const a = Sync2.encoderTampon(1000, 0, 'a1b2');
  const b = Sync2.encoderTampon(1000, 1, 'a1b2');
  const c = Sync2.encoderTampon(1001, 0, 'a1b2');
  const d = Sync2.encoderTampon(1001, 0, 'ffff');
  assert.ok(a < b && b < c && c < d);
  assert.strictEqual(Sync2.decoderL(c), 1001);
  assert.strictEqual(Sync2.decoderC(b), 1);
  assert.strictEqual(Sync2.decoderAppareil(a), 'a1b2');
  assert.strictEqual(a.length, 13 + 8 + 4);
});

test('ISO 8601 aller-retour, dates bancalles refusées', () => {
  assert.strictEqual(Sync2.isoVersMs('2026-11-11T14:05:00.000Z'), T0);
  assert.strictEqual(Sync2.isoVersMs('1970-01-01T00:00:00.000Z'), 0);
  assert.strictEqual(Sync2.isoVersMs('2026-02-29T00:00:00Z'), null); // 2026 n'est pas bissextile
  assert.strictEqual(Sync2.isoVersMs('2024-02-29T12:00:00Z'), 1_709_208_000_000);
  assert.strictEqual(Sync2.isoVersMs('bancal'), null);
  assert.strictEqual(Sync2.isoDepuisTampon(Sync2.tamponDepuisIso('2026-11-11T14:05:00.000Z')), '2026-11-11T14:05:00.000Z');
});

/* ─── Horloge hybride ─── */

test("l'horloge incrémente son compteur à la même ms, repart de zéro après avance", () => {
  const h = new Sync2.Horloge(T0);
  const t1 = h.tic(T0, 'pc');
  const t2 = h.tic(T0, 'pc');
  const t3 = h.tic(T0 + 5, 'pc');
  assert.strictEqual(Sync2.decoderL(t1), T0);
  assert.strictEqual(Sync2.decoderC(t1), 1);
  assert.strictEqual(Sync2.decoderC(t2), 2);
  assert.strictEqual(Sync2.decoderL(t3), T0 + 5);
  assert.strictEqual(Sync2.decoderC(t3), 0);
  assert.ok(t1 < t2 && t2 < t3);
});

test("l'horloge suit un tampon reçu, sauf dans le futur lointain", () => {
  const h = new Sync2.Horloge(T0);
  assert.ok(h.observer(Sync2.encoderTampon(T0 + MINUT, 0, 'x'), T0));
  assert.strictEqual(h.l, T0 + MINUT);
  assert.ok(!h.observer(Sync2.encoderTampon(T0 + 10 * MINUT, 0, 'x'), T0));
  assert.strictEqual(h.l, T0 + MINUT);
  assert.ok(!h.observer(Sync2.encoderTampon(T0, 0, 'x'), T0 + MINUT));
  assert.strictEqual(h.l, T0 + MINUT);
});

test('apres plafonne au tampon du champ', () => {
  const h = new Sync2.Horloge(T0 - MINUT);
  const ancien = Sync2.encoderTampon(T0 + MINUT, 4, 'autre');
  const t = h.apres(T0, ancien, 'pc');
  assert.ok(t > ancien);
  assert.strictEqual(Sync2.decoderAppareil(t), 'pc');
  const t2 = h.apres(T0, null, 'pc');
  assert.ok(t2 > t);
});

/* ─── Migration v1 → v2 ─── */

test('la migration pose tampons hérités, marqueur, traces et réglages', () => {
  const v1 = copie([compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]);
  v1[Store.DELETED_KEY] = JSON.stringify({ accounts: { z1: '2026-03-01T00:00:00.000Z' }, historyClearedAt: '2026-02-01T00:00:00.000Z' });
  v1[Store.SETTINGS_KEY] = JSON.stringify({ policy: { value: { minLength: 12 }, at: '2026-02-01T00:00:00.000Z' } });
  const v2 = Sync2.migrer(v1, T0, 'pc');
  const item = JSON.parse(v2[Store.ACCOUNTS_KEY])[0];
  assert.strictEqual(item.h.issuer, Sync2.tamponDepuisIso('2026-01-01T00:00:00.000Z'));
  assert.strictEqual(item.h.secret, Sync2.tamponDepuisIso('2026-01-01T00:00:00.000Z'));
  assert.ok(Sync2.estVivant(item));
  const marqueur = Sync2.lireMarqueur(v2);
  assert.ok(v2[Sync2.SYNC_KEY]);
  assert.ok(!(Store.DELETED_KEY in v2));
  assert.deepStrictEqual(marqueur.v1, { z1: Sync2.tamponDepuisIso('2026-03-01T00:00:00.000Z') });
  assert.strictEqual(marqueur.historiqueVideLe, Sync2.tamponDepuisIso('2026-02-01T00:00:00.000Z'));
  assert.ok(marqueur.appareils.pc);
  const reglages = JSON.parse(v2[Store.SETTINGS_KEY]);
  assert.strictEqual(reglages.policy.h, Sync2.tamponDepuisIso('2026-02-01T00:00:00.000Z'));
  // Rejouer la migration ne change rien.
  assert.deepStrictEqual(Sync2.migrer(v2, T0, 'pc'), v2);
});

/* ─── Banc : les cinq scénarios du simulateur ─── */

function banc(skewPc = 0, skewTel = 0) {
  const initial = () => copie([compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]);
  const banc = {
    copies: {
      pc: { donnees: initial(), etat: Sync2.nouvelEtat('pc', T0 - MINUT), skew: skewPc },
      tel: { donnees: initial(), etat: Sync2.nouvelEtat('tel', T0 - MINUT), skew: skewTel },
    },
    drive: initial(),
    t: T0,
    rapports: [],
  };
  banc.position = (appareil) => banc.copies[appareil];
  banc.tic = (appareil, plancher) => {
    const c = banc.copies[appareil];
    return c.etat.horloge.apres(banc.t + c.skew, plancher, appareil);
  };
  banc.tamponChamp = (appareil, champ) => {
    const item = JSON.parse(banc.copies[appareil].donnees[Store.ACCOUNTS_KEY])[0];
    return (item.h && item.h[champ]) || '';
  };
  banc.plusGrandTamponItem = (appareil) => {
    const item = JSON.parse(banc.copies[appareil].donnees[Store.ACCOUNTS_KEY])[0];
    return Sync2.plusGrandTampon(item);
  };
  banc.edit = (appareil, champ, val) => {
    const tampon = banc.tic(appareil, banc.tamponChamp(appareil, champ));
    const items = JSON.parse(banc.copies[appareil].donnees[Store.ACCOUNTS_KEY]);
    items[0][champ] = val;
    if (!items[0].h) items[0].h = {};
    items[0].h[champ] = tampon;
    banc.copies[appareil].donnees[Store.ACCOUNTS_KEY] = JSON.stringify(items);
  };
  banc.supprime = (appareil) => {
    const tampon = banc.tic(appareil, banc.plusGrandTamponItem(appareil));
    const items = JSON.parse(banc.copies[appareil].donnees[Store.ACCOUNTS_KEY]);
    items[0].t = tampon;
    banc.copies[appareil].donnees[Store.ACCOUNTS_KEY] = JSON.stringify(items);
  };
  banc.sync = (appareil) => {
    const c = banc.copies[appareil];
    const { donnees, rapport } = Sync2.fusion(c.donnees, banc.drive, c.etat, banc.t);
    c.donnees = donnees;
    banc.rapports.push(rapport);
    if (rapport.aEnvoyer) banc.drive = donnees;
  };
  banc.converge = () => {
    for (let tour = 0; tour < 12; tour++) {
      let stable = true;
      for (const appareil of ['pc', 'tel']) {
        banc.sync(appareil);
        if (banc.rapports.at(-1).aEnvoyer) stable = false;
      }
      if (stable) return;
    }
    assert.fail('les copies ne convergent pas');
  };
  banc.valeur = (appareil, champ) => valeur(banc.copies[appareil].donnees, 'a1', champ);
  banc.vivant = (appareil) => {
    const items = JSON.parse(banc.copies[appareil].donnees[Store.ACCOUNTS_KEY] || '[]');
    return items.length ? Sync2.estVivant(items[0]) : false;
  };
  banc.identiques = () => Object.values(banc.copies).every((c) => !Sync2.differentDe(c.donnees, banc.drive));
  banc.entrees = (genre) => banc.rapports.filter((r) => r.entrees.some((e) => e.genre === genre)).length;
  return banc;
}

test('scénario « horloge en retard » : la correction faite après avoir vu gagne', () => {
  const b = banc(0, -10 * MINUT);
  b.edit('pc', 'issuer', 'GitHub Pro');
  b.sync('pc');
  b.sync('tel');
  b.edit('tel', 'issuer', 'GitHub Entreprise');
  b.sync('tel');
  b.sync('pc');
  b.converge();
  assert.strictEqual(b.valeur('pc', 'issuer'), 'GitHub Entreprise');
  assert.strictEqual(b.valeur('tel', 'issuer'), 'GitHub Entreprise');
  assert.ok(b.identiques());
});

test('scénario « deux champs en parallèle » : les deux changements survivent', () => {
  const b = banc();
  b.edit('pc', 'tag', 'travail');
  b.edit('tel', 'issuer', 'GH');
  b.sync('pc');
  b.sync('tel');
  b.sync('pc');
  b.converge();
  assert.strictEqual(b.valeur('pc', 'issuer'), 'GH');
  assert.strictEqual(b.valeur('pc', 'tag'), 'travail');
  assert.strictEqual(b.valeur('tel', 'issuer'), 'GH');
  assert.strictEqual(b.valeur('tel', 'tag'), 'travail');
  assert.ok(b.identiques());
});

test('scénario « modifié après une suppression » : la modification fait revivre, conflit signalé', () => {
  const b = banc();
  b.supprime('pc');
  b.sync('pc');
  b.edit('tel', 'description', 'clé de secours');
  b.sync('tel');
  b.sync('pc');
  b.converge();
  assert.ok(b.vivant('pc') && b.vivant('tel'));
  assert.strictEqual(b.valeur('pc', 'description'), 'clé de secours');
  assert.strictEqual(b.valeur('tel', 'description'), 'clé de secours');
  assert.ok(b.identiques());
  assert.ok(b.entrees('conflit') > 0, 'le conflit est journalisé');
});

test('scénario « horloge dans le futur » : tampon accepté sans contamination, la suite gagne', () => {
  const b = banc(0, 365 * 24 * 60 * MINUT);
  b.edit('tel', 'issuer', 'X');
  b.sync('tel');
  b.sync('pc');
  assert.ok(b.entrees('horloge') > 0, "l'horloge suspecte est journalisée");
  assert.ok(b.copies.pc.etat.horloge.l < T0 + 6 * MINUT, "l'horloge du pc n'a pas suivi le futur");
  b.edit('pc', 'issuer', 'Y');
  b.sync('pc');
  b.sync('tel');
  b.converge();
  assert.strictEqual(b.valeur('pc', 'issuer'), 'Y');
  assert.strictEqual(b.valeur('tel', 'issuer'), 'Y');
  assert.ok(b.identiques());
});

test('scénario « même milliseconde » : convergence vers la même valeur, conflit signalé', () => {
  const b = banc();
  b.edit('pc', 'issuer', 'A');
  b.edit('tel', 'issuer', 'B');
  b.sync('pc');
  b.sync('tel');
  b.sync('pc');
  b.sync('tel');
  b.converge();
  const attendu = b.valeur('pc', 'issuer');
  assert.ok(attendu === 'A' || attendu === 'B');
  assert.strictEqual(b.valeur('tel', 'issuer'), attendu);
  assert.ok(b.identiques());
  assert.ok(b.entrees('conflit') > 0, 'le conflit est journalisé');
});

/* ─── Fusion : règles ─── */

test('compteur HOTP : la valeur maximale, quel que soit le tampon', () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const gauche = copie([{ ...compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z'), counter: 5 }]);
  const droite = copie([{ ...compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z'), counter: 2, updatedAt: '2026-06-01T00:00:00.000Z' }]);
  const { donnees } = Sync2.fusion(gauche, droite, etat, T0);
  assert.strictEqual(valeur(donnees, 'a1', 'counter'), 5);
});

test('doublons de même identité : fusion champ par champ, le plus ancien fait foi', () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const gauche = copie([{ ...compte('nouveau', 'GitHub', '2026-06-01T00:00:00.000Z'), tag: 'travail' }]);
  const droite = copie([{ ...compte('ancien', 'GitHub', '2026-01-01T00:00:00.000Z'), description: 'perso' }]);
  const { donnees, rapport } = Sync2.fusion(gauche, droite, etat, T0);
  assert.deepStrictEqual(ids(donnees), ['ancien']);
  assert.strictEqual(valeur(donnees, 'ancien', 'tag'), 'travail');
  assert.ok(rapport.entrees.some((e) => e.genre === 'doublon'));
  // L'id enterré dans le marqueur meurt à son retour d'une autre copie.
  const retour = copie([{ ...compte('nouveau', 'GitHub', '2026-06-01T00:00:00.000Z'), tag: 'travail' }]);
  const { donnees: donnees2 } = Sync2.fusion(donnees, retour, etat, T0);
  assert.ok(!ids(donnees2).includes('nouveau'));
});

test('suppression datable : la modification plus récente fait revivre, la suppression plus récente tue', () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const supprime = { ...compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z'), t: Sync2.tamponDepuisIso('2026-03-01T00:00:00.000Z') };
  const modifie = {
    ...compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z'),
    description: 'clé de secours',
    updatedAt: '2026-04-01T00:00:00.000Z',
  };
  const { donnees } = Sync2.fusion(copie([supprime]), copie([modifie]), etat, T0);
  assert.ok(Sync2.estVivant(JSON.parse(donnees[Store.ACCOUNTS_KEY])[0]));
  const supprime2 = { ...supprime, t: Sync2.tamponDepuisIso('2026-05-01T00:00:00.000Z') };
  const { donnees: donnees2 } = Sync2.fusion(copie([supprime2]), copie([{ ...modifie }]), etat, T0);
  assert.ok(!Sync2.estVivant(JSON.parse(donnees2[Store.ACCOUNTS_KEY])[0]));
});

test("fusion d'une copie avec elle-même : stable dès la deuxième fusion", () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const x = Sync2.migrer(copie([compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]), T0, 'pc');
  const { donnees: une } = Sync2.fusion(x, x, etat, T0);
  const { donnees: deux, rapport } = Sync2.fusion(une, une, etat, T0);
  assert.ok(Sync2.differentDe(deux, une) === false);
  assert.strictEqual(rapport.aEnvoyer, false);
  assert.strictEqual(rapport.entrees.length, 0);
});

test("collections récentes absentes des deux côtés : rien d'écrit ; marqueur toujours posé", () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const { donnees } = Sync2.fusion(copie([compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]), {}, etat, T0);
  assert.ok(!(Store.LOGINS_KEY in donnees));
  assert.ok(!(Store.PASSKEYS_KEY in donnees));
  assert.ok(Store.ACCOUNTS_KEY in donnees);
  assert.ok(Sync2.SYNC_KEY in donnees);
  assert.ok(Store.HISTORY_KEY in donnees);
});

test('réglages : le plus grand tampon gagne, champ par nom', () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const gauche = Sync2.migrer(
    { [Store.SETTINGS_KEY]: JSON.stringify({ policy: { value: { minLength: 12 }, at: '2026-05-01T00:00:00.000Z' } }) },
    T0,
    'pc'
  );
  const droite = Sync2.migrer(
    {
      [Store.SETTINGS_KEY]: JSON.stringify({
        policy: { value: { minLength: 16 }, at: '2026-02-01T00:00:00.000Z' },
        prefs: { value: { theme: 'dark' }, at: '2026-03-01T00:00:00.000Z' },
      }),
    },
    T0,
    'tel'
  );
  const { donnees } = Sync2.fusion(gauche, droite, etat, T0);
  const reglages = JSON.parse(donnees[Store.SETTINGS_KEY]);
  assert.strictEqual(reglages.policy.value.minLength, 12);
  assert.strictEqual(reglages.prefs.value.theme, 'dark');
});

test('historique : union par id, sans ce qui précède le vidage tamponné, plafonné', () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const entreeH = (id, at) => ({ id, at, action: 'create', accountId: null, label: null, tag: null, details: null });
  const gauche = {};
  gauche[Store.HISTORY_KEY] = JSON.stringify(
    Array.from({ length: 600 }, (_, k) => entreeH(`h${k}`, `2026-09-${String((k % 28) + 1).padStart(2, '0')}T00:00:00.000Z`))
  );
  const droite = {};
  droite[Sync2.SYNC_KEY] = JSON.stringify({
    sync: 'v2',
    appareils: {},
    historiqueVideLe: Sync2.tamponDepuisIso('2026-09-15T00:00:00.000Z'),
  });
  const { donnees } = Sync2.fusion(gauche, droite, etat, T0);
  const histoire = JSON.parse(donnees[Store.HISTORY_KEY]);
  assert.ok(histoire.length <= Store.HISTORY_MAX);
  assert.ok(histoire.every((e) => e.at > '2026-09-15T00:00:00.000Z'));
  const ats = histoire.map((e) => e.at);
  assert.deepStrictEqual(ats, [...ats].sort().reverse());
});

/* ─── Pas de résurrection, tampon futur ─── */

test('pas de résurrection après convergence complète', () => {
  const etatPc = Sync2.nouvelEtat('pc', T0);
  const etatTel = Sync2.nouvelEtat('tel', T0);
  const initial = copie([compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]);
  let pc = Sync2.migrer(initial, T0, 'pc');
  let tel = Sync2.migrer(initial, T0, 'tel');
  // pc supprime puis synchronise ; tel synchronise (adopte la suppression).
  const items = JSON.parse(pc[Store.ACCOUNTS_KEY]);
  const plancher = Sync2.plusGrandTampon(items[0]);
  items[0].t = etatPc.horloge.apres(T0, plancher, 'pc');
  pc[Store.ACCOUNTS_KEY] = JSON.stringify(items);
  pc = Sync2.fusion(pc, {}, etatPc, T0).donnees;
  tel = Sync2.fusion(tel, pc, etatTel, T0).donnees;
  const telItems = JSON.parse(tel[Store.ACCOUNTS_KEY]);
  assert.ok(!telItems.length || !Sync2.estVivant(telItems[0]), 'tel a adopté la suppression');
  // Refusionner dans tous les sens ne ressuscite rien ; le contenu converge.
  const pc3 = Sync2.fusion(pc, tel, etatPc, T0 + MINUT).donnees;
  const tel3 = Sync2.fusion(tel, pc3, etatTel, T0 + MINUT).donnees;
  const pc4 = Sync2.fusion(pc3, tel3, etatPc, T0 + 2 * MINUT).donnees;
  assert.deepStrictEqual(JSON.parse(pc4[Store.ACCOUNTS_KEY]), JSON.parse(tel3[Store.ACCOUNTS_KEY]));
  assert.ok(!Sync2.estVivant(JSON.parse(pc4[Store.ACCOUNTS_KEY])[0]));
  assert.ok(!Sync2.estVivant(JSON.parse(tel3[Store.ACCOUNTS_KEY])[0]));
});

test('tampon futur : journalisé, contenu accepté, horloge locale inchangée', () => {
  const etat = Sync2.nouvelEtat('pc', T0);
  const lointain = Sync2.encoderTampon(T0 + 365 * 24 * 60 * MINUT, 3, 'tel');
  const futur = copie([compte('a1', 'GitHub', '2026-01-01T00:00:00.000Z')]);
  const items = JSON.parse(futur[Store.ACCOUNTS_KEY]);
  items[0].h = { issuer: lointain };
  items[0].issuer = 'Du futur';
  futur[Store.ACCOUNTS_KEY] = JSON.stringify(items);
  const { donnees, rapport } = Sync2.fusion({}, futur, etat, T0);
  assert.strictEqual(valeur(donnees, 'a1', 'issuer'), 'Du futur');
  assert.ok(rapport.entrees.some((e) => e.genre === "horloge" && e.champ === 'tel'), "l'appareil émetteur est nommé");
  assert.strictEqual(etat.horloge.l, T0, "l'horloge locale n'a pas suivi le futur");
  const tampon = etat.horloge.apres(T0 + MINUT, lointain, 'pc');
  assert.ok(tampon > lointain);
});

/* ─── Élagage : rétention et registre ─── */

test('trace vue par tous et retenue écoulée : effacée de toutes les copies', () => {
  const b = banc();
  b.copies.trois = { donnees: JSON.parse(JSON.stringify(b.drive)), etat: Sync2.nouvelEtat('trois', T0 - MINUT), skew: 0 };
  b.converge = function () {
    for (let tour = 0; tour < 12; tour++) {
      let stable = true;
      for (const appareil of ['pc', 'tel', 'trois']) {
        this.sync(appareil);
        if (this.rapports.at(-1).aEnvoyer) stable = false;
      }
      if (stable) return;
    }
    assert.fail('les copies ne convergent pas');
  };
  b.supprime('pc');
  b.converge();
  for (const [nom, c] of Object.entries(b.copies)) {
    const items = JSON.parse(c.donnees[Store.ACCOUNTS_KEY] || '[]');
    assert.ok(items.every((i) => !Sync2.estVivant(i)), `${nom} : le compte est supprimé partout`);
  }
  // Un an plus tard : la trace est vue partout et la rétention (30 j) est écoulée.
  b.t += Sync2.SILENCE_MAX_MS + MINUT;
  b.converge();
  for (const [nom, c] of Object.entries(b.copies)) {
    const items = JSON.parse(c.donnees[Store.ACCOUNTS_KEY] || '[]');
    assert.ok(items.length === 0, `${nom} : trace vue partout, l'élément sort de la copie`);
  }
});

/* ─── Registre : description des appareils (SYN-09) ─── */

const registre = (map) => JSON.parse(map[Sync2.SYNC_KEY]).appareils;

test("l'appareil se décrit dans le registre à chaque fusion", () => {
  const etat = Sync2.nouvelEtat('pc', T0, { type: 'web', nom: 'Firefox · Linux' });
  const { donnees } = Sync2.fusion(copie([compte('a', 'GitHub', '2026-11-11T14:00:00.000Z')]), {}, etat, T0);
  assert.deepStrictEqual(registre(donnees).pc, { vu: etat.repere, actifLe: T0, type: 'web', nom: 'Firefox · Linux' });
});

test('description : gardée de la copie reçue quand l’appareil ne sait pas se décrire', () => {
  const decrit = Sync2.fusion({}, {}, Sync2.nouvelEtat('pc', T0, { type: 'linux', nom: 'portable' }), T0).donnees;
  const muet = Sync2.nouvelEtat('pc', T0 + MINUT);
  const { donnees } = Sync2.fusion(decrit, {}, muet, T0 + MINUT);
  assert.strictEqual(registre(donnees).pc.type, 'linux');
  assert.strictEqual(registre(donnees).pc.nom, 'portable');
  assert.strictEqual(registre(donnees).pc.actifLe, T0 + MINUT);
});

test('description : fusion commutative, la plus récente activité fait foi, ancienne forme lue', () => {
  const marque = (appareils) => ({ [Sync2.SYNC_KEY]: JSON.stringify({ sync: 'v2', appareils, historiqueVideLe: null }) });
  const vu = Sync2.encoderTampon(T0, 0, 'tel');
  const a = marque({ tel: { vu, actifLe: T0, type: 'android', nom: 'ancien nom' }, pc: vu });
  const b = marque({ tel: { vu, actifLe: T0 + MINUT, type: 'android', nom: 'Pixel' }, pc: { vu, actifLe: T0 } });
  const ab = Sync2.fusion(a, b, Sync2.nouvelEtat('x', T0 + 2 * MINUT), T0 + 2 * MINUT).donnees;
  const ba = Sync2.fusion(b, a, Sync2.nouvelEtat('x', T0 + 2 * MINUT), T0 + 2 * MINUT).donnees;
  assert.deepStrictEqual(registre(ab).tel, { vu, actifLe: T0 + MINUT, type: 'android', nom: 'Pixel' });
  assert.deepStrictEqual(registre(ab), registre(ba));
  assert.deepStrictEqual(registre(ab).pc, { vu, actifLe: T0 }, 'ancienne forme : ni type ni nom inventés');
  // Une copie sans description ne l'efface pas.
  const c = marque({ tel: { vu, actifLe: T0 + 5 * MINUT } });
  const ac = Sync2.fusion(ab, c, Sync2.nouvelEtat('x', T0 + 6 * MINUT), T0 + 6 * MINUT).donnees;
  assert.strictEqual(registre(ac).tel.nom, 'Pixel');
  assert.strictEqual(registre(ac).tel.actifLe, T0 + 5 * MINUT);
});

test('etatPersistant : description posée, puis changée par decrire()', () => {
  const carte = new Map();
  const stockage = { getItem: (k) => (carte.has(k) ? carte.get(k) : null), setItem: (k, v) => carte.set(k, String(v)) };
  const temps = Sync2.etatPersistant(stockage, () => T0, { type: 'web', nom: 'Chrome · Linux' });
  assert.strictEqual(temps.etat.type, 'web');
  temps.decrire({ type: 'extension', nom: 'Extension · Chrome' });
  assert.strictEqual(temps.etat.type, 'extension');
  assert.strictEqual(temps.etat.nom, 'Extension · Chrome');
  temps.decrire(null);
  assert.ok(!('type' in temps.etat) && !('nom' in temps.etat));
});

test("rien de nouveau : l'activité n'est pas réécrite avant un jour, rien à envoyer", () => {
  const etat = Sync2.nouvelEtat('pc', T0, { type: 'web' });
  const premiere = Sync2.fusion(copie([compte('a', 'GitHub', '2026-11-11T14:00:00.000Z')]), {}, etat, T0).donnees;
  const plusTard = Sync2.fusion(premiere, premiere, etat, T0 + 3 * 60 * MINUT);
  assert.strictEqual(plusTard.rapport.aEnvoyer, false, 'trois heures après, sans nouveauté : rien à envoyer');
  assert.strictEqual(registre(plusTard.donnees).pc.actifLe, T0);
  const lendemain = Sync2.fusion(premiere, premiere, etat, T0 + Sync2.ACTIVITE_PAS_MS);
  assert.strictEqual(lendemain.rapport.aEnvoyer, true, 'un jour après : activité rafraîchie');
  assert.strictEqual(registre(lendemain.donnees).pc.actifLe, T0 + Sync2.ACTIVITE_PAS_MS);
});
