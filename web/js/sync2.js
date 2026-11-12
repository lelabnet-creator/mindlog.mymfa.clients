/*
 * Synchro v2 (SYN-07) : fusion champ par champ par horloge hybride — réplique fidèle
 * de ../android/crates/mymfa-core/src/sync2.rs (tests d'interopérabilité : fixtures
 * sync2-web.json générées d'ici et rejouées en Rust, sync2-rust.json l'inverse).
 *
 * La fusion v1 (js/sync.js : l'élément entier dont updatedAt est le plus récent
 * gagne) dépend des horloges locales : une correction faite plus tard sur un
 * appareil qui retarde perd, une horloge dans le futur gagne jusqu'en 2027, deux
 * horloges à la même milliseconde ne convergent pas. La v2 sépare deux questions :
 *  - Qu'est-ce qui s'enchaîne ? Une horloge hybride (l, c, D) : heure de référence
 *    en ms, compteur, identifiant d'appareil. Une modification faite après avoir
 *    vu une version reçoit toujours un tampon plus grand qu'elle.
 *  - Qu'est-ce qui est vraiment simultané ? Là seulement, l'heure départage — et
 *    elle vient d'une référence publique (T(), SYN-08 : heure Drive côté
 *    navigateur), jamais de l'horloge locale seule.
 *
 * Représentation (dans les données du coffre, mêmes clés que la v1) :
 *  - chaque élément garde ses champs actuels (l'interface ne casse pas) plus
 *    `h` : { champ → tampon }, et `t` : tampon de suppression ;
 *  - la clé `mymfa.sync.v2` (marqueur) porte le registre des appareils, le vidage
 *    d'historique tamponné et les traces v1 encore sans élément à qui s'attacher ;
 *    sa présence signale un coffre v2. Chaque appareil du registre peut se décrire
 *    (SYN-09) : `type` (web, extension, linux, android) et `nom` lisible — écrits
 *    par l'appareil lui-même à chaque fusion, facultatifs (ancienne forme lue) ;
 *  - l'enveloppe du coffre passe à `v: 2` quand les données portent le marqueur :
 *    un ancien client (enveloppe v: 1 exigée) refuse de lire — donc d'écrire ;
 *  - état par appareil, jamais synchronisé : identifiant, horloge (l, c), repère
 *    de dernière synchro. À persister par le client hors des données.
 *
 * La fusion est commutative, associative et idempotente : champ par champ, le
 * plus grand tampon gagne ; compteur HOTP = valeur maximale ; suppressions
 * datées (un élément vit si max(tampons de ses champs) > trace) ; doublons de
 * même identité fusionnés champ par champ ; traces effacées une fois vues par
 * tous les appareils du registre (et après rétention) ; journal des conflits,
 * doublons et horloges suspectes rendu à l'appelant (chiffré et conservé par
 * chaque client, pas synchronisé).
 */
(function (root, factory) {
  const api = factory(root.Store || (typeof require === 'function' ? require('./store.js') : null));
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Sync2 = api;
})(typeof self !== 'undefined' ? self : globalThis, function (Store) {
  'use strict';

  const { ACCOUNTS_KEY, LOGINS_KEY, PASSKEYS_KEY, HISTORY_KEY, SETTINGS_KEY, HISTORY_MAX } = Store;

  /** Clé du marqueur v2 dans les données (sa présence signale un coffre v2). */
  const SYNC_KEY = 'mymfa.sync.v2';
  /** Appareil fictif des tampons issus de la migration (updatedAt hérité de la v1). */
  const APPAREIL_HERITAGE = 'legacy';
  /** Un tampon reçu plus de 5 min dans le futur est accepté et journalisé, mais
   * ne contamine pas l'horloge locale. */
  const ECART_FUTUR_MS = 5 * 60 * 1000;
  /** Un appareil muet depuis plus d'un an sort du registre, avec avertissement. */
  const SILENCE_MAX_MS = 365 * 24 * 60 * 60 * 1000;
  /** Une trace de suppression n'est effacée qu'après cette rétention, même vue
   * partout : un appareil nouveau ou hors ligne pendant la suppression doit avoir
   * le temps de l'apprendre. */
  const RETENTION_TRACE_MS = 30 * 24 * 60 * 60 * 1000;
  /** L'entrée d'un appareil dans le registre (son activité actifLe, son repère vu) n'est
   * republiée que si autre chose part déjà vers la copie distante, ou si son activité date
   * de plus d'un jour : sinon chaque fusion différerait de Drive et le coffre repartirait à
   * chaque cycle. Un jour suffit largement face au silence d'un an ; un repère publié en
   * retard ne fait que retarder l'élagage des traces (il est prudent, jamais faux). */
  const ACTIVITE_PAS_MS = 24 * 60 * 60 * 1000;

  // `l` de référence : ms UTC sur 13 chiffres (jusqu'en 2286), compteur
  // hexadécimal sur 8 chiffres, identifiant d'appareil. Comparé en texte,
  // l'ordre est (l, c, D).
  const L_CHIFFRES = 13;
  const C_CHIFFRES = 8;

  /* ─── Tampons ── */

  /** Tampon d'horloge hybride (l, c, D) encodé en texte triable. */
  function encoderTampon(l, c, appareil) {
    return String(l).padStart(L_CHIFFRES, '0') + c.toString(16).padStart(C_CHIFFRES, '0') + appareil;
  }

  const decoderL = (tampon) => {
    const l = Number(tampon.slice(0, L_CHIFFRES));
    return Number.isFinite(l) && l >= 0 ? l : 0;
  };

  const decoderC = (tampon) => {
    const c = parseInt(tampon.slice(L_CHIFFRES, L_CHIFFRES + C_CHIFFRES), 16);
    return Number.isFinite(c) && c >= 0 ? c : 0;
  };

  const decoderAppareil = (tampon) => tampon.slice(L_CHIFFRES + C_CHIFFRES) || '';

  /** Le plus grand des deux tampons (chaîne vide = pas de tampon, le plus petit). */
  const tamponMax = (a, b) => (a >= b ? a : b);

  /** Tampon d'une date ISO 8601 (héritage v1) : compteur 0, appareil « legacy ». */
  function tamponDepuisIso(iso) {
    return encoderTampon(isoVersMs(iso) || 0, 0, APPAREIL_HERITAGE);
  }

  /** Date ISO du `l` d'un tampon (affichage, updatedAt dérivé). */
  function isoDepuisTampon(tampon) {
    return new Date(decoderL(tampon)).toISOString();
  }

  /** ISO 8601 UTC « YYYY-MM-DDTHH:MM:SS(.mmm)Z » → ms, ou null si format inconnu. */
  function isoVersMs(iso) {
    const m = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{3}))?Z$/.exec(String(iso || ''));
    if (!m) return null;
    const [, y, mo, d, h, mi, s, ms] = m.map(Number);
    const bissextile = (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
    const joursDuMois = [31, bissextile ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if (mo < 1 || mo > 12 || d < 1 || d > joursDuMois[mo - 1] || h > 23 || mi > 59 || s > 60) return null;
    // Jours depuis l'époque via un Date UTC (calendrier proleptique).
    return Date.UTC(y, mo - 1, d, h, mi, s, ms || 0);
  }

  /* ─── Horloge hybride ── */

  /** Horloge hybride d'un appareil : l (ms UTC de référence), c compteur.
   * Persistée par le client (jamais synchronisée) ; mise à l'heure par T(). */
  class Horloge {
    constructor(maintenant = 0) {
      this.l = maintenant;
      this.c = 0;
    }

    /** Un tampon pour une modification locale : l'avance à max(l, T()), le
     * compteur repart de 0 si l a bougé, s'incrémente sinon. */
    tic(maintenant, appareil) {
      const l = Math.max(this.l, maintenant);
      this.c = l === this.l ? (this.c + 1) >>> 0 : 0;
      this.l = l;
      return encoderTampon(l, this.c, appareil);
    }

    /** Réception d'un tampon : l'horloge avance s'il la dépasse — sauf s'il est
     * à plus de 5 min dans le futur (accepté, journalisé, sans contamination). */
    observer(tampon, maintenant) {
      if (!tampon) return false;
      const l = decoderL(tampon);
      const c = decoderC(tampon);
      if (l > maintenant + ECART_FUTUR_MS) return false;
      if (l > this.l || (l === this.l && c > this.c)) {
        this.l = l;
        this.c = c;
        return true;
      }
      return false;
    }

    /** Un tampon pour une nouvelle valeur d'un champ : après T(), et toujours
     * plus grand que le tampon actuel du champ — une modification faite après
     * avoir vu (ou porté) une version l'emporte sur elle, horloge faussée ou pas. */
    apres(maintenant, plancher, appareil) {
      const t = this.tic(maintenant, appareil);
      if (plancher && t <= plancher) {
        const l = decoderL(plancher);
        const c = (decoderC(plancher) + 1) >>> 0;
        this.l = l;
        this.c = c;
        return encoderTampon(l, c, appareil);
      }
      return t;
    }
  }

  /* ─── Éléments : champs tamponnés ── */

  const COLLECTIONS = [
    {
      cle: ACCOUNTS_KEY,
      champs: ['type', 'issuer', 'account', 'secret', 'algorithm', 'digits', 'period', 'counter', 'tag', 'description', 'favorite'],
      identite: (a) => [texte(a, 'secret'), texte(a, 'issuer'), texte(a, 'account')].join('\u0000'),
      toujours: true,
    },
    {
      cle: LOGINS_KEY,
      champs: ['origin', 'username', 'password', 'title', 'note', 'tag', 'source', 'favorite'],
      identite: (l) => [texte(l, 'origin'), texte(l, 'username')].join('\u0000'),
      toujours: false,
    },
    {
      cle: PASSKEYS_KEY,
      champs: ['credentialId', 'rpId', 'rpName', 'origin', 'userHandle', 'userName', 'userDisplayName', 'algorithm', 'privateKey'],
      identite: (p) => texte(p, 'credentialId'),
      toujours: false,
    },
  ];

  const collectionDe = (cle) => COLLECTIONS.find((c) => c.cle === cle);

  const texte = (item, champ) => {
    const v = item ? item[champ] : undefined;
    return typeof v === 'string' ? v : '';
  };

  const champDe = (item, champ) => (item && champ in item ? item[champ] : null);

  const tamponDe = (item, champ) => {
    const h = item && item.h;
    return h && typeof h[champ] === 'string' ? h[champ] : '';
  };

  function poserTampon(item, champ, tampon) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return;
    if (!item.h || typeof item.h !== 'object' || Array.isArray(item.h)) item.h = {};
    item.h[champ] = tampon;
  }

  /** Trace de suppression d'un élément (tampon), s'il en porte une. */
  const traceDe = (item) => (item && typeof item.t === 'string' && item.t ? item.t : null);

  /** Un élément vit si l'un de ses champs est plus récent que sa suppression :
   * une modification postérieure le fait revivre, une suppression postérieure le retire. */
  function estVivant(item) {
    const trace = traceDe(item);
    if (!trace) return true;
    let plusRecent = '';
    const h = item && item.h;
    if (h && typeof h === 'object') for (const t of Object.values(h)) if (typeof t === 'string' && t > plusRecent) plusRecent = t;
    return plusRecent > trace;
  }

  function liste(map, cle) {
    try {
      const value = JSON.parse((map || {})[cle] ?? '[]');
      return Array.isArray(value) ? value : [];
    } catch {
      return [];
    }
  }

  function ecrireListe(map, cle, items) {
    map[cle] = JSON.stringify(items);
  }

  /** Égalité JSON profonde : l'ordre des clés d'objet n'engage pas, les tableaux
   * se comparent élément par élément (même sémantique que PartialEq de serde). */
  function jsonEgal(a, b) {
    if (a === b) return true;
    if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false;
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    if (Array.isArray(a)) {
      return a.length === b.length && a.every((x, i) => jsonEgal(x, b[i]));
    }
    const clesA = Object.keys(a);
    const clesB = Object.keys(b);
    if (clesA.length !== clesB.length) return false;
    return clesA.every((cle) => cle in b && jsonEgal(a[cle], b[cle]));
  }

  /* ─── Marqueur v2 (clé mymfa.sync.v2) ── */

  function lireMarqueur(map) {
    const brut = (map || {})[SYNC_KEY];
    if (!brut) return { appareils: {}, historiqueVideLe: null, v1: {} };
    let objet;
    try {
      objet = JSON.parse(brut);
    } catch {
      return { appareils: {}, historiqueVideLe: null, v1: {} };
    }
    if (!objet || typeof objet !== 'object' || Array.isArray(objet)) return { appareils: {}, historiqueVideLe: null, v1: {} };
    const paires = (cle) => {
      const out = {};
      const m = objet[cle];
      if (m && typeof m === 'object' && !Array.isArray(m)) {
        for (const [k, v] of Object.entries(m)) if (typeof v === 'string' && v) out[k] = v;
      }
      return out;
    };
    const appareils = {};
    if (objet.appareils && typeof objet.appareils === 'object' && !Array.isArray(objet.appareils)) {
      for (const [k, v] of Object.entries(objet.appareils)) {
        // Forme riche { vu, actifLe, type?, nom? } ; une chaîne simple (ancienne
        // forme) vaut couverture seule, activité inconnue (0).
        if (v && typeof v === 'object' && !Array.isArray(v) && typeof v.vu === 'string') {
          appareils[k] = { vu: v.vu, actifLe: Number.isFinite(v.actifLe) ? v.actifLe : 0, ...lireDescription(v) };
        } else if (typeof v === 'string') {
          appareils[k] = { vu: v, actifLe: 0 };
        }
      }
    }
    return {
      appareils,
      historiqueVideLe: typeof objet.historiqueVideLe === 'string' && objet.historiqueVideLe ? objet.historiqueVideLe : null,
      v1: paires('v1'),
    };
  }

  /** Description d'un appareil (SYN-09) : `type` non vide, et `nom` s'il y en a
   * un. Sans type, pas de description (le nom seul ne se garde pas). */
  function lireDescription(v) {
    if (!v || typeof v.type !== 'string' || !v.type) return {};
    return typeof v.nom === 'string' && v.nom ? { type: v.type, nom: v.nom } : { type: v.type };
  }

  /** De deux entrées du registre pour le même appareil, celle dont la description
   * fait foi : celle qui en a une ; sinon la plus grande (actifLe, type, nom) —
   * la plus récente activité, puis un ordre total, pour que les deux côtés d'une
   * fusion choisissent la même. */
  function descriptionGagnante(a, b) {
    if (!b.type) return lireDescription(a);
    if (!a.type) return lireDescription(b);
    if (a.actifLe !== b.actifLe) return lireDescription(a.actifLe > b.actifLe ? a : b);
    if (a.type !== b.type) return lireDescription(a.type > b.type ? a : b);
    return lireDescription((a.nom || '') >= (b.nom || '') ? a : b);
  }

  function ecrireMarqueur(map, marqueur) {
    const appareils = {};
    for (const [a, vu] of Object.entries(marqueur.appareils)) {
      appareils[a] = { vu: vu.vu, actifLe: vu.actifLe, ...lireDescription(vu) };
    }
    const objet = { sync: 'v2', appareils, historiqueVideLe: marqueur.historiqueVideLe };
    if (Object.keys(marqueur.v1).length) objet.v1 = marqueur.v1;
    map[SYNC_KEY] = JSON.stringify(objet);
  }

  /* ─── État par appareil (jamais synchronisé) ── */

  /** Identifiant, horloge et repère de dernière synchro d'un appareil. À
   * persister localement (hors des données) et à repasser à chaque fusion. */
  function nouvelEtat(appareil, maintenant, description = null) {
    return { appareil, horloge: new Horloge(maintenant), repere: '', ...lireDescription(description) };
  }

  // État d'appareil jamais synchronisé : identifiant et horloge vivent hors des
  // données du coffre (Web Storage, clés sans valeur sensible).
  const APPAREIL_KEY = 'mymfa.appareil.v1';
  const HORLOGE_KEY = 'mymfa.horloge.v1';

  /**
   * État d'appareil persistant : identifiant stable (créé une fois), horloge
   * hybride et repère relus à chaque démarrage, écrits après chaque tic ou
   * fusion. `stockage` est n'importe quel objet compatible Web Storage ;
   * `T` est l'heure de référence (SYN-08, Heure.maintenant côté web).
   * @returns {{ appareil: string, etat: object, tic: () => string,
   *             tampon: (plancher?: string) => string, persister: () => void }}
   * `tampon(plancher)` donne un tampon pour une modification locale (toujours
   * plus grand que le plancher) ; après une fusion, l'état ayant été muté,
   * appeler `persister()`. `description` ({ type, nom }) : ce que l'appareil
   * écrit de lui-même dans le registre (SYN-09) ; `decrire()` la change.
   */
  function etatPersistant(stockage, T = () => Date.now(), description = null) {
    let appareil = stockage.getItem(APPAREIL_KEY);
    if (!appareil || !/^[0-9a-z]{6,32}$/.test(appareil)) {
      const octets = new Uint8Array(4);
      (globalThis.crypto || {}).getRandomValues?.(octets);
      appareil = [...octets].map((o) => o.toString(16).padStart(2, '0')).join('');
      try {
        stockage.setItem(APPAREIL_KEY, appareil);
      } catch {
        /* stockage indisponible : identifiant volatil */
      }
    }
    let etat = nouvelEtat(appareil, T(), description);
    try {
      const sauvegarde = JSON.parse(stockage.getItem(HORLOGE_KEY) || 'null');
      if (sauvegarde && Number.isFinite(sauvegarde.l) && sauvegarde.l > 0) {
        etat.horloge = new Horloge(sauvegarde.l);
        etat.horloge.c = Number.isFinite(sauvegarde.c) ? sauvegarde.c : 0;
        etat.repere = typeof sauvegarde.repere === 'string' ? sauvegarde.repere : '';
      }
    } catch {
      /* horloge illisible : on repart de T() */
    }
    const persister = () => {
      try {
        stockage.setItem(HORLOGE_KEY, JSON.stringify({ l: etat.horloge.l, c: etat.horloge.c, repere: etat.repere }));
      } catch {
        /* stockage indisponible : horloge volatile */
      }
    };
    return {
      appareil,
      etat,
      tic: () => {
        const tampon = etat.horloge.tic(T(), appareil);
        persister();
        return tampon;
      },
      tampon: (plancher) => {
        const t = etat.horloge.apres(T(), plancher || null, appareil);
        persister();
        return t;
      },
      persister,
      decrire: (nouvelle) => {
        delete etat.type;
        delete etat.nom;
        Object.assign(etat, lireDescription(nouvelle));
      },
    };
  }

  /* ─── Migration v1 → v2 ── */

  function lireSupprimesV1(map) {
    const out = {};
    try {
      const objet = JSON.parse((map || {})[Store.DELETED_KEY] || '{}');
      if (objet && typeof objet === 'object') {
        if (objet.accounts && typeof objet.accounts === 'object') {
          for (const [id, at] of Object.entries(objet.accounts)) if (typeof at === 'string') out[id] = at;
        }
        if (typeof objet.historyClearedAt === 'string' && objet.historyClearedAt) out.__vidage__ = objet.historyClearedAt;
      }
    } catch {
      /* pas de trace v1 lisible */
    }
    return out;
  }

  /** Porte une copie v1 (ou mixte) au format v2 : chaque updatedAt devient le
   * tampon initial de tous les champs de l'élément (appareil « legacy »), les
   * tombstones v1 s'attachent aux éléments (ou attendent dans le marqueur), les
   * réglages reçoivent leur tampon, le marqueur est posé. Rejouable sans effet. */
  function migrer(donnees, _maintenant, appareil) {
    const out = { ...(donnees || {}) };
    const supprimes = lireSupprimesV1(out);
    const v1Restants = {};

    for (const collection of COLLECTIONS) {
      if (!(collection.cle in out)) continue;
      const items = liste(out, collection.cle);
      const faits = items.map((item) => {
        if (!item || typeof item !== 'object' || Array.isArray(item)) return item;
        if (item.h && typeof item.h === 'object' && !Array.isArray(item.h)) return item;
        const base = texte(item, 'updatedAt') || texte(item, 'createdAt');
        const herite = tamponDepuisIso(base);
        const fait = { ...item };
        for (const champ of collection.champs) poserTampon(fait, champ, herite);
        const trace = supprimes[texte(item, 'id')];
        if (trace) fait.t = tamponDepuisIso(trace);
        return fait;
      });
      ecrireListe(out, collection.cle, faits);
    }

    // Tombstones v1 rattachés à aucun élément présent : gardés dans le marqueur,
    // appliqués à l'arrivée de l'élément (fusion) puis retirés.
    const presents = new Set();
    for (const collection of COLLECTIONS) {
      for (const item of liste(out, collection.cle)) presents.add(texte(item, 'id'));
    }
    for (const [id, at] of Object.entries(supprimes)) {
      if (id !== '__vidage__' && !presents.has(id)) v1Restants[id] = tamponDepuisIso(at);
    }

    // Réglages : chaque entrée reçoit le tampon de son `at` si elle n'en a pas.
    if (SETTINGS_KEY in out) {
      try {
        const entrees = JSON.parse(out[SETTINGS_KEY]);
        if (entrees && typeof entrees === 'object' && !Array.isArray(entrees)) {
          const faits = {};
          for (const [nom, entree] of Object.entries(entrees)) {
            if (entree && typeof entree === 'object' && !Array.isArray(entree) && !(entree.h && typeof entree.h === 'object')) {
              faits[nom] = { ...entree, h: tamponDepuisIso(typeof entree.at === 'string' ? entree.at : '') };
            } else {
              faits[nom] = entree;
            }
          }
          out[SETTINGS_KEY] = JSON.stringify(faits);
        }
      } catch {
        /* réglages illisibles : laissés tels quels */
      }
    }

    // Vidage d'historique v1 (ISO) → tampon dans le marqueur.
    const marqueur = lireMarqueur(out);
    const fusionneV1 = { ...v1Restants };
    for (const [id, t] of Object.entries(marqueur.v1)) if (!fusionneV1[id] || t > fusionneV1[id]) fusionneV1[id] = t;
    let historiqueVideLe = marqueur.historiqueVideLe;
    if (supprimes.__vidage__) {
      const t = tamponDepuisIso(supprimes.__vidage__);
      historiqueVideLe = !historiqueVideLe || t > historiqueVideLe ? t : historiqueVideLe;
    }
    const appareils = { ...marqueur.appareils };
    if (!appareils[appareil]) appareils[appareil] = { vu: encoderTampon(0, 0, APPAREIL_HERITAGE), actifLe: 0 };
    ecrireMarqueur(out, { appareils, historiqueVideLe, v1: fusionneV1 });
    // La trace v1 est consommée : les suppressions vivent dans les éléments.
    delete out[Store.DELETED_KEY];
    return out;
  }

  /* ─── Rapport ── */

  const entree = (genre, cle, champ, texteRapport, gagnant, perdant) => ({
    genre,
    cle,
    champ,
    texte: texteRapport,
    ...(gagnant !== undefined ? { gagnant } : {}),
    ...(perdant !== undefined ? { perdant } : {}),
    at: new Date().toISOString(),
  });

  /* ─── Fusion v2 ── */

  /** Réception d'un tampon vu dans le contenu : fait avancer l'horloge locale,
   * sauf s'il est à plus de 5 min dans le futur — accepté, journalisé (l'appareil
   * émetteur est nommé), sans contamination. */
  function surveiller(tampon, etat, maintenant, rapport) {
    if (!tampon) return;
    const l = decoderL(tampon);
    if (l > maintenant + ECART_FUTUR_MS) {
      const appareil = decoderAppareil(tampon);
      const minutes = Math.floor((l - maintenant) / 60000);
      const description = `Horloge de « ${appareil} » à ${minutes} min dans le futur : tampon accepté, horloge locale inchangée.`;
      if (!rapport.entrees.some((e) => e.genre === 'horloge' && e.champ === appareil && e.texte === description)) {
        rapport.entrees.push(entree('horloge', SYNC_KEY, appareil, description));
      }
      return;
    }
    etat.horloge.observer(tampon, maintenant);
  }

  /** Le plus grand tampon des champs d'un élément (champ sans tampon = rien). */
  function plusGrandTampon(item) {
    let sommet = '';
    const h = item && item.h;
    if (h && typeof h === 'object') for (const t of Object.values(h)) if (typeof t === 'string' && t > sommet) sommet = t;
    return sommet;
  }

  /** Fusionne deux versions du même élément : champ par champ, le plus grand
   * tampon gagne ; compteur HOTP = valeur maximale ; dernières utilisations = la
   * plus récente (sans compter comme une modification). Renvoie les conflits (le
   * même champ changé des deux côtés depuis le repère, deux valeurs différentes). */
  function fusionnerItems(gauche, droite, collection, repere) {
    const conflits = [];
    if (!gauche || typeof gauche !== 'object' || !droite || typeof droite !== 'object') return conflits;
    const copieGauche = JSON.parse(JSON.stringify(gauche));
    const copieDroite = JSON.parse(JSON.stringify(droite));
    const h = gauche.h && typeof gauche.h === 'object' && !Array.isArray(gauche.h) ? { ...gauche.h } : {};

    for (const champ of collection.champs) {
      const valeurGauche = champDe(gauche, champ);
      const valeurDroite = champDe(droite, champ);
      const tg = tamponDe(gauche, champ);
      const td = tamponDe(droite, champ);
      const [valeur, tampon] = td > tg ? [valeurDroite, td] : [valeurGauche, tg];
      if (valeur !== null || champ in gauche) gauche[champ] = valeur;
      if (tampon) h[champ] = tampon;
      // Conflit : le même champ a changé des deux côtés depuis le repère de
      // dernière synchro, avec deux valeurs différentes.
      if (tg > repere && td > repere && !jsonEgal(valeurGauche, valeurDroite)) {
        const [gagnant, perdant, tamponGagnant] = td > tg ? [valeurDroite, valeurGauche, td] : [valeurGauche, valeurDroite, tg];
        conflits.push([champ, { valeur: gagnant, tampon: tamponGagnant }, perdant]);
      }
    }

    // HOTP : la valeur maximale, quel que soit le tampon — jamais de réutilisation
    // de code. Le tampon du champ suit l'appareil qui portait la valeur maximale.
    // Les valeurs se lisent AVANT la fusion des champs (qui a pu écraser la gauche).
    const cg = typeof copieGauche.counter === 'number' ? copieGauche.counter : undefined;
    const cd = typeof copieDroite.counter === 'number' ? copieDroite.counter : undefined;
    if (cg !== undefined && cd !== undefined) {
      if (cg > cd) {
        gauche.counter = cg;
        const tampon = tamponDe(copieGauche, 'counter');
        if (tampon) h.counter = tampon;
      } else if (cd > cg) {
        gauche.counter = cd;
        const tampon = tamponDe(copieDroite, 'counter');
        if (tampon) h.counter = tampon;
      }
    }

    // Trace de suppression : le plus grand tampon.
    const tga = traceDe(gauche);
    const tdr = traceDe(droite);
    const trace = tga && tdr ? tamponMax(tga, tdr) : tga || tdr || null;
    if (trace) gauche.t = trace;
    else delete gauche.t;

    // Champs dérivés : updatedAt du plus grand tampon, passwordChangedAt du tampon
    // du mot de passe, dernière utilisation = la plus récente, création = la plus
    // ancienne. Les tampons sont resérialisés dans l'ordre canonique des champs
    // (deux côtés doivent écrire la même chaîne, quel que soit l'ordre où leurs
    // éditions sont arrivées).
    const hCanonique = {};
    for (const champ of collection.champs) if (h[champ]) hCanonique[champ] = h[champ];
    gauche.h = hCanonique;
    const sommet = plusGrandTampon(gauche);
    if (sommet) gauche.updatedAt = isoDepuisTampon(sommet);
    if (collection.cle === LOGINS_KEY) {
      const tp = tamponDe(gauche, 'password');
      if (tp) gauche.passwordChangedAt = isoDepuisTampon(tp);
    }
    const usedG = texte(gauche, 'usedAt');
    const usedD = texte(droite, 'usedAt');
    if (usedD > usedG) gauche.usedAt = usedD;
    const createdG = texte(gauche, 'createdAt');
    const createdD = texte(droite, 'createdAt');
    if (createdD && (!createdG || createdD < createdG)) gauche.createdAt = createdD;
    return conflits;
  }

  /** Le résultat diffère-t-il de la copie distante (toutes les clés présentes) ?
   * Comparaison sémantique (JSON parsé) : deux objets aux mêmes paires clé-valeur
   * mais d'ordres de sérialisation différents sont le même contenu — les comparer
   * en texte ferait se renvoyer les appareils sans fin. */
  function differentDe(resultat, distante) {
    const cles = new Set([...Object.keys(resultat || {}), ...Object.keys(distante || {})]);
    for (const cle of cles) {
      const a = resultat[cle];
      const b = distante[cle];
      if (a === b) continue;
      if (a === undefined || b === undefined) return true;
      let xa, xb;
      try {
        xa = JSON.parse(a);
        xb = JSON.parse(b);
      } catch {
        return true;
      }
      if (!jsonEgal(xa, xb)) return true;
    }
    return false;
  }

  /** Applique les traces v1 en attente aux éléments qui arrivent (un élément
   * apparu après coup sous un id déjà supprimé reste supprimé si sa trace est
   * plus récente que ses champs) ; les appliquées sortent du marqueur. */
  function appliquerV1(resultat, marqueur, rapport) {
    const ids = Object.keys(marqueur.v1);
    if (!ids.length) return;
    const restants = { ...marqueur.v1 };
    let total = 0;
    for (const collection of COLLECTIONS) {
      if (!(collection.cle in resultat)) continue;
      const items = liste(resultat, collection.cle);
      let changements = 0;
      const faits = items.map((item) => {
        const id = texte(item, 'id');
        if (id in restants) {
          const trace = restants[id];
          if (plusGrandTampon(item) < trace) {
            const fait = { ...item, t: trace };
            changements++;
            delete restants[id];
            return fait;
          }
          delete restants[id];
        }
        return item;
      });
      if (changements) {
        ecrireListe(resultat, collection.cle, faits);
        total += changements;
      }
    }
    if (total) {
      rapport.entrees.push(
        entree('depart', 'collections', '', `Suppressions v1 rattachées à des éléments arrivés entre-temps (${total}).`)
      );
    }
    marqueur.v1 = restants;
  }

  function fusionnerHistorique(locale, distante, videLe, resultat, rapport) {
    const vues = new Map();
    for (const entreeH of [...liste(locale, HISTORY_KEY), ...liste(distante, HISTORY_KEY)]) {
      if (!entreeH || typeof entreeH.id !== 'string' || vues.has(entreeH.id)) continue;
      if (videLe) {
        const ms = isoVersMs(entreeH.at) || 0;
        if (ms <= decoderL(videLe)) continue;
      }
      vues.set(entreeH.id, entreeH);
    }
    const histoire = [...vues.values()]
      .sort((a, b) => (b.at || '').localeCompare(a.at || '') || (a.id || '').localeCompare(b.id || ''))
      .slice(0, HISTORY_MAX);
    const avant = Math.max(liste(locale, HISTORY_KEY).length, liste(distante, HISTORY_KEY).length);
    if (histoire.length < avant) {
      rapport.entrees.push(entree('vidage', HISTORY_KEY, '', 'Historique écourté par le vidage le plus récent.'));
    }
    ecrireListe(resultat, HISTORY_KEY, histoire);
  }

  /** Réglages : union par nom, le plus grand tampon (`h`, sinon `at`) l'emporte.
   * Absents des deux côtés : rien d'écrit. */
  function fusionnerReglages(locale, distante, resultat) {
    if (!(SETTINGS_KEY in locale) && !(SETTINGS_KEY in distante)) return;
    const objet = (map) => {
      try {
        const value = JSON.parse(map[SETTINGS_KEY]);
        return value && typeof value === 'object' && !Array.isArray(value) ? value : {};
      } catch {
        return {};
      }
    };
    const tamponReglage = (entreeR) => {
      if (entreeR && typeof entreeR.h === 'string' && entreeR.h) return entreeR.h;
      return tamponDepuisIso(entreeR && typeof entreeR.at === 'string' ? entreeR.at : '');
    };
    const out = { ...objet(locale) };
    for (const [nom, entreeR] of Object.entries(objet(distante))) {
      if (!entreeR || typeof entreeR !== 'object' || Array.isArray(entreeR)) continue;
      if (!out[nom] || tamponReglage(entreeR) > tamponReglage(out[nom])) out[nom] = entreeR;
    }
    resultat[SETTINGS_KEY] = JSON.stringify(out);
  }

  /** Élagage des traces : un élément supprimé dont la trace a été vue par tous
   * les appareils actifs (registre du marqueur) ET dont la rétention est écoulée
   * sort de la copie. */
  function elaguer(resultat, marqueur, etat, maintenant, rapport) {
    for (const collection of COLLECTIONS) {
      if (!(collection.cle in resultat)) continue;
      const items = liste(resultat, collection.cle);
      let effaces = 0;
      const faits = [];
      for (const item of items) {
        const trace = traceDe(item);
        if (trace && plusGrandTampon(item) <= trace) {
          // « Vue par tous les appareils actifs » : au moins un autre appareil au
          // registre, chacun avec un repère qui couvre la trace, et la rétention
          // écoulée (un appareil nouveau ou hors ligne pendant la suppression
          // doit avoir le temps de l'apprendre). Registre vide ou trace
          // récente : on garde.
          const pairs = Object.entries(marqueur.appareils).filter(([a]) => a !== etat.appareil);
          const vuPartout = pairs.length > 0 && pairs.every(([, vu]) => vu.vu >= trace);
          const retenue = maintenant - decoderL(trace) >= RETENTION_TRACE_MS;
          if (vuPartout && retenue) {
            effaces++;
            continue; // trace propagée partout : l'élément sort de la copie
          }
        }
        faits.push(item);
      }
      if (effaces) {
        ecrireListe(resultat, collection.cle, faits);
        const nom = collection.cle === LOGINS_KEY ? 'logins' : collection.cle === PASSKEYS_KEY ? 'passkeys' : 'comptes';
        rapport.entrees.push(
          entree(
            'trace',
            collection.cle,
            nom,
            `Traces de suppression vues par tous les appareils actifs : ${effaces} élément(s) effacé(s) de la copie.`
          )
        );
      }
    }
  }

  /** Fusionne la copie locale avec la copie distante (Drive). Renvoie la copie
   * fusionnée (à écrire en local) et le rapport (à chiffrer dans le journal).
   * `maintenant` est T() en ms (SYN-08) : la fusion ne lit jamais l'horloge. */
  function fusion(locale, distante, etat, maintenant) {
    const rapport = { entrees: [], aEnvoyer: false };
    const local = migrer(locale, maintenant, etat.appareil);
    const distant = migrer(distante, maintenant, etat.appareil);
    const resultat = { ...local };

    // ── Marqueur : registre des appareils (union par le plus grand tampon, les
    // muets d'un an retirés), vidage d'historique, traces v1 en attente.
    const marqueur = fusionnerMarqueurs(lireMarqueur(local), lireMarqueur(distant), maintenant, rapport);
    for (const vu of Object.values(marqueur.appareils)) surveiller(vu.vu, etat, maintenant, rapport);
    if (marqueur.historiqueVideLe) surveiller(marqueur.historiqueVideLe, etat, maintenant, rapport);
    for (const t of Object.values(marqueur.v1)) surveiller(t, etat, maintenant, rapport);

    // ── Collections : champ par champ.
    const aEnterrer = [];
    for (const collection of COLLECTIONS) {
      if (!collection.toujours && !(collection.cle in local) && !(collection.cle in distant)) continue;
      // Union par id : même id → fusion champ par champ (la locale d'abord, la
      // distante fusionnée dedans — le résultat ne dépend pas de l'ordre).
      const parId = [];
      for (const item of [...liste(local, collection.cle), ...liste(distant, collection.cle)]) {
        if (!item || typeof item.id !== 'string') continue;
        const position = parId.findIndex((i) => i.id === item.id);
        if (position === -1) parId.push(JSON.parse(JSON.stringify(item)));
        else {
          for (const [champ, gagnant, perdant] of fusionnerItems(parId[position], item, collection, etat.repere)) {
            rapport.entrees.push(
              entree(
                'conflit',
                collection.cle,
                `${item.id}.${champ}`,
                'Conflit : le même champ a changé des deux côtés depuis la dernière synchro.',
                gagnant,
                perdant
              )
            );
          }
        }
      }
      // Doublons de même identité (même élément ajouté des deux côtés, ou deux
      // ajouts hors ligne) : fusionnés champ par champ, l'identifiant le plus
      // ancien fait foi, l'autre est enterré d'un tampon déterministe (les deux
      // côtés calculent le même, où qu'ils soient).
      parId.sort((a, b) => (texte(a, 'createdAt') || '').localeCompare(texte(b, 'createdAt') || '') || (a.id || '').localeCompare(b.id || ''));
      const identitesVues = new Set();
      const items = [];
      for (const item of parId) {
        if (!estVivant(item)) {
          items.push(item); // mort : gardé pour propager la trace, invisible côté interface
          continue;
        }
        const identite = collection.identite(item);
        if (identitesVues.has(identite)) {
          const idPerdu = item.id;
          const position = items.findIndex((i) => estVivant(i) && collection.identite(i) === identite);
          if (position !== -1) {
            fusionnerItems(items[position], item, collection, etat.repere);
            const sommet = plusGrandTampon(items[position]);
            const enterre = encoderTampon(decoderL(sommet), decoderC(sommet) + 1, APPAREIL_HERITAGE);
            aEnterrer.push([idPerdu, enterre]);
            rapport.entrees.push(
              entree(
                'doublon',
                collection.cle,
                idPerdu,
                "Doublon de même identité : fusionné champ par champ dans l'élément le plus ancien, cet identifiant enterré."
              )
            );
            continue;
          }
        }
        identitesVues.add(identite);
        items.push(item);
      }
      ecrireListe(resultat, collection.cle, items);
    }

    // ── Tombstones v1 en attente : appliqués aux éléments qui arrivent ; les ids
    // enterrés comme doublons le sont pour tout le monde de la même façon.
    for (const [id, tampon] of aEnterrer) {
      if (marqueur.v1[id]) marqueur.v1[id] = tamponMax(marqueur.v1[id], tampon);
      else marqueur.v1[id] = tampon;
    }
    appliquerV1(resultat, marqueur, rapport);

    // ── Historique : union par id, sans ce qui précède le vidage, plafonné.
    fusionnerHistorique(local, distant, marqueur.historiqueVideLe, resultat, rapport);

    // ── Réglages : union par nom, le plus grand tampon gagne.
    fusionnerReglages(local, distant, resultat);

    // ── Élagage : traces vues par tous (et rétention écoulée) effacées.
    elaguer(resultat, marqueur, etat, maintenant, rapport);

    // ── Le repère avance au plus grand tampon vu — jamais à un tampon créé :
    // une fusion sans rien de nouveau ne doit rien changer au marqueur, sinon
    // les appareils se renverraient des mises à jour sans fin.
    let repere = etat.repere;
    for (const collection of COLLECTIONS) {
      for (const item of liste(resultat, collection.cle)) {
        const sommet = plusGrandTampon(item);
        surveiller(sommet, etat, maintenant, rapport);
        repere = tamponMax(repere, sommet);
        const trace = traceDe(item);
        if (trace) {
          surveiller(trace, etat, maintenant, rapport);
          repere = tamponMax(repere, trace);
        }
      }
    }
    for (const vu of Object.values(marqueur.appareils)) repere = tamponMax(repere, vu.vu);
    if (marqueur.historiqueVideLe) repere = tamponMax(repere, marqueur.historiqueVideLe);
    etat.repere = repere;
    // L'appareil publie son repère (les traces qu'il a vues pourront être
    // effacées) et son activité fraîche : il ne se fera pas retirer du registre
    // tant qu'il se synchronise. Il se décrit s'il sait le faire (SYN-09), sinon
    // garde la description reçue.
    const precedent = marqueur.appareils[etat.appareil];
    const description = etat.type ? lireDescription(etat) : lireDescription(precedent);
    // Récente : à moins d'un jour, dans un sens comme dans l'autre — T() peut reculer quand il
    // est corrigé par une référence publique (SYN-08) ; l'activité ne doit pas reculer avec lui.
    const actifRecent = precedent && precedent.actifLe > 0 && Math.abs(maintenant - precedent.actifLe) < ACTIVITE_PAS_MS;
    if (actifRecent) {
      // D'abord l'entrée telle que la copie distante la porte déjà (rien à republier), puis
      // le repère frais sans toucher à l'activité.
      const publiee = lireMarqueur(distant).appareils[etat.appareil];
      const candidats = [];
      // Jamais de recul : ni du repère, ni de l'activité la plus récente connue.
      if (publiee && publiee.vu <= etat.repere && publiee.actifLe >= precedent.actifLe) {
        candidats.push({ vu: publiee.vu, actifLe: publiee.actifLe, ...description });
      }
      candidats.push({ vu: etat.repere, actifLe: precedent.actifLe, ...description });
      for (const soi of candidats) {
        marqueur.appareils[etat.appareil] = soi;
        ecrireMarqueur(resultat, marqueur);
        if (!differentDe(resultat, distant)) {
          rapport.aEnvoyer = false;
          return { donnees: resultat, rapport };
        }
      }
    }
    marqueur.appareils[etat.appareil] = { vu: etat.repere, actifLe: maintenant, ...description };
    ecrireMarqueur(resultat, marqueur);

    rapport.aEnvoyer = differentDe(resultat, distant);
    return { donnees: resultat, rapport };
  }

  /** Fusionne les registres des deux copies. Les appareils muets depuis plus d'un
   * an (aucune synchro) sont retirés — le filtrage fait partie de l'union, mêmes
   * entrées et même horloge de référence de chaque côté, sinon l'entrée retirée
   * par un côté réapparaîtrait par l'autre et les appareils ne convergeraient pas. */
  function fusionnerMarqueurs(a, b, maintenant, rapport) {
    const appareils = {};
    const poser = (id, vu) => {
      if (!appareils[id]) appareils[id] = { vu: vu.vu, actifLe: vu.actifLe, ...lireDescription(vu) };
      else {
        // La description se choisit sur les entrées d'origine, avant le max d'actifLe.
        const description = descriptionGagnante(appareils[id], vu);
        appareils[id] = {
          vu: tamponMax(appareils[id].vu, vu.vu),
          actifLe: Math.max(appareils[id].actifLe, vu.actifLe),
          ...description,
        };
      }
    };
    for (const [id, vu] of Object.entries(a.appareils)) poser(id, vu);
    for (const [id, vu] of Object.entries(b.appareils)) poser(id, vu);
    const muets = [];
    for (const [id, vu] of Object.entries(appareils)) {
      if (vu.actifLe > 0 && vu.actifLe < maintenant - SILENCE_MAX_MS) {
        muets.push(id);
        delete appareils[id];
      }
    }
    for (const appareil of muets) {
      rapport.entrees.push(
        entree(
          'appareil',
          SYNC_KEY,
          appareil,
          "Appareil muet depuis plus d'un an, retiré du registre : ses traces de suppression pourraient revenir s'il se réveille."
        )
      );
    }
    const v1 = {};
    for (const [id, t] of Object.entries(a.v1)) v1[id] = t;
    for (const [id, t] of Object.entries(b.v1)) {
      v1[id] = v1[id] ? tamponMax(v1[id], t) : t;
    }
    const historiqueVideLe =
      a.historiqueVideLe && b.historiqueVideLe
        ? tamponMax(a.historiqueVideLe, b.historiqueVideLe)
        : a.historiqueVideLe || b.historiqueVideLe || null;
    return { appareils, historiqueVideLe, v1 };
  }

  return {
    SYNC_KEY,
    APPAREIL_HERITAGE,
    COLLECTIONS,
    ECART_FUTUR_MS,
    SILENCE_MAX_MS,
    RETENTION_TRACE_MS,
    ACTIVITE_PAS_MS,
    Horloge,
    encoderTampon,
    decoderL,
    decoderC,
    decoderAppareil,
    tamponMax,
    tamponDepuisIso,
    isoDepuisTampon,
    isoVersMs,
    estVivant,
    migrer,
    fusion,
    nouvelEtat,
    etatPersistant,
    APPAREIL_KEY,
    HORLOGE_KEY,
    differentDe,
    jsonEgal,
    lireMarqueur,
    plusGrandTampon,
  };
});
