/*
 * Synchro v2 avec Google Drive (SYN-10) — le cycle de l'app web et de l'extension,
 * même déroulé que le démon Linux (linux/crates/mymfa-linux/src/demon.rs) :
 *   1. lire la copie Drive (mymfa-vault.json, appDataFolder) en notant sa version ;
 *   2. l'ouvrir avec la clé de ce coffre — une autre clé est un autre coffre : pas de
 *      fusion (driveOtherVault), « Restaurer » reste le moyen de l'adopter ;
 *   3. fusionner champ par champ (Sync2.fusion), écrire en local si cela change ;
 *   4. envoyer si la fusion apporte quelque chose à Drive, après avoir revérifié que
 *      Drive n'a pas changé entre-temps — sinon relire et refusionner (3 tours) ;
 *   5. consigner le cycle dans le journal de l'appareil (chiffré, jamais synchronisé) :
 *      changements reçus et envoyés (élément, champs, appareil auteur et date, tirés des
 *      tampons), conflits (valeurs sensibles jamais écrites), doublons, horloges.
 * Dépendances injectées (testable sous Node) : client Drive, coffre, état d'appareil.
 */
(function (root, factory) {
  const req = (name, path) => root[name] || (typeof require === 'function' ? require(path) : null);
  const api = factory(req('Sync2', './sync2.js'), req('Vault', './vault.js'), req('Store', './store.js'));
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.DriveSync = api;
})(typeof self !== 'undefined' ? self : globalThis, function (Sync2, Vault, Store) {
  'use strict';

  const TOURS_MAX = 3;
  /** Archives gardées sur Drive : au-delà, les plus anciennes sont supprimées. */
  const ARCHIVES_GARDEES = 30;
  const LISTE_MAX = 50; // éléments détaillés par sens et par cycle (les totaux restent exacts)
  /** Champs dont la valeur n'entre jamais dans le journal, même chiffré. */
  const SENSIBLES = new Set(['secret', 'password', 'privateKey', 'note', 'userHandle']);
  const NOMS_COLLECTIONS = {
    [Store.ACCOUNTS_KEY]: 'accounts',
    [Store.LOGINS_KEY]: 'logins',
    [Store.PASSKEYS_KEY]: 'passkeys',
  };

  class SyncError extends Error {
    constructor(code) {
      super(code);
      this.code = code;
    }
  }

  function liste(map, cle) {
    try {
      const v = JSON.parse((map || {})[cle] || '[]');
      return Array.isArray(v) ? v : [];
    } catch {
      return [];
    }
  }

  function hote(origin) {
    try {
      return new URL(origin).host;
    } catch {
      return String(origin || '');
    }
  }

  /** Libellé lisible d'un élément (jamais un secret). */
  function libelle(cle, item) {
    const parts =
      cle === Store.LOGINS_KEY
        ? [hote(item.origin), item.username] // comme l'historique : site — identifiant
        : cle === Store.PASSKEYS_KEY
        ? [item.rpName || item.rpId, item.userName]
        : [item.issuer, item.account];
    return parts.filter(Boolean).join(' — ');
  }

  const tamponDe = (item, champ) => (item && item.h && typeof item.h[champ] === 'string' ? item.h[champ] : '');
  const auteur = (tampon) => (tampon ? { appareil: Sync2.decoderAppareil(tampon), at: Sync2.isoDepuisTampon(tampon) } : { appareil: null, at: null });

  /**
   * Ce qui distingue `apres` de `avant`, élément par élément : ajouts, modifications
   * (champs dont le tampon a changé), suppressions — chacun avec l'appareil auteur et
   * la date du tampon qui l'a emporté. Les dernières utilisations ne comptent pas.
   */
  function changements(avant, apres) {
    const out = [];
    for (const collection of Sync2.COLLECTIONS) {
      const precedents = new Map(liste(avant, collection.cle).filter((i) => i && i.id).map((i) => [i.id, i]));
      const vus = new Set();
      for (const item of liste(apres, collection.cle)) {
        if (!item || !item.id) continue;
        vus.add(item.id);
        const prev = precedents.get(item.id);
        const vivant = Sync2.estVivant(item);
        const etaitVivant = Boolean(prev) && Sync2.estVivant(prev);
        const base = { collection: NOMS_COLLECTIONS[collection.cle], id: item.id, libelle: libelle(collection.cle, item) };
        if (vivant && !etaitVivant) {
          out.push({ ...base, action: 'ajout', ...auteur(Sync2.plusGrandTampon(item)) });
        } else if (!vivant && etaitVivant) {
          out.push({ ...base, action: 'suppression', ...auteur(item.t) });
        } else if (vivant) {
          const champs = collection.champs.filter((c) => tamponDe(item, c) !== tamponDe(prev, c));
          if (!champs.length) continue;
          const sommet = champs.map((c) => tamponDe(item, c)).reduce((a, b) => (b > a ? b : a), '');
          out.push({ ...base, action: 'modification', champs, ...auteur(sommet) });
        }
      }
      // Élément vivant disparu sans trace (élagage inattendu) : une suppression d'auteur inconnu.
      for (const [id, prev] of precedents) {
        if (!vus.has(id) && Sync2.estVivant(prev)) {
          out.push({ collection: NOMS_COLLECTIONS[collection.cle], id, libelle: libelle(collection.cle, prev), action: 'suppression', appareil: null, at: null });
        }
      }
    }
    return out;
  }

  function totaux(liste) {
    const t = { ajout: 0, modification: 0, suppression: 0 };
    for (const c of liste) t[c.action] += 1;
    return t;
  }

  /** Valeur de conflit présentable : les champs sensibles sont masqués, le reste abrégé. */
  function valeurJournal(champ, valeur) {
    if (SENSIBLES.has(champ)) return { masque: true };
    const texte = typeof valeur === 'string' ? valeur : JSON.stringify(valeur);
    return { valeur: texte && texte.length > 80 ? `${texte.slice(0, 79)}…` : texte ?? null };
  }

  /** Les entrées du rapport de fusion, mises en forme pour le journal. */
  function entreesRapport(rapport, donnees) {
    const libelles = new Map();
    for (const collection of Sync2.COLLECTIONS) {
      for (const item of liste(donnees, collection.cle)) if (item && item.id) libelles.set(item.id, libelle(collection.cle, item));
    }
    const conflits = [];
    const autres = [];
    for (const e of rapport.entrees) {
      if (e.genre === 'conflit') {
        const point = e.champ.lastIndexOf('.');
        const id = e.champ.slice(0, point);
        const champ = e.champ.slice(point + 1);
        conflits.push({
          collection: NOMS_COLLECTIONS[e.cle] || e.cle,
          id,
          libelle: libelles.get(id) || '',
          champ,
          gagnant: { ...auteur(e.gagnant && e.gagnant.tampon), ...valeurJournal(champ, e.gagnant && e.gagnant.valeur) },
          perdant: valeurJournal(champ, e.perdant),
        });
      } else {
        autres.push({ genre: e.genre, champ: e.champ, libelle: libelles.get(e.champ) || '', texte: e.texte });
      }
    }
    return { conflits, autres };
  }

  const resumeFichier = (f) => (f ? { name: f.name, size: f.size, createdTime: f.createdTime, modifiedTime: f.modifiedTime } : null);

  function identifiant() {
    try {
      return Vault.toB64Url(Vault.randomBytes(9));
    } catch {
      return Math.random().toString(36).slice(2);
    }
  }

  /**
   * client  : { find(), download(fichier), upload(contenu, fichier) } (js/drive.js)
   * coffre  : { donnees(), dechiffrerAutre(record), remplacerDonnees(map, avant), exporter(), ajouterJournal(entree) }
 *           (donnees peut être asynchrone ; remplacerDonnees reçoit aussi la copie lue avant la fusion)
   * temps   : état d'appareil persistant (Sync2.etatPersistant) — { appareil, etat, persister() }
   * maintenant : T() en ms ; source : 'app' | 'extension' (qui conduit le cycle) ;
   * surFichier(meta) : métadonnées du fichier Drive lu ou écrit (nom, taille, dates) ;
   * surHeure(meta) : réponse à un ENVOI — son modifiedTime est l'heure des serveurs Google
   *   à l'instant de l'écriture (SYN-08). Celui d'un fichier simplement lu date de sa
   *   dernière modification : jamais une référence d'heure.
   */
  function creer({ client, coffre, temps, maintenant = () => Date.now(), source = 'app', surFichier = () => {}, surHeure = () => {} }) {
    async function cycle() {
      const base = { id: identifiant(), at: new Date(maintenant()).toISOString(), source, appareil: temps.appareil };
      try {
        for (let tour = 1; tour <= TOURS_MAX; tour++) {
          const fichier = await client.find();
          let distante = {};
          if (fichier) {
            surFichier(fichier);
            const lu = await client.download(fichier);
            const record = Vault.parse(lu.content);
            if (!record) throw new SyncError('invalidBackup');
            try {
              distante = await coffre.dechiffrerAutre(record);
            } catch {
              throw new SyncError('driveOtherVault');
            }
          }

          const avant = await coffre.donnees();
          const { donnees, rapport } = Sync2.fusion(avant, distante, temps.etat, maintenant());
          temps.persister();
          if (Sync2.differentDe(donnees, avant)) await coffre.remplacerDonnees(donnees, avant);

          let envoye = false;
          let meta = fichier;
          if (!fichier || rapport.aEnvoyer) {
            // Drive a-t-il bougé depuis la lecture ? Alors relire et refusionner.
            const actuel = await client.find();
            const inchange = fichier
              ? actuel && actuel.id === fichier.id && actuel.modifiedTime === fichier.modifiedTime && (actuel.headRevisionId || '') === (fichier.headRevisionId || '')
              : !actuel;
            if (!inchange) {
              if (tour < TOURS_MAX) continue;
              throw new SyncError('driveCourse');
            }
            meta = await client.upload(await coffre.exporter(), actuel || null);
            surFichier(meta);
            surHeure(meta);
            envoye = true;
          }

          const recus = changements(avant, donnees);
          const envoyes = envoye ? changements(Sync2.migrer(distante, 0, temps.appareil), donnees) : [];
          const entree = {
            ...base,
            resultat: !fichier ? 'premier' : envoye ? 'envoye' : recus.length ? 'recu' : 'aJour',
            tour,
            totaux: { recus: totaux(recus), envoyes: totaux(envoyes) },
            recus: recus.slice(0, LISTE_MAX),
            envoyes: envoyes.slice(0, LISTE_MAX),
            ...entreesRapport(rapport, donnees),
            fichier: resumeFichier(meta),
          };
          await coffre.ajouterJournal(entree);
          return entree;
        }
        throw new SyncError('driveCourse');
      } catch (err) {
        const code = (err && err.code) || 'generic';
        try {
          await coffre.ajouterJournal({ ...base, resultat: code === 'driveOtherVault' ? 'autreCoffre' : 'erreur', code });
        } catch {
          /* journal indisponible (verrouillé entre-temps) */
        }
        throw err;
      }
    }
    return { cycle };
  }

  const resumeArchive = (f) => (f ? { id: f.id, name: f.name, size: f.size, createdTime: f.createdTime } : null);

  /**
   * Archive (sauvegarde figée) : une copie du coffre chiffré dans un fichier à part,
   * mymfa-backup-<date>.json — écrite une fois, jamais modifiée ensuite, restaurable.
   * Rien n'est fait si la plus récente a moins de `intervalleMs` (sauf `force`). Au-delà
   * de `garder` archives, les plus anciennes sont supprimées (jamais celle qui vient
   * d'être écrite). Consignée dans le journal de l'appareil.
   * Réponse : { archive (ou null), archives (après rétention), supprimees }.
   */
  async function archiver({ client, coffre, appareil, source = 'app', intervalleMs = 0, force = false, garder = ARCHIVES_GARDEES, maintenant = () => Date.now() }) {
    const archives = await client.listArchives();
    const derniere = archives[0];
    if (!force && derniere && Date.parse(derniere.createdTime) > maintenant() - intervalleMs) {
      return { archive: null, archives, supprimees: [] };
    }
    const contenu = await coffre.exporter();
    if (!Vault.parse(contenu)) throw new SyncError('locked');
    const archive = await client.createArchive(contenu, { appareil: appareil || '', source }, new Date(maintenant()));
    const toutes = [archive, ...archives.filter((a) => a.id !== archive.id)];
    const supprimees = [];
    for (const vieille of toutes.slice(Math.max(1, garder))) {
      await client.remove(vieille.id);
      supprimees.push(vieille.name);
    }
    try {
      await coffre.ajouterJournal({
        id: identifiant(),
        at: new Date(maintenant()).toISOString(),
        source,
        appareil,
        resultat: 'archive',
        archive: resumeArchive(archive),
        supprimees: supprimees.length,
      });
    } catch {
      /* journal indisponible : l'archive est faite quand même */
    }
    return { archive, archives: toutes.slice(0, Math.max(1, garder)), supprimees };
  }

  return { creer, archiver, changements, SyncError, SENSIBLES, TOURS_MAX, ARCHIVES_GARDEES };
});
