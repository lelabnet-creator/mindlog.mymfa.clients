/*
 * Heure de référence T() (SYN-08) : l'horloge de l'appareil corrigée par une
 * référence publique. Le navigateur ne parle pas NTP : la référence vient de
 * l'heure des serveurs Google renvoyée par Drive (modifiedTime d'un fichier,
 * transmise par TLS) — marquée « non vérifiée » tant qu'aucun échange Drive n'a
 * eu lieu, et après le dernier. Linux et Android ont leur propre référence
 * (NTS, SYN-08 côté Rust) : ce module ne les concerne pas.
 *
 *  - décalage ≤ 2 s : rien (bruit de mesure) ;
 *  - décalage > 2 s : corrigé — T() = horloge locale + décalage ;
 *  - décalage > 5 min : alerte (l'utilisateur doit revoir l'horloge de
 *    l'appareil), l'entrée est disponible pour le journal de synchro ;
 *  - hors ligne : dernier décalage connu, marqué « non vérifié ».
 *
 * L'horloge hybride (js/sync2.js) ne recule jamais : T() ne fait qu'alimenter
 * ses tics — un décalage corrigeant vers le passé ne fait pas reculer les
 * tampons déjà posés.
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.Heure = api;
})(typeof self !== 'undefined' ? self : globalThis, function () {
  'use strict';

  /** Décalage en dessous duquel la référence n'est pas appliquée (bruit). */
  const SEUIL_CORRECTION_MS = 2000;
  /** Décalage au-delà duquel l'utilisateur est alerté. */
  const SEUIL_ALERTE_MS = 5 * 60 * 1000;

  /**
   * Crée une référence de temps.
   * @param {object} options
   * @param {() => number} [options.horloge] l'horloge locale (Date.now par défaut) ;
   * @param {() => number} [options.depart] l'instant de création (tests) ;
   * @param {number} [options.decalageInitial] dernier décalage connu d'une
   *   session précédente — appliqué d'emblée, sans marquer la référence vérifiée
   *   (« hors ligne : dernier décalage connu, marqué non vérifié »).
   */
  function create({ horloge = () => Date.now(), depart = null, decalageInitial = 0 } = {}) {
    let decalage = Number.isFinite(decalageInitial) ? decalageInitial : 0;
    let verifiee = false;
    let depuisLe = depart ?? horloge();
    let alerte = null; // { decalageMs, depuisLe } tant que le décalage dépasse 5 min

    /** T() : l'heure de référence, en millisecondes. */
    function maintenant() {
      return horloge() + decalage;
    }

    /**
     * Reçoit l'heure d'un serveur de référence (heure Drive en ms, extraite de
     * `modifiedTime` au moment de la réponse). Mesure le décalage de l'horloge
     * locale, le corrige s'il dépasse 2 s, alerte au-delà de 5 min.
     * @param {number} heureServeur ms
     * @param {number} [heureLocale] horloge locale au moment de la réponse (tests)
     * @returns {{ decalageMs: number, corrige: boolean, alerte: boolean }}
     */
    function recevoirReference(heureServeur, heureLocale = horloge()) {
      if (!Number.isFinite(heureServeur)) return { decalageMs: 0, corrige: false, alerte: false };
      const decalageMs = heureServeur - heureLocale;
      const corrige = Math.abs(decalageMs) > SEUIL_CORRECTION_MS;
      if (corrige) {
        decalage = decalageMs;
        depuisLe = heureLocale;
      }
      verifiee = true;
      const alerteHorloge = Math.abs(decalageMs) > SEUIL_ALERTE_MS;
      alerte = alerteHorloge ? { decalageMs, depuisLe: heureLocale } : null;
      return { decalageMs, corrige, alerte: alerteHorloge };
    }

    /**
     * Entrée de journal pour la synchro (SYN-07) : décrit l'état de la référence.
     * Hors ligne (aucune référence reçue) ou alerte en cours : l'entrée dit quoi
     * faire ; sinon null (rien à journaliser).
     */
    function entreeJournal() {
      if (!verifiee) {
        return {
          genre: 'horloge',
          texte: "Heure de référence inconnue (hors ligne, aucun échange Drive) : horloge locale non vérifiée.",
        };
      }
      if (alerte) {
        const minutes = Math.round(Math.abs(alerte.decalageMs) / 60000);
        const sens = alerte.decalageMs > 0 ? "en avance" : "en retard";
        return {
          genre: 'horloge',
          texte: `Horloge de l'appareil ${sens} de ${minutes} min : corrigée par l'heure des serveurs Google, à revoir côté système.`,
        };
      }
      return null;
    }

    /** État lisible pour les réglages. */
    function etat() {
      return {
        verifiee,
        decalageMs: verifiee ? decalage : null,
        alerte: alerte ? { decalageMs: alerte.decalageMs } : null,
        T: maintenant(),
      };
    }

    return { maintenant, recevoirReference, entreeJournal, etat };
  }

  /**
   * Heure des serveurs Google extraite d'une réponse Drive : le champ
   * `modifiedTime` (ISO 8601, ex. « 2026-11-11T14:05:00.000Z ») du fichier ou du
   * résultat d'envoi. Renvoie des ms, ou null si absent.
   */
  function heureDrive(entreeDrive) {
    const iso = entreeDrive && entreeDrive.modifiedTime;
    if (!iso) return null;
    const ms = Date.parse(iso);
    return Number.isFinite(ms) ? ms : null;
  }

  return { create, heureDrive, SEUIL_CORRECTION_MS, SEUIL_ALERTE_MS };
});
