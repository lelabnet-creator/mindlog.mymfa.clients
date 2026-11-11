/*
 * Heure de référence T() (SYN-08, côté navigateur) : correction par l'heure
 * des serveurs Google (Drive), seuils de correction (2 s) et d'alerte (5 min),
 * hors ligne = dernier décalage connu marqué non vérifié.
 */
const test = require('node:test');
const assert = require('node:assert');
const Heure = require('../js/heure.js');

test('T() suit l\u2019horloge locale tant qu\u2019aucune référence n\u2019est reçue, marquée non vérifiée', () => {
  let locale = 1_000_000;
  const h = Heure.create({ horloge: () => locale, depart: locale });
  assert.strictEqual(h.maintenant(), 1_000_000);
  assert.strictEqual(h.etat().verifiee, false);
  const entree = h.entreeJournal();
  assert.strictEqual(entree.genre, 'horloge');
  assert.ok(entree.texte.includes('non vérifiée'));
});

test('décalage de bruit (\u2264 2 s) : rien ne change', () => {
  let locale = 1_000_000;
  const h = Heure.create({ horloge: () => locale });
  const mesure = h.recevoirReference(1_000_000 + 1500, locale);
  assert.strictEqual(mesure.corrige, false);
  assert.ok(!mesure.alerte);
  assert.strictEqual(h.maintenant(), 1_000_000); // pas de correction
  assert.strictEqual(h.entreeJournal(), null);
  assert.ok(h.etat().verifiee);
});

test('décalage > 2 s : corrigé, sans alerte en dessous de 5 min', () => {
  let locale = 1_000_000;
  const h = Heure.create({ horloge: () => locale });
  const mesure = h.recevoirReference(1_000_000 + 2500, locale);
  assert.strictEqual(mesure.corrige, true);
  assert.ok(!mesure.alerte);
  locale += 500;
  assert.strictEqual(h.maintenant(), 1_000_000 + 2500 + 500);
  assert.strictEqual(h.entreeJournal(), null);
});

test('décalage > 5 min : corrigé ET alerte journalisée', () => {
  let locale = 1_000_000;
  const h = Heure.create({ horloge: () => locale });
  const mesure = h.recevoirReference(1_000_000 + 6 * 60 * 1000, locale);
  assert.strictEqual(mesure.corrige, true);
  assert.ok(mesure.alerte);
  const entree = h.entreeJournal();
  assert.strictEqual(entree.genre, 'horloge');
  assert.ok(entree.texte.includes('en avance'));
  assert.ok(entree.texte.includes('6 min'));
  assert.ok(h.etat().alerte);
  // Retour à la normale : l'alerte tombe.
  h.recevoirReference(locale + 3000, locale);
  assert.strictEqual(h.entreeJournal(), null);
  assert.strictEqual(h.etat().alerte, null);
});

test('horloge en retard : la correction va vers le futur, alerte symétrique', () => {
  let locale = 1_000_000;
  const h = Heure.create({ horloge: () => locale });
  const mesure = h.recevoirReference(1_000_000 - 7 * 60 * 1000, locale);
  assert.strictEqual(mesure.corrige, true);
  assert.ok(mesure.alerte);
  assert.ok(h.entreeJournal().texte.includes('en retard'));
});

test('hors ligne après une référence : dernier décalage connu, non vérifié à la reprise', () => {
  let locale = 1_000_000;
  const h = Heure.create({ horloge: () => locale });
  h.recevoirReference(1_000_000 + 10_000, locale);
  // La session suivante reprend le dernier décalage connu (persisté par l'app) :
  // nouvelle référence, non vérifiée, qui applique le décalage connu.
  const reprise = Heure.create({ horloge: () => locale + 5000 });
  assert.strictEqual(reprise.etat().verifiee, false);
  reprise.recevoirReference(1_000_000 + 10_000 + 5000, locale + 5000);
  assert.strictEqual(reprise.etat().verifiee, true);
  assert.strictEqual(reprise.etat().decalageMs, 10_000);
});

test('heureDrive : extraire l\u2019heure des serveurs Google d\u2019une entrée Drive', () => {
  assert.strictEqual(Heure.heureDrive({ modifiedTime: '2026-11-11T14:05:00.000Z' }), 1_794_405_900_000);
  assert.strictEqual(Heure.heureDrive({}), null);
  assert.strictEqual(Heure.heureDrive(null), null);
  assert.strictEqual(Heure.heureDrive({ modifiedTime: 'bancal' }), null);
});
