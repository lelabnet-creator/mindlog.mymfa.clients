/*
 * Thème appliqué avant le premier rendu pour éviter un flash.
 * Fichier externe (et non script en ligne) : la CSP du serveur interdit les scripts inline,
 * et un hash dans la CSP casserait en silence à la moindre retouche de ce code.
 */
try {
  var savedTheme = localStorage.getItem('mymfa.theme');
  if (savedTheme === 'light' || savedTheme === 'dark') document.documentElement.dataset.theme = savedTheme;
} catch (e) { /* stockage indisponible : thème automatique */ }
