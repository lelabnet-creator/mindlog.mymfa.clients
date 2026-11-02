/*
 * Configuration de déploiement de myMFA.
 *
 * googleClientId : identifiant client OAuth « Application Web » de Google Cloud,
 * nécessaire pour la sauvegarde Google Drive (voir README, section Google Drive).
 * Ce n'est pas un secret : il est visible par le navigateur de toute façon.
 * Vide = sauvegarde Drive désactivée.
 */
window.MYMFA_CONFIG = {
  googleClientId: '399049616505-qopsl9safjogvkik16n0rded5tkv0cvf.apps.googleusercontent.com',
};
