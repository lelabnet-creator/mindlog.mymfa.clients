# Simulateur de la synchro myMFA (v1 ↔ v2)

Copie locale de l'explication de référence (artefact Claude du 11 novembre
2026) : la fusion actuelle v1 et ses défauts, la v2 (horloge hybride, fusion
champ par champ, suppressions datées), et un simulateur qui rejoue les cinq
scénarios avec les deux algorithmes (`runV1`, `runV2` — l'implémentation
JavaScript de référence de la v2).

Ouvrir `synchro-mymfa.html` dans un navigateur. Les cinq scénarios sont
rejoués en tests de non-régression côté Rust (`android/crates/mymfa-core/src/sync2.rs`)
et côté web (`web/test/sync2.test.js`).
