/*
 * Heure de référence T() (SYN-08) : l'horloge de l'appareil corrigée par une
 * référence publique. Linux et Android sondent `time.cloudflare.com` en NTS
 * (NTP authentifié, RFC 8915) — la sonde vit sous la fonctionnalité « nts »
 * (rkik-nts), activée par le démon Linux ; Android l'activera quand il se
 * synchronisera (AND-03). Le navigateur a sa propre référence (l'heure des
 * serveurs Google via Drive, web/js/heure.js) : la logique de seuils est
 * identique des deux côtés, seul le transport change.
 *
 *  - décalage ≤ 2 s : rien (bruit de mesure) ;
 *  - décalage > 2 s : corrigé — T() = horloge locale + décalage ;
 *  - décalage > 5 min : alerte (à revoir côté système), entrée de journal ;
 *  - hors ligne : dernier décalage connu, marqué « non vérifié ».
 *
 * L'horloge hybride (sync2.rs) ne recule jamais : T() ne fait qu'alimenter ses
 * tics — un décalage corrigeant vers le passé ne fait pas reculer les tampons
 * déjà posés.
 */

/// Décalage en dessous duquel la référence n'est pas appliquée (bruit).
pub const SEUIL_CORRECTION_MS: i64 = 2000;
/// Décalage au-delà duquel l'utilisateur est alerté.
pub const SEUIL_ALERTE_MS: i64 = 5 * 60 * 1000;
/// Serveur NTS public de référence.
pub const SERVEUR_NTS: &str = "time.cloudflare.com";

/// État de la référence de temps d'un appareil. Le client le persiste s'il
/// veut retrouver son dernier décalage connu au démarrage (voir `avec_decalage`).
#[derive(Clone, Debug, PartialEq)]
pub struct ReferenceTemps {
    decalage: i64,
    verifiee: bool,
    /// Décalage en cours d'alerte (> 5 min), sinon rien.
    alerte: Option<i64>,
}

/// Mesure rendue par une réception de référence.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Mesure {
    pub decalage_ms: i64,
    pub corrige: bool,
    pub alerte: bool,
}

impl Default for ReferenceTemps {
    fn default() -> Self {
        Self { decalage: 0, verifiee: false, alerte: None }
    }
}

impl ReferenceTemps {
    /// Référence neuve : horloge locale non vérifiée, aucun décalage.
    pub fn nouvelle() -> Self {
        Self::default()
    }

    /// Reprend le dernier décalage connu d'une session précédente : appliqué
    /// d'emblée, sans marquer la référence vérifiée (« hors ligne : dernier
    /// décalage connu, marqué non vérifié »).
    pub fn avec_decalage_connu(decalage_ms: i64) -> Self {
        Self { decalage: decalage_ms, verifiee: false, alerte: None }
    }

    /// T() : l'heure de référence, en millisecondes (horloge + décalage).
    pub fn maintenant(&self, horloge_locale_ms: i64) -> i64 {
        horloge_locale_ms + self.decalage
    }

    /// La référence a-t-elle été mesurée auprès du serveur ?
    pub fn verifiee(&self) -> bool {
        self.verifiee
    }

    /// Décalage en cours, si alerte (> 5 min) — pour l'affichage et le journal.
    pub fn alerte(&self) -> Option<i64> {
        self.alerte
    }

    /// Reçoit l'heure du serveur de référence (ms, mesurée à `horloge_locale_ms`
    /// d'horloge locale) : mesure le décalage, le corrige au-delà de 2 s,
    /// alerte au-delà de 5 min.
    pub fn recevoir_reference(&mut self, heure_serveur_ms: i64, horloge_locale_ms: i64) -> Mesure {
        let decalage_ms = heure_serveur_ms - horloge_locale_ms;
        let corrige = decalage_ms.abs() > SEUIL_CORRECTION_MS;
        if corrige {
            self.decalage = decalage_ms;
        }
        self.verifiee = true;
        let alerte = decalage_ms.abs() > SEUIL_ALERTE_MS;
        self.alerte = if alerte { Some(decalage_ms) } else { None };
        Mesure { decalage_ms, corrige, alerte }
    }

    /// Entrée de journal pour la synchro (SYN-07) : décrit l'état de la
    /// référence. Hors ligne ou alerte en cours : l'entrée dit quoi faire ;
    /// sinon rien (None).
    pub fn entree_journal(&self) -> Option<String> {
        if !self.verifiee {
            return Some(
                "Heure de référence inconnue (hors ligne, serveur NTS injoignable) : horloge locale non vérifiée.".to_string(),
            );
        }
        if let Some(decalage) = self.alerte {
            let minutes = decalage.abs() / 60_000;
            let sens = if decalage > 0 { "en avance" } else { "en retard" };
            return Some(format!(
                "Horloge de l'appareil {sens} de {minutes} min : corrigée par le serveur de temps, à revoir côté système."
            ));
        }
        None
    }
}

#[cfg(feature = "nts")]
pub mod sonde {
    //! Sonde NTS (NTP authentifié) : requête réelle vers le serveur de référence.
    //! Sous la fonctionnalité « nts » : le démon Linux l'active, le cœur reste
    //! léger pour Android.

    use super::{ReferenceTemps, SERVEUR_NTS};
    use crate::AppError;
    use rkik_nts::{NtsClient, NtsClientConfig};

    /// Interroge le serveur NTS et renvoie (heure du serveur, horloge locale)
    /// en ms, mesurées au même instant. `client` est réutilisable d'une sonde à
    /// l'autre (les cookies NTS servent plusieurs requêtes) — passer None pour
    /// un nouveau client connecté à time.cloudflare.com.
    pub async fn interroger(client: Option<&mut NtsClient>) -> crate::Result<(i64, i64)> {
        let reponse = if let Some(client) = client {
            client.get_time().await
        } else {
            let mut nouveau = NtsClient::new(NtsClientConfig::new(SERVEUR_NTS));
            nouveau.connect().await.map_err(erreur_nts)?;
            nouveau.get_time().await
        }
        .map_err(erreur_nts)?;
        let en_ms = |t: std::time::SystemTime| {
            t.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
        };
        Ok((en_ms(reponse.network_time), en_ms(reponse.system_time)))
    }

    fn erreur_nts(_: rkik_nts::Error) -> AppError {
        AppError::new("timeUnavailable")
    }

    /// Chaîne une sonde sur une référence : interroge le serveur (ou réutilise
    /// `client`), applique la mesure. Renvoie la mesure pour le journal.
    pub async fn synchroniser(
        reference: &mut ReferenceTemps,
        client: Option<&mut NtsClient>,
    ) -> crate::Result<super::Mesure> {
        let (heure_serveur, horloge_locale) = interroger(client).await?;
        Ok(reference.recevoir_reference(heure_serveur, horloge_locale))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T0: i64 = 1_794_405_900_000;

    #[test]
    fn sans_reference_l_horloge_locale_passe_telle_quelle_et_est_non_verifiee() {
        let r = ReferenceTemps::nouvelle();
        assert_eq!(r.maintenant(T0), T0);
        assert!(!r.verifiee());
        assert_eq!(r.entree_journal().as_deref().map(|t| t.contains("non vérifiée")), Some(true));
    }

    #[test]
    fn decalage_de_bruit_ignored_et_sans_alerte() {
        let mut r = ReferenceTemps::nouvelle();
        let m = r.recevoir_reference(T0 + 1500, T0);
        assert!(!m.corrige);
        assert!(!m.alerte);
        assert_eq!(r.maintenant(T0), T0, "pas de correction sous 2 s");
        assert_eq!(r.entree_journal(), None);
        assert!(r.verifiee());
    }

    #[test]
    fn decalage_corrige_au_dela_de_2_s_sans_alerte_sous_5_min() {
        let mut r = ReferenceTemps::nouvelle();
        let m = r.recevoir_reference(T0 + 2500, T0);
        assert!(m.corrige);
        assert!(!m.alerte);
        assert_eq!(r.maintenant(T0 + 500), T0 + 3000);
        assert_eq!(r.entree_journal(), None);
    }

    #[test]
    fn decalage_de_plus_de_5_min_corrige_et_alerte() {
        let mut r = ReferenceTemps::nouvelle();
        let m = r.recevoir_reference(T0 + 6 * 60_000, T0);
        assert!(m.corrige);
        assert!(m.alerte);
        let entree = r.entree_journal().expect("alerte journalisée");
        assert!(entree.contains("en avance"));
        assert!(entree.contains("6 min"));
        assert_eq!(r.alerte(), Some(6 * 60_000));
        // Retour à la normale : l'alerte tombe.
        r.recevoir_reference(T0 + 3000, T0);
        assert_eq!(r.entree_journal(), None);
        assert_eq!(r.alerte(), None);
    }

    #[test]
    fn horloge_en_retard_corrigee_vers_le_futur_alerte_symetrique() {
        let mut r = ReferenceTemps::nouvelle();
        let m = r.recevoir_reference(T0 - 7 * 60_000, T0);
        assert!(m.corrige);
        assert!(m.alerte);
        assert!(r.entree_journal().unwrap().contains("en retard"));
    }

    #[test]
    fn dernier_decalage_connu_applique_sans_verification() {
        let r = ReferenceTemps::avec_decalage_connu(10_000);
        assert_eq!(r.maintenant(T0 + 5000), T0 + 15_000);
        assert!(!r.verifiee(), "hors ligne : non vérifié");
        assert!(r.entree_journal().is_some());
    }
}

#[cfg(all(test, feature = "nts"))]
mod tests_nts {
    use super::sonde::synchroniser;

    /// Sonde réelle vers time.cloudflare.com — réseau requis :
    /// `cargo test -p mymfa-core --features nts -- --ignored`.
    #[test]
    #[ignore = "réseau : interroge réellement time.cloudflare.com en NTS"]
    fn sonde_nts_reelle_mesure_un_decalage_faible() {
        let mut reference = super::ReferenceTemps::nouvelle();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let mesure = runtime.block_on(synchroniser(&mut reference, None)).expect("sonde NTS");
        assert!(mesure.decalage_ms.abs() < 60_000, "décalage plausible : {}", mesure.decalage_ms);
        assert!(reference.verifiee());
    }
}
