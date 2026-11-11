/*
 * État du démon et ses transitions : verrouillé ↔ déverrouillé, sceau de
 * session, remise PAM, persistance du trousseau local. Sans D-Bus : les
 * interfaces (service.rs, interface.rs) appellent ces opérations, puis
 * annoncent les changements sur le bus.
 *
 * Verrou d'état (std::sync::Mutex) jamais tenu à travers un `.await` : on
 * copie ce qu'il faut, on relâche, puis on attend (PBKDF2 hors de la boucle,
 * dans spawn_blocking).
 */
use crate::chemins::{self, Chemins};
use crate::coffre::{self, CoffreOuvert, ErreurCoffre};
use crate::session::Chiffrement;
use crate::trousseau::Trousseau;
use mymfa_sceau::remise::{self, Remise, Renouvellement};
use mymfa_sceau::Sceau;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use tokio::sync::watch;
use zeroize::Zeroizing;

/// Journal (stderr → journald). Jamais un secret, jamais un mot de passe.
#[macro_export]
macro_rules! journal {
    ($($arg:tt)*) => { eprintln!("mymfa: {}", format!($($arg)*)) };
}

pub struct Etat {
    pub coffre: Option<CoffreOuvert>,
    pub trousseau: Trousseau,
    /// Clé de session remise par PAM, gardée tant qu'elle n'a pas servi à
    /// sceller (premier déverrouillage manuel, ou sceau périmé).
    pub cle_session: Option<Remise>,
    /// Sessions Secret Service ouvertes : chemin → chiffrement.
    pub sessions: HashMap<String, Chiffrement>,
    /// Le démon tient org.freedesktop.secrets (sinon : autre service, en file).
    pub secret_service: bool,
}

pub struct Demon {
    pub chemins: Chemins,
    etat: Mutex<Etat>,
    pub connexion: OnceLock<zbus::Connection>,
    /// `true` = verrouillé. Les invites (Prompt) s'y abonnent.
    pub verrou: watch::Sender<bool>,
    compteur: AtomicU64,
    /// Chemins D-Bus des logins du coffre publiés (collection « mymfa »).
    publies: Mutex<Vec<String>>,
}

pub type Partage = Arc<Demon>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refus {
    Coffre(ErreurCoffre),
    /// Aucune clé de session : pas de connexion par pam_mymfa depuis le démarrage.
    PasDeCleSession,
    Echec(String),
}

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refus::Coffre(e) => e.fmt(f),
            Refus::PasDeCleSession => f.write_str("aucune clé de session (connexion sans pam_mymfa)"),
            Refus::Echec(m) => f.write_str(m),
        }
    }
}

impl From<ErreurCoffre> for Refus {
    fn from(e: ErreurCoffre) -> Self {
        Refus::Coffre(e)
    }
}

impl Demon {
    pub fn nouveau(chemins: Chemins) -> Partage {
        let trousseau = charger_trousseau(&chemins);
        let (verrou, _) = watch::channel(true);
        Arc::new(Demon {
            chemins,
            etat: Mutex::new(Etat {
                coffre: None,
                trousseau,
                cle_session: None,
                sessions: HashMap::new(),
                secret_service: false,
            }),
            connexion: OnceLock::new(),
            verrou,
            compteur: AtomicU64::new(1),
            publies: Mutex::new(Vec::new()),
        })
    }

    pub fn etat(&self) -> MutexGuard<'_, Etat> {
        self.etat.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn publies_coffre(&self) -> MutexGuard<'_, Vec<String>> {
        self.publies.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn suivant(&self) -> u64 {
        self.compteur.fetch_add(1, Ordering::Relaxed)
    }

    pub fn verrouille(&self) -> bool {
        self.etat().coffre.is_none()
    }

    pub fn coffre_present(&self) -> bool {
        self.chemins.coffre().exists()
    }

    pub fn scelle(&self) -> bool {
        self.chemins.sceau().exists()
    }

    /* ───── Déverrouillage ───── */

    /// Déverrouille avec le mot de passe du coffre. Si une clé de session
    /// attend (remise PAM), scelle ce mot de passe par elle.
    pub async fn deverrouiller(self: &Partage, mot_de_passe: Zeroizing<String>) -> Result<(), Refus> {
        if !self.verrouille() {
            return Ok(());
        }
        let chemin = self.chemins.coffre();
        let modification = chemins::modification(&chemin);
        let record = coffre::lire(chemins::lire(&chemin).as_deref())?;
        let mdp = mot_de_passe.clone();
        let ouvert = tokio::task::spawn_blocking(move || coffre::deverrouiller(&record, &mdp, modification))
            .await
            .map_err(|_| Refus::Echec("déverrouillage interrompu".into()))??;
        self.installer(ouvert, Some(&mot_de_passe));
        Ok(())
    }

    /// Installe un coffre ouvert : trousseau déchiffré, sceau posé au besoin.
    fn installer(&self, ouvert: CoffreOuvert, mot_de_passe: Option<&str>) {
        {
            let mut etat = self.etat();
            if etat.coffre.is_some() {
                return; // déverrouillé entre-temps par une autre voie
            }
            if let Err(e) = etat.trousseau.ouvrir(ouvert.dek()) {
                let _ = e;
                // Coffre recréé ailleurs (autre DEK) : le trousseau est mis de
                // côté, intact, plutôt qu'écrasé — il s'ouvre avec l'ancien coffre.
                let cote = self.chemins.trousseau().with_extension(format!("illisible-{}.json", chemins::maintenant()));
                journal!("trousseau local illisible avec ce coffre : mis de côté ({})", cote.display());
                let _ = std::fs::rename(self.chemins.trousseau(), &cote);
                etat.trousseau = Trousseau::neuf();
                let _ = etat.trousseau.ouvrir(ouvert.dek());
            }
            if let (Some(mdp), Some(remise)) = (mot_de_passe, etat.cle_session.as_ref()) {
                if !self.chemins.sans_sceau().exists() {
                    let sceau = mymfa_sceau::sceller(&remise.cle, remise.iterations, mdp);
                    match ecrire_sceau(&self.chemins, &sceau) {
                        Ok(()) => {
                            journal!("mot de passe du coffre scellé par la session : déverrouillage à la connexion actif");
                            etat.cle_session = None;
                        }
                        Err(e) => journal!("sceau non écrit : {e}"),
                    }
                }
            }
            journal!("coffre déverrouillé ({} comptes, {} logins)", ouvert.comptes.len(), ouvert.logins.len());
            etat.coffre = Some(ouvert);
        }
        self.persister();
        self.verrou.send_replace(false);
    }

    pub fn verrouiller(&self) -> bool {
        let etait_ouvert = {
            let mut etat = self.etat();
            let ouvert = etat.coffre.take().is_some();
            etat.trousseau.fermer();
            ouvert
        };
        if etait_ouvert {
            journal!("coffre verrouillé");
            self.verrou.send_replace(true);
        }
        etait_ouvert
    }

    /* ───── Sceau et remise PAM ───── */

    /// Clé de session remise par pam_mymfa : descelle et ouvre, ou garde la
    /// clé pour sceller au prochain déverrouillage manuel.
    pub async fn recevoir_cle(self: &Partage, remise: Remise) {
        let sceau = lire_sceau(&self.chemins);
        let Some(sceau) = sceau else {
            journal!("clé de session reçue : sera scellée au prochain déverrouillage");
            self.etat().cle_session = Some(remise);
            return;
        };
        if !self.verrouille() {
            self.etat().cle_session = Some(remise);
            return;
        }
        match mymfa_sceau::desceller(&remise.cle, &sceau) {
            Ok(mdp) => match self.deverrouiller(mdp).await {
                Ok(()) => journal!("coffre ouvert à la connexion"),
                Err(e) => {
                    // Mot de passe du coffre changé ailleurs : rescellé au prochain déverrouillage.
                    journal!("sceau périmé ({e}) : déverrouillage manuel requis, puis nouveau sceau");
                    self.etat().cle_session = Some(remise);
                }
            },
            Err(e) => {
                journal!("sceau refusé par la clé de session ({e}) : nouveau sceau au prochain déverrouillage");
                self.etat().cle_session = Some(remise);
            }
        }
    }

    /// Changement du mot de passe de session (pam_sm_chauthtok) : nouveau sceau.
    pub fn renouveler(&self, r: Renouvellement) {
        let Some(sceau) = lire_sceau(&self.chemins) else { return };
        match mymfa_sceau::desceller(&r.ancienne, &sceau) {
            Ok(mdp) => {
                let nouveau = mymfa_sceau::sceller(&r.nouvelle, r.iterations, &mdp);
                match ecrire_sceau(&self.chemins, &nouveau) {
                    Ok(()) => journal!("mot de passe de session changé : sceau renouvelé"),
                    Err(e) => journal!("sceau non renouvelé : {e}"),
                }
            }
            Err(_) => journal!("changement de mot de passe de session : ancien sceau déjà périmé, ignoré"),
        }
    }

    /// Scelle à la demande (`mymfa seal`) : vérifie le mot de passe (et
    /// déverrouille au passage), avec la clé de session reçue.
    pub async fn sceller(self: &Partage, mot_de_passe: Zeroizing<String>) -> Result<(), Refus> {
        if self.etat().cle_session.is_none() {
            return Err(Refus::PasDeCleSession);
        }
        let _ = std::fs::remove_file(self.chemins.sans_sceau());
        if self.verrouille() {
            self.deverrouiller(mot_de_passe).await?;
            return if self.scelle() { Ok(()) } else { Err(Refus::Echec("sceau non écrit".into())) };
        }
        let record = coffre::lire(chemins::lire(&self.chemins.coffre()).as_deref())?;
        let mdp = mot_de_passe.clone();
        tokio::task::spawn_blocking(move || mymfa_core::vault::unlock_with_password(&record, &mdp).map(|_| ()))
            .await
            .map_err(|_| Refus::Echec("vérification interrompue".into()))?
            .map_err(|_| Refus::Coffre(ErreurCoffre::MauvaisMotDePasse))?;
        let mut etat = self.etat();
        let remise = etat.cle_session.as_ref().ok_or(Refus::PasDeCleSession)?;
        let sceau = mymfa_sceau::sceller(&remise.cle, remise.iterations, &mot_de_passe);
        ecrire_sceau(&self.chemins, &sceau).map_err(|e| Refus::Echec(e.to_string()))?;
        etat.cle_session = None;
        journal!("mot de passe du coffre scellé par la session");
        Ok(())
    }

    /// Renonce au déverrouillage à la connexion : sceau effacé, plus d'auto-sceau.
    pub fn oublier_sceau(&self) -> std::io::Result<()> {
        let _ = std::fs::remove_file(self.chemins.sceau());
        chemins::ecrire_prive(&self.chemins.sans_sceau(), b"")?;
        journal!("sceau oublié : déverrouillage à la connexion désactivé");
        Ok(())
    }

    /* ───── Trousseau local ───── */

    /// Rechiffre et écrit le trousseau (après chaque changement).
    pub fn persister(&self) {
        let mut etat = self.etat();
        let texte = match etat.coffre.as_ref().map(|c| *c.dek()) {
            Some(mut dek) => {
                let t = etat.trousseau.serialiser(&dek);
                zeroize::Zeroize::zeroize(&mut dek);
                match t {
                    Ok(t) => t,
                    Err(_) => return,
                }
            }
            None => etat.trousseau.fichier(),
        };
        drop(etat);
        if let Err(e) = chemins::ecrire_prive(&self.chemins.trousseau(), texte.as_bytes()) {
            journal!("trousseau non écrit : {e}");
        }
    }

    /* ───── Surveillance ───── */

    /// Une passe de surveillance : remises PAM, coffre remplacé sur le disque.
    pub async fn surveiller_une_fois(self: &Partage) {
        match remise::consommer(&self.chemins.execution, remise::FICHIER_CLE) {
            Ok(Some(octets)) => match Remise::decoder(&octets) {
                Some(r) => self.recevoir_cle(r).await,
                None => journal!("remise de clé de session illisible, ignorée"),
            },
            Ok(None) => {}
            Err(e) => journal!("remise de clé de session refusée : {e}"),
        }
        match remise::consommer(&self.chemins.execution, remise::FICHIER_RENOUVELLEMENT) {
            Ok(Some(octets)) => match Renouvellement::decoder(&octets) {
                Some(r) => self.renouveler(r),
                None => journal!("remise de renouvellement illisible, ignorée"),
            },
            Ok(None) => {}
            Err(e) => journal!("remise de renouvellement refusée : {e}"),
        }
        self.recharger_coffre_si_remplace();
    }

    /// Coffre remplacé (sauvegarde restaurée, autre client) : relu avec la
    /// même DEK ; s'il ne s'ouvre plus (autre coffre), on verrouille.
    fn recharger_coffre_si_remplace(&self) {
        let chemin = self.chemins.coffre();
        let actuelle = chemins::modification(&chemin);
        let dek = {
            let etat = self.etat();
            match etat.coffre.as_ref() {
                Some(c) if c.modification != actuelle => c.dek_clone(),
                _ => return,
            }
        };
        let relu = coffre::lire(chemins::lire(&chemin).as_deref()).and_then(|r| coffre::ouvrir_avec(dek, &r, actuelle));
        match relu {
            Ok(ouvert) => {
                let mut etat = self.etat();
                if etat.coffre.is_some() {
                    journal!("coffre modifié sur le disque : relu");
                    etat.coffre = Some(ouvert);
                }
            }
            Err(_) => {
                journal!("coffre remplacé par un coffre d'une autre clé : verrouillage");
                self.verrouiller();
            }
        }
    }
}

fn charger_trousseau(chemins: &Chemins) -> Trousseau {
    let texte = chemins::lire(&chemins.trousseau());
    match Trousseau::charger(texte.as_deref()) {
        Ok(t) => t,
        Err(_) => {
            let cote = chemins.trousseau().with_extension(format!("illisible-{}.json", chemins::maintenant()));
            journal!("trousseau local illisible : mis de côté ({})", cote.display());
            let _ = std::fs::rename(chemins.trousseau(), &cote);
            Trousseau::neuf()
        }
    }
}

pub fn lire_sceau(chemins: &Chemins) -> Option<Sceau> {
    serde_json::from_str(&chemins::lire(&chemins.sceau())?).ok()
}

fn ecrire_sceau(chemins: &Chemins, sceau: &Sceau) -> std::io::Result<()> {
    let texte = serde_json::to_string_pretty(sceau).expect("sérialisation interne");
    chemins::ecrire_prive(&chemins.sceau(), texte.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mymfa_core::vault;
    use mymfa_sceau::remise::FICHIER_CLE;

    const RAPIDE: u32 = 1000;
    const MDP: &str = "correct horse battery";

    /// Dossier jetable avec un coffre (PBKDF2 réduit pour les tests).
    fn demon(nom: &str) -> Partage {
        let base = std::env::temp_dir().join(format!("mymfa-demon-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let chemins = Chemins { donnees: base.join("data"), execution: base.join("run") };
        std::fs::create_dir_all(&chemins.execution).unwrap();
        let (record, _) = vault::create(MDP, &Default::default(), RAPIDE).unwrap();
        chemins::ecrire_prive(&chemins.coffre(), serde_json::to_string(&record).unwrap().as_bytes()).unwrap();
        Demon::nouveau(chemins)
    }

    fn deposer_cle(d: &Demon, mot_de_passe_session: &[u8]) {
        let cle = mymfa_sceau::deriver(mot_de_passe_session, &mymfa_sceau::sel("m", 1, "u"), RAPIDE);
        let r = Remise { iterations: RAPIDE, cle };
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        remise::deposer(&d.chemins.execution, uid, gid, FICHIER_CLE, &r.encoder()).unwrap();
    }

    #[tokio::test]
    async fn verrouillage_et_mauvais_mot_de_passe() {
        let d = demon("verrou");
        assert!(d.verrouille());
        assert_eq!(d.deverrouiller(Zeroizing::new("faux mot de passe".into())).await, Err(Refus::Coffre(ErreurCoffre::MauvaisMotDePasse)));
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        assert!(!d.verrouille() && !*d.verrou.borrow());
        assert!(d.chemins.trousseau().exists(), "trousseau écrit au déverrouillage");
        assert!(d.verrouiller());
        assert!(d.verrouille() && *d.verrou.borrow());
    }

    /// Parcours complet : connexion (remise) → déverrouillage manuel (sceau
    /// posé) → verrou → nouvelle connexion : ouvert sans saisie.
    #[tokio::test]
    async fn sceau_puis_deverrouillage_a_la_connexion() {
        let d = demon("sceau");
        deposer_cle(&d, b"session-1");
        d.surveiller_une_fois().await;
        assert!(d.verrouille(), "sans sceau, la clé seule n'ouvre rien");
        assert!(d.etat().cle_session.is_some());
        assert!(!d.chemins.execution.join("mymfa").join(FICHIER_CLE).exists(), "remise consommée");

        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        assert!(d.scelle(), "premier déverrouillage manuel : sceau posé");
        assert!(d.etat().cle_session.is_none(), "clé effacée après usage");
        let texte = std::fs::read_to_string(d.chemins.sceau()).unwrap();
        assert!(!texte.contains("correct"), "sceau chiffré");

        d.verrouiller();
        deposer_cle(&d, b"session-1");
        d.surveiller_une_fois().await;
        assert!(!d.verrouille(), "connexion suivante : coffre ouvert sans saisie");
    }

    #[tokio::test]
    async fn sceau_perime_puis_renouvele() {
        let d = demon("perime");
        deposer_cle(&d, b"ancien");
        d.surveiller_une_fois().await;
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        d.verrouiller();
        // Mot de passe de session changé hors PAM : la clé ne descelle plus.
        deposer_cle(&d, b"nouveau");
        d.surveiller_une_fois().await;
        assert!(d.verrouille());
        assert!(d.etat().cle_session.is_some(), "clé gardée pour resceller");
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        d.verrouiller();
        deposer_cle(&d, b"nouveau");
        d.surveiller_une_fois().await;
        assert!(!d.verrouille(), "nouveau sceau effectif");
    }

    #[tokio::test]
    async fn changement_de_mot_de_passe_de_session() {
        let d = demon("chauthtok");
        deposer_cle(&d, b"ancien");
        d.surveiller_une_fois().await;
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        d.verrouiller();
        let s = mymfa_sceau::sel("m", 1, "u");
        let r = Renouvellement {
            iterations: RAPIDE,
            ancienne: mymfa_sceau::deriver(b"ancien", &s, RAPIDE),
            nouvelle: mymfa_sceau::deriver(b"nouveau", &s, RAPIDE),
        };
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        remise::deposer(&d.chemins.execution, uid, gid, remise::FICHIER_RENOUVELLEMENT, &r.encoder()).unwrap();
        d.surveiller_une_fois().await;
        deposer_cle(&d, b"nouveau");
        d.surveiller_une_fois().await;
        assert!(!d.verrouille(), "sceau renouvelé par chauthtok");
    }

    #[tokio::test]
    async fn renoncer_au_sceau() {
        let d = demon("oubli");
        deposer_cle(&d, b"session");
        d.surveiller_une_fois().await;
        d.oublier_sceau().unwrap();
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        assert!(!d.scelle(), "pas d'auto-sceau après un refus explicite");
        // Sceller à la demande lève le refus.
        d.sceller(Zeroizing::new(MDP.into())).await.unwrap();
        assert!(d.scelle() && !d.chemins.sans_sceau().exists());
        assert_eq!(d.sceller(Zeroizing::new(MDP.into())).await, Err(Refus::PasDeCleSession));
    }

    #[tokio::test]
    async fn trousseau_survit_au_verrouillage() {
        let d = demon("trousseau");
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        {
            let mut etat = d.etat();
            let attrs = [("app".to_string(), "essai".to_string())].into_iter().collect();
            etat.trousseau
                .creer_element("login", "Essai", attrs, Zeroizing::new(b"valeur".to_vec()), "text/plain", true)
                .unwrap();
        }
        d.persister();
        d.verrouiller();
        let relu = Demon::nouveau(d.chemins.clone());
        relu.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        let etat = relu.etat();
        let trouve = etat.trousseau.rechercher(None, &[("app".to_string(), "essai".to_string())].into_iter().collect());
        assert_eq!(trouve.len(), 1);
        assert_eq!(etat.trousseau.element(&trouve[0].0, &trouve[0].1).unwrap().secret.as_slice(), b"valeur");
    }
}
