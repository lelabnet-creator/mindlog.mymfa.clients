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
use crate::drive::{Jetons, Pkce, SauvegardeDrive};
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
    /// Compteur de changements du contenu du coffre (modification, coffre
    /// relu) : publication des logins et signal ContentChanged s'y abonnent.
    pub contenu: watch::Sender<u64>,
    compteur: AtomicU64,
    /// Chemins D-Bus des logins du coffre publiés (collection « mymfa »).
    publies: Mutex<Vec<String>>,
    /// Synchronisation Drive (LIN-06) : état par appareil, jetons, journal,
    /// points de restauration — verrou séparé du coffre (jamais tenu à travers
    /// un .await), demandes de cycle regroupées.
    pub synchro: Mutex<Synchro>,
    /// Identifiant de cet appareil dans le registre v2 : noté dans l'historique de
    /// chaque modification (SYN-09), sans prendre le verrou de synchro.
    pub appareil: String,
    /// Un cycle de synchro est demandé (modification, ouverture, SyncNow).
    pub demande_synchro: tokio::sync::Notify,
}

/// Tout ce que la synchronisation Drive garde hors du coffre.
pub struct Synchro {
    /// État de l'appareil pour sync2::fusion (identifiant, horloge, repère).
    pub etat: Option<mymfa_core::sync2::EtatSynchro>,
    /// La sauvegarde Drive telle que nous l'avons lue (id + révision).
    pub sauvegarde: Option<SauvegardeDrive>,
    /// Jetons OAuth (mémoire ; persistés chiffrés dans mymfa-drive.json).
    pub jetons: Option<Jetons>,
    /// Heure de référence T() : horloge corrigée par la sonde NTS (SYN-08).
    pub reference: mymfa_core::temps::ReferenceTemps,
    /// Journal de synchro (persisté chiffré dans mymfa-journal.json).
    pub journal: crate::synchro::Journal,
    /// Points de restauration (persistés chiffrés dans mymfa-drive-backup.json).
    pub points: crate::synchro::Points,
    /// Un cycle tourne (SyncNow pendant un cycle : statut « en cours »).
    pub en_cours: bool,
    /// Dernier statut sérialisé (SyncStatus le rend tel quel).
    pub statut: Option<serde_json::Value>,
}

impl Synchro {
    fn neuf(appareil: &str) -> Self {
        Self {
            etat: Some(mymfa_core::sync2::EtatSynchro::nouvelle(appareil, chemins::maintenant() as i64)),
            sauvegarde: None,
            jetons: None,
            reference: mymfa_core::temps::ReferenceTemps::nouvelle(),
            journal: crate::synchro::Journal::default(),
            points: crate::synchro::Points::default(),
            en_cours: false,
            statut: None,
        }
    }
}

pub type Partage = Arc<Demon>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refus {
    Coffre(ErreurCoffre),
    /// Aucune clé de session : pas de connexion par pam_mymfa depuis le démarrage.
    PasDeCleSession,
    /// Création demandée alors qu'un coffre existe déjà.
    CoffreExistant,
    /// Mot de passe d'un nouveau coffre trop court.
    MotDePasseFaible,
    /// Opération qui demande le coffre ouvert.
    Verrouille,
    /// Opération refusée (code i18n du web) ou élément introuvable.
    Operation(crate::edition::ErreurOp),
    Echec(String),
}

impl std::fmt::Display for Refus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refus::Coffre(e) => e.fmt(f),
            Refus::PasDeCleSession => f.write_str("aucune clé de session (connexion sans pam_mymfa)"),
            Refus::CoffreExistant => f.write_str("un coffre existe déjà sur cet ordinateur"),
            Refus::Verrouille => f.write_str("le coffre myMFA est verrouillé"),
            Refus::Operation(e) => e.fmt(f),
            Refus::MotDePasseFaible => write!(f, "mot de passe trop court ({} caractères au moins)", mymfa_core::vault::PASSWORD_MIN_LENGTH),
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
        let synchro = charger_synchro(&chemins);
        let appareil = synchro.etat.as_ref().map(|e| e.appareil.clone()).unwrap_or_default();
        let (verrou, _) = watch::channel(true);
        let (contenu, _) = watch::channel(0);
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
            contenu,
            compteur: AtomicU64::new(1),
            publies: Mutex::new(Vec::new()),
            synchro: Mutex::new(synchro),
            appareil,
            demande_synchro: tokio::sync::Notify::new(),
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

    /* ───── Modification ───── */

    /// Modifie le coffre ouvert : `f` sur le magasin ; s'il réussit, coffre
    /// rechiffré écrit sur le disque sous le verrou d'état (deux modifications
    /// ne se croisent pas), puis changement annoncé. Refusé par `f` : rien
    /// n'est écrit.
    pub fn modifier<T, E>(&self, f: impl FnOnce(&mut mymfa_core::store::Store) -> Result<T, E>) -> Result<Result<T, E>, Refus> {
        // Horloge de synchro v2 de cet appareil : les écritures sont tamponnées (SYN-07),
        // comme celles du web. Lue avant le verrou du coffre (jamais imbriqués dans cet
        // ordre-là), reportée après l'écriture — elle a avancé.
        let temps = {
            let s = self.synchro();
            s.etat.as_ref().map(|e| mymfa_core::store::TempsStore {
                horloge: e.horloge,
                appareil: e.appareil.clone(),
                maintenant: s.reference.maintenant(chemins::maintenant() as i64),
            })
        };
        let mut horloge_apres: Option<mymfa_core::sync2::Horloge> = None;
        let r = {
            let mut etat = self.etat();
            let c = etat.coffre.as_mut().ok_or(Refus::Verrouille)?;
            let appareil = (!self.appareil.is_empty()).then(|| self.appareil.clone());
            let sortie = &mut horloge_apres;
            let (r, texte) = c.modifier(move |store| {
                store.appareil = appareil; // l'historique nomme cet appareil (SYN-09)
                store.temps = temps;
                let r = f(store);
                *sortie = store.temps.take().map(|t| t.horloge);
                r
            })?;
            if let Some(h) = horloge_apres {
                avancer_horloge(&mut self.synchro(), h);
            }
            let Some(texte) = texte else { return Ok(r) };
            let chemin = self.chemins.coffre();
            chemins::ecrire_prive(&chemin, texte.as_bytes()).map_err(|e| Refus::Echec(format!("coffre non écrit : {e}")))?;
            c.modification = chemins::modification(&chemin);
            r
        };
        self.contenu.send_modify(|n| *n += 1);
        self.demande_synchro.notify_one();
        Ok(r)
    }

    /// Lecture du coffre ouvert.
    pub fn lire<T>(&self, f: impl FnOnce(&CoffreOuvert) -> T) -> Result<T, Refus> {
        let etat = self.etat();
        etat.coffre.as_ref().map(f).ok_or(Refus::Verrouille)
    }

    /* ───── Création ───── */

    /// Crée le coffre (aucun n'existe encore) puis l'ouvre : si une clé de
    /// session attend (connexion par pam_mymfa), le mot de passe est scellé
    /// au passage et la connexion suivante ouvre le coffre sans saisie.
    pub async fn creer(self: &Partage, mot_de_passe: Zeroizing<String>) -> Result<(), Refus> {
        if self.coffre_present() {
            return Err(Refus::CoffreExistant);
        }
        mymfa_core::vault::validate_password(&mot_de_passe).map_err(|_| Refus::MotDePasseFaible)?;
        let mdp = mot_de_passe.clone();
        let (record, dek) = tokio::task::spawn_blocking(move || {
            mymfa_core::vault::create(&mdp, &Default::default(), mymfa_core::vault::PBKDF2_ITERATIONS)
        })
        .await
        .map_err(|_| Refus::Echec("création interrompue".into()))?
        .map_err(|e| Refus::Echec(e.to_string()))?;
        self.poser(record, dek, &mot_de_passe)
    }

    /// Installe une sauvegarde du web (`mymfa-vault.json`) : le mot de passe
    /// (celui du web) est vérifié avant d'écrire quoi que ce soit, puis le
    /// coffre est ouvert et scellé comme à la création.
    pub async fn installer_sauvegarde(self: &Partage, texte: String, mot_de_passe: Zeroizing<String>) -> Result<(), Refus> {
        if self.coffre_present() {
            return Err(Refus::CoffreExistant);
        }
        let record = mymfa_core::vault::parse(&texte).ok_or(Refus::Coffre(ErreurCoffre::Corrompu))?;
        let mdp = mot_de_passe.clone();
        let (record, dek) = tokio::task::spawn_blocking(move || {
            mymfa_core::vault::unlock_with_password(&record, &mdp).map(|dek| (record, dek))
        })
        .await
        .map_err(|_| Refus::Echec("vérification interrompue".into()))?
        .map_err(|_| Refus::Coffre(ErreurCoffre::MauvaisMotDePasse))?;
        self.poser(record, dek, &mot_de_passe)
    }

    /// Écrit le coffre neuf et l'installe ouvert (sans second PBKDF2).
    fn poser(&self, record: mymfa_core::vault::VaultRecord, dek: mymfa_core::vault::Dek, mot_de_passe: &str) -> Result<(), Refus> {
        let chemin = self.chemins.coffre();
        if chemin.exists() {
            return Err(Refus::CoffreExistant);
        }
        let texte = serde_json::to_string(&record).map_err(|e| Refus::Echec(e.to_string()))?;
        chemins::ecrire_prive(&chemin, texte.as_bytes()).map_err(|e| Refus::Echec(e.to_string()))?;
        journal!("coffre installé ({})", chemin.display());
        let ouvert = coffre::ouvrir_avec(dek, &record, chemins::modification(&chemin))?;
        self.installer(ouvert, Some(mot_de_passe));
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
        // Jetons, journal et points de restauration : chiffrés par la DEK, ils
        // ne s'ouvrent qu'ici. Une clé qui n'ouvre plus (coffre recréé
        // ailleurs) : la connexion Drive est oubliée, pas les fichiers.
        {
            let dek = self.etat().coffre.as_ref().map(|c| c.dek_pleine());
            if let Some(dek) = dek {
                let mut s = self.synchro();
                let jetons = chemins::lire(&self.chemins.drive_jetons()).unwrap_or_default();
                if jetons.trim().is_empty() {
                    s.jetons = None;
                } else if let Ok(Some(j)) = crate::drive::jetons_depuis_texte(&jetons, &dek) {
                    s.jetons = Some(j);
                } else {
                    journal!("jetons Drive illisibles avec ce coffre : connexion oubliée");
                    let _ = std::fs::remove_file(self.chemins.drive_jetons());
                    s.jetons = None;
                }
                let brut = chemins::lire(&self.chemins.drive_journal()).unwrap_or_default();
                if let Ok(j) = crate::synchro::Journal::depuis_texte(&brut, &dek) {
                    s.journal = j;
                }
                let brut = chemins::lire(&self.chemins.drive_points()).unwrap_or_default();
                if let Ok(p) = crate::synchro::Points::depuis_texte(&brut, &dek) {
                    s.points = p;
                }
            }
        }
        self.persister();
        self.verrou.send_replace(false);
        self.demande_synchro.notify_one(); // à l'ouverture du coffre : cycle
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

    /// Arrêt du démon (mise à jour, redémarrage de l'unit) : la clé de session
    /// qui attend encore est redéposée là où pam_mymfa l'avait mise (même
    /// fichier 0600 de /run/user/UID), pour que le démon suivant scelle à sa
    /// place. Sans cela, créer le coffre après une mise à jour ne le scellerait
    /// pas avant la connexion suivante.
    pub fn rendre_cle(&self) {
        let Some(r) = self.etat().cle_session.take() else { return };
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        match remise::deposer(&self.chemins.execution, uid, gid, remise::FICHIER_CLE, &r.encoder()) {
            Ok(()) => journal!("clé de session en attente rendue pour le démon suivant"),
            Err(e) => journal!("clé de session perdue à l'arrêt : {e}"),
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
                    drop(etat);
                    self.contenu.send_modify(|n| *n += 1);
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


/* ───── Synchronisation Drive (LIN-06) ───── */

impl Demon {
    pub fn synchro(&self) -> MutexGuard<'_, Synchro> {
        self.synchro.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sonde NTS hors cycle Drive (SYN-08) : l'heure de référence est vérifiée
    /// même sans Drive connecté — le cycle, lui, ne tourne qu'avec Drive.
    /// Rend `true` si la mesure a abouti.
    pub async fn sonder_horloge(&self) -> bool {
        let mut reference = self.synchro().reference.clone();
        match mymfa_core::temps::sonde::synchroniser(&mut reference, None).await {
            Ok(m) => {
                if m.alerte {
                    journal!("temps : horloge locale décalée de {} s (corrigée)", m.decalage_ms / 1000);
                }
                self.synchro().reference = reference;
                true
            }
            Err(_) => {
                journal!("temps : sonde NTS injoignable, horloge non vérifiée");
                false
            }
        }
    }

    /// Le statut JSON rendu à hyprdesk (SyncNow, SyncStatus, fin de cycle).
    pub fn statut_synchro(&self) -> serde_json::Value {
        let s = self.synchro();
        let ouvert = !self.verrouille();
        serde_json::json!({
            "connecte": s.jetons.is_some(),
            "coffreOuvert": ouvert,
            "enCours": s.en_cours,
            "horlogeVerifiee": s.reference.verifiee(),
            "alerteHorloge": s.reference.alerte().map(|d| d.to_string()),
            "revision": s.sauvegarde.as_ref().map(|sauv| sauv.revision.clone()),
            "modifieeLe": s.sauvegarde.as_ref().map(|sauv| sauv.modifiee_le.clone()),
            "statut": s.statut,
        })
    }

    /// Le journal de synchro, chiffré et conservé (restaurable) — rendu en JSON
    /// sans les valeurs (les textes suffisent à la fenêtre hyprdesk).
    pub fn journal_synchro(&self) -> Result<serde_json::Value, Refus> {
        let s = self.synchro();
        Ok(serde_json::json!({
            "entrees": s.journal.entrees.iter().map(|e| serde_json::json!({
                "genre": e.genre, "cle": e.cle, "champ": e.champ, "texte": e.texte, "at": e.at,
            })).collect::<Vec<_>>(),
        }))
    }

    /// Restaure une version gardée en point de restauration : même chemin que
    /// l'installation d'une sauvegarde (mot de passe de la version demandé,
    /// coffre remplacé puis ouvert et scellé). Le coffre actuel reste sous
    /// PREVIOUS équivalent ? Non : c'est une restauration complète, comme le web.
    pub async fn restaurer_drive(self: &Partage, revision: &str, mot_de_passe: Zeroizing<String>) -> Result<(), Refus> {
        // Révision vide : la dernière version reçue de Drive.
        let enveloppe = {
            let s = self.synchro();
            let point = if revision.is_empty() {
                s.points.sauvegardes.first()
            } else {
                s.points.sauvegardes.iter().find(|p| p.revision == revision)
            };
            point.map(|p| p.enveloppe.to_string()).ok_or_else(|| {
                Refus::Echec(if revision.is_empty() {
                    "aucune version de Drive reçue : connectez Drive et synchronisez d'abord".into()
                } else {
                    format!("revision {revision} introuvable dans les points de restauration")
                })
            })?
        };
        if !self.coffre_present() {
            return self.installer_sauvegarde(enveloppe, mot_de_passe).await;
        }
        self.remplacer_par(enveloppe, mot_de_passe).await
    }

    /// Remplace le coffre local, ouvert, par la version d'un AUTRE coffre (celle
    /// de Drive : `driveAutreCoffre`), ouverte par son propre mot de passe.
    /// L'ancien coffre est gardé à côté (`mymfa-vault.avant-drive-<t>.json`),
    /// le trousseau des applications aussi (copie) ; le trousseau en mémoire,
    /// les jetons Drive, le journal et les points sont rechiffrés par la
    /// nouvelle clé — rien n'est perdu ni mis de côté. L'état de fusion
    /// repart de zéro (même appareil) ; le sceau de session, périmé, se refait
    /// au prochain déverrouillage manuel.
    async fn remplacer_par(self: &Partage, texte: String, mot_de_passe: Zeroizing<String>) -> Result<(), Refus> {
        if self.verrouille() {
            return Err(Refus::Verrouille);
        }
        let record = mymfa_core::vault::parse(&texte).ok_or(Refus::Coffre(ErreurCoffre::Corrompu))?;
        let mdp = mot_de_passe.clone();
        let (record, dek) = tokio::task::spawn_blocking(move || {
            mymfa_core::vault::unlock_with_password(&record, &mdp).map(|dek| (record, dek))
        })
        .await
        .map_err(|_| Refus::Echec("vérification interrompue".into()))?
        .map_err(|_| Refus::Coffre(ErreurCoffre::MauvaisMotDePasse))?;
        let instant = chemins::maintenant();
        let chemin = self.chemins.coffre();
        let copie = chemin.with_extension(format!("avant-drive-{instant}.json"));
        let texte_neuf = serde_json::to_string(&record).map_err(|e| Refus::Echec(e.to_string()))?;
        {
            // Verrou d'état tenu de l'écriture à l'échange : la surveillance du
            // disque ne voit jamais le nouveau fichier avec l'ancienne clé.
            let mut etat = self.etat();
            if etat.coffre.is_none() {
                return Err(Refus::Verrouille);
            }
            std::fs::rename(&chemin, &copie).map_err(|e| Refus::Echec(format!("ancien coffre non mis de côté : {e}")))?;
            let trousseau = self.chemins.trousseau();
            if trousseau.exists() {
                let _ = std::fs::copy(&trousseau, trousseau.with_extension(format!("avant-drive-{instant}.json")));
            }
            if let Err(e) = chemins::ecrire_prive(&chemin, texte_neuf.as_bytes()) {
                let _ = std::fs::rename(&copie, &chemin);
                return Err(Refus::Echec(format!("coffre de Drive non écrit : {e}")));
            }
            let ouvert = match coffre::ouvrir_avec(dek, &record, chemins::modification(&chemin)) {
                Ok(o) => o,
                Err(e) => {
                    let _ = std::fs::rename(&copie, &chemin);
                    return Err(e.into());
                }
            };
            journal!(
                "coffre local remplacé par la version de Drive ({} comptes, {} logins) ; l'ancien est gardé : {}",
                ouvert.comptes.len(),
                ouvert.logins.len(),
                copie.display()
            );
            etat.coffre = Some(ouvert);
        }
        // Trousseau des applications : toujours ouvert en mémoire, réécrit avec la nouvelle clé.
        self.persister();
        let dek = self.etat().coffre.as_ref().map(|c| c.dek_pleine()).ok_or(Refus::Verrouille)?;
        {
            let mut s = self.synchro();
            if let Some(j) = &s.jetons {
                if let Ok(t) = crate::drive::jetons_en_texte(j, &dek) {
                    let _ = chemins::ecrire_prive(&self.chemins.drive_jetons(), t.as_bytes());
                }
            }
            if let Ok(t) = s.journal.en_texte(&dek) {
                let _ = chemins::ecrire_prive(&self.chemins.drive_journal(), t.as_bytes());
            }
            if let Ok(t) = s.points.en_texte(&dek) {
                let _ = chemins::ecrire_prive(&self.chemins.drive_points(), t.as_bytes());
            }
            let appareil = s.etat.as_ref().map(|e| e.appareil.clone()).unwrap_or_else(|| "mymfa".into());
            let etat = mymfa_core::sync2::EtatSynchro::nouvelle(&appareil, instant as i64).avec_description("linux", nom_d_hote());
            let _ = chemins::ecrire_prive(&self.chemins.drive_etat(), crate::synchro::etat_en_texte(&etat, None).as_bytes());
            s.etat = Some(etat);
            s.sauvegarde = None;
            s.statut = None;
        }
        self.contenu.send_modify(|n| *n += 1);
        self.demande_synchro.notify_one();
        Ok(())
    }

    /// Connecte Drive : boucle locale + PKCE, navigateur ouvert, jetons échangés
    /// puis conservés chiffrés par la DEK. Renvoie le statut.
    pub async fn connecter_drive(self: &Partage) -> Result<serde_json::Value, Refus> {
        if self.verrouille() {
            return Err(Refus::Verrouille);
        }
        // Sans secret client, Google refuserait l'échange du code après la
        // connexion dans le navigateur : refus avant, et la marche à suivre.
        let Some(secret) = crate::drive::secret_client() else {
            return Err(Refus::Echec(format!(
                "Connexion Google Drive impossible : secret client OAuth absent. Posez celui du client « Application de bureau » de myMFA (console Google Cloud) dans {}, puis réessayez.",
                crate::drive::fichier_secret_client().display()
            )));
        };
        let pkce = Pkce::nouveau();
        let etat_cs = crate::drive::b64url(&mymfa_core::vault::random_bytes(16));
        let ecouteur = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| Refus::Echec(format!("port de boucle locale : {e}")))?;
        let port = ecouteur.local_addr().map_err(|e| Refus::Echec(e.to_string()))?.port();
        let url = crate::drive::url_autorisation(&pkce.challenge, port, &etat_cs);
        // Le navigateur s'ouvre ; l'URL est journalisée si xdg-open manque.
        match tokio::process::Command::new("xdg-open").arg(&url).spawn() {
            Ok(_) => journal!("connexion Drive : navigateur ouvert"),
            Err(e) => journal!("connexion Drive : ouvrez cette adresse : {url} ({e})"),
        }
        let code = crate::drive::attendre_code(ecouteur, &etat_cs, std::time::Duration::from_secs(5 * 60))
            .await
            .map_err(|_| Refus::Echec("connexion Drive interrompue ou refusée".into()))?;
        let jetons = crate::drive::echanger_code(&crate::drive::transport_reel(), &code, &pkce.verifier, port, Some(&secret))
            .await
            .map_err(refus_drive)?;
        self.poser_jetons(jetons).await?;
        self.cycler_synchro().await;
        Ok(self.statut_synchro())
    }

    /// Oublie la connexion Drive : jetons effacés (mémoire et disque).
    pub fn deconnecter_drive(&self) {
        let _ = std::fs::remove_file(self.chemins.drive_jetons());
        let mut s = self.synchro();
        s.jetons = None;
        s.sauvegarde = None;
        s.statut = Some(serde_json::json!({ "etat": "deconnecte" }));
    }

    async fn poser_jetons(self: &Partage, jetons: Jetons) -> Result<(), Refus> {
        let (dek, texte) = {
            let etat = self.etat();
            let c = etat.coffre.as_ref().ok_or(Refus::Verrouille)?;
            let dek = c.dek_pleine();
            (dek.clone(), c.texte())
        };
        let _ = texte; // le coffre n'est pas réécrit ici : seuls les jetons changent
        let texte_jetons = crate::drive::jetons_en_texte(&jetons, &dek).map_err(refus_drive)?;
        chemins::ecrire_prive(&self.chemins.drive_jetons(), texte_jetons.as_bytes())
            .map_err(|e| Refus::Echec(format!("jetons Drive non écrits : {e}")))?;
        self.synchro().jetons = Some(jetons);
        Ok(())
    }

    /// Un cycle complet de synchro : lire Drive (révision notée), déchiffrer,
    /// sonder le temps (NTS), fusionner champ par champ, écrire en local,
    /// revérifier la révision avant l'envoi (course → relire et refusionner,
    /// trois tours au plus), renvoyer si le résultat apporte quelque chose,
    /// journaliser. Verrou du coffre jamais tenu à travers un .await.
    pub async fn cycler_synchro(self: &Partage) -> serde_json::Value {
        {
            let mut s = self.synchro();
            if s.en_cours {
                return s.statut.clone().unwrap_or_else(|| serde_json::json!({ "enCours": true }));
            }
            s.en_cours = true;
        }
        let statut = self.cycle_interne().await;
        self.synchro().en_cours = false;
        self.synchro().statut = Some(statut.clone());
        statut
    }

    async fn cycle_interne(self: &Partage) -> serde_json::Value {
        let transport = crate::drive::transport_reel();
        for tour in 1..=3 {
            // ── Capture (verrou du coffre, puis verrou de synchro) : la copie
            // locale, le coffre chiffré, la DEK, l'état de fusion, le journal.
            let (dek, local, mut etat, mut sauvegarde, jetons, mut reference, mut journal, mut points) = {
                let etat_demon = self.etat();
                let Some(c) = etat_demon.coffre.as_ref() else {
                    return serde_json::json!({ "etat": "verrouille" });
                };
                let s = self.synchro();
                if s.jetons.is_none() {
                    return serde_json::json!({ "etat": "nonConnecte" });
                }
                (
                    c.dek_pleine(),
                    c.donnees(),
                    s.etat.clone().unwrap_or_else(|| mymfa_core::sync2::EtatSynchro::nouvelle("mymfa", chemins::maintenant() as i64)),
                    s.sauvegarde.clone(),
                    s.jetons.clone(),
                    s.reference.clone(),
                    s.journal.clone(),
                    s.points.clone(),
                )
            };
            let Some(mut jetons) = jetons else {
                return serde_json::json!({ "etat": "nonConnecte" });
            };

            // ── Jeton d'accès périmé : rafraîchi avant toute requête (le jeton
            // de rafraîchissement, lui, vit des années).
            let seconde = chemins::maintenant();
            if jetons.acces_expire_le <= seconde {
                match crate::drive::rafraichir(&transport, &jetons, crate::drive::secret_client().as_deref()).await {
                    Ok(renouveles) => {
                        jetons = renouveles;
                        if let Some(dek) = self.etat().coffre.as_ref().map(|c| c.dek_pleine()) {
                            if let Ok(texte) = crate::drive::jetons_en_texte(&jetons, &dek) {
                                let _ = chemins::ecrire_prive(&self.chemins.drive_jetons(), texte.as_bytes());
                            }
                        }
                        self.synchro().jetons = Some(jetons.clone());
                    }
                    Err(e) => {
                        journal!("synchro : jetons non renouvelés ({})", e.code);
                        self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                        return serde_json::json!({ "etat": "erreur", "code": "driveAuth" });
                    }
                }
            }

            // ── Heure de référence (SYN-08) : sonde NTS, dernier décalage sinon.
            match mymfa_core::temps::sonde::synchroniser(&mut reference, None).await {
                Ok(_) => {}
                Err(_) => journal!("temps : sonde NTS injoignable, dernier décalage connu conservé"),
            }
            let maintenant = reference.maintenant(chemins::maintenant() as i64);

            // ── Lire Drive et déchiffrer (une autre DEK : pas de fusion).
            let distante = match crate::synchro::lire_distante(&transport, &jetons, &dek, &mut points).await {
                Ok(d) => d,
                Err(e) => {
                    let code = e.code.to_string();
                    journal!("synchro : lecture Drive impossible ({code})");
                    self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                    return serde_json::json!({ "etat": "erreur", "code": code });
                }
            };
            if let Some((_, sauv)) = &distante {
                // L'heure des serveurs Google, consignée pour le journal (la
                // référence du web ; le démon, lui, fait NTS).
                if !sauv.modifiee_le.is_empty() {
                    journal!("Drive : sauvegarde modifiée {}", sauv.modifiee_le);
                }
            }

            // ── Fusion champ par champ (SYN-07) : pure, aucune écriture.
            let vide = mymfa_core::DataMap::new();
            let (fusion, rapport) =
                mymfa_core::sync2::fusion(&local, distante.as_ref().map(|(m, _)| m).unwrap_or(&vide), &mut etat, maintenant);

            // ── Écrire en local si la fusion a changé quelque chose (rien
            // n'est écrit si verrouillé entre-temps : statut et fin).
            if fusion != local {
                let ecrit = self.modifier(|store| {
                    store.data = fusion.clone();
                    Ok::<(), mymfa_core::AppError>(())
                });
                match ecrit {
                    Ok(Ok(())) => {}
                    Ok(Err(_)) => {}
                    Err(Refus::Verrouille) => {
                        self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                        return serde_json::json!({ "etat": "verrouille" });
                    }
                    Err(e) => {
                        journal!("synchro : coffre non écrit ({e})");
                        self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                        return serde_json::json!({ "etat": "erreur", "code": "driveEcriture" });
                    }
                }
            }

            // ── Envoyer si le résultat apporte quelque chose (le record local,
            // rechiffré par modifier, EST la version fusionnée).
            let record_json = {
                let etat_demon = self.etat();
                match etat_demon.coffre.as_ref() {
                    Some(c) => c.texte().unwrap_or_default(),
                    None => {
                        self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                        return serde_json::json!({ "etat": "verrouille" });
                    }
                }
            };
            match crate::synchro::pousser(&transport, &jetons, sauvegarde.as_ref(), &record_json, rapport.a_envoyer).await {
                Ok(crate::synchro::Envoi::Pose(revision)) => {
                    if !revision.is_empty() {
                        if let Some(sauv) = &mut sauvegarde {
                            sauv.revision = revision;
                        }
                    }
                    let envoye = !rapport.entrees.is_empty() || rapport.a_envoyer;
                    journal.ajouter_rapport(&rapport, Some(envoye));
                    self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                    return serde_json::json!({ "etat": "ok", "envoye": rapport.a_envoyer, "tour": tour });
                }
                Ok(crate::synchro::Envoi::Course) => {
                    journal!("synchro : Drive a changé pendant le cycle, relecture (tour {tour})");
                    journal.ajouter_rapport(&rapport, None);
                    continue;
                }
                Err(e) => {
                    let code = e.code.to_string();
                    journal!("synchro : envoi impossible ({code})");
                    journal.ajouter_rapport(&rapport, None);
                    self.terminer_cycle(&etat, sauvegarde, jetons, reference, journal, points);
                    return serde_json::json!({ "etat": "erreur", "code": code });
                }
            }
        }
        serde_json::json!({ "etat": "course", "code": "driveCourse" })
    }

    /// Persister l'état de synchro (mymfa-sync.json), le journal et les points
    /// (chiffrés), et la sauvegarde vue (révision courante) — puis annoncer.
    fn terminer_cycle(
        &self,
        etat_fusion: &mymfa_core::sync2::EtatSynchro,
        mut sauvegarde: Option<SauvegardeDrive>,
        jetons: Jetons,
        reference: mymfa_core::temps::ReferenceTemps,
        journal: crate::synchro::Journal,
        points: crate::synchro::Points,
    ) {
        // Sans id de sauvegarde (premier envoi multipart), la prochaine
        // lecture (lire_distante) posera l'id et la révision.
        let _ = &mut sauvegarde;
        {
            let mut s = self.synchro();
            // Une modification faite pendant le cycle a pu avancer l'horloge : jamais de recul.
            let horloge_courante = s.etat.as_ref().map(|e| e.horloge);
            s.etat = Some(etat_fusion.clone());
            if let Some(h) = horloge_courante {
                avancer_horloge(&mut s, h);
            }
            s.sauvegarde = sauvegarde.clone();
            s.jetons = Some(jetons);
            s.reference = reference;
            s.journal = journal.clone();
            s.points = points.clone();
        }
        let texte_etat = crate::synchro::etat_en_texte(etat_fusion, sauvegarde.as_ref());
        let _ = chemins::ecrire_prive(&self.chemins.drive_etat(), texte_etat.as_bytes());
        if let Some(dek) = self.etat().coffre.as_ref().map(|c| c.dek_pleine()) {
            if let Ok(texte) = journal.en_texte(&dek) {
                let _ = chemins::ecrire_prive(&self.chemins.drive_journal(), texte.as_bytes());
            }
            if let Ok(texte) = points.en_texte(&dek) {
                let _ = chemins::ecrire_prive(&self.chemins.drive_points(), texte.as_bytes());
            }
        }
    }
}

/// Erreur AppError (codes i18n du web) → Refus du démon.
fn refus_drive(e: mymfa_core::AppError) -> Refus {
    Refus::Echec(format!("drive : {}", e.code))
}

/// Charge l'état de synchro persisté (identifiant d'appareil, horloge, repère,
/// révision Drive vue). Rien de secret : fichier en clair.
/// L'horloge hybride de l'appareil ne recule jamais : (l, c) le plus grand gagne.
fn avancer_horloge(s: &mut Synchro, h: mymfa_core::sync2::Horloge) {
    if let Some(etat) = s.etat.as_mut() {
        if (h.l, h.c) > (etat.horloge.l, etat.horloge.c) {
            etat.horloge = h;
        }
    }
}

/// Nom lisible de ce poste pour le registre des appareils (SYN-09) : le nom
/// d'hôte, rien de plus.
fn nom_d_hote() -> Option<String> {
    ["/proc/sys/kernel/hostname", "/etc/hostname"]
        .iter()
        .find_map(|chemin| std::fs::read_to_string(chemin).ok())
        .map(|nom| nom.trim().to_string())
        .filter(|nom| !nom.is_empty())
}

fn charger_synchro(chemins: &Chemins) -> Synchro {
    let brut = chemins::lire(&chemins.drive_etat()).unwrap_or_default();
    let relu = crate::synchro::etat_depuis_texte(&brut).ok().flatten();
    let mut s = match relu {
        Some((etat, sauvegarde)) => {
            let mut s = Synchro::neuf(&etat.appareil);
            s.etat = Some(etat);
            s.sauvegarde = sauvegarde;
            s
        }
        None => {
            // Identifiant persisté dès sa création : un redémarrage avant le premier
            // cycle ne doit pas faire naître un second appareil dans le registre.
            let s = Synchro::neuf(&format!("mymfa-{}", crate::drive::b64url(&mymfa_core::vault::random_bytes(6))));
            if let Some(etat) = &s.etat {
                let _ = chemins::ecrire_prive(&chemins.drive_etat(), crate::synchro::etat_en_texte(etat, None).as_bytes());
            }
            s
        }
    };
    // Description (non persistée : recalculée à chaque démarrage, le nom d'hôte peut changer).
    if let Some(etat) = s.etat.take() {
        s.etat = Some(etat.avec_description("linux", nom_d_hote()));
    }
    s
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

    /// SYN-09 : l'identifiant d'appareil est persisté dès la création (un redémarrage
    /// avant le premier cycle garde le même), le démon se décrit « linux », et chaque
    /// modification nomme l'appareil dans l'historique.
    #[tokio::test]
    async fn appareil_persiste_decrit_et_note_dans_l_historique() {
        let d = demon("appareil");
        assert!(d.appareil.starts_with("mymfa-"));
        assert!(d.chemins.drive_etat().exists(), "identifiant écrit dès la création");
        let relance = Demon::nouveau(Chemins { donnees: d.chemins.donnees.clone(), execution: d.chemins.execution.clone() });
        assert_eq!(relance.appareil, d.appareil, "même appareil après un redémarrage");
        let description = d.synchro().etat.as_ref().unwrap().description.clone().unwrap();
        assert_eq!(description.type_, "linux");

        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        let horloge_avant = d.synchro().etat.as_ref().unwrap().horloge;
        d.modifier(|store| {
            store.add(&mymfa_core::store::NewAccount { issuer: "GitHub".into(), secret: "JBSWY3DPEHPK3PXP".into(), ..Default::default() }, None);
            Ok::<(), ()>(())
        })
        .unwrap()
        .unwrap();
        let historique = d.lire(|c| c.store().history()).unwrap();
        assert_eq!(historique[0].appareil.as_deref(), Some(d.appareil.as_str()));
        // Écriture tamponnée v2 par cet appareil ; l'horloge de synchro a avancé.
        let compte = d.lire(|c| c.store().list()).unwrap().remove(0);
        let h = compte.h.expect("champs tamponnés");
        assert!(h["issuer"].ends_with(&d.appareil), "tampon de cet appareil");
        let horloge_apres = d.synchro().etat.as_ref().unwrap().horloge;
        assert!((horloge_apres.l, horloge_apres.c) > (horloge_avant.l, horloge_avant.c));
        // Une suppression laisse une trace (v2), pas un enterrement v1.
        let id = compte.id.clone();
        d.modifier(|store| Ok::<bool, ()>(store.remove(&id))).unwrap().unwrap();
        assert!(d.lire(|c| c.store().list()).unwrap().is_empty());
        assert!(d.lire(|c| c.store().data.contains_key(mymfa_core::store::DELETED_KEY)).unwrap() == false);
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

    /// Drive porte un AUTRE coffre (driveAutreCoffre) : la version reçue
    /// remplace le coffre local, ouverte par son propre mot de passe ; les
    /// secrets des applications survivent (rechiffrés), l'ancien coffre reste à côté.
    #[tokio::test]
    async fn coffre_local_remplace_par_celui_de_drive() {
        let d = demon("remplace");
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        let mut attributs = crate::trousseau::Attributs::new();
        attributs.insert("application".into(), "essai".into());
        d.etat()
            .trousseau
            .creer_element("login", "Essai", attributs.clone(), Zeroizing::new(b"secret-app".to_vec()), "text/plain", false)
            .unwrap();
        d.persister();
        let autre = "mot de passe du web";
        let (record, _) = vault::create(autre, &Default::default(), RAPIDE).unwrap();
        d.synchro().points.pousser(crate::synchro::PointRestauration {
            revision: "R1".into(),
            modifiee_le: String::new(),
            enveloppe: Zeroizing::new(serde_json::to_string(&record).unwrap()),
        });
        assert!(
            matches!(
                d.restaurer_drive("", Zeroizing::new("faux".into())).await,
                Err(Refus::Coffre(ErreurCoffre::MauvaisMotDePasse))
            ),
            "mauvais mot de passe : rien ne change"
        );
        d.restaurer_drive("", Zeroizing::new(autre.into())).await.unwrap();
        assert!(!d.verrouille());
        let copies = std::fs::read_dir(&d.chemins.donnees)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("avant-drive"))
            .count();
        assert_eq!(copies, 2, "ancien coffre et trousseau gardés");
        // Le nouveau coffre s'ouvre avec le mot de passe du web, et le
        // trousseau, rechiffré, avec lui.
        d.verrouiller();
        assert!(d.deverrouiller(Zeroizing::new(MDP.into())).await.is_err());
        d.deverrouiller(Zeroizing::new(autre.into())).await.unwrap();
        assert_eq!(d.etat().trousseau.rechercher(None, &attributs).len(), 1, "secret d'application conservé");
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

    /// Dossier jetable sans coffre (première connexion).
    fn demon_vide(nom: &str) -> Partage {
        let d = demon(nom);
        std::fs::remove_file(d.chemins.coffre()).unwrap();
        d
    }

    /// Première connexion : clé de session reçue, pas de coffre ; la
    /// sauvegarde du web installée est ouverte et scellée d'un coup.
    #[tokio::test]
    async fn sauvegarde_installee_puis_scellee() {
        let d = demon_vide("sauvegarde");
        assert!(!d.coffre_present());
        deposer_cle(&d, b"session");
        d.surveiller_une_fois().await;
        assert!(d.etat().cle_session.is_some(), "clé gardée en attendant le coffre");
        let (record, _) = vault::create(MDP, &Default::default(), RAPIDE).unwrap();
        let texte = serde_json::to_string(&record).unwrap();

        assert_eq!(
            d.installer_sauvegarde(texte.clone(), Zeroizing::new("pas le bon".into())).await,
            Err(Refus::Coffre(ErreurCoffre::MauvaisMotDePasse))
        );
        assert!(!d.coffre_present(), "rien d'écrit sur un mauvais mot de passe");
        assert_eq!(
            d.installer_sauvegarde("{}".into(), Zeroizing::new(MDP.into())).await,
            Err(Refus::Coffre(ErreurCoffre::Corrompu))
        );

        d.installer_sauvegarde(texte.clone(), Zeroizing::new(MDP.into())).await.unwrap();
        assert!(d.coffre_present() && !d.verrouille());
        assert!(d.scelle(), "scellé dès l'installation");
        assert_eq!(d.installer_sauvegarde(texte, Zeroizing::new(MDP.into())).await, Err(Refus::CoffreExistant));

        d.verrouiller();
        deposer_cle(&d, b"session");
        d.surveiller_une_fois().await;
        assert!(!d.verrouille(), "connexion suivante : ouvert sans saisie");
    }

    /// Redémarrage du démon avant la création : la clé survit.
    #[tokio::test]
    async fn cle_rendue_a_l_arret() {
        let d = demon_vide("rendue");
        deposer_cle(&d, b"session");
        d.surveiller_une_fois().await;
        assert!(d.etat().cle_session.is_some());
        d.rendre_cle();
        assert!(d.etat().cle_session.is_none());
        let suivant = Demon::nouveau(d.chemins.clone());
        suivant.surveiller_une_fois().await;
        assert!(suivant.etat().cle_session.is_some(), "clé reprise par le démon suivant");
        let (record, _) = vault::create(MDP, &Default::default(), RAPIDE).unwrap();
        suivant
            .installer_sauvegarde(serde_json::to_string(&record).unwrap(), Zeroizing::new(MDP.into()))
            .await
            .unwrap();
        assert!(suivant.scelle());
    }

    /// Une modification réécrit le coffre : relu avec le mot de passe, elle y est ;
    /// le contenu est annoncé ; verrouillé, rien ne s'écrit.
    #[tokio::test]
    async fn modification_ecrite_et_relue() {
        let d = demon("modif");
        let op = serde_json::json!({"op":"add_account","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","issuer":"GitHub"});
        assert_eq!(d.modifier(|s| crate::edition::appliquer(s, &op, 0)).err(), Some(Refus::Verrouille));
        d.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        let avant = *d.contenu.borrow();
        d.modifier(|s| crate::edition::appliquer(s, &op, 0)).unwrap().unwrap();
        assert_eq!(*d.contenu.borrow(), avant + 1, "changement annoncé");
        assert!(d.modifier(|s| crate::edition::appliquer(s, &op, 0)).unwrap().is_err(), "doublon");
        assert_eq!(*d.contenu.borrow(), avant + 1, "refus : rien d'écrit ni d'annoncé");
        d.surveiller_une_fois().await;
        assert!(!d.verrouille(), "sa propre écriture n'est pas prise pour un remplacement");
        d.verrouiller();
        let relu = Demon::nouveau(d.chemins.clone());
        relu.deverrouiller(Zeroizing::new(MDP.into())).await.unwrap();
        assert_eq!(relu.lire(|c| c.comptes.len()).unwrap(), 1);
    }

    #[tokio::test]
    async fn creation_refusee() {
        let d = demon("creation");
        assert_eq!(d.creer(Zeroizing::new("un autre mot de passe".into())).await, Err(Refus::CoffreExistant));
        let d = demon_vide("creation-courte");
        assert_eq!(d.creer(Zeroizing::new("court".into())).await, Err(Refus::MotDePasseFaible));
        assert!(!d.coffre_present());
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
