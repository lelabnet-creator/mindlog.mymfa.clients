/*
 * today.mindlog.MyMfa1 — l'interface du bureau (hyprdesk, CLI `mymfa`).
 *
 * Nom de bus `today.mindlog.MyMfa1`, objet `/today/mindlog/MyMfa1`. Contrat
 * détaillé dans linux/README.md (« Interface D-Bus pour hyprdesk »). Le
 * contenu (Content) ne porte aucun secret ; un mot de passe de site ne sort
 * qu'à la demande (RevealPassword, comme « afficher » dans le web) ou par le
 * presse-papiers, vidé au bout de 30 s.
 */
use mymfa_core::AppError;
use crate::demon::{Partage, Refus};
use crate::presse_papiers;
use crate::trousseau::{self, Attributs};
use crate::coffre::{self, ErreurCoffre};
use crate::edition;
use crate::service::{self, ObjetElement};
use std::collections::HashMap;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::OwnedObjectPath;
use zbus::{interface, ObjectServer};
use zeroize::Zeroizing;

pub const NOM: &str = "today.mindlog.MyMfa1";
pub const CHEMIN: &str = "/today/mindlog/MyMfa1";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "today.mindlog.MyMfa1.Error")]
pub enum ErreurMyMfa {
    #[zbus(error)]
    ZBus(zbus::Error),
    /// Mot de passe du coffre incorrect.
    WrongPassword(String),
    /// Aucun coffre (`mymfa init`).
    NoVault(String),
    /// Coffre illisible.
    Corrupted(String),
    /// Opération qui demande le coffre déverrouillé.
    Locked(String),
    NotFound(String),
    /// Aucune clé de session remise par pam_mymfa depuis le démarrage.
    NoSessionKey(String),
    /// Création demandée alors qu'un coffre existe.
    VaultExists(String),
    /// Mot de passe d'un nouveau coffre trop court.
    WeakPassword(String),
    /// Opération refusée : le message est le code i18n du web (`duplicate:<id>`,
    /// `invalidSecret`, `invalidUri`…).
    Invalid(String),
    Failed(String),
    /// Connexion Drive refusée ou jetons périmés.
    DriveAuth(String),
    /// Google Drive a répondu une erreur HTTP.
    DriveHttp(String),
    /// Réseau indisponible (sonde NTS, requêtes Drive).
    DriveUnavailable(String),
    /// La sauvegarde Drive appartient à un autre coffre : pas de fusion.
    DriveOtherVault(String),
}

impl From<Refus> for ErreurMyMfa {
    fn from(r: Refus) -> Self {
        let m = r.to_string();
        match r {
            Refus::Coffre(ErreurCoffre::MauvaisMotDePasse) => ErreurMyMfa::WrongPassword(m),
            Refus::Coffre(ErreurCoffre::Absent) => ErreurMyMfa::NoVault(m),
            Refus::Coffre(ErreurCoffre::Corrompu) => ErreurMyMfa::Corrupted(m),
            Refus::PasDeCleSession => ErreurMyMfa::NoSessionKey(m),
            Refus::CoffreExistant => ErreurMyMfa::VaultExists(m),
            Refus::MotDePasseFaible => ErreurMyMfa::WeakPassword(m),
            Refus::Verrouille => ErreurMyMfa::Locked(m),
            Refus::Operation(crate::edition::ErreurOp::Invalide(code)) => ErreurMyMfa::Invalid(code),
            Refus::Operation(crate::edition::ErreurOp::Introuvable(id)) => ErreurMyMfa::NotFound(id),
            Refus::Echec(_) => ErreurMyMfa::Failed(m),
        }
    }
}

impl From<AppError> for ErreurMyMfa {
    fn from(e: AppError) -> Self {
        let m = e.to_string();
        match e.code {
            "driveAuth" => ErreurMyMfa::DriveAuth(m),
            "driveHttp" => ErreurMyMfa::DriveHttp(m),
            "driveUnavailable" => ErreurMyMfa::DriveUnavailable(m),
            "driveAutreCoffre" => ErreurMyMfa::DriveOtherVault(m),
            _ => ErreurMyMfa::Failed(m),
        }
    }
}

fn verrouille() -> ErreurMyMfa {
    ErreurMyMfa::Locked("le coffre myMFA est verrouillé".into())
}

pub struct MyMfa {
    pub d: Partage,
}

/// Code en cours : (id, émetteur, compte, tag, code, secondes restantes, période, favori).
pub type CodeDbus = (String, String, String, String, String, u32, u32, bool);
/// Login : (id, titre, hôte, adresse, identifiant).
pub type LoginDbus = (String, String, String, String, String);

#[interface(name = "today.mindlog.MyMfa1")]
impl MyMfa {
    /// Déverrouille avec le mot de passe du coffre (celui du web et d'Android).
    async fn unlock(&self, password: String) -> Result<(), ErreurMyMfa> {
        let mdp = Zeroizing::new(password);
        Ok(self.d.deverrouiller(mdp).await?)
    }

    /// Crée le coffre de cet ordinateur et l'ouvre ; scellé par la clé de
    /// session s'il en attend une (la connexion suivante l'ouvrira seule).
    async fn create_vault(&self, password: String) -> Result<(), ErreurMyMfa> {
        let mdp = Zeroizing::new(password);
        Ok(self.d.creer(mdp).await?)
    }

    /// Installe une sauvegarde du web (`mymfa-vault.json`, chemin lisible par
    /// l'utilisateur) avec son mot de passe, vérifié avant toute écriture ;
    /// ouverte et scellée comme à la création.
    async fn install_vault(&self, path: String, password: String) -> Result<(), ErreurMyMfa> {
        let mdp = Zeroizing::new(password);
        let texte = std::fs::read_to_string(&path).map_err(|e| ErreurMyMfa::Failed(format!("{path} : {e}")))?;
        Ok(self.d.installer_sauvegarde(texte, mdp).await?)
    }

    async fn lock(&self) {
        self.d.verrouiller();
    }

    /// Codes 2FA en cours, dans l'ordre du coffre.
    async fn codes(&self) -> Result<Vec<CodeDbus>, ErreurMyMfa> {
        let etat = self.d.etat();
        let c = etat.coffre.as_ref().ok_or_else(verrouille)?;
        Ok(c
            .codes(coffre::maintenant_ms())
            .into_iter()
            .map(|c| (c.id, c.issuer, c.account, c.tag, c.code.to_string(), c.restant, c.periode, c.favori))
            .collect())
    }

    /// Logins dont le titre, l'adresse ou l'identifiant contient `query`
    /// (insensible à la casse ; vide = tous). Jamais le mot de passe.
    async fn search_logins(&self, query: String) -> Result<Vec<LoginDbus>, ErreurMyMfa> {
        let etat = self.d.etat();
        let c = etat.coffre.as_ref().ok_or_else(verrouille)?;
        Ok(c
            .rechercher_logins(&query)
            .into_iter()
            .map(|l| (l.id.clone(), l.title.clone(), mymfa_core::store::host_of(&l.origin), l.origin.clone(), l.username.clone()))
            .collect())
    }

    /// Copie le code en cours d'un compte dans le presse-papiers.
    async fn copy_code(&self, id: String) -> Result<(), ErreurMyMfa> {
        let code = {
            let etat = self.d.etat();
            let c = etat.coffre.as_ref().ok_or_else(verrouille)?;
            c.codes(coffre::maintenant_ms())
                .into_iter()
                .find(|c| c.id == id)
                .map(|c| c.code)
                .ok_or_else(|| ErreurMyMfa::NotFound(id.clone()))?
        };
        presse_papiers::copier(self.d.connexion.get(), code, false).await.map_err(ErreurMyMfa::Failed)
    }

    /// Copie un champ d'un login : `password` (vidé au bout de 30 s) ou `username`.
    async fn copy_login(&self, id: String, field: String) -> Result<(), ErreurMyMfa> {
        let (valeur, sensible) = {
            let etat = self.d.etat();
            let c = etat.coffre.as_ref().ok_or_else(verrouille)?;
            let l = c.login(&id).ok_or_else(|| ErreurMyMfa::NotFound(id.clone()))?;
            match field.as_str() {
                "password" => (Zeroizing::new(l.password.clone()), true),
                "username" => (Zeroizing::new(l.username.clone()), false),
                _ => return Err(ErreurMyMfa::Failed("champ attendu : password ou username".into())),
            }
        };
        presse_papiers::copier(self.d.connexion.get(), valeur, sensible).await.map_err(ErreurMyMfa::Failed)
    }

    /* ───── Contenu et modifications (LIN-05) ───── */

    /// Tout le contenu du coffre, en JSON, sans aucun secret : comptes,
    /// logins, passkeys, étiquettes, historique, réglages.
    async fn content(&self) -> Result<String, ErreurMyMfa> {
        Ok(self.d.lire(|c| edition::contenu(c.store()).to_string())?)
    }

    /// Applique une opération JSON (`{"op": "add_account", …}`, voir
    /// edition.rs) ; rend son résultat en JSON.
    async fn apply(&self, operation: String) -> Result<String, ErreurMyMfa> {
        let op: serde_json::Value =
            serde_json::from_str(&operation).map_err(|_| ErreurMyMfa::Invalid("invalidOperation".into()))?;
        let maintenant = coffre::maintenant_ms();
        let r = self.d.modifier(|s| edition::appliquer(s, &op, maintenant))?;
        Ok(r.map_err(Refus::Operation)?.to_string())
    }

    /// Aperçu d'un compte avant ajout (URI otpauth ou champs) : champs lus et
    /// code actuel. Rien n'est écrit ; le coffre n'a pas à être ouvert.
    async fn preview(&self, account: String) -> Result<String, ErreurMyMfa> {
        let op: serde_json::Value =
            serde_json::from_str(&account).map_err(|_| ErreurMyMfa::Invalid("invalidOperation".into()))?;
        edition::apercu(&op, coffre::maintenant_ms())
            .map(|v| v.to_string())
            .map_err(|e| Refus::Operation(e).into())
    }

    /// Mot de passe d'un site, affiché à la demande (comme le web).
    async fn reveal_password(&self, id: String) -> Result<String, ErreurMyMfa> {
        self.d
            .lire(|c| c.login(&id).map(|l| l.password.clone()))?
            .ok_or(ErreurMyMfa::NotFound(id))
    }

    /// Mot de passe généré : `{"length": 20, "digits": true, "symbols": true, "words": false}`.
    async fn generate(&self, options: String) -> String {
        let o: serde_json::Value = serde_json::from_str(&options).unwrap_or_default();
        edition::generer(&o)
    }

    /// Exporte comptes et historique (JSON du web, en clair) dans `path`.
    async fn export_to(&self, path: String) -> Result<(), ErreurMyMfa> {
        let texte = self.d.lire(|c| edition::exporter(c.store()))?;
        crate::chemins::ecrire_prive(std::path::Path::new(&path), texte.as_bytes())
            .map_err(|e| ErreurMyMfa::Failed(format!("{path} : {e}")))
    }

    /// Importe un export JSON du web (`path`) : comptes absents ajoutés.
    async fn import_from(&self, path: String) -> Result<String, ErreurMyMfa> {
        let payload = std::fs::read_to_string(&path).map_err(|e| ErreurMyMfa::Failed(format!("{path} : {e}")))?;
        let op = serde_json::json!({ "op": "import", "payload": payload });
        let r = self.d.modifier(|s| edition::appliquer(s, &op, 0))?;
        Ok(r.map_err(Refus::Operation)?.to_string())
    }

    /// Scelle le mot de passe du coffre par la clé de session (pam_mymfa) :
    /// la connexion suivante ouvrira le coffre sans saisie.
    async fn seal(&self, password: String) -> Result<(), ErreurMyMfa> {
        Ok(self.d.sceller(Zeroizing::new(password)).await?)
    }

    /// Renonce au déverrouillage à la connexion (sceau effacé).
    async fn forget_seal(&self) -> Result<(), ErreurMyMfa> {
        self.d.oublier_sceau().map_err(|e| ErreurMyMfa::Failed(e.to_string()))?;
        announce(&self.d).await;
        Ok(())
    }

    /// Importe un secret dans le trousseau local (reprise de gnome-keyring) :
    /// collection désignée par son identifiant (créée au besoin, `label`
    /// comme libellé), élément remplacé s'il a les mêmes attributs.
    #[allow(clippy::too_many_arguments)]
    async fn import_secret(
        &self,
        collection: String,
        collection_label: String,
        label: String,
        attributes: HashMap<String, String>,
        secret: Vec<u8>,
        content_type: String,
        #[zbus(object_server)] serveur: &ObjectServer,
    ) -> Result<OwnedObjectPath, ErreurMyMfa> {
        let secret = Zeroizing::new(secret);
        if self.d.verrouille() {
            return Err(verrouille());
        }
        let attributs: Attributs = attributes.into_iter().collect();
        let (cid, nouvelle, eid, cree) = {
            let mut etat = self.d.etat();
            let mut cid = trousseau::identifiant(&collection, "import");
            let mut nouvelle = false;
            if cid == trousseau::RESERVEE {
                cid = format!("{cid}_import");
            }
            if !etat.trousseau.existe(&cid) {
                let label = if collection_label.is_empty() { collection.clone() } else { collection_label };
                cid = etat.trousseau.creer_collection(&label).map_err(|_| verrouille())?;
                nouvelle = true;
            }
            let ct = if content_type.is_empty() { "text/plain".to_string() } else { content_type };
            let (eid, cree) = etat
                .trousseau
                .creer_element(&cid, &label, attributs, secret, &ct, true)
                .map_err(|_| ErreurMyMfa::Failed("écriture refusée".into()))?;
            (cid, nouvelle, eid, cree)
        };
        self.d.persister();
        if nouvelle {
            let _ = serveur
                .at(
                    service::chemin_collection(&cid),
                    service::ObjetCollection { d: self.d.clone(), cible: service::Cible::Id(cid.clone()) },
                )
                .await;
        }
        let chemin_e = service::chemin_element(&cid, &eid);
        if cree {
            let _ = serveur.at(chemin_e.as_str(), ObjetElement { d: self.d.clone(), collection: cid, id: eid }).await;
        }
        Ok(service::chemin(&chemin_e))
    }

    /// Santé des mots de passe (tableau de bord, MLG-46) : faibles,
    /// réutilisés, à renouveler — ids et libellés, jamais de mot de passe.
    async fn audit(&self) -> Result<String, ErreurMyMfa> {
        let etat = self.d.etat();
        let c = etat.coffre.as_ref().ok_or_else(verrouille)?;
        Ok(crate::edition::audit(c.store()).to_string())
    }

    /* ───── Synchronisation Drive (LIN-06) ───── */

    /// Lance un cycle de synchro maintenant, rend son statut JSON.
    async fn sync_now(&self) -> Result<String, ErreurMyMfa> {
        Ok(self.d.cycler_synchro().await.to_string())
    }

    /// Statut de la synchronisation (connecté, dernière révision, en cours…).
    async fn sync_status(&self) -> Result<String, ErreurMyMfa> {
        Ok(self.d.statut_synchro().to_string())
    }

    /// Journal de synchro (arrivées, départs, conflits, doublons, horloges).
    async fn sync_journal(&self) -> Result<String, ErreurMyMfa> {
        Ok(self.d.journal_synchro().map_err(ErreurMyMfa::from)?.to_string())
    }

    /// Connecte Google Drive : ouvre le navigateur (boucle locale + PKCE),
    /// échange les jetons, lance un premier cycle. Rend le statut.
    async fn drive_connect(&self) -> Result<String, ErreurMyMfa> {
        Ok(self.d.connecter_drive().await.map_err(ErreurMyMfa::from)?.to_string())
    }

    /// Oublie la connexion Drive : jetons effacés, plus de synchro.
    async fn drive_disconnect(&self) -> Result<(), ErreurMyMfa> {
        Ok(self.d.deconnecter_drive())
    }

    /// L'appareil (onglet Appareil de hyprdesk) : identité, coffre d'appareil,
    /// liaison, trousseau des applications (sans secret), appareils du coffre.
    async fn device(&self) -> String {
        self.d.description_appareil().to_string()
    }

    /// Lie ce coffre d'appareil au coffre partagé de Drive (son mot de passe,
    /// une fois) : chacun garde sa clé, ils fusionnent à chaque cycle (SYN-13).
    /// Rend le statut de synchro après un premier cycle.
    async fn link_drive(&self, password: String) -> Result<String, ErreurMyMfa> {
        let mdp = Zeroizing::new(password);
        Ok(self.d.lier_drive(mdp).await?.to_string())
    }

    /// Restaure une version gardée en point de restauration (révision Drive) :
    /// le coffre actuel est remplacé par cette version (mot de passe demandé).
    async fn restore_drive(&self, revision: String, password: String) -> Result<(), ErreurMyMfa> {
        let mdp = Zeroizing::new(password);
        Ok(self.d.restaurer_drive(&revision, mdp).await?)
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.d.verrouille()
    }

    #[zbus(property)]
    async fn vault_present(&self) -> bool {
        self.d.coffre_present()
    }

    /// Le déverrouillage à la connexion est en place (sceau présent).
    #[zbus(property)]
    async fn sealed(&self) -> bool {
        self.d.scelle()
    }

    /// Une clé de session attend d'être scellée (déverrouiller la scellera).
    #[zbus(property)]
    async fn session_key(&self) -> bool {
        self.d.etat().cle_session.is_some()
    }

    /// Le démon tient org.freedesktop.secrets (sinon : un autre service,
    /// gnome-keyring par exemple, et le démon attend son tour).
    #[zbus(property)]
    async fn secret_service(&self) -> bool {
        self.d.etat().secret_service
    }

    #[zbus(property)]
    async fn version(&self) -> String {
        VERSION.into()
    }

    /// Verrouillé ↔ déverrouillé.
    #[zbus(signal)]
    async fn state_changed(e: &SignalEmitter<'_>, locked: bool) -> zbus::Result<()>;

    /// Contenu du coffre changé (modification, coffre relu ou synchronisé) :
    /// relire Content.
    #[zbus(signal)]
    async fn content_changed(e: &SignalEmitter<'_>) -> zbus::Result<()>;

    /// Une application demande le coffre (Secret Service) : hyprdesk affiche
    /// son invite et répond par Unlock. `application` : nom du processus
    /// demandeur, vide s'il est inconnu.
    #[zbus(signal)]
    async fn unlock_requested(e: &SignalEmitter<'_>, application: &str) -> zbus::Result<()>;
}

/// Propriétés et signal d'état, après un changement.
async fn announce(d: &Partage) {
    let Some(conn) = d.connexion.get() else { return };
    let Ok(i) = conn.object_server().interface::<_, MyMfa>(CHEMIN).await else { return };
    let g = i.get().await;
    let e = i.signal_emitter();
    let _ = g.locked_changed(e).await;
    let _ = g.sealed_changed(e).await;
    let _ = g.session_key_changed(e).await;
    let _ = g.vault_present_changed(e).await;
    let _ = g.secret_service_changed(e).await;
}

pub async fn annoncer_etat(d: &Partage) {
    announce(d).await;
    if let Some(conn) = d.connexion.get() {
        if let Ok(e) = SignalEmitter::new(conn, CHEMIN) {
            let _ = MyMfa::state_changed(&e, d.verrouille()).await;
        }
    }
}

pub async fn annoncer_proprietes(d: &Partage) {
    announce(d).await;
}

pub async fn annoncer_contenu(d: &Partage) {
    if let Some(conn) = d.connexion.get() {
        if let Ok(e) = SignalEmitter::new(conn, CHEMIN) {
            let _ = MyMfa::content_changed(&e).await;
        }
    }
}

pub async fn demander_deverrouillage(d: &Partage, application: &str) {
    if let Some(conn) = d.connexion.get() {
        if let Ok(e) = SignalEmitter::new(conn, CHEMIN) {
            let _ = MyMfa::unlock_requested(&e, application).await;
        }
    }
}
