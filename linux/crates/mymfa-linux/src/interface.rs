/*
 * today.mindlog.MyMfa1 — l'interface du bureau (hyprdesk, CLI `mymfa`).
 *
 * Nom de bus `today.mindlog.MyMfa1`, objet `/today/mindlog/MyMfa1`. Contrat
 * détaillé dans linux/README.md (« Interface D-Bus pour hyprdesk »). Aucune
 * méthode ne rend un mot de passe de site : la copie passe par le
 * presse-papiers, vidé au bout de 30 s.
 */
use crate::demon::{Partage, Refus};
use crate::presse_papiers;
use crate::trousseau::{self, Attributs};
use crate::coffre::{self, ErreurCoffre};
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
    Failed(String),
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
            Refus::Echec(_) => ErreurMyMfa::Failed(m),
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

pub async fn demander_deverrouillage(d: &Partage, application: &str) {
    if let Some(conn) = d.connexion.get() {
        if let Ok(e) = SignalEmitter::new(conn, CHEMIN) {
            let _ = MyMfa::unlock_requested(&e, application).await;
        }
    }
}
