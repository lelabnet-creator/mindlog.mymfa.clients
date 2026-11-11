/*
 * org.freedesktop.secrets — l'API Secret Service, à la place de gnome-keyring.
 *
 * Objets :
 *   /org/freedesktop/secrets                       Service
 *   /org/freedesktop/secrets/collection/<id>       Collection (locales + « mymfa »)
 *   /org/freedesktop/secrets/collection/<id>/<id>  Item
 *   /org/freedesktop/secrets/aliases/<alias>       Collection (vue par alias)
 *   /org/freedesktop/secrets/session/<n>           Session (plain, DH)
 *   /org/freedesktop/secrets/prompt/<n>            Prompt (déverrouillage)
 *
 * Un seul verrou pour tout : celui du coffre myMFA. Les collections locales
 * vivent dans le trousseau local (trousseau.rs) ; la collection « mymfa »
 * expose en lecture seule les logins des sites du coffre.
 */
use crate::demon::Partage;
use crate::session::{self, SecretDbus};
use crate::trousseau::{self, Attributs, ErreurTrousseau};
use crate::{interface, invite, journal};
use mymfa_core::store::{host_of, Login};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Notify;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zbus::{fdo, interface, ObjectServer};
use zeroize::Zeroizing;

pub const NOM: &str = "org.freedesktop.secrets";
pub const RACINE: &str = "/org/freedesktop/secrets";
/// Schéma des logins du coffre exposés aux applications.
pub const SCHEMA_LOGIN: &str = "today.mindlog.MyMfa.Login";
const LABEL_PROP: &str = "org.freedesktop.Secret.Item.Label";
const ATTRS_PROP: &str = "org.freedesktop.Secret.Item.Attributes";
const LABEL_COLLECTION_PROP: &str = "org.freedesktop.Secret.Collection.Label";

#[derive(Debug, zbus::DBusError)]
#[zbus(prefix = "org.freedesktop.Secret.Error")]
pub enum ErreurSecret {
    #[zbus(error)]
    ZBus(zbus::Error),
    IsLocked(String),
    NoSession(String),
    NoSuchObject(String),
}


fn fdo_err(e: fdo::Error) -> ErreurSecret {
    ErreurSecret::ZBus(zbus::Error::FDO(Box::new(e)))
}

fn non_pris_en_charge(m: &str) -> ErreurSecret {
    fdo_err(fdo::Error::NotSupported(m.into()))
}

fn depuis(e: ErreurTrousseau) -> ErreurSecret {
    match e {
        ErreurTrousseau::Verrouille => ErreurSecret::IsLocked("le coffre myMFA est verrouillé".into()),
        ErreurTrousseau::Introuvable => ErreurSecret::NoSuchObject("objet inconnu".into()),
        ErreurTrousseau::Illisible => fdo_err(fdo::Error::Failed("trousseau illisible".into())),
    }
}

/// Connexion du démon (posée au démarrage, avant toute requête).
fn connexion(d: &Partage) -> zbus::Connection {
    d.connexion.get().cloned().expect("connexion posée au démarrage")
}

fn verrouille_err() -> ErreurSecret {
    ErreurSecret::IsLocked("le coffre myMFA est verrouillé".into())
}

/* ───── Chemins ───── */

pub fn chemin(texte: &str) -> OwnedObjectPath {
    OwnedObjectPath::try_from(texte.to_string()).unwrap_or_else(|_| racine_vide())
}

fn racine_vide() -> OwnedObjectPath {
    OwnedObjectPath::try_from("/").expect("chemin racine")
}

pub fn chemin_collection(id: &str) -> String {
    format!("{RACINE}/collection/{id}")
}

pub fn chemin_element(collection: &str, id: &str) -> String {
    format!("{RACINE}/collection/{collection}/{id}")
}

pub fn chemin_alias(alias: &str) -> String {
    format!("{RACINE}/aliases/{alias}")
}

/// Objet désigné par un chemin, alias résolu.
enum Objet {
    Collection(String),
    Element(String, String),
}

fn resoudre(d: &Partage, texte: &str) -> Option<Objet> {
    let reste = texte.strip_prefix(RACINE)?;
    let parties: Vec<&str> = reste.trim_start_matches('/').split('/').collect();
    let (collection, element) = match parties.as_slice() {
        ["collection", c] => ((*c).to_string(), None),
        ["collection", c, e] => ((*c).to_string(), Some((*e).to_string())),
        ["aliases", a] => (d.etat().trousseau.alias(a)?, None),
        ["aliases", a, e] => (d.etat().trousseau.alias(a)?, Some((*e).to_string())),
        _ => return None,
    };
    Some(match element {
        Some(e) => Objet::Element(collection, e),
        None => Objet::Collection(collection),
    })
}

/* ───── Logins du coffre (collection « mymfa ») ───── */

fn id_login(l: &Login) -> String {
    trousseau::identifiant(&l.id, "login")
}

fn attributs_login(l: &Login) -> Attributs {
    [
        ("xdg:schema", SCHEMA_LOGIN.to_string()),
        ("origin", l.origin.clone()),
        ("host", host_of(&l.origin)),
        ("username", l.username.clone()),
    ]
    .into_iter()
    .map(|(n, v)| (n.to_string(), v))
    .collect()
}

fn label_login(l: &Login) -> String {
    if l.title.is_empty() {
        host_of(&l.origin)
    } else {
        l.title.clone()
    }
}

fn avec_login<T>(d: &Partage, id: &str, f: impl FnOnce(&Login) -> T) -> Option<T> {
    let etat = d.etat();
    etat.coffre.as_ref()?.logins.iter().find(|l| id_login(l) == id).map(f)
}

fn elements_coffre(d: &Partage) -> Vec<String> {
    let etat = d.etat();
    etat.coffre.as_ref().map(|c| c.logins.iter().map(id_login).collect()).unwrap_or_default()
}

/* ───── Recherche commune ───── */

/// Éléments correspondants : (déverrouillés, verrouillés).
fn rechercher(d: &Partage, collection: Option<&str>, attributs: &Attributs) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
    let etat = d.etat();
    let trouves: Vec<OwnedObjectPath> = etat
        .trousseau
        .rechercher(collection, attributs)
        .into_iter()
        .map(|(c, e)| chemin(&chemin_element(&c, &e)))
        .collect();
    let mut ouverts = Vec::new();
    let mut fermes = Vec::new();
    if etat.coffre.is_some() {
        ouverts = trouves;
    } else {
        fermes = trouves;
    }
    if let Some(c) = etat.coffre.as_ref() {
        if collection.is_none_or(|x| x == trousseau::RESERVEE) {
            for l in &c.logins {
                let a = attributs_login(l);
                if attributs.iter().all(|(n, v)| a.get(n) == Some(v)) {
                    ouverts.push(chemin(&chemin_element(trousseau::RESERVEE, &id_login(l))));
                }
            }
        }
    }
    (ouverts, fermes)
}

fn secret_de(d: &Partage, collection: &str, id: &str) -> Result<(Zeroizing<Vec<u8>>, String), ErreurSecret> {
    if d.verrouille() {
        return Err(verrouille_err());
    }
    if collection == trousseau::RESERVEE {
        return avec_login(d, id, |l| (Zeroizing::new(l.password.as_bytes().to_vec()), "text/plain".to_string()))
            .ok_or_else(|| ErreurSecret::NoSuchObject(id.into()));
    }
    let etat = d.etat();
    let e = etat.trousseau.element(collection, id).map_err(depuis)?;
    Ok((e.secret.clone(), e.type_contenu.clone()))
}

fn encoder(d: &Partage, session: &OwnedObjectPath, secret: &[u8], type_contenu: String) -> Result<SecretDbus, ErreurSecret> {
    let etat = d.etat();
    let c = etat.sessions.get(session.as_str()).ok_or_else(|| ErreurSecret::NoSession(session.to_string()))?;
    let (parametres, valeur) = c.chiffrer(secret);
    Ok((session.clone(), parametres, valeur, type_contenu))
}

fn decoder(d: &Partage, secret: &SecretDbus) -> Result<Zeroizing<Vec<u8>>, ErreurSecret> {
    let etat = d.etat();
    let c = etat.sessions.get(secret.0.as_str()).ok_or_else(|| ErreurSecret::NoSession(secret.0.to_string()))?;
    c.dechiffrer(&secret.1, &secret.2).map_err(|_| fdo_err(fdo::Error::InvalidArgs("secret indéchiffrable".into())))
}

fn attributs_depuis(proprietes: &HashMap<String, OwnedValue>) -> Attributs {
    proprietes
        .get(ATTRS_PROP)
        .and_then(|v| v.try_clone().ok())
        .and_then(|v| HashMap::<String, String>::try_from(v).ok())
        .map(|h| h.into_iter().collect())
        .unwrap_or_default()
}

fn texte_depuis(proprietes: &HashMap<String, OwnedValue>, nom: &str) -> String {
    proprietes.get(nom).and_then(|v| String::try_from(v.try_clone().ok()?).ok()).unwrap_or_default()
}

/* ───── Service ───── */

pub struct Service {
    pub d: Partage,
}

#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    async fn open_session(
        &self,
        algorithm: String,
        input: OwnedValue,
        #[zbus(object_server)] serveur: &ObjectServer,
    ) -> Result<(OwnedValue, OwnedObjectPath), ErreurSecret> {
        let entree: Vec<u8> = if algorithm == session::PLAIN {
            Vec::new()
        } else {
            Vec::<u8>::try_from(input).map_err(|_| fdo_err(fdo::Error::InvalidArgs("clé publique attendue (ay)".into())))?
        };
        let (chiffrement, sortie) = session::negocier(&algorithm, &entree).map_err(|e| match e {
            session::ErreurSession::AlgorithmeInconnu => non_pris_en_charge("algorithme non pris en charge"),
            _ => fdo_err(fdo::Error::InvalidArgs("clé publique invalide".into())),
        })?;
        let texte = format!("{RACINE}/session/s{}", self.d.suivant());
        self.d.etat().sessions.insert(texte.clone(), chiffrement);
        let chemin_session = chemin(&texte);
        serveur.at(&chemin_session, ObjetSession { d: self.d.clone() }).await?;
        let sortie: OwnedValue = if algorithm == session::PLAIN {
            Value::from("").try_into().map_err(zbus::Error::from)?
        } else {
            Value::from(sortie).try_into().map_err(zbus::Error::from)?
        };
        Ok((sortie, chemin_session))
    }

    async fn create_collection(
        &self,
        properties: HashMap<String, OwnedValue>,
        alias: String,
        #[zbus(object_server)] serveur: &ObjectServer,
        #[zbus(header)] entete: zbus::message::Header<'_>,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), ErreurSecret> {
        if !alias.is_empty() {
            if let Some(id) = self.d.etat().trousseau.alias(&alias) {
                return Ok((chemin(&chemin_collection(&id)), racine_vide()));
            }
        }
        let label = texte_depuis(&properties, LABEL_COLLECTION_PROP);
        if self.d.verrouille() {
            let demandeur = entete.sender().map(|s| s.to_string()).unwrap_or_default();
            let invite = creer_invite(&self.d, serveur, Action::CreerCollection { label, alias }, demandeur).await?;
            return Ok((racine_vide(), invite));
        }
        let id = creer_collection(&self.d, serveur, &label, &alias).await?;
        Ok((chemin(&chemin_collection(&id)), racine_vide()))
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        rechercher(&self.d, None, &attributes.into_iter().collect())
    }

    async fn unlock(
        &self,
        objects: Vec<OwnedObjectPath>,
        #[zbus(object_server)] serveur: &ObjectServer,
        #[zbus(header)] entete: zbus::message::Header<'_>,
    ) -> Result<(Vec<OwnedObjectPath>, OwnedObjectPath), ErreurSecret> {
        if !self.d.verrouille() {
            return Ok((objects, racine_vide()));
        }
        let demandeur = entete.sender().map(|s| s.to_string()).unwrap_or_default();
        let invite = creer_invite(&self.d, serveur, Action::Deverrouiller(objects), demandeur).await?;
        Ok((Vec::new(), invite))
    }

    async fn lock(&self, objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        // Un seul verrou : verrouiller un objet verrouille le coffre entier
        // (annonces : tâche de main.rs abonnée au verrou).
        self.d.verrouiller();
        (objects, racine_vide())
    }

    async fn get_secrets(
        &self,
        items: Vec<OwnedObjectPath>,
        session: OwnedObjectPath,
    ) -> Result<HashMap<OwnedObjectPath, SecretDbus>, ErreurSecret> {
        if !self.d.etat().sessions.contains_key(session.as_str()) {
            return Err(ErreurSecret::NoSession(session.to_string()));
        }
        let mut secrets = HashMap::new();
        for item in items {
            if let Some(Objet::Element(c, e)) = resoudre(&self.d, item.as_str()) {
                if let Ok((secret, type_contenu)) = secret_de(&self.d, &c, &e) {
                    secrets.insert(item.clone(), encoder(&self.d, &session, &secret, type_contenu)?);
                }
            }
        }
        Ok(secrets)
    }

    async fn read_alias(&self, name: String) -> OwnedObjectPath {
        match self.d.etat().trousseau.alias(&name) {
            Some(id) => chemin(&chemin_collection(&id)),
            None => racine_vide(),
        }
    }

    async fn set_alias(
        &self,
        name: String,
        collection: OwnedObjectPath,
        #[zbus(object_server)] serveur: &ObjectServer,
    ) -> Result<(), ErreurSecret> {
        let cible = match collection.as_str() {
            "/" => None,
            texte => match resoudre(&self.d, texte) {
                Some(Objet::Collection(id)) if id != trousseau::RESERVEE => Some(id),
                _ => return Err(ErreurSecret::NoSuchObject(collection.to_string())),
            },
        };
        if trousseau::identifiant(&name, "") != name {
            return Err(fdo_err(fdo::Error::InvalidArgs("alias : [a-z0-9_] seulement".into())));
        }
        self.d.etat().trousseau.definir_alias(&name, cible.as_deref()).map_err(depuis)?;
        self.d.persister();
        if cible.is_some() {
            serveur.at(chemin_alias(&name), ObjetCollection { d: self.d.clone(), cible: Cible::Alias(name) }).await?;
        }
        Ok(())
    }

    #[zbus(property)]
    async fn collections(&self) -> Vec<OwnedObjectPath> {
        let mut ids = self.d.etat().trousseau.collections();
        ids.push(trousseau::RESERVEE.into());
        ids.iter().map(|id| chemin(&chemin_collection(id))).collect()
    }

    #[zbus(signal)]
    pub async fn collection_created(e: &SignalEmitter<'_>, collection: ObjectPath<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn collection_deleted(e: &SignalEmitter<'_>, collection: ObjectPath<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    pub async fn collection_changed(e: &SignalEmitter<'_>, collection: ObjectPath<'_>) -> zbus::Result<()>;
}

async fn creer_collection(d: &Partage, serveur: &ObjectServer, label: &str, alias: &str) -> Result<String, ErreurSecret> {
    let id = {
        let mut etat = d.etat();
        let id = etat.trousseau.creer_collection(if label.is_empty() { "Sans titre" } else { label }).map_err(depuis)?;
        if !alias.is_empty() && trousseau::identifiant(alias, "") == alias {
            let _ = etat.trousseau.definir_alias(alias, Some(&id));
        }
        id
    };
    d.persister();
    serveur.at(chemin_collection(&id), ObjetCollection { d: d.clone(), cible: Cible::Id(id.clone()) }).await?;
    if !alias.is_empty() {
        serveur.at(chemin_alias(alias), ObjetCollection { d: d.clone(), cible: Cible::Alias(alias.into()) }).await?;
    }
    if let Ok(e) = SignalEmitter::new(&connexion(d), RACINE) {
        let _ = Service::collection_created(&e, ObjectPath::try_from(chemin_collection(&id).as_str()).unwrap()).await;
    }
    journal!("collection créée : {id}");
    Ok(id)
}

/* ───── Collection ───── */

#[derive(Clone)]
pub enum Cible {
    Id(String),
    Alias(String),
}

pub struct ObjetCollection {
    pub d: Partage,
    pub cible: Cible,
}

impl ObjetCollection {
    fn id(&self) -> Result<String, ErreurSecret> {
        match &self.cible {
            Cible::Id(id) => Ok(id.clone()),
            Cible::Alias(a) => self.d.etat().trousseau.alias(a).ok_or_else(|| ErreurSecret::NoSuchObject(a.clone())),
        }
    }

    fn coffre(&self) -> bool {
        matches!(&self.cible, Cible::Id(id) if id == trousseau::RESERVEE)
    }
}

/// Chemins sur lesquels annoncer un changement d'une collection : son
/// chemin propre et ceux des alias qui la désignent.
fn chemins_de_collection(d: &Partage, id: &str) -> Vec<String> {
    let etat = d.etat();
    let mut chemins = vec![chemin_collection(id)];
    for (alias, cible) in &etat.trousseau.index.aliases {
        if cible == id {
            chemins.push(chemin_alias(alias));
        }
    }
    chemins
}

async fn annoncer_element(d: &Partage, collection: &str, element: &str, quoi: &str) {
    let chemin_e = chemin_element(collection, element);
    let Ok(p) = ObjectPath::try_from(chemin_e.as_str()) else { return };
    for c in chemins_de_collection(d, collection) {
        if let Ok(e) = SignalEmitter::new(&connexion(d), c) {
            let _ = match quoi {
                "created" => ObjetCollection::item_created(&e, p.clone()).await,
                "deleted" => ObjetCollection::item_deleted(&e, p.clone()).await,
                _ => ObjetCollection::item_changed(&e, p.clone()).await,
            };
        }
    }
}

#[interface(name = "org.freedesktop.Secret.Collection")]
impl ObjetCollection {
    async fn delete(&self, #[zbus(object_server)] serveur: &ObjectServer) -> Result<OwnedObjectPath, ErreurSecret> {
        if self.coffre() {
            return Err(non_pris_en_charge("la collection myMFA reflète le coffre : lecture seule"));
        }
        let id = self.id()?;
        let annonces = chemins_de_collection(&self.d, &id);
        let elements = self.d.etat().trousseau.supprimer_collection(&id).map_err(depuis)?;
        self.d.persister();
        for e in elements {
            let _ = serveur.remove::<ObjetElement, _>(chemin_element(&id, &e)).await;
        }
        for c in annonces {
            let _ = serveur.remove::<ObjetCollection, _>(c).await;
        }
        if let Ok(e) = SignalEmitter::new(&connexion(&self.d), RACINE) {
            let _ = Service::collection_deleted(&e, ObjectPath::try_from(chemin_collection(&id).as_str()).unwrap()).await;
        }
        journal!("collection supprimée : {id}");
        Ok(racine_vide())
    }

    async fn search_items(&self, attributes: HashMap<String, String>) -> Result<Vec<OwnedObjectPath>, ErreurSecret> {
        let id = self.id()?;
        let (mut ouverts, fermes) = rechercher(&self.d, Some(&id), &attributes.into_iter().collect());
        ouverts.extend(fermes);
        Ok(ouverts)
    }

    async fn create_item(
        &self,
        properties: HashMap<String, OwnedValue>,
        secret: SecretDbus,
        replace: bool,
        #[zbus(object_server)] serveur: &ObjectServer,
    ) -> Result<(OwnedObjectPath, OwnedObjectPath), ErreurSecret> {
        if self.coffre() {
            return Err(non_pris_en_charge("la collection myMFA reflète le coffre : lecture seule"));
        }
        let id = self.id()?;
        if self.d.verrouille() {
            return Err(verrouille_err());
        }
        let valeur = decoder(&self.d, &secret)?;
        let label = texte_depuis(&properties, LABEL_PROP);
        let attributs = attributs_depuis(&properties);
        let (element, cree) = self
            .d
            .etat()
            .trousseau
            .creer_element(&id, &label, attributs, valeur, &secret.3, replace)
            .map_err(depuis)?;
        self.d.persister();
        let chemin_e = chemin_element(&id, &element);
        if cree {
            serveur.at(chemin_e.as_str(), ObjetElement { d: self.d.clone(), collection: id.clone(), id: element.clone() }).await?;
        }
        annoncer_element(&self.d, &id, &element, if cree { "created" } else { "changed" }).await;
        Ok((chemin(&chemin_e), racine_vide()))
    }

    #[zbus(property)]
    async fn items(&self) -> Vec<OwnedObjectPath> {
        let Ok(id) = self.id() else { return Vec::new() };
        let elements = if id == trousseau::RESERVEE { elements_coffre(&self.d) } else { self.d.etat().trousseau.elements(&id) };
        elements.iter().map(|e| chemin(&chemin_element(&id, e))).collect()
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        let Ok(id) = self.id() else { return String::new() };
        if id == trousseau::RESERVEE {
            return "myMFA".into();
        }
        self.d.etat().trousseau.index_collection(&id).map(|c| c.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> fdo::Result<()> {
        if self.coffre() {
            return Err(fdo::Error::NotSupported("lecture seule".into()));
        }
        let id = self.id().map_err(|_| fdo::Error::UnknownObject("collection".into()))?;
        self.d.etat().trousseau.renommer_collection(&id, &label).map_err(|_| fdo::Error::Failed("coffre verrouillé".into()))?;
        self.d.persister();
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.d.verrouille()
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let Ok(id) = self.id() else { return 0 };
        self.d.etat().trousseau.index_collection(&id).map(|c| c.created).unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let Ok(id) = self.id() else { return 0 };
        self.d.etat().trousseau.index_collection(&id).map(|c| c.modified).unwrap_or(0)
    }

    #[zbus(signal)]
    async fn item_created(e: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn item_deleted(e: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn item_changed(e: &SignalEmitter<'_>, item: ObjectPath<'_>) -> zbus::Result<()>;
}

/* ───── Item ───── */

pub struct ObjetElement {
    pub d: Partage,
    pub collection: String,
    pub id: String,
}

impl ObjetElement {
    fn coffre(&self) -> bool {
        self.collection == trousseau::RESERVEE
    }
}

#[interface(name = "org.freedesktop.Secret.Item")]
impl ObjetElement {
    async fn delete(&self, #[zbus(object_server)] serveur: &ObjectServer) -> Result<OwnedObjectPath, ErreurSecret> {
        if self.coffre() {
            return Err(non_pris_en_charge("login du coffre : à supprimer depuis myMFA"));
        }
        self.d.etat().trousseau.supprimer_element(&self.collection, &self.id).map_err(depuis)?;
        self.d.persister();
        annoncer_element(&self.d, &self.collection, &self.id, "deleted").await;
        let _ = serveur.remove::<ObjetElement, _>(chemin_element(&self.collection, &self.id)).await;
        Ok(racine_vide())
    }

    /// Un seul argument de sortie, de type struct (oayays) : d'où le 1-uplet.
    async fn get_secret(&self, session: OwnedObjectPath) -> Result<(SecretDbus,), ErreurSecret> {
        let (secret, type_contenu) = secret_de(&self.d, &self.collection, &self.id)?;
        Ok((encoder(&self.d, &session, &secret, type_contenu)?,))
    }

    async fn set_secret(&self, secret: SecretDbus) -> Result<(), ErreurSecret> {
        if self.coffre() {
            return Err(non_pris_en_charge("login du coffre : à modifier depuis myMFA"));
        }
        if self.d.verrouille() {
            return Err(verrouille_err());
        }
        let valeur = decoder(&self.d, &secret)?;
        let type_contenu = secret.3.clone();
        self.d
            .etat()
            .trousseau
            .modifier_element(&self.collection, &self.id, move |e| {
                e.secret = valeur;
                e.type_contenu = type_contenu;
            })
            .map_err(depuis)?;
        self.d.persister();
        annoncer_element(&self.d, &self.collection, &self.id, "changed").await;
        Ok(())
    }

    #[zbus(property)]
    async fn locked(&self) -> bool {
        self.d.verrouille()
    }

    #[zbus(property)]
    async fn attributes(&self) -> HashMap<String, String> {
        if self.coffre() {
            return avec_login(&self.d, &self.id, |l| attributs_login(l).into_iter().collect()).unwrap_or_default();
        }
        let etat = self.d.etat();
        etat.trousseau.element(&self.collection, &self.id).map(|e| e.attributs.clone().into_iter().collect()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_attributes(&mut self, attributes: HashMap<String, String>) -> fdo::Result<()> {
        if self.coffre() {
            return Err(fdo::Error::NotSupported("lecture seule".into()));
        }
        self.d
            .etat()
            .trousseau
            .modifier_element(&self.collection, &self.id, |e| e.attributs = attributes.into_iter().collect())
            .map_err(|_| fdo::Error::Failed("coffre verrouillé".into()))?;
        self.d.persister();
        Ok(())
    }

    #[zbus(property)]
    async fn label(&self) -> String {
        if self.coffre() {
            return avec_login(&self.d, &self.id, label_login).unwrap_or_default();
        }
        let etat = self.d.etat();
        etat.trousseau.element(&self.collection, &self.id).map(|e| e.label.clone()).unwrap_or_default()
    }

    #[zbus(property)]
    async fn set_label(&mut self, label: String) -> fdo::Result<()> {
        if self.coffre() {
            return Err(fdo::Error::NotSupported("lecture seule".into()));
        }
        self.d
            .etat()
            .trousseau
            .modifier_element(&self.collection, &self.id, |e| e.label = label)
            .map_err(|_| fdo::Error::Failed("coffre verrouillé".into()))?;
        self.d.persister();
        Ok(())
    }

    #[zbus(property)]
    async fn created(&self) -> u64 {
        let etat = self.d.etat();
        etat.trousseau.element(&self.collection, &self.id).map(|e| e.cree).unwrap_or(0)
    }

    #[zbus(property)]
    async fn modified(&self) -> u64 {
        let etat = self.d.etat();
        etat.trousseau.element(&self.collection, &self.id).map(|e| e.modifie).unwrap_or(0)
    }
}

/* ───── Session ───── */

pub struct ObjetSession {
    d: Partage,
}

#[interface(name = "org.freedesktop.Secret.Session")]
impl ObjetSession {
    async fn close(
        &self,
        #[zbus(object_server)] serveur: &ObjectServer,
        #[zbus(header)] entete: zbus::message::Header<'_>,
    ) -> fdo::Result<()> {
        if let Some(p) = entete.path() {
            let texte = p.to_string();
            self.d.etat().sessions.remove(&texte);
            let _ = serveur.remove::<ObjetSession, _>(texte).await;
        }
        Ok(())
    }
}

/* ───── Prompt ───── */

pub enum Action {
    Deverrouiller(Vec<OwnedObjectPath>),
    CreerCollection { label: String, alias: String },
}

pub struct ObjetInvite {
    d: Partage,
    chemin: String,
    action: Arc<std::sync::Mutex<Option<Action>>>,
    annule: Arc<Notify>,
    demandeur: String,
}

async fn creer_invite(d: &Partage, serveur: &ObjectServer, action: Action, demandeur: String) -> Result<OwnedObjectPath, ErreurSecret> {
    let texte = format!("{RACINE}/prompt/p{}", d.suivant());
    let objet = ObjetInvite {
        d: d.clone(),
        chemin: texte.clone(),
        action: Arc::new(std::sync::Mutex::new(Some(action))),
        annule: Arc::new(Notify::new()),
        demandeur,
    };
    serveur.at(texte.as_str(), objet).await?;
    Ok(chemin(&texte))
}

#[interface(name = "org.freedesktop.Secret.Prompt")]
impl ObjetInvite {
    async fn prompt(&self, window_id: String) -> fdo::Result<()> {
        let _ = window_id; // pas de rattachement de fenêtre sous Wayland
        let Some(action) = self.action.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            return Ok(()); // déjà lancée
        };
        let (d, chemin_invite, annule, demandeur) = (self.d.clone(), self.chemin.clone(), self.annule.clone(), self.demandeur.clone());
        tokio::spawn(async move { executer_invite(d, chemin_invite, action, annule, demandeur).await });
        Ok(())
    }

    async fn dismiss(&self) -> fdo::Result<()> {
        self.annule.notify_one();
        Ok(())
    }

    #[zbus(signal)]
    async fn completed(e: &SignalEmitter<'_>, dismissed: bool, result: Value<'_>) -> zbus::Result<()>;
}

/// Attend le déverrouillage (hyprdesk via MyMfa1.Unlock, `mymfa unlock`, ou
/// pinentry), puis termine l'action et émet Completed.
async fn executer_invite(d: Partage, chemin_invite: String, action: Action, annule: Arc<Notify>, demandeur: String) {
    let mut verrou = d.verrou.subscribe();
    let mut saisie = None;
    let annulee = if !*verrou.borrow() {
        false
    } else {
        let application = nom_application(&d, &demandeur).await;
        interface::demander_deverrouillage(&d, &application).await;
        if invite::active() {
            let d2 = d.clone();
            let application = application.clone();
            saisie = Some(tokio::spawn(async move { invite::demander(&d2, &application).await }));
        }
        loop {
            tokio::select! {
                change = verrou.changed() => {
                    if change.is_err() { break true; }
                    if !*verrou.borrow() { break false; }
                }
                _ = annule.notified() => break true,
                fin = async { match saisie.as_mut() { Some(t) => t.await.ok(), None => std::future::pending().await } } => {
                    saisie = None;
                    if fin != Some(true) && *verrou.borrow() { break true; }
                }
            }
        }
    };
    if let Some(t) = saisie {
        t.abort(); // pinentry fermé (kill_on_drop)
    }
    let Some(conn) = d.connexion.get().cloned() else { return };
    let serveur = conn.object_server();
    let resultat: OwnedValue = match (&action, annulee) {
        (Action::Deverrouiller(objets), false) => Value::from(objets.clone()).try_into().unwrap(),
        (Action::Deverrouiller(_), true) => Value::from(Vec::<OwnedObjectPath>::new()).try_into().unwrap(),
        (Action::CreerCollection { label, alias }, false) => match creer_collection(&d, serveur, label, alias).await {
            Ok(id) => Value::from(chemin(&chemin_collection(&id))).try_into().unwrap(),
            Err(_) => Value::from(racine_vide()).try_into().unwrap(),
        },
        (Action::CreerCollection { .. }, true) => Value::from(racine_vide()).try_into().unwrap(),
    };
    if !annulee {
        apres_changement_de_verrou(&d).await;
    }
    if let Ok(e) = SignalEmitter::new(&conn, chemin_invite.as_str()) {
        let _ = ObjetInvite::completed(&e, annulee, Value::from(resultat)).await;
    }
    let _ = serveur.remove::<ObjetInvite, _>(chemin_invite.as_str()).await;
}

/// Nom lisible du demandeur (« chromium », « nm-applet ») pour l'invite.
async fn nom_application(d: &Partage, demandeur: &str) -> String {
    let Some(conn) = d.connexion.get() else { return String::new() };
    let Ok(proxy) = fdo::DBusProxy::new(conn).await else { return String::new() };
    let Ok(nom) = zbus::names::BusName::try_from(demandeur) else { return String::new() };
    match proxy.get_connection_unix_process_id(nom).await {
        Ok(pid) => std::fs::read_to_string(format!("/proc/{pid}/comm")).map(|s| s.trim().to_string()).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

/* ───── Publication des objets ───── */

/// Au démarrage : service, collections locales, alias, éléments connus de
/// l'index (même verrouillé : leurs chemins répondent « verrouillé »).
pub async fn publier(d: &Partage, serveur: &ObjectServer) -> zbus::Result<()> {
    serveur.at(RACINE, Service { d: d.clone() }).await?;
    let (collections, alias) = {
        let etat = d.etat();
        let c: Vec<(String, Vec<String>)> =
            etat.trousseau.collections().into_iter().map(|id| (id.clone(), etat.trousseau.elements(&id))).collect();
        let a: Vec<String> = etat.trousseau.index.aliases.keys().cloned().collect();
        (c, a)
    };
    for (id, elements) in collections {
        serveur.at(chemin_collection(&id), ObjetCollection { d: d.clone(), cible: Cible::Id(id.clone()) }).await?;
        for e in elements {
            serveur.at(chemin_element(&id, &e), ObjetElement { d: d.clone(), collection: id.clone(), id: e }).await?;
        }
    }
    for a in alias {
        serveur.at(chemin_alias(&a), ObjetCollection { d: d.clone(), cible: Cible::Alias(a.clone()) }).await?;
    }
    serveur
        .at(chemin_collection(trousseau::RESERVEE), ObjetCollection { d: d.clone(), cible: Cible::Id(trousseau::RESERVEE.into()) })
        .await?;
    Ok(())
}

/// Après un changement du contenu du coffre : logins republiés dans la
/// collection « myMFA », collection annoncée, signal MyMfa1.ContentChanged.
pub async fn apres_changement_de_contenu(d: &Partage) {
    let Some(conn) = d.connexion.get().cloned() else { return };
    let serveur = conn.object_server();
    republier_coffre(d, serveur).await;
    if let Ok(i) = serveur.interface::<_, ObjetCollection>(chemin_collection(trousseau::RESERVEE)).await {
        let _ = i.get().await.items_changed(i.signal_emitter()).await;
    }
    interface::annoncer_contenu(d).await;
}

/// Éléments du coffre (logins) retirés puis publiés à nouveau s'il est ouvert.
async fn republier_coffre(d: &Partage, serveur: &ObjectServer) {
    let verrouille = d.verrouille();
    let publies = { std::mem::take(&mut *d.publies_coffre()) };
    for p in &publies {
        let _ = serveur.remove::<ObjetElement, _>(p.as_str()).await;
    }
    if !verrouille {
        let mut nouveaux = Vec::new();
        for e in elements_coffre(d) {
            let p = chemin_element(trousseau::RESERVEE, &e);
            if serveur
                .at(p.as_str(), ObjetElement { d: d.clone(), collection: trousseau::RESERVEE.into(), id: e })
                .await
                .is_ok()
            {
                nouveaux.push(p);
            }
        }
        *d.publies_coffre() = nouveaux;
    }
}

/// Après un changement d'état : éléments du coffre publiés ou retirés,
/// propriétés Locked annoncées, signal MyMfa1.StateChanged.
pub async fn apres_changement_de_verrou(d: &Partage) {
    let Some(conn) = d.connexion.get().cloned() else { return };
    let serveur = conn.object_server();
    republier_coffre(d, serveur).await;
    // Locked sur les collections et les éléments locaux (caches de libsecret).
    let (collections, elements) = {
        let etat = d.etat();
        let mut c: Vec<String> = etat.trousseau.collections();
        c.push(trousseau::RESERVEE.into());
        let e: Vec<String> = etat
            .trousseau
            .collections()
            .iter()
            .flat_map(|id| etat.trousseau.elements(id).into_iter().map(move |e| chemin_element(id, &e)))
            .collect();
        (c, e)
    };
    for id in collections {
        if let Ok(i) = serveur.interface::<_, ObjetCollection>(chemin_collection(&id)).await {
            let _ = i.get().await.locked_changed(i.signal_emitter()).await;
            let _ = i.get().await.items_changed(i.signal_emitter()).await;
        }
    }
    for p in elements {
        if let Ok(i) = serveur.interface::<_, ObjetElement>(p).await {
            let _ = i.get().await.locked_changed(i.signal_emitter()).await;
        }
    }
    interface::annoncer_etat(d).await;
}
