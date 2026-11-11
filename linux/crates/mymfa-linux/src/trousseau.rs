/*
 * Trousseau local : les secrets que les applications confient au Secret
 * Service (Chromium, NetworkManager, Evolution…). Ils ne sont PAS dans le
 * coffre myMFA — jamais synchronisés, jamais exportés — mais chiffrés par la
 * clé du coffre (DEK) avec une AAD propre : déverrouiller le coffre les ouvre,
 * le verrouiller les referme.
 *
 * Fichier `mymfa-keyring.json` :
 *   { v: 1,
 *     salt,                           // hex, sel des empreintes d'attributs
 *     index: { aliases: { default: "login", … },
 *              collections: { <id>: { label, created, modified,
 *                                     items: { <id>: [empreinte, …] } } } },
 *     data: { iv, ct } | null }       // AES-256-GCM(DEK, JSON, AAD_TROUSSEAU)
 *
 * L'index reste en clair pour qu'une recherche faite coffre verrouillé
 * réponde « verrouillé » plutôt que « rien » (sans quoi une application
 * recréerait sa clé et perdrait ses données) : il ne contient que des
 * empreintes salées des attributs, comme le format de gnome-keyring, jamais
 * un libellé d'élément ni un secret.
 */
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use mymfa_core::vault::{from_b64, random_bytes, to_b64, DataBlob};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::chemins::maintenant;

pub const AAD_TROUSSEAU: &str = "mymfa:linux:keyring:v1";
/// Collection par défaut (alias « default » et « login »), comme gnome-keyring.
pub const CONNEXION: &str = "login";
/// Réservée à la collection en lecture seule des logins du coffre.
pub const RESERVEE: &str = "mymfa";

pub type Attributs = BTreeMap<String, String>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErreurTrousseau {
    /// La clé du coffre n'ouvre pas ce trousseau (coffre recréé ailleurs).
    Illisible,
    Verrouille,
    Introuvable,
}

pub struct Element {
    pub label: String,
    pub attributs: Attributs,
    pub secret: Zeroizing<Vec<u8>>,
    pub type_contenu: String,
    pub cree: u64,
    pub modifie: u64,
}

pub struct Collection {
    pub label: String,
    pub cree: u64,
    pub modifie: u64,
    pub elements: BTreeMap<String, Element>,
}

/* ───── Formats sérialisés ───── */

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct IndexCollection {
    pub label: String,
    pub created: u64,
    pub modified: u64,
    #[serde(default)]
    pub items: BTreeMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Index {
    #[serde(default)]
    pub aliases: BTreeMap<String, String>,
    #[serde(default)]
    pub collections: BTreeMap<String, IndexCollection>,
}

#[derive(Serialize, Deserialize)]
struct Fichier {
    v: u32,
    salt: String,
    index: Index,
    data: Option<DataBlob>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ElementClair {
    label: String,
    attributes: Attributs,
    secret: String, // base64
    content_type: String,
    created: u64,
    modified: u64,
}

#[derive(Serialize, Deserialize)]
struct CollectionClaire {
    label: String,
    created: u64,
    modified: u64,
    items: BTreeMap<String, ElementClair>,
}

#[derive(Serialize, Deserialize)]
struct ContenuClair {
    collections: BTreeMap<String, CollectionClaire>,
}

/* ───── Trousseau ───── */

pub struct Trousseau {
    sel: Vec<u8>,
    pub index: Index,
    chiffre: Option<DataBlob>,
    /// Présent quand le coffre est déverrouillé.
    contenu: Option<BTreeMap<String, Collection>>,
}

fn index_neuf() -> Index {
    let t = maintenant();
    let mut index = Index::default();
    index.aliases.insert("default".into(), CONNEXION.into());
    index.aliases.insert("login".into(), CONNEXION.into());
    index
        .collections
        .insert(CONNEXION.into(), IndexCollection { label: "Connexion".into(), created: t, modified: t, items: BTreeMap::new() });
    index
}

impl Trousseau {
    pub fn neuf() -> Self {
        Trousseau { sel: random_bytes(16), index: index_neuf(), chiffre: None, contenu: None }
    }

    /// Lit le fichier ; un fichier illisible donne `Err` (le démon le met de côté).
    pub fn charger(texte: Option<&str>) -> Result<Self, ErreurTrousseau> {
        let Some(texte) = texte else { return Ok(Self::neuf()) };
        let f: Fichier = serde_json::from_str(texte).map_err(|_| ErreurTrousseau::Illisible)?;
        if f.v != 1 {
            return Err(ErreurTrousseau::Illisible);
        }
        let sel = mymfa_sceau::de_hex(&f.salt).ok_or(ErreurTrousseau::Illisible)?;
        let mut t = Trousseau { sel, index: f.index, chiffre: f.data, contenu: None };
        if !t.index.collections.contains_key(CONNEXION) {
            let defaut = index_neuf();
            t.index.collections.insert(CONNEXION.into(), defaut.collections[CONNEXION].clone());
        }
        Ok(t)
    }

    #[cfg(test)]
    pub fn ouvert(&self) -> bool {
        self.contenu.is_some()
    }

    /// Déchiffre le contenu avec la clé du coffre.
    pub fn ouvrir(&mut self, dek: &[u8; 32]) -> Result<(), ErreurTrousseau> {
        let mut collections = BTreeMap::new();
        if let Some(blob) = &self.chiffre {
            let iv = from_b64(&blob.iv).map_err(|_| ErreurTrousseau::Illisible)?;
            let ct = from_b64(&blob.ct).map_err(|_| ErreurTrousseau::Illisible)?;
            if iv.len() != 12 {
                return Err(ErreurTrousseau::Illisible);
            }
            let clair = Zeroizing::new(
                Aes256Gcm::new(dek.into())
                    .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: AAD_TROUSSEAU.as_bytes() })
                    .map_err(|_| ErreurTrousseau::Illisible)?,
            );
            let mut contenu: ContenuClair = serde_json::from_slice(&clair).map_err(|_| ErreurTrousseau::Illisible)?;
            for (id, c) in std::mem::take(&mut contenu.collections) {
                let mut elements = BTreeMap::new();
                for (eid, mut e) in c.items {
                    let secret = Zeroizing::new(from_b64(&e.secret).map_err(|_| ErreurTrousseau::Illisible)?);
                    zeroize::Zeroize::zeroize(&mut e.secret);
                    elements.insert(
                        eid,
                        Element {
                            label: e.label,
                            attributs: e.attributes,
                            secret,
                            type_contenu: e.content_type,
                            cree: e.created,
                            modifie: e.modified,
                        },
                    );
                }
                collections.insert(id, Collection { label: c.label, cree: c.created, modifie: c.modified, elements });
            }
        }
        // Collections connues de l'index mais absentes du contenu (fichier neuf).
        for (id, ic) in &self.index.collections {
            collections.entry(id.clone()).or_insert_with(|| Collection {
                label: ic.label.clone(),
                cree: ic.created,
                modifie: ic.modified,
                elements: BTreeMap::new(),
            });
        }
        self.contenu = Some(collections);
        self.reindexer();
        Ok(())
    }

    /// Referme : les secrets en clair quittent la mémoire (Zeroizing).
    pub fn fermer(&mut self) {
        self.contenu = None;
    }

    /// Rechiffre le contenu et rend le texte du fichier à écrire.
    pub fn serialiser(&mut self, dek: &[u8; 32]) -> Result<Zeroizing<String>, ErreurTrousseau> {
        if let Some(collections) = &self.contenu {
            let clair = ContenuClair {
                collections: collections
                    .iter()
                    .map(|(id, c)| {
                        (
                            id.clone(),
                            CollectionClaire {
                                label: c.label.clone(),
                                created: c.cree,
                                modified: c.modifie,
                                items: c
                                    .elements
                                    .iter()
                                    .map(|(eid, e)| {
                                        (
                                            eid.clone(),
                                            ElementClair {
                                                label: e.label.clone(),
                                                attributes: e.attributs.clone(),
                                                secret: to_b64(&e.secret),
                                                content_type: e.type_contenu.clone(),
                                                created: e.cree,
                                                modified: e.modifie,
                                            },
                                        )
                                    })
                                    .collect(),
                            },
                        )
                    })
                    .collect(),
            };
            let texte = Zeroizing::new(serde_json::to_string(&clair).map_err(|_| ErreurTrousseau::Illisible)?);
            let mut clair = clair;
            for c in clair.collections.values_mut() {
                for e in c.items.values_mut() {
                    zeroize::Zeroize::zeroize(&mut e.secret);
                }
            }
            let iv = random_bytes(12);
            let ct = Aes256Gcm::new(dek.into())
                .encrypt(Nonce::from_slice(&iv), Payload { msg: texte.as_bytes(), aad: AAD_TROUSSEAU.as_bytes() })
                .map_err(|_| ErreurTrousseau::Illisible)?;
            self.chiffre = Some(DataBlob { iv: to_b64(&iv), ct: to_b64(&ct) });
            self.reindexer();
        }
        Ok(self.fichier())
    }

    /// Texte du fichier tel quel (index modifié coffre verrouillé : alias).
    pub fn fichier(&self) -> Zeroizing<String> {
        let f = Fichier { v: 1, salt: mymfa_sceau::hex(&self.sel), index: self.index.clone(), data: self.chiffre.clone() };
        Zeroizing::new(serde_json::to_string_pretty(&f).expect("sérialisation interne"))
    }

    fn empreinte(&self, nom: &str, valeur: &str) -> String {
        let mut h = Sha256::new();
        h.update(&self.sel);
        h.update(nom.as_bytes());
        h.update([0]);
        h.update(valeur.as_bytes());
        mymfa_sceau::hex(&h.finalize()[..16])
    }

    fn reindexer(&mut self) {
        let Some(collections) = &self.contenu else { return };
        let mut nouvelles = BTreeMap::new();
        for (id, c) in collections {
            let items = c
                .elements
                .iter()
                .map(|(eid, e)| {
                    let mut empreintes: Vec<String> = e.attributs.iter().map(|(n, v)| self.empreinte(n, v)).collect();
                    empreintes.sort();
                    (eid.clone(), empreintes)
                })
                .collect();
            nouvelles.insert(id.clone(), IndexCollection { label: c.label.clone(), created: c.cree, modified: c.modifie, items });
        }
        self.index.collections = nouvelles;
        let connues: Vec<String> = self.index.collections.keys().cloned().collect();
        self.index.aliases.retain(|_, c| connues.contains(c));
    }

    /* ───── Lecture ───── */

    pub fn collections(&self) -> Vec<String> {
        self.index.collections.keys().cloned().collect()
    }

    pub fn existe(&self, collection: &str) -> bool {
        self.index.collections.contains_key(collection)
    }

    pub fn elements(&self, collection: &str) -> Vec<String> {
        self.index.collections.get(collection).map(|c| c.items.keys().cloned().collect()).unwrap_or_default()
    }

    pub fn index_collection(&self, collection: &str) -> Option<&IndexCollection> {
        self.index.collections.get(collection)
    }

    pub fn element(&self, collection: &str, id: &str) -> Result<&Element, ErreurTrousseau> {
        let contenu = self.contenu.as_ref().ok_or(ErreurTrousseau::Verrouille)?;
        contenu.get(collection).and_then(|c| c.elements.get(id)).ok_or(ErreurTrousseau::Introuvable)
    }

    /// Éléments dont les attributs contiennent tous ceux demandés. Coffre
    /// verrouillé, la recherche passe par les empreintes de l'index.
    pub fn rechercher(&self, collection: Option<&str>, attributs: &Attributs) -> Vec<(String, String)> {
        let mut trouves = Vec::new();
        if let Some(contenu) = &self.contenu {
            for (cid, c) in contenu.iter().filter(|(cid, _)| collection.is_none_or(|x| x == cid.as_str())) {
                for (eid, e) in &c.elements {
                    if attributs.iter().all(|(n, v)| e.attributs.get(n) == Some(v)) {
                        trouves.push((cid.clone(), eid.clone()));
                    }
                }
            }
        } else {
            let voulues: Vec<String> = attributs.iter().map(|(n, v)| self.empreinte(n, v)).collect();
            for (cid, c) in self.index.collections.iter().filter(|(cid, _)| collection.is_none_or(|x| x == cid.as_str())) {
                for (eid, empreintes) in &c.items {
                    if voulues.iter().all(|v| empreintes.contains(v)) {
                        trouves.push((cid.clone(), eid.clone()));
                    }
                }
            }
        }
        trouves
    }

    pub fn alias(&self, nom: &str) -> Option<String> {
        self.index.aliases.get(nom).cloned()
    }

    /* ───── Écriture (coffre déverrouillé) ───── */

    fn contenu_mut(&mut self) -> Result<&mut BTreeMap<String, Collection>, ErreurTrousseau> {
        self.contenu.as_mut().ok_or(ErreurTrousseau::Verrouille)
    }

    /// Alias vers une collection locale ; `None` le retire.
    pub fn definir_alias(&mut self, nom: &str, collection: Option<&str>) -> Result<(), ErreurTrousseau> {
        match collection {
            None => {
                self.index.aliases.remove(nom);
            }
            Some(c) if self.existe(c) => {
                self.index.aliases.insert(nom.into(), c.into());
            }
            Some(_) => return Err(ErreurTrousseau::Introuvable),
        }
        Ok(())
    }

    /// Crée une collection ; son identifiant dérive du libellé (chemin D-Bus).
    pub fn creer_collection(&mut self, label: &str) -> Result<String, ErreurTrousseau> {
        let base = identifiant(label, "collection");
        let mut id = base.clone();
        let mut n = 2;
        while self.existe(&id) || id == RESERVEE {
            id = format!("{base}_{n}");
            n += 1;
        }
        let t = maintenant();
        self.contenu_mut()?
            .insert(id.clone(), Collection { label: label.into(), cree: t, modifie: t, elements: BTreeMap::new() });
        self.reindexer();
        Ok(id)
    }

    pub fn supprimer_collection(&mut self, collection: &str) -> Result<Vec<String>, ErreurTrousseau> {
        let c = self.contenu_mut()?.remove(collection).ok_or(ErreurTrousseau::Introuvable)?;
        self.reindexer();
        Ok(c.elements.into_keys().collect())
    }

    pub fn renommer_collection(&mut self, collection: &str, label: &str) -> Result<(), ErreurTrousseau> {
        let c = self.contenu_mut()?.get_mut(collection).ok_or(ErreurTrousseau::Introuvable)?;
        c.label = label.into();
        c.modifie = maintenant();
        self.reindexer();
        Ok(())
    }

    /// Crée un élément, ou remplace celui aux attributs identiques si
    /// `remplacer` (sémantique de CreateItem). Rend (id, créé ?).
    pub fn creer_element(
        &mut self,
        collection: &str,
        label: &str,
        attributs: Attributs,
        secret: Zeroizing<Vec<u8>>,
        type_contenu: &str,
        remplacer: bool,
    ) -> Result<(String, bool), ErreurTrousseau> {
        let t = maintenant();
        let c = self.contenu_mut()?.get_mut(collection).ok_or(ErreurTrousseau::Introuvable)?;
        if remplacer {
            if let Some((id, e)) = c.elements.iter_mut().find(|(_, e)| e.attributs == attributs) {
                e.label = label.into();
                e.secret = secret;
                e.type_contenu = type_contenu.into();
                e.modifie = t;
                let id = id.clone();
                c.modifie = t;
                self.reindexer();
                return Ok((id, false));
            }
        }
        let id = loop {
            let candidat = mymfa_sceau::hex(&random_bytes(8));
            if !c.elements.contains_key(&candidat) {
                break candidat;
            }
        };
        c.elements.insert(
            id.clone(),
            Element { label: label.into(), attributs, secret, type_contenu: type_contenu.into(), cree: t, modifie: t },
        );
        c.modifie = t;
        self.reindexer();
        Ok((id, true))
    }

    pub fn supprimer_element(&mut self, collection: &str, id: &str) -> Result<(), ErreurTrousseau> {
        let c = self.contenu_mut()?.get_mut(collection).ok_or(ErreurTrousseau::Introuvable)?;
        c.elements.remove(id).ok_or(ErreurTrousseau::Introuvable)?;
        c.modifie = maintenant();
        self.reindexer();
        Ok(())
    }

    pub fn modifier_element(
        &mut self,
        collection: &str,
        id: &str,
        modifier: impl FnOnce(&mut Element),
    ) -> Result<(), ErreurTrousseau> {
        let c = self.contenu_mut()?.get_mut(collection).ok_or(ErreurTrousseau::Introuvable)?;
        let e = c.elements.get_mut(id).ok_or(ErreurTrousseau::Introuvable)?;
        modifier(e);
        e.modifie = maintenant();
        c.modifie = e.modifie;
        self.reindexer();
        Ok(())
    }
}

/// Identifiant sûr pour un chemin D-Bus : [a-z0-9_], jamais vide.
pub fn identifiant(texte: &str, repli: &str) -> String {
    let mut id: String = texte
        .to_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    id.truncate(48);
    if id.trim_matches('_').is_empty() {
        repli.into()
    } else {
        id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(paires: &[(&str, &str)]) -> Attributs {
        paires.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect()
    }

    fn secret(s: &str) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(s.as_bytes().to_vec())
    }

    #[test]
    fn neuf_avec_collection_de_connexion() {
        let t = Trousseau::neuf();
        assert_eq!(t.collections(), vec!["login"]);
        assert_eq!(t.alias("default").as_deref(), Some("login"));
        assert_eq!(t.alias("login").as_deref(), Some("login"));
        assert!(!t.ouvert());
    }

    #[test]
    fn chiffrement_aller_retour() {
        let dek = [7u8; 32];
        let mut t = Trousseau::neuf();
        t.ouvrir(&dek).unwrap();
        let a = attrs(&[("application", "chromium"), ("xdg:schema", "chrome_libsecret_os_crypt_password_v2")]);
        let (id, cree) = t.creer_element(CONNEXION, "Chromium Safe Storage", a.clone(), secret("s3cr3t-clé"), "text/plain", true).unwrap();
        assert!(cree);
        let texte = t.serialiser(&dek).unwrap();
        assert!(!texte.contains("s3cr3t"), "secret jamais en clair");
        assert!(!texte.contains("Chromium Safe Storage"), "libellé jamais en clair");
        assert!(!texte.contains("chromium"), "attributs seulement en empreintes");

        let mut relu = Trousseau::charger(Some(&texte)).unwrap();
        assert!(!relu.ouvert());
        // Verrouillé : la recherche répond par les empreintes.
        assert_eq!(relu.rechercher(None, &attrs(&[("application", "chromium")])), vec![(CONNEXION.into(), id.clone())]);
        assert!(relu.rechercher(None, &attrs(&[("application", "firefox")])).is_empty());
        assert_eq!(relu.element(CONNEXION, &id).err(), Some(ErreurTrousseau::Verrouille));
        relu.ouvrir(&dek).unwrap();
        let e = relu.element(CONNEXION, &id).unwrap();
        assert_eq!(e.secret.as_slice(), "s3cr3t-clé".as_bytes());
        assert_eq!(e.label, "Chromium Safe Storage");
        assert_eq!(e.attributs, a);
    }

    #[test]
    fn autre_cle_refusee_et_aad_propre() {
        let dek = [7u8; 32];
        let mut t = Trousseau::neuf();
        t.ouvrir(&dek).unwrap();
        t.creer_element(CONNEXION, "x", attrs(&[("a", "b")]), secret("v"), "text/plain", false).unwrap();
        let texte = t.serialiser(&dek).unwrap();
        let mut relu = Trousseau::charger(Some(&texte)).unwrap();
        assert_eq!(relu.ouvrir(&[8u8; 32]).err(), Some(ErreurTrousseau::Illisible));
        // Le blob du trousseau n'est pas un blob de données du coffre (AAD distinctes).
        let f: serde_json::Value = serde_json::from_str(&texte).unwrap();
        let blob: DataBlob = serde_json::from_value(f["data"].clone()).unwrap();
        let dek_coffre = mymfa_core::vault::Dek(dek);
        assert!(mymfa_core::vault::decrypt_data(&dek_coffre, &blob).is_err());
    }

    #[test]
    fn remplacement_et_recherche() {
        let dek = [1u8; 32];
        let mut t = Trousseau::neuf();
        t.ouvrir(&dek).unwrap();
        let a = attrs(&[("service", "wifi"), ("ssid", "maison")]);
        let (id1, _) = t.creer_element(CONNEXION, "Wi-Fi", a.clone(), secret("un"), "text/plain", true).unwrap();
        let (id2, cree) = t.creer_element(CONNEXION, "Wi-Fi", a.clone(), secret("deux"), "text/plain", true).unwrap();
        assert_eq!((id1.clone(), cree), (id2, false), "mêmes attributs + replace : remplacé");
        let (id3, cree) = t.creer_element(CONNEXION, "Wi-Fi", a.clone(), secret("trois"), "text/plain", false).unwrap();
        assert!(cree && id3 != id1, "sans replace : doublon permis (spécification)");
        assert_eq!(t.rechercher(None, &attrs(&[("service", "wifi")])).len(), 2);
        assert_eq!(t.rechercher(None, &Attributs::new()).len(), 2, "aucun attribut : tout");
        assert_eq!(t.element(CONNEXION, &id1).unwrap().secret.as_slice(), b"deux");
        t.supprimer_element(CONNEXION, &id3).unwrap();
        assert_eq!(t.elements(CONNEXION), vec![id1]);
    }

    #[test]
    fn collections_et_alias() {
        let dek = [1u8; 32];
        let mut t = Trousseau::neuf();
        assert_eq!(t.creer_collection("Perso").err(), Some(ErreurTrousseau::Verrouille));
        t.ouvrir(&dek).unwrap();
        let id = t.creer_collection("Mes clés SSH").unwrap();
        assert_eq!(id, "mes_cl_s_ssh");
        assert_eq!(t.creer_collection("myMFA").unwrap(), "mymfa_2", "identifiant réservé");
        t.definir_alias("travail", Some(&id)).unwrap();
        assert_eq!(t.alias("travail"), Some(id.clone()));
        t.supprimer_collection(&id).unwrap();
        assert_eq!(t.alias("travail"), None, "alias d'une collection supprimée retiré");
        let texte = t.serialiser(&dek).unwrap();
        let relu = Trousseau::charger(Some(&texte)).unwrap();
        assert_eq!(relu.index_collection("mymfa_2").unwrap().label, "myMFA", "libellé de collection lisible verrouillé");
    }

    #[test]
    fn fichier_illisible() {
        assert!(Trousseau::charger(Some("{pas du json")).is_err());
        assert!(Trousseau::charger(Some(r#"{"v":2,"salt":"00","index":{},"data":null}"#)).is_err());
    }

    #[test]
    fn identifiants() {
        assert_eq!(identifiant("Login", "x"), "login");
        assert_eq!(identifiant("---", "repli"), "repli");
        assert_eq!(identifiant("Défaut 2", "x"), "d_faut_2");
    }
}
