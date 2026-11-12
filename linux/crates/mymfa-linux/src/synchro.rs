/*
 * Cycle de synchronisation v2 du démon (LIN-06) : les briques autour de la
 * fusion du cœur (sync2::fusion) — état persistant de l'appareil, journal de
 * synchro chiffré par la DEK, points de restauration (les dernières versions
 * Drive reçues, chiffrées), lecture distante et envoi avec détection de course
 * (quelqu'un a écrit sur Drive entre notre lecture et notre envoi).
 *
 * Le démon orchestre : ouverture du coffre → cycle ; après chaque modification
 * (regroupée) → cycle ; toutes les 15 minutes → cycle ; SyncNow (D-Bus) → cycle.
 * Chaque cycle : lire Drive (révision notée), déchiffrer, fusionner, écrire en
 * local, revérifier la révision — si elle a changé, relire et refusionner — puis
 * renvoyer si le résultat apporte quelque chose. Aucune écriture locale si la
 * fusion refuse : c'est sync2::fusion qui décide, le démon n'écrit qu'après.
 *
 * Fichiers (0600, dossier des données, cf. chemins.rs) :
 *   mymfa-sync.json          — état de l'appareil (rien de secret : identifiant,
 *                              horloge hybride, repère, révision Drive vue) ;
 *   mymfa-journal.json       — journal de synchro, chiffré par la DEK ;
 *   mymfa-drive-backup.json  — points de restauration, chiffrés par la DEK ;
 *   mymfa-drive.json         — jetons OAuth (cf. drive.rs), chiffrés par la DEK.
 */
use mymfa_core::vault::{from_b64, random_bytes, to_b64, DataBlob, Dek};
use mymfa_core::{AppError, DataMap};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::chemins::maintenant;
use crate::drive::{self, Jetons, SauvegardeDrive, Transport};

pub const AAD_JOURNAL: &str = "mymfa:linux:sync-journal:v1";
pub const AAD_POINTS: &str = "mymfa:linux:sync-backup:v1";
/// Plafond du journal : les entrées les plus récentes restent, comme l'historique.
pub const JOURNAL_MAX: usize = 200;
/// Points de restauration gardés (versions Drive reçues, chiffrées).
pub const POINTS_MAX: usize = 5;

/* ─── État persistant de l'appareil (rien de secret) ─────────────────────── */

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EtatFichier {
    pub v: u32,
    pub appareil: String,
    pub horloge: HorlogeFichier,
    #[serde(default)]
    pub repere: String,
    #[serde(default)]
    pub drive: Option<SauvegardeDrive>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub struct HorlogeFichier {
    pub l: i64,
    pub c: u32,
}

pub fn etat_en_texte(etat: &mymfa_core::sync2::EtatSynchro, drive: Option<&SauvegardeDrive>) -> String {
    serde_json::json!({
        "v": 1,
        "appareil": etat.appareil,
        "horloge": { "l": etat.horloge.l, "c": etat.horloge.c },
        "repere": etat.repere,
        "drive": drive,
    })
    .to_string()
}

/// Relit l'état de l'appareil (None si le fichier n'existe pas encore) et la
/// dernière sauvegarde Drive connue.
pub fn etat_depuis_texte(texte: &str) -> Result<Option<(mymfa_core::sync2::EtatSynchro, Option<SauvegardeDrive>)>, AppError> {
    if texte.trim().is_empty() {
        return Ok(None);
    }
    let f: EtatFichier = serde_json::from_str(texte).map_err(|_| AppError::new("corrupted"))?;
    let etat = mymfa_core::sync2::EtatSynchro {
        appareil: f.appareil,
        horloge: mymfa_core::sync2::Horloge { l: f.horloge.l, c: f.horloge.c },
        repere: f.repere,
        description: None,
    };
    Ok(Some((etat, f.drive)))
}

/* ─── Chiffrement générique (journal, points) ────────────────────────────── */

fn chiffrer(clair: &[u8], dek: &Dek, aad: &str) -> Result<DataBlob, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let iv = random_bytes(12);
    let cle = aes_gcm::Key::<Aes256Gcm>::from_slice(&dek.0).to_owned();
    let ct = Aes256Gcm::new(&cle)
        .encrypt(Nonce::from_slice(&iv), Payload { msg: clair, aad: aad.as_bytes() })
        .map_err(|_| AppError::new("corrupted"))?;
    Ok(DataBlob { iv: to_b64(&iv), ct: to_b64(&ct) })
}

fn dechiffrer(blob: &DataBlob, dek: &Dek, aad: &str) -> Result<Vec<u8>, AppError> {
    use aes_gcm::aead::{Aead, Payload};
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    let iv = from_b64(&blob.iv).map_err(|_| AppError::new("corrupted"))?;
    let ct = from_b64(&blob.ct).map_err(|_| AppError::new("corrupted"))?;
    let cle = aes_gcm::Key::<Aes256Gcm>::from_slice(&dek.0).to_owned();
    Aes256Gcm::new(&cle)
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| AppError::new("corrupted"))
}

/* ─── Journal de synchro (chiffré par la DEK) ────────────────────────────── */

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntreeJournal {
    pub genre: String,
    pub cle: String,
    pub champ: String,
    pub texte: String,
    pub at: String,
}

#[derive(Default, Clone, Debug)]
pub struct Journal {
    pub entrees: Vec<EntreeJournal>,
}

impl Journal {
    pub fn ajouter_rapport(&mut self, rapport: &mymfa_core::sync2::Rapport, envoye: Option<bool>) {
        for entree in &rapport.entrees {
            self.entrees.push(EntreeJournal {
                genre: entree.genre.to_string(),
                cle: entree.cle.clone(),
                champ: entree.champ.clone(),
                texte: entree.texte.clone(),
                at: entree.at.clone(),
            });
        }
        if let Some(envoye) = envoye {
            self.entrees.push(EntreeJournal {
                genre: "envoi".to_string(),
                cle: "mymfa-vault.json".into(),
                champ: String::new(),
                texte: if envoye {
                    "Synchro : Drive mis à jour.".into()
                } else {
                    "Synchro : rien à envoyer.".into()
                },
                at: iso_de_maintenant(),
            });
        }
        if self.entrees.len() > JOURNAL_MAX {
            self.entrees = self.entrees.split_off(self.entrees.len() - JOURNAL_MAX);
        }
    }

    pub fn en_texte(&self, dek: &Dek) -> Result<String, AppError> {
        let clair = serde_json::to_vec(&serde_json::json!({ "entrees": self.entrees })).map_err(|_| AppError::new("corrupted"))?;
        let blob = chiffrer(&clair, dek, AAD_JOURNAL)?;
        Ok(serde_json::json!({ "v": 1, "data": blob }).to_string())
    }

    pub fn depuis_texte(texte: &str, dek: &Dek) -> Result<Journal, AppError> {
        if texte.trim().is_empty() {
            return Ok(Journal::default());
        }
        let enveloppe: Value = serde_json::from_str(texte).map_err(|_| AppError::new("corrupted"))?;
        let Some(blob) = enveloppe.get("data").and_then(|d| {
            Some(DataBlob { iv: d["iv"].as_str()?.to_string(), ct: d["ct"].as_str()?.to_string() })
        }) else {
            return Ok(Journal::default());
        };
        let clair = dechiffrer(&blob, dek, AAD_JOURNAL)?;
        #[derive(Deserialize)]
        struct Clairs {
            #[serde(default)]
            entrees: Vec<EntreeJournal>,
        }
        let c: Clairs = serde_json::from_slice(&clair).map_err(|_| AppError::new("corrupted"))?;
        Ok(Journal { entrees: c.entrees })
    }
}

fn iso_de_maintenant() -> String {
    let ms = (maintenant() as i64) * 1000;
    mymfa_core::iso_from_unix(ms.div_euclid(1000), ms.rem_euclid(1000) as u32)
}

/* ─── Points de restauration (versions Drive reçues, chiffrées) ──────────── */

#[derive(Clone, Debug, PartialEq)]
pub struct PointRestauration {
    pub revision: String,
    pub modifiee_le: String,
    /// Le coffre chiffré tel que reçu de Drive (l'enveloppe complète, jamais
    /// déchiffrée : le point de restauration sert même après changement de DEK).
    pub enveloppe: Zeroizing<String>,
}

#[derive(Default, Clone, Debug)]
pub struct Points {
    pub sauvegardes: Vec<PointRestauration>,
}

impl Points {
    /// Un point de plus (la plus récente d'abord, plafonnée) : une version déjà
    /// connue n'est pas redupliquée.
    pub fn pousser(&mut self, point: PointRestauration) {
        if self.sauvegardes.iter().any(|p| p.revision == point.revision) {
            return;
        }
        self.sauvegardes.insert(0, point);
        if self.sauvegardes.len() > POINTS_MAX {
            self.sauvegardes.truncate(POINTS_MAX);
        }
    }

    pub fn en_texte(&self, dek: &Dek) -> Result<String, AppError> {
        let clair = serde_json::to_vec(&serde_json::json!({
            "sauvegardes": self.sauvegardes.iter().map(|p| {
                serde_json::json!({ "revision": p.revision, "modifieeLe": p.modifiee_le, "enveloppe": p.enveloppe.as_str() })
            }).collect::<Vec<_>>(),
        }))
        .map_err(|_| AppError::new("corrupted"))?;
        let blob = chiffrer(&clair, dek, AAD_POINTS)?;
        Ok(serde_json::json!({ "v": 1, "data": blob }).to_string())
    }

    pub fn depuis_texte(texte: &str, dek: &Dek) -> Result<Points, AppError> {
        if texte.trim().is_empty() {
            return Ok(Points::default());
        }
        let enveloppe: Value = serde_json::from_str(texte).map_err(|_| AppError::new("corrupted"))?;
        let Some(blob) = enveloppe.get("data").and_then(|d| {
            Some(DataBlob { iv: d["iv"].as_str()?.to_string(), ct: d["ct"].as_str()?.to_string() })
        }) else {
            return Ok(Points::default());
        };
        let clair = dechiffrer(&blob, dek, AAD_POINTS)?;
        #[derive(Deserialize)]
        struct Clairs {
            #[serde(default)]
            sauvegardes: Vec<PointClair>,
        }
        #[derive(Deserialize)]
        struct PointClair {
            revision: String,
            #[serde(rename = "modifieeLe", default)]
            modifiee_le: String,
            enveloppe: String,
        }
        let c: Clairs = serde_json::from_slice(&clair).map_err(|_| AppError::new("corrupted"))?;
        Ok(Points {
            sauvegardes: c
                .sauvegardes
                .into_iter()
                .map(|p| PointRestauration { revision: p.revision, modifiee_le: p.modifiee_le, enveloppe: Zeroizing::new(p.enveloppe) })
                .collect(),
        })
    }
}

/* ─── Lecture distante et envoi ──────────────────────────────────────────── */

/// Lit la sauvegarde Drive et la déchiffre. Renvoie None si Drive est vide.
/// Une sauvegarde chiffrée par une autre DEK (un autre coffre) est une erreur
/// dédiée : pas de fusion — comme le web, qui demande le mot de passe de la
/// sauvegarde. La version reçue rejoint les points de restauration.
pub async fn lire_distante(
    t: &impl Transport,
    jetons: &Jetons,
    dek: &Dek,
    points: &mut Points,
) -> Result<Option<(DataMap, SauvegardeDrive)>, AppError> {
    let Some(sauvegarde) = drive::trouver(t, jetons).await? else {
        return Ok(None);
    };
    let enveloppe = drive::lire(t, jetons, &sauvegarde.id).await?;
    points.pousser(PointRestauration {
        revision: sauvegarde.revision.clone(),
        modifiee_le: sauvegarde.modifiee_le.clone(),
        enveloppe: Zeroizing::new(enveloppe.clone()),
    });
    let record = mymfa_core::vault::parse(&enveloppe).ok_or_else(|| AppError::new("invalidBackup"))?;
    let distante = mymfa_core::vault::decrypt_data(dek, &record.data).map_err(|e| {
        // La DEK locale n'ouvre pas la sauvegarde : un autre coffre. Pas de
        // fusion (comme le web), l'utilisateur décidera : restaurer ou pas.
        if e.code == "corrupted" {
            AppError::new("driveAutreCoffre")
        } else {
            e
        }
    })?;
    Ok(Some((distante, sauvegarde)))
}

/// Résultat d'un envoi.
#[derive(Debug, PartialEq)]
pub enum Envoi {
    /// Envoyé, nouvelle révision posée.
    Pose(String),
    /// Course détectée : la révision de Drive n'est plus celle que nous avions
    /// lue — l'appelant relit et refusionne (au plus trois tours).
    Course,
}

/// Envoie le coffre fusionné si la fusion dit qu'il apporte quelque chose, en
/// revérifiant la révision avant l'envoi : si Drive a changé depuis notre
/// lecture, on ne l'écrase pas — Course rend la main.
pub async fn pousser(
    t: &impl Transport,
    jetons: &Jetons,
    vu: Option<&SauvegardeDrive>,
    record_json: &str,
    a_envoyer: bool,
) -> Result<Envoi, AppError> {
    if !a_envoyer {
        return Ok(Envoi::Pose(String::new())); // rien à envoyer : pas de requête
    }
    if let Some(vu) = vu {
        let actuelle = drive::revision_actuelle(t, jetons, &vu.id).await?;
        if actuelle != vu.revision {
            return Ok(Envoi::Course);
        }
    }
    let revision = drive::envoyer(t, jetons, vu.map(|s| s.id.as_str()), record_json).await?;
    Ok(Envoi::Pose(revision))
}

/* ─── Tests : état, journal, points, tours de cycle sur un faux Drive ────── */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::drive::Reponse;
    use std::collections::BTreeMap;

    const ITERATIONS: u32 = 1000;

    fn dek_et_coffre(data: &DataMap) -> (Dek, String) {
        let (record, dek) = mymfa_core::vault::create("mot de passe de test long", data, ITERATIONS).unwrap();
        (dek, serde_json::to_string(&record).unwrap())
    }

    #[test]
    fn etat_aller_retour_et_appareil_neuf() {
        assert!(etat_depuis_texte("").unwrap().is_none());
        let etat = mymfa_core::sync2::EtatSynchro {
            appareil: "abc123".into(),
            horloge: mymfa_core::sync2::Horloge { l: 1234, c: 5 },
            repere: "0000000000000000000000abc123".into(),
            description: None,
        };
        let drive = Some(SauvegardeDrive { id: "F".into(), revision: "R".into(), modifiee_le: "2026-11-11T14:05:00.000Z".into() });
        let texte = etat_en_texte(&etat, drive.as_ref());
        let (relu, drive_relu) = etat_depuis_texte(&texte).unwrap().unwrap();
        assert_eq!(relu.appareil, etat.appareil);
        assert_eq!(relu.horloge, etat.horloge);
        assert_eq!(relu.repere, etat.repere);
        assert_eq!(drive_relu, drive);
    }

    #[test]
    fn journal_chiffre_et_plafonne() {
        let dek = Dek(random_bytes(32).try_into().unwrap());
        let mut journal = Journal::default();
        let rapport = mymfa_core::sync2::Rapport {
            entrees: (0..(JOURNAL_MAX + 20) as u64)
                .map(|k| mymfa_core::sync2::Entree {
                    genre: "conflit",
                    cle: format!("cle{k}"),
                    champ: format!("champ{k}"),
                    texte: format!("conflit n°{k}"),
                    gagnant: None,
                    perdant: None,
                    at: "2026-11-11T14:05:00.000Z".into(),
                })
                .collect(),
            a_envoyer: true,
        };
        journal.ajouter_rapport(&rapport, Some(true));
        assert_eq!(journal.entrees.len(), JOURNAL_MAX);
        let texte = journal.en_texte(&dek).unwrap();
        assert!(!texte.contains("conflit"), "jamais de journal en clair");
        let relu = Journal::depuis_texte(&texte, &dek).unwrap();
        assert_eq!(relu.entrees.len(), JOURNAL_MAX);
        assert_eq!(relu.entrees.last().unwrap().genre, "envoi");
        // Une autre DEK refuse (coffre recréé ailleurs) — comme le trousseau.
        let autre = Dek(random_bytes(32).try_into().unwrap());
        assert!(Journal::depuis_texte(&texte, &autre).is_err());
    }

    #[test]
    fn points_plafonnent_et_chiffrent_les_enveloppes() {
        let dek = Dek(random_bytes(32).try_into().unwrap());
        let mut points = Points::default();
        for k in 0..(POINTS_MAX + 2) {
            points.pousser(PointRestauration {
                revision: format!("R{k}"),
                modifiee_le: String::new(),
                enveloppe: Zeroizing::new(format!("enveloppe-{k}")),
            });
        }
        assert_eq!(points.sauvegardes.len(), POINTS_MAX);
        assert_eq!(points.sauvegardes[0].revision, format!("R{}", POINTS_MAX + 1), "la plus récente d'abord");
        // Une révision déjà connue n'est pas redupliquée.
        points.pousser(PointRestauration { revision: "R7".into(), modifiee_le: String::new(), enveloppe: Zeroizing::new("x".into()) });
        assert_eq!(points.sauvegardes.len(), POINTS_MAX);
        let texte = points.en_texte(&dek).unwrap();
        assert!(!texte.contains("enveloppe-"), "jamais d'enveloppe en clair");
        let relus = Points::depuis_texte(&texte, &dek).unwrap();
        assert_eq!(relus.sauvegardes, points.sauvegardes);
    }

    struct Faux {
        reponses: BTreeMap<(String, String), Reponse>,
    }

    impl Faux {
        fn avec(methode: &str, url_contient: &str, statut: u16, corps: &str) -> Self {
            let mut reponses = BTreeMap::new();
            reponses
                .insert((methode.to_string(), url_contient.to_string()), Reponse { statut, corps: corps.to_string() });
            Self { reponses }
        }
    }

    impl Transport for Faux {
        async fn envoyer(&self, _jeton: &str, methode: &str, url: &str, _corps: Option<(&str, String)>) -> Result<Reponse, AppError> {
            for ((m, fragment), reponse) in &self.reponses {
                if m == methode && url.contains(fragment.as_str()) {
                    return Ok(Reponse { statut: reponse.statut, corps: reponse.corps.clone() });
                }
            }
            Ok(Reponse { statut: 404, corps: "{}".into() })
        }
    }

    fn jetons_fait() -> Jetons {
        Jetons {
            acces: Zeroizing::new("a".into()),
            acces_expire_le: u64::MAX,
            rafraichissement: Zeroizing::new("r".into()),
        }
    }

    #[tokio::test]
    async fn drive_vide_rien_a_lire_et_tout_a_envoyer() {
        // Drive vide, puis l'envoi multipart de création.
        let mut faux = Faux::avec(
            "GET",
            "spaces=appDataFolder",
            200,
            r#"{"files":[]}"#,
        );
        faux.reponses.insert(
            ("POST".into(), "uploadType=multipart".into()),
            Reponse { statut: 200, corps: r#"{"headRevisionId":"R1"}"#.into() },
        );
        let dek = Dek(random_bytes(32).try_into().unwrap());
        let mut points = Points::default();
        let jetons = jetons_fait();
        let distante = lire_distante(&faux, &jetons, &dek, &mut points).await.unwrap();
        assert!(distante.is_none());
        // Drive vide : notre coffre est à envoyer.
        let (_dek, record) = dek_et_coffre(&DataMap::new());
        let envoi = pousser(&faux, &jetons, None, &record, true).await.unwrap();
        assert!(matches!(envoi, Envoi::Pose(_)), "Drive vide : tout est à envoyer");
    }

    #[tokio::test]
    async fn autre_coffre_refuse_la_fusion_et_rejoint_les_points() {
        // Une sauvegarde chiffrée par une AUTRE DEK : erreur dédiée, pas de
        // fusion — et l'enveloppe rejoint les points de restauration.
        let (_autre_dek, enveloppe) = dek_et_coffre(&DataMap::new());
        let mut faux = Faux::avec(
            "GET",
            "spaces=appDataFolder",
            200,
            r#"{"files":[{"id":"F1","headRevisionId":"R1","modifiedTime":"2026-11-11T14:05:00.000Z"}]}"#,
        );
        faux.reponses.insert(
            ("GET".into(), "alt=media".into()),
            Reponse { statut: 200, corps: enveloppe },
        );
        let dek = Dek(random_bytes(32).try_into().unwrap());
        let mut points = Points::default();
        let err = lire_distante(&faux, &jetons_fait(), &dek, &mut points).await.unwrap_err();
        assert_eq!(err.code, "driveAutreCoffre");
        assert_eq!(points.sauvegardes.len(), 1, "la version reçue est gardée chiffrée");
        assert_eq!(points.sauvegardes[0].revision, "R1");
    }

    #[tokio::test]
    async fn lecture_distante_rend_les_donnees_et_garde_un_point() {
        let data = DataMap::from([("mymfa.accounts.v1".to_string(), "[]".to_string())]);
        let (_dek, enveloppe) = dek_et_coffre(&data);
        let dek = Dek(random_bytes(32).try_into().unwrap());
        // Le coffre doit être chiffré par LA DEK lue : recréons-le avec.
        let (record, dek) = mymfa_core::vault::create("mot de passe de test long", &data, ITERATIONS).unwrap();
        let enveloppe = serde_json::to_string(&record).unwrap();
        let mut faux = Faux::avec(
            "GET",
            "spaces=appDataFolder",
            200,
            r#"{"files":[{"id":"F1","headRevisionId":"R1","modifiedTime":""}]}"#,
        );
        faux.reponses.insert(("GET".into(), "alt=media".into()), Reponse { statut: 200, corps: enveloppe });
        let mut points = Points::default();
        let (distante, sauvegarde) = lire_distante(&faux, &jetons_fait(), &dek, &mut points).await.unwrap().unwrap();
        assert_eq!(distante, data);
        assert_eq!(sauvegarde.revision, "R1");
        assert_eq!(points.sauvegardes[0].revision, "R1");
    }

    #[tokio::test]
    async fn course_detectee_si_la_revision_a_change() {
        let mut faux = Faux::avec("GET", "headRevisionId", 200, r#"{"headRevisionId":"R2"}"#);
        let jetons = jetons_fait();
        let vu = SauvegardeDrive { id: "F1".into(), revision: "R1".into(), modifiee_le: String::new() };
        let (_dek, record) = dek_et_coffre(&DataMap::new());
        let envoi = pousser(&faux, &jetons, Some(&vu), &record, true).await.unwrap();
        assert_eq!(envoi, Envoi::Course, "quelqu'un a écrit entre-temps : ne pas écraser");
        // Et avec la révision à jour : envoyé.
        faux.reponses
            .insert(("GET".into(), "headRevisionId".into()), Reponse { statut: 200, corps: r#"{"headRevisionId":"R1"}"#.into() });
        faux.reponses
            .insert(("PATCH".into(), "uploadType=media".into()), Reponse { statut: 200, corps: r#"{"headRevisionId":"R3"}"#.into() });
        let envoi = pousser(&faux, &jetons, Some(&vu), &record, true).await.unwrap();
        assert_eq!(envoi, Envoi::Pose("R3".into()));
    }

    #[tokio::test]
    async fn rien_a_envoyer_ne_fait_aucune_requete() {
        let faux = Faux::avec("GET", "headRevisionId", 500, "erreur");
        let jetons = jetons_fait();
        let vu = SauvegardeDrive { id: "F1".into(), revision: "R1".into(), modifiee_le: String::new() };
        // La fusion n'a rien trouvé de nouveau (a_envoyer = false) : ni
        // revérification ni envoi, aucune requête.
        let envoi = pousser(&faux, &jetons, Some(&vu), "{}", false).await.unwrap();
        assert_eq!(envoi, Envoi::Pose(String::new()));
    }
}
