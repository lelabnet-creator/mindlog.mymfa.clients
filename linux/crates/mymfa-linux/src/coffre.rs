/*
 * Le coffre myMFA, vu du bureau. Le démon déverrouille le fichier
 * `mymfa-vault.json` (même format que le web et Android, cœur mymfa-core) et
 * garde son magasin déchiffré tant qu'il est ouvert : comptes 2FA, logins et
 * passkeys des sites, historique, réglages — le même contenu que le web, que
 * hyprdesk consulte et modifie (LIN-05). Chaque modification réécrit le
 * coffre chiffré par la DEK ; les enveloppes de la clé (mot de passe,
 * passkeys) restent celles du fichier lu. Tout est effacé au verrouillage.
 */
use mymfa_core::otp::{self, Algorithm};
use mymfa_core::store::{Account, Login, Store};
use mymfa_core::DataMap;
use mymfa_core::vault::{self, Dek, VaultRecord};
use zeroize::{Zeroize, Zeroizing};

/// Coffre déverrouillé : la DEK, l'enregistrement lu (enveloppes de la clé)
/// et le magasin déchiffré ; `comptes` et `logins` en sont tirés à chaque
/// changement.
pub struct CoffreOuvert {
    dek: Dek,
    record: VaultRecord,
    store: Store,
    pub comptes: Vec<Account>,
    pub logins: Vec<Login>,
    /// Date de modification du fichier lu (repérer un remplacement).
    pub modification: Option<u128>,
}

fn effacer_listes(comptes: &mut [Account], logins: &mut [Login]) {
    for c in comptes {
        c.secret.zeroize();
    }
    for l in logins {
        l.password.zeroize();
        l.username.zeroize();
        l.note.zeroize();
    }
}

fn effacer_donnees(data: &mut DataMap) {
    for v in data.values_mut() {
        v.zeroize();
    }
}

impl Drop for CoffreOuvert {
    fn drop(&mut self) {
        self.dek.0.zeroize();
        effacer_listes(&mut self.comptes, &mut self.logins);
        effacer_donnees(&mut self.store.data);
    }
}

impl std::fmt::Debug for CoffreOuvert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CoffreOuvert({} comptes, {} logins)", self.comptes.len(), self.logins.len())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErreurCoffre {
    Absent,
    MauvaisMotDePasse,
    Corrompu,
}

impl std::fmt::Display for ErreurCoffre {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ErreurCoffre::Absent => "aucun coffre (mymfa init)",
            ErreurCoffre::MauvaisMotDePasse => "mot de passe incorrect",
            ErreurCoffre::Corrompu => "coffre illisible",
        })
    }
}

pub fn lire(texte: Option<&str>) -> Result<VaultRecord, ErreurCoffre> {
    let texte = texte.ok_or(ErreurCoffre::Absent)?;
    vault::parse(texte).ok_or(ErreurCoffre::Corrompu)
}

/// Déverrouille (PBKDF2 1 000 000 : à lancer hors de la boucle d'événements).
pub fn deverrouiller(record: &VaultRecord, mot_de_passe: &str, modification: Option<u128>) -> Result<CoffreOuvert, ErreurCoffre> {
    let dek = vault::unlock_with_password(record, mot_de_passe).map_err(|_| ErreurCoffre::MauvaisMotDePasse)?;
    ouvrir_avec(dek, record, modification)
}

/// Relit les données avec une DEK déjà connue (coffre remplacé sur le disque
/// par une version plus récente, même clé).
pub fn ouvrir_avec(dek: Dek, record: &VaultRecord, modification: Option<u128>) -> Result<CoffreOuvert, ErreurCoffre> {
    let donnees = vault::decrypt_data(&dek, &record.data).map_err(|_| ErreurCoffre::Corrompu)?;
    let store = Store::from_map(donnees);
    let comptes = store.list();
    let logins = store.logins();
    Ok(CoffreOuvert { dek, record: record.clone(), store, comptes, logins, modification })
}

impl CoffreOuvert {
    /// Magasin déchiffré, en lecture.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Applique `f` au magasin ; s'il réussit, rafraîchit comptes et logins et
    /// rend le texte du coffre rechiffré (à écrire sur le disque). Un refus de
    /// `f` ne change rien et ne rend pas de texte.
    pub fn modifier<T, E>(&mut self, f: impl FnOnce(&mut Store) -> Result<T, E>) -> Result<(Result<T, E>, Option<String>), ErreurCoffre> {
        let r = f(&mut self.store);
        if r.is_err() {
            return Ok((r, None));
        }
        effacer_listes(&mut self.comptes, &mut self.logins);
        self.comptes = self.store.list();
        self.logins = self.store.logins();
        self.record.data = vault::encrypt_data(&self.dek, &self.store.data).map_err(|_| ErreurCoffre::Corrompu)?;
        let texte = serde_json::to_string(&self.record).map_err(|_| ErreurCoffre::Corrompu)?;
        Ok((r, Some(texte)))
    }

    pub fn dek(&self) -> &[u8; 32] {
        &self.dek.0
    }

    pub fn dek_clone(&self) -> Dek {
        self.dek.clone()
    }

    pub fn codes(&self, maintenant_ms: u64) -> Vec<Code> {
        self.comptes.iter().filter_map(|a| code_de(a, maintenant_ms)).collect()
    }

    pub fn login(&self, id: &str) -> Option<&Login> {
        self.logins.iter().find(|l| l.id == id)
    }

    /// Recherche insensible à la casse dans le titre, l'adresse et l'identifiant.
    pub fn rechercher_logins(&self, requete: &str) -> Vec<&Login> {
        let q = requete.trim().to_lowercase();
        self.logins
            .iter()
            .filter(|l| {
                q.is_empty()
                    || l.title.to_lowercase().contains(&q)
                    || l.origin.to_lowercase().contains(&q)
                    || l.username.to_lowercase().contains(&q)
            })
            .collect()
    }
}

/// Code en cours d'un compte, tel que l'affiche la vue Codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Code {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub tag: String,
    pub code: Zeroizing<String>,
    /// Secondes avant le prochain code (TOTP), 0 pour un HOTP.
    pub restant: u32,
    pub periode: u32,
    pub favori: bool,
}

fn code_de(a: &Account, maintenant_ms: u64) -> Option<Code> {
    let algo = Algorithm::parse(&a.algorithm).unwrap_or(Algorithm::Sha1);
    let (code, restant, periode) = if a.type_ == "hotp" {
        // Le compteur avance chez les clients qui écrivent le coffre : ici,
        // le code du compteur enregistré, sans l'incrémenter.
        (otp::hotp(&a.secret, a.counter as u64, a.digits, algo).ok()?, 0, 0)
    } else {
        let periode = if a.period == 0 { otp::DEFAULT_PERIOD } else { a.period };
        (
            otp::totp(&a.secret, periode, a.digits, algo, maintenant_ms).ok()?,
            otp::remaining_seconds(periode, maintenant_ms) as u32,
            periode as u32,
        )
    };
    Some(Code {
        id: a.id.clone(),
        issuer: a.issuer.clone(),
        account: a.account.clone(),
        tag: a.tag.clone(),
        code: Zeroizing::new(code),
        restant,
        periode,
        favori: a.favorite,
    })
}

pub fn maintenant_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use mymfa_core::DataMap;

    const RAPIDE: u32 = 1000;

    fn donnees() -> DataMap {
        [
            (
                "mymfa.accounts.v1",
                r#"[{"id":"a1","type":"totp","issuer":"GitHub","account":"moi@example.net","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":8,"period":30,"counter":0,"tag":"travail","description":"","favorite":true,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z"},
                    {"id":"a2","type":"hotp","issuer":"Banque","account":"moi","secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ","algorithm":"SHA1","digits":6,"period":30,"counter":1,"tag":"","description":"","favorite":false,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z"}]"#,
            ),
            (
                "mymfa.logins.v1",
                r#"[{"id":"l1","origin":"https://github.com","username":"moi","password":"hunter2-très-long","title":"GitHub","note":"","createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z","passwordChangedAt":"2026-01-01T00:00:00.000Z"}]"#,
            ),
            ("mymfa.history.v1", "[]"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
    }

    /// Interop : un coffre écrit par mymfa-core (donc par le web, cf. les
    /// fixtures d'android/) s'ouvre par le chemin du démon, fichier compris.
    #[test]
    fn coffre_du_coeur_ouvert_par_le_demon() {
        let (record, _) = vault::create("correct horse battery", &donnees(), RAPIDE).unwrap();
        let texte = serde_json::to_string(&record).unwrap();
        let lu = lire(Some(&texte)).unwrap();
        let ouvert = deverrouiller(&lu, "correct horse battery", None).unwrap();
        assert_eq!(ouvert.comptes.len(), 2);
        assert_eq!(ouvert.logins[0].password, "hunter2-très-long");
        assert_eq!(deverrouiller(&lu, "mauvais mot de passe", None).unwrap_err(), ErreurCoffre::MauvaisMotDePasse);
        assert_eq!(lire(None).unwrap_err(), ErreurCoffre::Absent);
        assert_eq!(lire(Some("{}")).unwrap_err(), ErreurCoffre::Corrompu);
    }

    #[test]
    fn codes_rfc6238() {
        let (record, dek) = vault::create("correct horse battery", &donnees(), RAPIDE).unwrap();
        let ouvert = ouvrir_avec(dek, &record, None).unwrap();
        // RFC 6238, annexe B : T = 59 s, SHA1, 8 chiffres → 94287082.
        let codes = ouvert.codes(59_000);
        assert_eq!(codes[0].code.as_str(), "94287082");
        assert_eq!((codes[0].restant, codes[0].periode, codes[0].favori), (1, 30, true));
        // RFC 4226, annexe D : compteur 1 → 287082.
        assert_eq!(codes[1].code.as_str(), "287082");
        assert_eq!(codes[1].restant, 0);
    }

    #[test]
    fn recherche_de_logins() {
        let (record, dek) = vault::create("correct horse battery", &donnees(), RAPIDE).unwrap();
        let ouvert = ouvrir_avec(dek, &record, None).unwrap();
        assert_eq!(ouvert.rechercher_logins("git").len(), 1);
        assert_eq!(ouvert.rechercher_logins("GITHUB.COM").len(), 1);
        assert_eq!(ouvert.rechercher_logins("").len(), 1);
        assert!(ouvert.rechercher_logins("gitlab").is_empty());
    }

    /// Fixture d'android/ (coffre chiffré par le vrai vault.js du web), si
    /// elle a été générée (`cd android && npm run gen`).
    #[test]
    fn coffre_du_web_si_fixture() {
        let chemin = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../android/crates/mymfa-core/tests/fixtures/vault-web.json");
        let Ok(texte) = std::fs::read_to_string(&chemin) else {
            eprintln!("fixture absente ({}) : test sauté", chemin.display());
            return;
        };
        let fixture: serde_json::Value = serde_json::from_str(&texte).unwrap();
        let record: VaultRecord = serde_json::from_value(fixture["records"]["simple"].clone()).unwrap();
        let ouvert = deverrouiller(&record, "correct horse battery", None).expect("coffre du web ouvert par le démon");
        let attendu: DataMap = fixture["data"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
            .collect();
        let comptes = Store::from_map(attendu).list();
        assert_eq!(ouvert.comptes, comptes);
    }
}
