/*
 * Sceau du mot de passe myMFA par la session — partagé par le démon `mymfa`
 * et le module PAM `pam_mymfa.so`.
 *
 *  - Le mot de passe de session n'est jamais conservé ni transmis : le module
 *    PAM en dérive une clé de session (PBKDF2-SHA256, sel propre à
 *    l'utilisateur et à la machine) et ne remet que cette clé au démon.
 *  - Au premier déverrouillage manuel, le démon scelle le mot de passe du
 *    coffre par cette clé (AES-256-GCM, AAD propre) ; aux connexions
 *    suivantes, la clé remise descelle le mot de passe et ouvre le coffre.
 *  - Le mot de passe du coffre reste celui du web et d'Android : le sceau n'en
 *    est qu'une copie chiffrée, locale, jamais synchronisée.
 *
 * Le sel est déterministe (machine-id, uid, nom) : le module PAM le calcule
 * sans lire le dossier personnel de l'utilisateur (éventuellement chiffré, pas
 * encore monté, et qu'un processus root n'a pas à parcourir). Un sel n'a pas à
 * être secret, seulement propre à chaque (machine, utilisateur).
 */
pub mod remise;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// Même exigence que le coffre (vault.js) : le sceau est brute-forçable hors
/// ligne s'il fuit, et ce coût n'est payé qu'une fois par connexion.
pub const ITERATIONS: u32 = 1_000_000;
pub const KDF: &str = "PBKDF2-SHA256";
pub const AAD_SCEAU: &str = "mymfa:linux:seal:v1";
pub const PREFIXE_SEL: &str = "mymfa:linux:seal-salt:v1";

/// Clé de session (32 octets), effacée de la mémoire à sa libération.
pub type Cle = Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErreurSceau {
    /// Clé ou sceau ne correspondent pas (mot de passe de session changé
    /// hors PAM, machine-id changé, fichier altéré).
    Refuse,
    /// Enregistrement illisible.
    Corrompu,
}

impl std::fmt::Display for ErreurSceau {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ErreurSceau::Refuse => "sceau refusé par la clé de session",
            ErreurSceau::Corrompu => "sceau illisible",
        })
    }
}

impl std::error::Error for ErreurSceau {}

/* ───── Dérivation ───── */

/// Sel de la clé de session : SHA-256(préfixe ‖ 0 ‖ machine-id ‖ 0 ‖ uid ‖ 0 ‖ nom).
pub fn sel(machine_id: &str, uid: u32, utilisateur: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PREFIXE_SEL.as_bytes());
    h.update([0]);
    h.update(machine_id.trim().as_bytes());
    h.update([0]);
    h.update(uid.to_string().as_bytes());
    h.update([0]);
    h.update(utilisateur.as_bytes());
    h.finalize().into()
}

/// Identifiant de la machine (systemd), chaîne vide s'il manque : le sel reste
/// alors propre à l'utilisateur.
pub fn machine_id() -> String {
    for chemin in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
        if let Ok(texte) = std::fs::read_to_string(chemin) {
            let id = texte.trim();
            if !id.is_empty() {
                return id.to_string();
            }
        }
    }
    String::new()
}

/// Clé de session : PBKDF2-SHA256 du mot de passe de session, octets bruts
/// (PAM ne normalise pas : l'octet tapé est l'octet vérifié).
pub fn deriver(mot_de_passe_session: &[u8], sel: &[u8; 32], iterations: u32) -> Cle {
    let mut cle = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<Sha256>(mot_de_passe_session, sel, iterations, cle.as_mut());
    cle
}

/* ───── Sceau ───── */

/// Enregistrement du sceau (`~/.local/share/mymfa/session-seal.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Sceau {
    pub v: u32,
    /// Paramètres de la clé qui a scellé (informatif : une clé dérivée
    /// autrement est simplement refusée, et le démon rescelle).
    pub kdf: String,
    pub iterations: u32,
    pub iv: String,
    pub ct: String,
}

/// Scelle le mot de passe du coffre par la clé de session.
pub fn sceller(cle: &Cle, iterations: u32, mot_de_passe_coffre: &str) -> Sceau {
    let mut iv = [0u8; 12];
    getrandom::fill(&mut iv).expect("getrandom");
    let chiffre = Aes256Gcm::new(cle.as_ref().into())
        .encrypt(
            Nonce::from_slice(&iv),
            Payload { msg: mot_de_passe_coffre.as_bytes(), aad: AAD_SCEAU.as_bytes() },
        )
        .expect("AES-GCM ne refuse pas un message de cette taille");
    Sceau { v: 1, kdf: KDF.into(), iterations, iv: hex(&iv), ct: hex(&chiffre) }
}

/// Descelle le mot de passe du coffre.
pub fn desceller(cle: &Cle, sceau: &Sceau) -> Result<Zeroizing<String>, ErreurSceau> {
    if sceau.v != 1 {
        return Err(ErreurSceau::Corrompu);
    }
    let iv = de_hex(&sceau.iv).ok_or(ErreurSceau::Corrompu)?;
    let ct = de_hex(&sceau.ct).ok_or(ErreurSceau::Corrompu)?;
    if iv.len() != 12 {
        return Err(ErreurSceau::Corrompu);
    }
    let clair = Aes256Gcm::new(cle.as_ref().into())
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: AAD_SCEAU.as_bytes() })
        .map_err(|_| ErreurSceau::Refuse)?;
    let clair = Zeroizing::new(clair);
    let texte = std::str::from_utf8(&clair).map_err(|_| ErreurSceau::Corrompu)?;
    Ok(Zeroizing::new(texte.to_string()))
}

/* ───── Hexadécimal ───── */

pub fn hex(octets: &[u8]) -> String {
    const CHIFFRES: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(octets.len() * 2);
    for &o in octets {
        s.push(CHIFFRES[(o >> 4) as usize] as char);
        s.push(CHIFFRES[(o & 15) as usize] as char);
    }
    s
}

pub fn de_hex(texte: &str) -> Option<Vec<u8>> {
    let t = texte.trim().as_bytes();
    if !t.len().is_multiple_of(2) {
        return None;
    }
    let val = |c: u8| -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'a'..=b'f' => Some(c - b'a' + 10),
            b'A'..=b'F' => Some(c - b'A' + 10),
            _ => None,
        }
    };
    t.chunks(2).map(|p| Some((val(p[0])? << 4) | val(p[1])?)).collect()
}

/// Clé de 32 octets depuis son hexadécimal.
pub fn cle_de_hex(texte: &str) -> Option<Cle> {
    let octets = Zeroizing::new(de_hex(texte)?);
    let tableau: [u8; 32] = octets.as_slice().try_into().ok()?;
    Some(Zeroizing::new(tableau))
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAPIDE: u32 = 1000;

    #[test]
    fn sceau_aller_retour() {
        let cle = deriver(b"mot de passe de session", &sel("abc", 1000, "jacques"), RAPIDE);
        let sceau = sceller(&cle, RAPIDE, "correct horse battery");
        assert!(!sceau.ct.contains(&hex(b"correct")), "le mot de passe n'apparaît pas en clair");
        assert_eq!(desceller(&cle, &sceau).unwrap().as_str(), "correct horse battery");
        // Chaque sceau a son propre IV.
        assert_ne!(sceller(&cle, RAPIDE, "correct horse battery").iv, sceau.iv);
    }

    #[test]
    fn mauvaise_cle_refusee() {
        let s = sel("abc", 1000, "jacques");
        let sceau = sceller(&deriver(b"ancien", &s, RAPIDE), RAPIDE, "coffre");
        assert_eq!(desceller(&deriver(b"nouveau", &s, RAPIDE), &sceau).unwrap_err(), ErreurSceau::Refuse);
        // Même mot de passe, autre machine : autre sel, autre clé.
        let ailleurs = deriver(b"ancien", &sel("xyz", 1000, "jacques"), RAPIDE);
        assert_eq!(desceller(&ailleurs, &sceau).unwrap_err(), ErreurSceau::Refuse);
    }

    #[test]
    fn sceau_altere_refuse() {
        let cle = deriver(b"session", &sel("m", 1, "u"), RAPIDE);
        let mut sceau = sceller(&cle, RAPIDE, "coffre");
        let mut ct = de_hex(&sceau.ct).unwrap();
        ct[0] ^= 1;
        sceau.ct = hex(&ct);
        assert_eq!(desceller(&cle, &sceau).unwrap_err(), ErreurSceau::Refuse);
        sceau.iv = "zz".into();
        assert_eq!(desceller(&cle, &sceau).unwrap_err(), ErreurSceau::Corrompu);
    }

    #[test]
    fn sel_propre_a_chaque_utilisateur() {
        let a = sel("machine", 1000, "alice");
        assert_eq!(a, sel(" machine\n", 1000, "alice"), "machine-id lu avec son saut de ligne");
        assert_ne!(a, sel("machine", 1001, "alice"));
        assert_ne!(a, sel("machine", 1000, "bob"));
        assert_ne!(a, sel("autre", 1000, "alice"));
    }

    #[test]
    fn derivation_stable() {
        // PBKDF2-HMAC-SHA256, vecteur de RFC 7914 §11 (P="passwd", S="salt", c=1).
        let mut out = [0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(b"passwd", b"salt", 1, &mut out);
        assert_eq!(hex(&out[..8]), "55ac046e56e3089f");
        let s = sel("m", 1, "u");
        assert_eq!(*deriver(b"x", &s, RAPIDE), *deriver(b"x", &s, RAPIDE));
    }

    #[test]
    fn hexadecimal() {
        assert_eq!(hex(&[0, 15, 255]), "000fff");
        assert_eq!(de_hex("000fFF").unwrap(), vec![0, 15, 255]);
        assert!(de_hex("abc").is_none());
        assert!(de_hex("zz").is_none());
        assert!(cle_de_hex(&hex(&[7u8; 32])).is_some());
        assert!(cle_de_hex(&hex(&[7u8; 31])).is_none());
    }
}
