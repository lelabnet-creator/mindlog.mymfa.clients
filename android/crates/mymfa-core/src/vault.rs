/*
 * Coffre chiffré de myMFA (cryptographie uniquement) — réplique de ../web/js/vault.js.
 *
 *  - Une clé de coffre (DEK) AES-256-GCM aléatoire chiffre les données sensibles.
 *  - La DEK est « enveloppée » une fois par moyen de déverrouillage : mot de passe
 *    maître (PBKDF2-SHA256) ou passkey (sortie PRF WebAuthn → HKDF-SHA256).
 *  - Chaque chiffré est lié à son rôle par des données additionnelles (AAD).
 *
 * Enregistrement (JSON) :
 *   { v: 1,
 *     password: { kdf: 'PBKDF2-SHA256', iterations, salt, iv, wrapped },
 *     passkeys: [{ id, name, prfSalt, iv, wrapped, createdAt }],
 *     data: { iv, ct } }   // ct = JSON { clé localStorage → valeur }
 */
use crate::{now_iso, AppError, DataMap, Result};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

pub const VAULT_KEY: &str = "mymfa.vault.v1";
/// Au-delà de la recommandation OWASP (600 000) : le coffre — et sa sauvegarde Drive —
/// est brute-forçable hors ligne, et ce coût n'est payé qu'au déverrouillage.
pub const PBKDF2_ITERATIONS: u32 = 1_000_000;
/// Le mot de passe maître est la seule barrière du coffre et de sa sauvegarde.
pub const PASSWORD_MIN_LENGTH: usize = 10;
pub const AAD_DATA: &str = "mymfa:vault:data:v1";
pub const AAD_PASSWORD: &str = "mymfa:vault:wrap:password:v1";
pub const AAD_PASSKEY: &str = "mymfa:vault:wrap:passkey:v1:";
pub const HKDF_INFO: &str = "mymfa:vault:passkey-kek:v1";

/* ───── Encodages ───── */

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// base64 standard avec remplissage (btoa).
pub fn to_b64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// base64 standard (atob, dit « forgiving ») : espaces ASCII ignorés, '='
/// uniquement en fin (au plus deux), longueurs % 4 == 1 rejetées.
pub fn from_b64(text: &str) -> Result<Vec<u8>> {
    let clean: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    let stem_len = clean.iter().position(|&b| b == b'=').unwrap_or(clean.len());
    if clean.len() - stem_len > 2 {
        return Err(AppError::new("invalidBase64"));
    }
    let stem = &clean[..stem_len];
    if stem.len() % 4 == 1 {
        return Err(AppError::new("invalidBase64"));
    }
    let mut out = Vec::with_capacity(stem.len() * 3 / 4);
    for chunk in stem.chunks(4) {
        let mut n: u32 = 0;
        for (i, &byte) in chunk.iter().enumerate() {
            let v = B64.iter().position(|&c| c == byte).ok_or(AppError::new("invalidBase64"))? as u32;
            n |= v << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// base64url sans remplissage : format des identifiants de credential WebAuthn.
pub fn to_b64url(bytes: &[u8]) -> String {
    to_b64(bytes).replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
}

pub fn from_b64url(text: &str) -> Result<Vec<u8>> {
    let b64 = text.replace('-', "+").replace('_', "/");
    let padded = format!("{b64}{}", "=".repeat((4 - b64.len() % 4) % 4));
    from_b64(&padded)
}

pub fn random_bytes(length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    getrandom::fill(&mut buf).expect("getrandom");
    buf
}

/* ───── Enregistrement ───── */

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasswordEntry {
    pub kdf: String,
    pub iterations: u32,
    pub salt: String,
    pub iv: String,
    pub wrapped: String,
}

#[allow(non_snake_case)] // champs camelCase : noms JSON du web
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PasskeyEntry {
    pub id: String,
    pub name: String,
    pub prfSalt: String,
    pub createdAt: String,
    pub iv: String,
    pub wrapped: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DataBlob {
    pub iv: String,
    pub ct: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultRecord {
    pub v: u32,
    pub password: PasswordEntry,
    #[serde(default)]
    pub passkeys: Vec<PasskeyEntry>,
    pub data: DataBlob,
}

/// Clé de coffre (DEK) en clair, en mémoire seulement.
#[derive(Clone)]
pub struct Dek(pub [u8; 32]);

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Dek(…)")
    }
}

/* ───── Primitives ───── */

fn encrypt(key: &[u8; 32], plaintext: &[u8], aad: &str) -> Result<DataBlob> {
    let iv = random_bytes(12);
    let cipher = Aes256Gcm::new(key.into());
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            Payload { msg: plaintext, aad: aad.as_bytes() },
        )
        .map_err(|_| AppError::new("corrupted"))?;
    Ok(DataBlob { iv: to_b64(&iv), ct: to_b64(&ct) })
}

fn decrypt(key: &[u8; 32], blob: &DataBlob, aad: &str, fail_code: &'static str) -> Result<Vec<u8>> {
    let iv = from_b64(&blob.iv).map_err(|_| AppError::new(fail_code))?;
    let ct = from_b64(&blob.ct).map_err(|_| AppError::new(fail_code))?;
    if iv.len() != 12 {
        return Err(AppError::new(fail_code));
    }
    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: aad.as_bytes() })
        .map_err(|_| AppError::new(fail_code))
}

/// Clé d'enveloppe mot de passe : PBKDF2-SHA256, mot de passe normalisé NFC.
fn password_kek(password: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let normalized: String = password.nfc().collect();
    let mut out = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(normalized.as_bytes(), salt, iterations, &mut out);
    out
}

/// Clé d'enveloppe passkey : HKDF-SHA256, sel de 32 octets nuls.
fn prf_kek(prf_output: &[u8]) -> [u8; 32] {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(&[0u8; 32]), prf_output);
    let mut out = [0u8; 32];
    hk.expand(HKDF_INFO.as_bytes(), &mut out).expect("32 octets tiennent dans HKDF-SHA256");
    out
}

fn wrap_dek(dek: &Dek, kek: &[u8; 32], aad: &str) -> Result<DataBlob> {
    encrypt(kek, &dek.0, aad)
}

fn unwrap_dek(entry_iv: &str, entry_wrapped: &str, kek: &[u8; 32], aad: &str, fail_code: &'static str) -> Result<Dek> {
    let raw = decrypt(kek, &DataBlob { iv: entry_iv.into(), ct: entry_wrapped.into() }, aad, fail_code)?;
    let dek: [u8; 32] = raw.try_into().map_err(|_| AppError::new(fail_code))?;
    Ok(Dek(dek))
}

/* ───── API ───── */

/// La longueur compte les unités UTF-16, comme `password.length` en JavaScript.
fn utf16_length(password: &str) -> usize {
    password.encode_utf16().count()
}

pub fn validate_password(password: &str) -> Result<()> {
    if utf16_length(password) < PASSWORD_MIN_LENGTH {
        return Err(AppError::param("passwordTooShort", "min", PASSWORD_MIN_LENGTH.to_string()));
    }
    Ok(())
}

/* ───── Solidité d'un mot de passe (heuristique d'affichage) ───── */

const COMMON_PASSWORDS: &[&str] = &[
    "password", "motdepasse", "azerty", "qwerty", "123456", "12345678", "admin", "bonjour", "soleil",
    "welcome", "iloveyou", "letmein", "dragon", "monkey", "football", "princesse", "chocolat",
    "loulou", "doudou", "maman", "secret",
];
const COMMON_SEQUENCES: &[&str] = &[
    "012", "123", "234", "345", "456", "567", "678", "789", "890", "abc", "bcd", "cde", "def", "efg",
    "fgh", "ghi", "hij", "ijk", "jkl", "klm", "lmn", "mno", "nop", "opq", "pqr", "qrs", "rst", "stu",
    "tuv", "uvw", "vwx", "wxy", "xyz", "aze", "rty", "qwe", "wer", "sdf", "dfg",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Strength {
    pub level: u8,
    pub bits: u32,
}

/// Estimation (0 à 4) : entropie de la composition, pénalisée par les répétitions,
/// les suites de touches et les mots courants. Pour guider la saisie, pas un oracle.
pub fn password_strength(password: &str) -> Strength {
    let length = utf16_length(password);
    if length == 0 {
        return Strength { level: 0, bits: 0 };
    }
    let mut pool = 0u32;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool += 26;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool += 10;
    }
    if password.chars().any(|c| !c.is_ascii_alphanumeric()) {
        pool += 33;
    }
    let mut bits = length as f64 * (pool.max(1) as f64).log2();
    // Trois fois le même caractère d'affilée.
    if has_triple_repeat(password) {
        bits *= 0.75;
    }
    // Un seul caractère répété.
    if password.chars().all(|c| c == password.chars().next().unwrap_or(c)) {
        bits = bits.min(8.0);
    }
    let lower = password.to_lowercase();
    if COMMON_SEQUENCES.iter().any(|seq| lower.contains(seq)) {
        bits *= 0.7;
    }
    if COMMON_PASSWORDS.iter().any(|word| lower.contains(word)) {
        bits = bits.min(24.0);
    }
    let level = if bits < 36.0 { 1 } else if bits < 60.0 { 2 } else if bits < 80.0 { 3 } else { 4 };
    Strength { level, bits: bits.round() as u32 }
}

fn has_triple_repeat(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    chars.windows(3).any(|w| w[0] == w[1] && w[1] == w[2])
}

/// Comme `Vault.parse` : enregistrement valide ou rien.
pub fn parse(raw: &str) -> Option<VaultRecord> {
    if raw.is_empty() {
        return None;
    }
    let record: VaultRecord = serde_json::from_str(raw).ok()?;
    (record.v == 1).then_some(record)
}

pub fn encrypt_data(dek: &Dek, data: &DataMap) -> Result<DataBlob> {
    let plaintext = serde_json::to_string(data).map_err(|_| AppError::new("corrupted"))?;
    encrypt(&dek.0, plaintext.as_bytes(), AAD_DATA)
}

pub fn decrypt_data(dek: &Dek, blob: &DataBlob) -> Result<DataMap> {
    let plaintext = decrypt(&dek.0, blob, AAD_DATA, "corrupted")?;
    serde_json::from_slice(&plaintext).map_err(|_| AppError::new("corrupted"))
}

fn password_entry(dek: &Dek, password: &str, iterations: u32) -> Result<PasswordEntry> {
    let salt = random_bytes(16);
    let kek = password_kek(password, &salt, iterations);
    let blob = wrap_dek(dek, &kek, AAD_PASSWORD)?;
    Ok(PasswordEntry {
        kdf: "PBKDF2-SHA256".into(),
        iterations,
        salt: to_b64(&salt),
        iv: blob.iv,
        wrapped: blob.ct,
    })
}

/// Crée un coffre : nouvelle DEK, données chiffrées, DEK enveloppée par le mot de passe.
pub fn create(password: &str, data: &DataMap, iterations: u32) -> Result<(VaultRecord, Dek)> {
    validate_password(password)?;
    let dek = Dek(random_bytes(32).try_into().expect("32 octets"));
    let entry = password_entry(&dek, password, iterations)?;
    let data_blob = encrypt_data(&dek, data)?;
    Ok((VaultRecord { v: 1, password: entry, passkeys: Vec::new(), data: data_blob }, dek))
}

pub fn unlock_with_password(record: &VaultRecord, password: &str) -> Result<Dek> {
    let entry = &record.password;
    let salt = from_b64(&entry.salt).map_err(|_| AppError::new("wrongPassword"))?;
    let kek = password_kek(password, &salt, entry.iterations);
    unwrap_dek(&entry.iv, &entry.wrapped, &kek, AAD_PASSWORD, "wrongPassword")
}

pub fn unlock_with_prf(record: &VaultRecord, credential_id: &str, prf_output: &[u8]) -> Result<Dek> {
    let entry = record.passkeys.iter().find(|p| p.id == credential_id).ok_or(AppError::new("unknownPasskey"))?;
    let kek = prf_kek(prf_output);
    unwrap_dek(&entry.iv, &entry.wrapped, &kek, &format!("{AAD_PASSKEY}{}", entry.id), "passkeyRejected")
}

/// Nouveau mot de passe : seule l'enveloppe change, les passkeys restent valides.
pub fn change_password(record: &VaultRecord, dek: &Dek, new_password: &str, iterations: u32) -> Result<VaultRecord> {
    validate_password(new_password)?;
    let mut next = record.clone();
    next.password = password_entry(dek, new_password, iterations)?;
    Ok(next)
}

pub fn add_passkey(
    record: &VaultRecord,
    dek: &Dek,
    id: &str,
    name: &str,
    prf_salt: &[u8],
    prf_output: &[u8],
) -> Result<VaultRecord> {
    let kek = prf_kek(prf_output);
    let blob = wrap_dek(dek, &kek, &format!("{AAD_PASSKEY}{id}"))?;
    let entry = PasskeyEntry {
        id: id.into(),
        name: name.into(),
        prfSalt: to_b64(prf_salt),
        createdAt: now_iso(),
        iv: blob.iv,
        wrapped: blob.ct,
    };
    let mut next = record.clone();
    next.passkeys.retain(|p| p.id != id);
    next.passkeys.push(entry);
    Ok(next)
}

pub fn remove_passkey(record: &VaultRecord, id: &str) -> VaultRecord {
    let mut next = record.clone();
    next.passkeys.retain(|p| p.id != id);
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: u32 = 1000;
    fn sample_data() -> DataMap {
        [
            ("mymfa.accounts.v1", r#"[{"id":"a","secret":"JBSWY3DPEHPK3PXP"}]"#),
            ("mymfa.history.v1", "[]"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }

    #[test]
    fn parametres_par_defaut() {
        assert_eq!(PBKDF2_ITERATIONS, 1_000_000);
        assert_eq!(PASSWORD_MIN_LENGTH, 10);
        assert_eq!(AAD_DATA, "mymfa:vault:data:v1");
        assert_eq!(AAD_PASSWORD, "mymfa:vault:wrap:password:v1");
        assert_eq!(AAD_PASSKEY, "mymfa:vault:wrap:passkey:v1:");
        assert_eq!(HKDF_INFO, "mymfa:vault:passkey-kek:v1");
    }

    #[test]
    fn password_strength_aligne_sur_le_web() {
        assert_eq!(password_strength("").level, 0);
        assert_eq!(password_strength("password").level, 1, "mot courant : plafonné");
        assert_eq!(password_strength("motdepasse123").level, 1, "mot courant + chiffres : plafonné");
        assert_eq!(password_strength("aaaaaaaa").level, 1, "un caractère répété");
        assert_eq!(password_strength("azertyuiop").level, 1, "suite de clavier");
        assert!(password_strength("Br3iz-kouign-amann!").level >= 3, "long et varié");
        assert!(password_strength("correct horse battery staple").bits >= 80, "longue phrase");
        let s = password_strength("xK9#mL2v");
        assert!(s.bits > 0 && s.level >= 2, "court mais varié : au moins moyen");
    }

    #[test]
    fn creation_puis_deverrouillage_donnees_intactes() {
        let data = sample_data();
        let (record, _) = create("correct horse battery", &data, FAST).unwrap();
        assert_eq!(record.v, 1);
        assert!(!serde_json::to_string(&record).unwrap().contains("JBSWY3DP"), "le secret ne doit pas apparaître en clair");
        let dek = unlock_with_password(&record, "correct horse battery").unwrap();
        assert_eq!(decrypt_data(&dek, &record.data).unwrap(), data);
    }

    #[test]
    fn mauvais_mot_de_passe() {
        let (record, _) = create("correct horse battery", &sample_data(), FAST).unwrap();
        assert_eq!(unlock_with_password(&record, "mauvais mot de passe").unwrap_err().code, "wrongPassword");
    }

    #[test]
    fn mot_de_passe_trop_court_refuse() {
        for password in ["court", "neuf.char"] {
            assert_eq!(create(password, &sample_data(), FAST).unwrap_err().code, "passwordTooShort");
        }
        let (record, _) = create("dix-caractères", &sample_data(), FAST).unwrap();
        assert_eq!(record.v, 1);
    }

    #[test]
    fn changement_de_mot_de_passe() {
        let data = sample_data();
        let (record, dek) = create("ancien mot de passe", &data, FAST).unwrap();
        let next = change_password(&record, &dek, "nouveau mot de passe", FAST).unwrap();
        assert_eq!(unlock_with_password(&next, "ancien mot de passe").unwrap_err().code, "wrongPassword");
        let dek2 = unlock_with_password(&next, "nouveau mot de passe").unwrap();
        assert_eq!(decrypt_data(&dek2, &next.data).unwrap(), data);
    }

    #[test]
    fn passkey_prf_simulee() {
        let data = sample_data();
        let (record, dek) = create("mot de passe maître", &data, FAST).unwrap();
        let prf_output = random_bytes(32);
        let with_key = add_passkey(&record, &dek, "cred-1", "Portable", &random_bytes(32), &prf_output).unwrap();
        assert_eq!(with_key.passkeys.len(), 1);
        let dek2 = unlock_with_prf(&with_key, "cred-1", &prf_output).unwrap();
        assert_eq!(decrypt_data(&dek2, &with_key.data).unwrap(), data);
        assert_eq!(unlock_with_prf(&with_key, "cred-1", &random_bytes(32)).unwrap_err().code, "passkeyRejected");
        assert_eq!(unlock_with_prf(&with_key, "inconnu", &prf_output).unwrap_err().code, "unknownPasskey");
        assert_eq!(remove_passkey(&with_key, "cred-1").passkeys.len(), 0);
    }

    #[test]
    fn enveloppes_non_interchangeables_et_alteration_detectee() {
        let data = sample_data();
        let (record, dek) = create("mot de passe maître", &data, FAST).unwrap();
        let prf_output = random_bytes(32);
        let r = add_passkey(&record, &dek, "cred-1", "Clé", &random_bytes(32), &prf_output).unwrap();
        // Enveloppe du passkey copiée sous un autre identifiant : refusée.
        let mut swapped = r.clone();
        swapped.passkeys[0].id = "cred-2".into();
        assert_eq!(unlock_with_prf(&swapped, "cred-2", &prf_output).unwrap_err().code, "passkeyRejected");
        // Données altérées : refusées.
        let mut ct = from_b64(&r.data.ct).unwrap();
        ct[0] ^= 1;
        let tampered = DataBlob { iv: r.data.iv.clone(), ct: to_b64(&ct) };
        assert_eq!(decrypt_data(&dek, &tampered).unwrap_err().code, "corrupted");
    }

    #[test]
    fn parse_enregistrement() {
        let (record, _) = create("mot de passe maître", &sample_data(), FAST).unwrap();
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(parse(&json), Some(record));
        assert_eq!(parse("{pas du json"), None);
        assert_eq!(parse(""), None);
        assert_eq!(parse(r#"{"v":2}"#), None);
    }

    #[test]
    fn base64_et_base64url_aller_retour() {
        let bytes = random_bytes(40);
        assert_eq!(from_b64(&to_b64(&bytes)).unwrap(), bytes);
        assert_eq!(from_b64url(&to_b64url(&bytes)).unwrap(), bytes);
        assert!(!to_b64url(&bytes).contains(['+', '/', '=']));
        assert_eq!(to_b64(b"foob"), "Zm9vYg==");
        assert_eq!(to_b64(b"fooba"), "Zm9vYmE=");
        assert_eq!(to_b64(b"foobar"), "Zm9vYmFy");
    }
}
