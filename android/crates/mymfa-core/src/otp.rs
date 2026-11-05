/*
 * Cœur OTP : base32, HOTP (RFC 4226), TOTP (RFC 6238).
 * Réplique de ../web/js/otp.js — mêmes tolérances, mêmes erreurs codées.
 */
use crate::AppError;
use hmac::{Mac, SimpleHmac};
use sha1::Sha1;
use sha2::digest::{core_api::BlockSizeUser, Digest};
use sha2::{Sha256, Sha512};

pub const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub const DEFAULT_DIGITS: u32 = 6;
pub const DEFAULT_PERIOD: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl Algorithm {
    /// Nom tel que stocké dans les comptes et les URI (`SHA1`, `SHA256`, `SHA512`).
    pub fn name(&self) -> &'static str {
        match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        }
    }

    /// Accepte la casse quelconque, comme `(params.get('algorithm') || 'SHA1').toUpperCase()`.
    pub fn parse(text: &str) -> Option<Self> {
        match text.to_uppercase().as_str() {
            "SHA1" => Some(Algorithm::Sha1),
            "SHA256" => Some(Algorithm::Sha256),
            "SHA512" => Some(Algorithm::Sha512),
            _ => None,
        }
    }
}

/// Normalise une clé saisie à la main : majuscules, sans espaces/tirets/padding.
pub fn normalize_secret(secret: &str) -> String {
    let mut out = String::with_capacity(secret.len());
    for ch in secret.to_uppercase().chars() {
        if !ch.is_whitespace() && ch != '-' {
            out.push(ch);
        }
    }
    while out.ends_with('=') {
        out.pop();
    }
    out
}

/// Décode une clé base32 (RFC 4648). Les bits restants (< 8) sont ignorés,
/// comme côté web. Erreurs : `secretEmpty`, `secretInvalidChar`, `secretTooShort`.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, AppError> {
    let clean = normalize_secret(input);
    if clean.is_empty() {
        return Err(AppError::new("secretEmpty"));
    }
    let mut bits = 0u32;
    let mut value = 0u32;
    let mut out = Vec::new();
    for ch in clean.chars() {
        let idx = match BASE32_ALPHABET.iter().position(|&a| a as char == ch) {
            Some(i) => i as u32,
            None => {
                return Err(AppError::param("secretInvalidChar", "char", ch.to_string()));
            }
        };
        value = (value << 5) | idx;
        bits += 5;
        if bits >= 8 {
            out.push(((value >> (bits - 8)) & 0xff) as u8);
            bits -= 8;
        }
    }
    if out.is_empty() {
        return Err(AppError::new("secretTooShort"));
    }
    Ok(out)
}

pub fn is_valid_secret(secret: &str) -> bool {
    base32_decode(secret).is_ok()
}

fn counter_bytes(counter: u64) -> [u8; 8] {
    counter.to_be_bytes()
}

fn sign<D>(key: &[u8], counter: u64) -> Vec<u8>
where
    D: Digest + BlockSizeUser + Clone,
{
    let mut mac = <SimpleHmac<D> as Mac>::new_from_slice(key).expect("HMAC accepte toute taille de clé");
    mac.update(&counter_bytes(counter));
    mac.finalize().into_bytes().to_vec()
}

/// Code HOTP (RFC 4226) : compteur 8 octets big-endian, troncature dynamique,
/// `mod 10^digits`, zéros de tête. `counter` négatif (saisi via une URI) suit le
/// complément à deux de BigInt, comme `counterBytes` côté web.
pub fn hotp(secret: &str, counter: u64, digits: u32, algorithm: Algorithm) -> Result<String, AppError> {
    let key = base32_decode(secret)?;
    let mac = match algorithm {
        Algorithm::Sha1 => sign::<Sha1>(&key, counter),
        Algorithm::Sha256 => sign::<Sha256>(&key, counter),
        Algorithm::Sha512 => sign::<Sha512>(&key, counter),
    };
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = (((mac[offset] & 0x7f) as u64) << 24)
        | ((mac[offset + 1] as u64) << 16)
        | ((mac[offset + 2] as u64) << 8)
        | mac[offset + 3] as u64;
    let modulus = 10u64.checked_pow(digits).unwrap_or(u64::MAX);
    let code = (bin % modulus).to_string();
    let width = digits as usize;
    Ok(format!("{code:0>width$}"))
}

/// Code TOTP (RFC 6238) : `counter = floor(timestamp_ms / 1000 / period)`.
pub fn totp(
    secret: &str,
    period: u64,
    digits: u32,
    algorithm: Algorithm,
    timestamp_ms: u64,
) -> Result<String, AppError> {
    let counter = timestamp_ms / 1000 / period;
    hotp(secret, counter, digits, algorithm)
}

/// Secondes restantes avant le prochain code.
pub fn remaining_seconds(period: u64, timestamp_ms: u64) -> u64 {
    period - (timestamp_ms / 1000 % period)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Miroir de web/test/helpers.js : encodeur base32 pour bâtir les graines RFC.
    fn base32_encode(text: &str) -> String {
        let mut acc = 0u32;
        let mut bits = 0u32;
        let mut out = String::new();
        for byte in text.as_bytes() {
            acc = (acc << 8) | *byte as u32;
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(BASE32_ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
            }
        }
        if bits > 0 {
            out.push(BASE32_ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
        }
        out
    }

    fn seeds(algorithm: Algorithm) -> String {
        match algorithm {
            Algorithm::Sha1 => base32_encode("12345678901234567890"),
            Algorithm::Sha256 => base32_encode("12345678901234567890123456789012"),
            Algorithm::Sha512 => base32_encode(
                "1234567890123456789012345678901234567890123456789012345678901234",
            ),
        }
    }

    // RFC 6238, annexe B (8 chiffres, période 30 s) : [secondes, SHA1, SHA256, SHA512].
    const RFC6238: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn totp_vecteurs_rfc6238() {
        for &(seconds, sha1, sha256, sha512) in RFC6238 {
            for (algorithm, expected) in [
                (Algorithm::Sha1, sha1),
                (Algorithm::Sha256, sha256),
                (Algorithm::Sha512, sha512),
            ] {
                let code = totp(&seeds(algorithm), 30, 8, algorithm, seconds * 1000).unwrap();
                assert_eq!(code, expected, "{algorithm:?} @ {seconds}");
            }
        }
    }

    #[test]
    fn hotp_vecteurs_rfc4226() {
        let expected =
            ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
        let seed = seeds(Algorithm::Sha1);
        for (counter, expected) in expected.iter().enumerate() {
            assert_eq!(hotp(&seed, counter as u64, 6, Algorithm::Sha1).unwrap(), *expected);
        }
    }

    #[test]
    fn base32_tolerances() {
        let reference = base32_decode("JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(base32_decode("jbsw y3dp-ehpk 3pxp==").unwrap(), reference);
        assert_eq!(&String::from_utf8_lossy(&reference[..6]), "Hello!");
    }

    #[test]
    fn base32_erreurs_codees() {
        assert_eq!(base32_decode("").unwrap_err().code, "secretEmpty");
        let err = base32_decode("ABC1").unwrap_err();
        assert_eq!(err.code, "secretInvalidChar");
        assert_eq!(err.get("char"), Some("1"));
        assert_eq!(base32_decode("A").unwrap_err().code, "secretTooShort");
        assert!(is_valid_secret("JBSWY3DPEHPK3PXP"));
        assert!(!is_valid_secret("not valid!"));
    }

    #[test]
    fn remaining_seconds_aligne_sur_la_periode() {
        assert_eq!(remaining_seconds(30, 0), 30);
        assert_eq!(remaining_seconds(30, 29_000), 1);
        assert_eq!(remaining_seconds(30, 30_000), 30);
    }
}
