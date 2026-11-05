/*
 * Parsing et construction des URI otpauth:// (voir ../web/js/otp.js).
 * Les bizarreries viennent de JavaScript et sont volontaires :
 *  - `parseInt` tolérant (« 30x » → 30, « abc » → NaN) ;
 *  - sérialisation URLSearchParams (espace → +, tout sauf alphanumériques et *-._ encodé) ;
 *  - encodeURIComponent pour le libellé (jeu non réservé étendu !'()*-._~).
 */
use crate::otp::{normalize_secret, Algorithm, DEFAULT_DIGITS, DEFAULT_PERIOD};
use crate::AppError;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtpType {
    Totp,
    Hotp,
}

impl OtpType {
    pub fn as_str(&self) -> &'static str {
        match self {
            OtpType::Totp => "totp",
            OtpType::Hotp => "hotp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpAuth {
    pub type_: OtpType,
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub period: u64,
    pub counter: i64,
}

impl Default for OtpAuth {
    fn default() -> Self {
        Self {
            type_: OtpType::Totp,
            issuer: String::new(),
            account: String::new(),
            secret: String::new(),
            algorithm: Algorithm::Sha1,
            digits: DEFAULT_DIGITS,
            period: DEFAULT_PERIOD,
            counter: 0,
        }
    }
}

/// `parseInt` de JavaScript : espaces de tête ignorées, signe optionnel, chiffres
/// de tête lus, le reste ignoré ; aucun chiffre → NaN (None).
fn js_parse_int(text: &str) -> Option<i64> {
    let trimmed = text.trim_start();
    let mut chars = trimmed.chars().peekable();
    let mut digits = String::new();
    if let Some(&'+' | &'-') = chars.peek() {
        digits.push(chars.next().unwrap());
    }
    for ch in chars {
        if ch.is_ascii_digit() {
            digits.push(ch);
        } else {
            break;
        }
    }
    let signed = digits.strip_prefix('+').unwrap_or(&digits);
    if signed == "-" || signed.is_empty() {
        return None;
    }
    signed.parse::<i64>().ok()
}

/// Décodage percent d'un composant d'URI (UTF-8), comme decodeURIComponent :
/// échoue (→ `invalidUri`) sur une séquence % malformée ou de l'UTF-8 invalide.
fn percent_decode_component(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3)?;
                let hi = (hex[0] as char).to_digit(16)?;
                let lo = (hex[1] as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// encodeURIComponent de JavaScript : échappe tout sauf A-Za-z0-9 et -_.!~*'().
fn js_encode_uri_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')');
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// Sérialisation URLSearchParams : espace → +, seuls A-Za-z0-9*-._ passent tels quels.
fn form_urlencode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for &byte in text.as_bytes() {
        let keep = byte.is_ascii_alphanumeric() || matches!(byte, b'*' | b'-' | b'.' | b'_');
        match byte {
            b' ' => out.push('+'),
            b if keep => out.push(b as char),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// `parseInt(params.get(name) || '6', 10)` : absent ou vide → défaut ;
/// renvoie (valeur, texte brut pour les messages d'erreur).
fn param_int(pairs: &[(String, String)], name: &str, default: &str) -> (Option<i64>, String) {
    let raw = param(pairs, name).filter(|v| !v.is_empty()).unwrap_or(default).to_string();
    let parsed = if raw.is_empty() { None } else { js_parse_int(&raw) };
    (parsed, raw)
}

fn digits_string(value: Option<i64>) -> String {
    // Côté web, le paramètre vaut NaN dans ce cas ; l'i18n affiche « NaN ».
    value.map(|v| v.to_string()).unwrap_or_else(|| "NaN".into())
}

/// Parse une URI otpauth://totp/Label?secret=…&issuer=…
/// Erreurs (codes web) : `migrationUnsupported`, `invalidUri`, `notOtpauth`,
/// `unknownType`, `missingSecret`, `unsupportedAlgorithm`, `unsupportedDigits`,
/// `invalidPeriod`, plus celles de la clé base32.
pub fn parse(uri: &str) -> Result<OtpAuth, AppError> {
    let text = uri.trim();
    if text.len() >= 18 && text[..18].eq_ignore_ascii_case("otpauth-migration:") {
        return Err(AppError::new("migrationUnsupported"));
    }
    let url = Url::parse(text).map_err(|_| AppError::new("invalidUri"))?;
    if url.scheme() != "otpauth" {
        return Err(AppError::new("notOtpauth"));
    }
    let type_text = url.host_str().unwrap_or("").to_lowercase();
    let type_ = match type_text.as_str() {
        "totp" => OtpType::Totp,
        "hotp" => OtpType::Hotp,
        _ => return Err(AppError::param("unknownType", "type", type_text)),
    };

    // Label : chemin sans son premier '/', décodé (decodeURIComponent).
    let path = url.path();
    let label_raw = path.strip_prefix('/').unwrap_or(path);
    let label = percent_decode_component(label_raw).ok_or_else(|| AppError::new("invalidUri"))?;
    let mut label_issuer = String::new();
    let mut account = label.clone();
    if let Some(sep) = label.find(':') {
        label_issuer = label[..sep].trim().to_string();
        account = label[sep + 1..].trim().to_string();
    }

    let pairs: Vec<(String, String)> = url
        .query_pairs()
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();

    let secret = normalize_secret(param(&pairs, "secret").unwrap_or(""));
    if secret.is_empty() {
        return Err(AppError::new("missingSecret"));
    }
    crate::otp::base32_decode(&secret)?;

    let algorithm_text = param(&pairs, "algorithm").filter(|v| !v.is_empty()).unwrap_or("SHA1").to_uppercase();
    let algorithm = Algorithm::parse(&algorithm_text)
        .ok_or_else(|| AppError::param("unsupportedAlgorithm", "algorithm", algorithm_text.clone()))?;

    let (digits, _) = param_int(&pairs, "digits", "6");
    let digits = match digits {
        Some(d @ 6..=8) => d as u32,
        _ => return Err(AppError::param("unsupportedDigits", "digits", digits_string(digits))),
    };
    let (period, period_raw) = param_int(&pairs, "period", "30");
    let period = match period {
        Some(p) if p > 0 => p as u64,
        _ => return Err(AppError::param("invalidPeriod", "period", period_raw)),
    };
    let (counter, _) = param_int(&pairs, "counter", "0");
    let counter = counter.unwrap_or(0);

    let issuer_param = param(&pairs, "issuer").unwrap_or("");
    let issuer = if issuer_param.is_empty() { label_issuer } else { issuer_param.to_string() };

    Ok(OtpAuth { type_, issuer, account, secret, algorithm, digits, period, counter })
}

/// Reconstruit une URI otpauth:// (export, ré-affichage en QR). L'ordre des
/// paramètres est celui du web : secret, issuer, algorithm, digits, counter|period.
pub fn build(auth: &OtpAuth) -> String {
    let label = js_encode_uri_component(&if auth.issuer.is_empty() {
        auth.account.clone()
    } else {
        format!("{}:{}", auth.issuer, auth.account)
    });
    let mut query = format!("secret={}", form_urlencode(&normalize_secret(&auth.secret)));
    if !auth.issuer.is_empty() {
        query.push_str(&format!("&issuer={}", form_urlencode(&auth.issuer)));
    }
    query.push_str(&format!("&algorithm={}", form_urlencode(auth.algorithm.name())));
    query.push_str(&format!("&digits={}", auth.digits));
    match auth.type_ {
        OtpType::Hotp => query.push_str(&format!("&counter={}", auth.counter)),
        OtpType::Totp => query.push_str(&format!("&period={}", auth.period)),
    }
    format!("otpauth://{}/{}?{}", auth.type_.as_str(), label, query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_uri_complete() {
        let p = parse(
            "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(p.type_, OtpType::Totp);
        assert_eq!(p.issuer, "ACME Co");
        assert_eq!(p.account, "john.doe@email.com");
        assert_eq!(p.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ");
        assert_eq!(p.algorithm, Algorithm::Sha256);
        assert_eq!(p.digits, 8);
        assert_eq!(p.period, 60);
        assert_eq!(p.counter, 0);
    }

    #[test]
    fn parse_valeurs_par_defaut() {
        let p = parse("otpauth://totp/GitHub:me?secret=jbswy3dpehpk3pxp").unwrap();
        assert_eq!(p.issuer, "GitHub");
        assert_eq!(p.account, "me");
        assert_eq!(p.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(p.algorithm, Algorithm::Sha1);
        assert_eq!(p.digits, 6);
        assert_eq!(p.period, 30);
        let h = parse("otpauth://hotp/me?secret=JBSWY3DPEHPK3PXP&counter=7").unwrap();
        assert_eq!(h.type_, OtpType::Hotp);
        assert_eq!(h.counter, 7);
        assert_eq!(h.issuer, "");
    }

    #[test]
    fn parse_erreurs_codees() {
        let cases = [
            ("nimporte quoi", "invalidUri"),
            ("https://example.com", "notOtpauth"),
            ("otpauth://xotp/a?secret=JBSWY3DP", "unknownType"),
            ("otpauth://totp/a", "missingSecret"),
            ("otpauth://totp/a?secret=JBSWY3DP&algorithm=MD5", "unsupportedAlgorithm"),
            ("otpauth://totp/a?secret=JBSWY3DP&digits=4", "unsupportedDigits"),
            ("otpauth-migration://offline?data=abc", "migrationUnsupported"),
            ("otpauth://totp/a?secret=JBSWY3DP&period=0", "invalidPeriod"),
        ];
        for (uri, code) in cases {
            assert_eq!(parse(uri).unwrap_err().code, code, "{uri}");
        }
    }

    #[test]
    fn build_puis_parse_aller_retour() {
        let account = OtpAuth {
            issuer: "Le Lab".into(),
            account: "jacques@le-lab.net".into(),
            secret: "JBSWY3DPEHPK3PXP".into(),
            algorithm: Algorithm::Sha512,
            digits: 8,
            period: 45,
            ..OtpAuth::default()
        };
        let parsed = parse(&build(&account)).unwrap();
        assert_eq!(parsed, account);
    }

    #[test]
    fn build_format_exact() {
        let account = OtpAuth {
            issuer: "ACME Co".into(),
            account: "john.doe@email.com".into(),
            secret: "jbsw y3dp".into(),
            ..OtpAuth::default()
        };
        assert_eq!(
            build(&account),
            "otpauth://totp/ACME%20Co%3Ajohn.doe%40email.com?secret=JBSWY3DP&issuer=ACME+Co&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn js_parse_int_tolerance() {
        assert_eq!(js_parse_int("30x"), Some(30));
        assert_eq!(js_parse_int(" 7"), Some(7));
        assert_eq!(js_parse_int("-1"), Some(-1));
        assert_eq!(js_parse_int("abc"), None);
        assert_eq!(js_parse_int(""), None);
    }
}
