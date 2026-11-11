/*
 * Cœur myMFA pour le client Android : réplique fidèle de l'app web (../web/js).
 *
 * Les constantes (AAD du coffre, itérations PBKDF2, clés localStorage, plafonds
 * d'historique…) doivent rester identiques à leurs sources JavaScript : un coffre
 * écrit par l'app ou l'extension doit s'ouvrir ici, et inversement. Les tests
 * rejouent les vecteurs RFC de web/test/ et des coffres réellement chiffrés par
 * web/js/vault.js (fixtures générées par ../scripts/make-fixtures.mjs).
 */
pub mod otp;
pub mod otpauth;
pub mod passgen;
pub mod store;
pub mod sync;
pub mod sync2;
pub mod temps;
#[cfg(feature = "texts")]
pub mod texts;
pub mod vault;

/// Une « copie des données » : { clé localStorage → valeur brute (JSON en texte) },
/// tel que stocké par Store côté web — c'est aussi le texte en clair du coffre.
pub type DataMap = std::collections::BTreeMap<String, String>;

/// Erreur porteuse d'un code traduisible (clé i18n `error.<code>`), comme
/// VaultError / OtpError côté web.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppError {
    pub code: &'static str,
    pub params: Vec<(&'static str, String)>,
}

impl AppError {
    pub fn new(code: &'static str) -> Self {
        Self { code, params: Vec::new() }
    }

    pub fn with(code: &'static str, params: Vec<(&'static str, String)>) -> Self {
        Self { code, params }
    }

    pub fn param(code: &'static str, name: &'static str, value: impl Into<String>) -> Self {
        Self { code, params: vec![(name, value.into())] }
    }

    /// Valeur d'un paramètre d'erreur, pour l'interpolation i18n.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.params.iter().find(|(n, _)| *n == name).map(|(_, v)| v.as_str())
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}

impl std::error::Error for AppError {}

pub type Result<T> = std::result::Result<T, AppError>;

/// Horodatage ISO 8601 UTC (millisecondes), identique à `new Date().toISOString()`.
pub fn now_iso() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    iso_from_unix(now.as_secs() as i64, now.subsec_millis())
}

pub fn iso_from_unix(secs: i64, millis: u32) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

/// Jours écoulés → date civile (algorithme de Howard Hinnant, calendrier proleptique grégorien).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

