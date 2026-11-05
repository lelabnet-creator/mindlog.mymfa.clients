/*
 * Textes FR/EN — même source que l'app web : web/js/locales/{fr,en}.js,
 * convertis en Rust par ../../scripts/sync-locales.mjs (`npm run gen`).
 * Les fichiers fr.rs / en.rs sont générés (non versionnés), comme les copies
 * de l'extension.
 */
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    Fr,
    En,
}

impl Locale {
    pub fn code(&self) -> &'static str {
        match self {
            Locale::Fr => "fr",
            Locale::En => "en",
        }
    }

    pub fn parse(code: &str) -> Option<Self> {
        match code.trim().to_lowercase().as_str() {
            "fr" => Some(Locale::Fr),
            "en" => Some(Locale::En),
            _ => None,
        }
    }
}

mod fr {
    include!("fr.rs");
}
mod en {
    include!("en.rs");
}

/// (clé plate « a.b.c », texte) et (clé, pluriel one, pluriel other), triés par clé.
pub struct Catalog {
    strings: HashMap<&'static str, &'static str>,
    plurals: HashMap<&'static str, (&'static str, &'static str)>,
}

fn catalog(locale: Locale) -> &'static Catalog {
    static FR: OnceLock<Catalog> = OnceLock::new();
    static EN: OnceLock<Catalog> = OnceLock::new();
    fn build(strings: &[(&'static str, &'static str)], plurals: &[(&'static str, &'static str, &'static str)]) -> Catalog {
        Catalog {
            strings: strings.iter().copied().collect(),
            plurals: plurals.iter().map(|(k, one, other)| (*k, (*one, *other))).collect(),
        }
    }
    match locale {
        Locale::Fr => FR.get_or_init(|| build(fr::STRINGS, fr::PLURALS)),
        Locale::En => EN.get_or_init(|| build(en::STRINGS, en::PLURALS)),
    }
}

/// Choix du pluriel, comme `Intl.PluralRules` : fr → un pour 0 et 1 ; en → un pour 1 seul.
fn is_one(locale: Locale, n: i64) -> bool {
    match locale {
        Locale::Fr => n.abs() <= 1,
        Locale::En => n == 1,
    }
}

fn interpolate(template: &str, params: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (name, value) in params {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

/// Texte simple ; repli sur le français puis sur la clé, comme l'i18n web.
pub fn t(locale: Locale, key: &str) -> String {
    let text = catalog(locale)
        .strings
        .get(key)
        .copied()
        .or_else(|| catalog(Locale::Fr).strings.get(key).copied())
        .unwrap_or(key);
    text.to_string()
}

/// Texte avec interpolation `{param}`.
pub fn tf(locale: Locale, key: &str, params: &[(&str, &str)]) -> String {
    interpolate(&t(locale, key), params)
}

/// Texte à pluriel (clé sans suffixe) : choisit `one`/`other` selon la locale
/// et la quantité, puis interpole `{n}` et `{count}`.
pub fn tn(locale: Locale, key: &str, n: i64) -> String {
    let (one, other) = catalog(locale)
        .plurals
        .get(key)
        .copied()
        .or_else(|| catalog(Locale::Fr).plurals.get(key).copied())
        .unwrap_or((key, key));
    let template = if is_one(locale, n) { one } else { other };
    interpolate(template, &[("n", &n.to_string()), ("count", &n.to_string())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn textes_francais_anglais() {
        assert_eq!(t(Locale::Fr, "nav.home"), "Codes");
        assert_eq!(t(Locale::En, "nav.home"), "Codes");
        assert_eq!(t(Locale::Fr, "theme.dark"), "Sombre");
        assert_eq!(t(Locale::En, "theme.dark"), "Dark");
        // Clé absente : repli sur la clé elle-même.
        assert_eq!(t(Locale::Fr, "nexiste.pas"), "nexiste.pas");
    }

    #[test]
    fn interpolation_et_pluriels() {
        let with_param = tf(Locale::Fr, "new.currentCodeHint", &[("issuer", "GitHub")]);
        assert!(with_param.contains("GitHub"), "{with_param}");
        // Pluriel : le français dit « un » pour 0 et 1, l'anglais pour 1 seul.
        assert_eq!(is_one(Locale::Fr, 0), true);
        assert_eq!(is_one(Locale::En, 0), false);
        assert_eq!(is_one(Locale::En, 1), true);
    }
}
