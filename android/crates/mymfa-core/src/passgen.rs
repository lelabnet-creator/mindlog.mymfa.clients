/*
 * Générateur de mots de passe de la vue Mots de passe — réplique du
 * `generatePassword` de web/js/credentials.js : caractères (sans biais, au
 * moins un caractère de chaque famille demandée, majuscules comme minuscules)
 * ou phrase de syllabes. Ce n'est pas web/js/passgen.js (politiques de sites,
 * pour le remplissage automatique de l'extension) : ici, un seul générateur
 * libre, celui de l'app.
 */
use getrandom::fill;

pub const LETTERS: &str = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub const DIGITS: &str = "23456789";
pub const SYMBOLS: &str = "-_.!@#%+=?*";
const CONSONANTS: &str = "bcdfghjklmnprstvz";
const VOWELS: &str = "aeiou";

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct GenOptions {
    /// Caractères (défaut 20) ou mots de la phrase (défaut web : 5 à la bascule).
    pub length: usize,
    pub digits: bool,
    pub symbols: bool,
    /// Phrase de syllabes plutôt que caractères.
    pub words: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self { length: 20, digits: true, symbols: true, words: false }
    }
}

/// Entier uniforme dans [0, n) (rejet des valeurs qui biaiseraient le modulo,
/// comme `randomBelow` du web). n = 0 interdit : appelant garanti par l'UI.
fn random_below(n: u32) -> u32 {
    let limit = (u32::MAX / n) * n; // = floor(2^32 / n) * n
    loop {
        let mut buf = [0u8; 4];
        fill(&mut buf).expect("getrandom");
        let value = u32::from_le_bytes(buf);
        if value < limit {
            return value % n;
        }
    }
}

fn pick(chars: &str) -> char {
    let bytes: Vec<char> = chars.chars().collect();
    bytes[random_below(bytes.len() as u32) as usize]
}

/// Mot de passe selon les options ; familles demandées toujours présentes
/// (sauf pool impossible, voir garde-fou : la boucle du web ne s'arrête pas
/// non plus).
pub fn generate_password(options: &GenOptions) -> String {
    let opts = *options;
    if opts.words {
        let length = opts.length.max(3).min(8); // bornes du curseur web
        // Syllabes consonne-voyelle-consonne, comme le web.
        let mut words: Vec<String> = (0..length)
            .map(|_| format!("{}{}{}", pick(CONSONANTS), pick(VOWELS), pick(CONSONANTS)))
            .collect();
        let capital = random_below(words.len() as u32) as usize;
        let mut chars = words[capital].chars();
        let first = chars.next().unwrap_or('a');
        words[capital] = first.to_uppercase().collect::<String>() + chars.as_str();
        if opts.digits {
            let index = random_below(words.len() as u32) as usize;
            words[index].push(pick(DIGITS));
        }
        return words.join(if opts.symbols { "-" } else { "" });
    }
    let length = opts.length.clamp(12, 40); // bornes du curseur web
    let pool = format!("{}{}{}", LETTERS, if opts.digits { DIGITS } else { "" }, if opts.symbols { SYMBOLS } else { "" });
    let mut out = String::new();
    for _ in 0..1000 {
        out = (0..length).map(|_| pick(&pool)).collect();
        let has_upper = out.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = out.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = out.chars().any(|c| DIGITS.contains(c));
        let has_symbol = out.chars().any(|c| SYMBOLS.contains(c));
        if has_upper && has_lower
            && (!opts.digits || has_digit)
            && (!opts.symbols || has_symbol)
        {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaut_vingt_caracteres_quatre_classes() {
        for _ in 0..50 {
            let value = generate_password(&GenOptions::default());
            assert_eq!(value.chars().count(), 20);
            assert!(value.chars().any(|c| c.is_ascii_lowercase()));
            assert!(value.chars().any(|c| c.is_ascii_uppercase()));
            assert!(value.chars().any(|c| DIGITS.contains(c)));
            assert!(value.chars().any(|c| SYMBOLS.contains(c)));
            assert!(value.chars().all(|c| LETTERS.contains(c) || DIGITS.contains(c) || SYMBOLS.contains(c)));
        }
    }

    #[test]
    fn sans_chiffres_ni_symboles_lettres_seules() {
        let opts = GenOptions { length: 16, digits: false, symbols: false, words: false };
        for _ in 0..20 {
            let value = generate_password(&opts);
            assert_eq!(value.chars().count(), 16);
            assert!(value.chars().all(|c| LETTERS.contains(c)));
        }
    }

    #[test]
    fn phrase_de_syllabes() {
        let opts = GenOptions { length: 5, digits: true, symbols: true, words: true };
        for _ in 0..20 {
            let value = generate_password(&opts);
            let words: Vec<&str> = value.split('-').collect();
            assert_eq!(words.len(), 5, "{value}");
            assert!(value.chars().any(|c| c.is_ascii_uppercase()), "{value}");
            assert!(value.chars().any(|c| DIGITS.contains(c)), "{value}");
            // Syllabes consonne-voyelle alternées, alphabet restreint.
            assert!(value.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'), "{value}");
        }
    }
}
