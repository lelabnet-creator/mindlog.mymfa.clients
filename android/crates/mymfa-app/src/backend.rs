/*
 * Backend de l'app : état (coffre, comptes, préférences), persistance fichier,
 * ticker des codes, verrouillage automatique — miroir de web/js/{lock,app}.js
 * pour la part du socle (vues Codes, Nouveau compte, Réglages) et de
 * web/js/credentials.js pour la vue Mots de passe.
 */
use crate::storage;
use crate::{AccountRow, MainWindow, NewAccountInput, PreviewInput, PreviewResult};
use crate::{CredCodeRow, CredLoginInput, CredPasskeyRow, CredentialDetail, CredentialRow};
use mymfa_core::otp::{self, Algorithm};
use mymfa_core::passgen::{self, GenOptions};
use mymfa_core::store::{self, Account, SitePasskey, Store};
use mymfa_core::texts::{self, Locale};
use mymfa_core::vault::{self, Dek, VaultRecord};
use mymfa_core::DataMap;
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;
use std::time::{Duration, Instant};

/* ───── Préférences (prefs.json, hors coffre — comme localStorage côté web) ───── */

#[derive(Serialize, Deserialize, Clone)]
#[serde(default)]
pub struct Prefs {
    pub locale: String,     // "fr" | "en"
    pub theme: i32,         // 0 auto, 1 clair, 2 sombre
    pub hide_codes: bool,
    pub auto_lock_min: i32, // 0 = jamais ; web : [1, 5, 15, 60, 0], défaut 5
}

impl Default for Prefs {
    fn default() -> Self {
        Self { locale: "fr".into(), theme: 0, hide_codes: false, auto_lock_min: 5 }
    }
}

/* ───── Aides de présentation (portées de web/js/app.js) ───── */

/// « 123456 » → « 123 456 », « 12345678 » → « 1234 5678 ».
pub fn format_code(code: &str) -> String {
    let half = code.len() / 2;
    format!("{} {}", &code[..half], &code[half..])
}

/// Masque « ••• ••• » de la longueur du code.
fn mask_code(digits: u32) -> String {
    let half = (digits / 2) as usize;
    let rest = digits as usize - half;
    format!("{} {}", "•".repeat(half), "•".repeat(rest))
}

/// Mot de passe masqué du détail (web : `'•'.repeat(12)`, longueur fixe).
fn mask_password() -> String {
    "•".repeat(12)
}

/// Date au format moyen de la locale (web : `Intl.DateTimeFormat(dateStyle: 'medium')`).
fn format_date(iso: &str, locale: Locale) -> String {
    // ISO : YYYY-MM-DDT… — le préfixe suffit.
    if iso.len() < 10 {
        return String::new();
    }
    let (year, month, day) = (&iso[0..4], &iso[5..7], &iso[8..10]);
    const FR_MONTHS: [&str; 12] = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."];
    const EN_MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let index = month.parse::<usize>().unwrap_or(1).saturating_sub(1).min(11);
    match locale {
        Locale::Fr => format!("{day} {} {year}", FR_MONTHS[index]),
        Locale::En => format!("{} {day}, {year}", EN_MONTHS[index]),
    }
}

/// Initiales du service (port exact de `initials` de credentials.js) :
/// « GitHub » → GH, « notion.so » → NO, « Google Cloud » → GC.
fn initials(name: &str) -> String {
    let text = name.trim();
    // Sans espace : la partie avant le premier point (« notion.so » → « notion »).
    let base = if text.chars().any(|c| c.is_whitespace()) { text } else { text.split('.').next().unwrap_or(text) };
    let words: Vec<&str> = base.split(|c: char| c.is_whitespace() || c == '_' || c == '@' || c == '-')
        .filter(|w| !w.is_empty())
        .collect();
    let up = |s: &str| s.to_uppercase();
    if words.len() > 1 {
        return format!("{}{}", up(&words[0][..1]), up(&words[1][..1]));
    }
    let word = words.first().copied().unwrap_or("?");
    let inner = word[1..].chars().find(|c| c.is_uppercase());
    let second = inner.map(|c| c.to_string()).unwrap_or_else(|| word[1..].chars().take(1).collect());
    format!("{}{}", up(&word[..1]), up(&second))
}

/// Couleur stable par service (brandColor du web : hsl(h, 62 %, 36 %)).
fn brand_color(name: &str) -> slint::Color {
    let mut hash: u32 = 0;
    for unit in name.to_lowercase().encode_utf16() {
        hash = hash.wrapping_mul(31).wrapping_add(u32::from(unit));
    }
    let hue = (hash % 360) as f32;
    // hsl → rgb (formule standard, s ∈ [0,1], l ∈ [0,1])
    let (s, l) = (0.62f32, 0.36f32);
    let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
    let x = c * (1.0 - ((hue / 60.0) % 2.0 - 1.0).abs());
    let m = l - c / 2.0;
    let (r, g, b) = match hue as u32 {
        0..=59 => (c, x, 0.0),
        60..=119 => (x, c, 0.0),
        120..=179 => (0.0, c, x),
        180..=239 => (0.0, x, c),
        240..=299 => (x, 0.0, c),
        _ => (c, 0.0, x),
    };
    slint::Color::from_rgb_u8(
        ((r + m) * 255.0).round() as u8,
        ((g + m) * 255.0).round() as u8,
        ((b + m) * 255.0).round() as u8,
    )
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// ISO 8601 → millisecondes Unix (pour « Récemment utilisés »), None si illisible.
fn iso_ms(iso: &str) -> Option<u64> {
    let secs = iso.get(0..19)?;
    // Format web : YYYY-MM-DDTHH:MM:SS.sssZ — comparaison lexicale suffisante
    // pour « est plus récent que » ; ici il faut un âge : parsing minimal.
    let year: i64 = secs.get(0..4)?.parse().ok()?;
    let month: i64 = secs.get(5..7)?.parse().ok()?;
    let day: i64 = secs.get(8..10)?.parse().ok()?;
    let hour: i64 = secs.get(11..13)?.parse().ok()?;
    let minute: i64 = secs.get(14..16)?.parse().ok()?;
    let second: i64 = secs.get(17..19)?.parse().ok()?;
    // Jours civils → secondes (epoch) : suffisant, pas de fuseau (ISO = UTC).
    let days = days_from_civil(year, month, day);
    Some(((days * 86_400 + hour * 3600 + minute * 60 + second) * 1000) as u64)
}

/// Date civile → jours depuis l'époque (algorithme de Howard Hinnant, inverse de lib.rs).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/* ───── État ───── */

struct Inner {
    writer: std::sync::mpsc::Sender<(String, String)>,
    prefs: Prefs,
    record: Option<VaultRecord>, // coffre sur disque (texte du fichier)
    dek: Option<Dek>,            // présent = déverrouillé
    store: Store,
    revealed: HashSet<String>,   // codes révélés (masquage)
    revealed_pw: HashSet<String>, // mots de passe révélés (détail Mots de passe)
    accounts: Vec<Account>,      // cache pour les actions de carte
    query: String,               // filtres de la vue Codes
    filter_mode: i32,            // 0 tous, 1 favoris, >=2 tag
    filter_tag: String,
    cred_query: String,          // filtres de la vue Mots de passe
    cred_filter: i32,            // 0 tout, 1 logins, 2 passkeys
    cred_selected: Option<String>,
    failures: u32,
    wait_until: Option<Instant>, // anti force brute (web/js/lock.js)
    last_activity: Instant,
}

impl Inner {
    fn locked(&self) -> bool {
        self.dek.is_none()
    }

    /// Rechiffre et écrit le coffre entier (comme Lock.persist côté web).
    fn persist(&mut self) -> Result<(), mymfa_core::AppError> {
        let Some(dek) = self.dek.clone() else { return Ok(()) };
        let Some(record) = self.record.as_mut() else { return Ok(()) };
        record.data = vault::encrypt_data(&dek, &self.store.data)?;
        let content = serde_json::to_string(&*record).unwrap_or_default();
        let _ = self.writer.send((storage::VAULT_FILE.to_string(), content));
        Ok(())
    }

    fn save_prefs(&self) {
        if let Ok(text) = serde_json::to_string(&self.prefs) {
            let _ = self.writer.send((storage::PREFS_FILE.to_string(), text));
        }
    }
}

pub struct Backend(#[allow(dead_code)] Rc<RefCell<Inner>>);

impl Backend {
    pub fn start(ui: MainWindow, app: crate::AppHandle) {
        let dir = storage::data_dir(&app);
        let prefs: Prefs = storage::read_text(&dir, storage::PREFS_FILE)
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default();
        let record = storage::read_text(&dir, storage::VAULT_FILE)
            .and_then(|text| vault::parse(&text));
        let lock_mode = if record.is_some() { 1 } else { 0 };

        // Toutes les écritures passent par ce thread, créé au démarrage (le
        // contexte d'exécution des callbacks Slint peut être plus restreint).
        let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
        let dir_clone = dir.clone();
        std::thread::spawn(move || {
            for (name, content) in rx {
                storage::write_text(&dir_clone, &name, &content);
            }
        });

        let backend = Rc::new(RefCell::new(Inner {
            writer: tx,
            prefs: prefs.clone(),
            record,
            dek: None,
            store: Store::new(),
            revealed: HashSet::new(),
            revealed_pw: HashSet::new(),
            accounts: Vec::new(),
            query: String::new(),
            filter_mode: 0,
            filter_tag: String::new(),
            cred_query: String::new(),
            cred_filter: 0,
            cred_selected: None,
            failures: 0,
            wait_until: None,
            last_activity: Instant::now(),
        }));

        Self::apply_prefs(&ui, &prefs);
        ui.set_lock_mode(lock_mode);
        Self::refresh(&ui, &backend.borrow());
        Self::wire(&ui, &backend);
        Self::start_ticker(ui.clone_strong(), backend.clone());
    }

    fn locale(prefs: &Prefs) -> Locale {
        Locale::parse(&prefs.locale).unwrap_or(Locale::Fr)
    }

    fn apply_prefs(ui: &MainWindow, prefs: &Prefs) {
        ui.global::<crate::I18n>().set_locale(prefs.locale.clone().into());
        ui.set_theme(prefs.theme);
        ui.set_hide_codes(prefs.hide_codes);
        ui.set_auto_lock_min(prefs.auto_lock_min);
        // Auto suit le réglage de l'appareil ; sans pont natif, auto = sombre (v1).
        ui.global::<crate::Theme>().set_light(prefs.theme == 1);
    }

    /// Traduit une erreur du cœur : « error.<code> » + paramètres.
    fn error_text(inner: &Inner, error: &mymfa_core::AppError) -> SharedString {
        let locale = Self::locale(&inner.prefs);
        let params: Vec<(&str, &str)> =
            error.params.iter().map(|(name, value)| (*name, value.as_str())).collect();
        texts::tf(locale, &format!("error.{}", error.code), &params).into()
    }

    fn lock(inner: &mut Inner, ui: &MainWindow) {
        inner.dek = None;
        inner.store = Store::new();
        inner.accounts.clear();
        inner.revealed.clear();
        inner.revealed_pw.clear();
        inner.cred_selected = None;
        inner.failures = 0;
        inner.wait_until = None;
        ui.set_lock_mode(if inner.record.is_some() { 1 } else { 0 });
        ui.set_accounts(ModelRc::new(VecModel::<AccountRow>::from(Vec::new())));
        ui.set_tags(ModelRc::new(VecModel::<SharedString>::from(Vec::new())));
        ui.set_cred_entries(ModelRc::new(VecModel::<CredentialRow>::from(Vec::new())));
        ui.set_cred_detail_open(false);
        ui.set_cred_codes(ModelRc::new(VecModel::<CredCodeRow>::from(Vec::new())));
        ui.set_cred_passkeys(ModelRc::new(VecModel::<CredPasskeyRow>::from(Vec::new())));
    }

    /// Une ligne passe-t-elle le filtre de la vue Codes ?
    fn matches(inner: &Inner, account: &Account) -> bool {
        if inner.filter_mode == 1 && !account.favorite {
            return false;
        }
        if inner.filter_mode >= 2 && account.tag != inner.filter_tag {
            return false;
        }
        if inner.query.is_empty() {
            return true;
        }
        let haystack = format!("{} {} {}", account.issuer, account.account, account.tag).to_lowercase();
        haystack.contains(&inner.query.to_lowercase())
    }

    /// Reconstruit les lignes de la vue Codes (filtrées) et les tags.
    fn refresh(ui: &MainWindow, inner: &Inner) {
        let mut rows: Vec<AccountRow> = Vec::new();
        let now = now_ms();
        for account in inner.accounts.iter().filter(|a| Self::matches(inner, a)) {
            let name = if !account.issuer.is_empty() { &account.issuer } else { &account.account };
            let masked = inner.prefs.hide_codes && !inner.revealed.contains(&account.id);
            let algorithm = Algorithm::parse(&account.algorithm).unwrap_or(Algorithm::Sha1);
            let hotp = account.type_ == "hotp";
            let counter = account.counter;
            let (code, remaining, progress) = if hotp {
                let code = otp::hotp(&account.secret, counter as u64, account.digits, algorithm)
                    .unwrap_or_else(|_| "—————".into());
                (code, 0, 1.0)
            } else {
                let code = otp::totp(&account.secret, account.period, account.digits, algorithm, now)
                    .unwrap_or_else(|_| "—————".into());
                let remaining = otp::remaining_seconds(account.period, now);
                (code, remaining, remaining as f32 / account.period as f32)
            };
            rows.push(AccountRow {
                id: account.id.clone().into(),
                issuer: name.clone().into(),
                account: account.account.clone().into(),
                tag: account.tag.clone().into(),
                code: if masked { mask_code(account.digits).into() } else { format_code(&code).into() },
                masked,
                remaining: remaining as i32,
                progress,
                favorite: account.favorite,
                hotp,
                tile_color: brand_color(name),
                initials: initials(if name.is_empty() { "?" } else { name }).into(),
            });
        }
        let tags = inner.store.tags().into_iter().map(SharedString::from).collect::<Vec<_>>();
        ui.set_accounts(ModelRc::new(VecModel::from(rows)));
        ui.set_tags(ModelRc::new(VecModel::from(tags)));
        ui.set_has_accounts(!inner.accounts.is_empty());
    }

    fn reload_accounts(inner: &mut Inner) {
        inner.accounts = if inner.locked() { Vec::new() } else { inner.store.list() };
    }

    /* ───── Vue Mots de passe (miroir de web/js/credentials.js) ───── */

    /// Nom d'un site : titre donné, sinon service du compte 2FA rattaché,
    /// sinon domaine registrable (web : `siteName`).
    fn site_name(host: &str, title: &str, accounts: &[Account]) -> String {
        if !title.is_empty() {
            return title.to_string();
        }
        accounts.iter()
            .find(|a| !a.issuer.is_empty() && store::account_matches_host(&a.issuer, host))
            .map(|a| a.issuer.clone())
            .unwrap_or_else(|| store::site_of(host))
    }

    /// Ce qui dépend d'un site : comptes 2FA (TOTP) et passkeys du même
    /// domaine registrable (web : `related`).
    fn related_accounts(accounts: &[Account], host: &str) -> Vec<Account> {
        accounts.iter()
            .filter(|a| a.type_ != "hotp" && store::account_matches_host(&a.issuer, host))
            .cloned()
            .collect()
    }

    fn related_passkeys(passkeys: &[SitePasskey], host: &str) -> Vec<SitePasskey> {
        let site = store::site_of(host);
        passkeys.iter().filter(|p| store::site_of(&p.rpId) == site).cloned().collect()
    }

    /// Lignes de la liste (web : `entries` + `visible` + sections).
    fn refresh_cred(ui: &MainWindow, inner: &Inner) {
        if inner.locked() {
            ui.set_cred_entries(ModelRc::new(VecModel::<CredentialRow>::from(Vec::new())));
            ui.set_cred_count_all(0);
            ui.set_cred_count_logins(0);
            ui.set_cred_count_passkeys(0);
            ui.set_cred_has_entries(false);
            ui.set_cred_detail_open(false);
            return;
        }
        let locale = Self::locale(&inner.prefs);
        let accounts = inner.store.list();
        let logins = inner.store.logins();
        let passkeys = inner.store.site_passkeys();

        struct Entry {
            kind: i32,
            id: String,
            name: String,
            sub: String,
            host: String,
            note: String,
            chip_2fa: bool,
            chip_passkey: bool,
            standalone: bool,
            used_at: Option<String>,
        }
        let mut entries: Vec<Entry> = Vec::new();
        let login_sites: Vec<String> = logins.iter()
            .map(|l| store::site_of(&store::host_of(&l.origin)))
            .collect();
        for login in &logins {
            let host = store::host_of(&login.origin);
            let related = Self::related_accounts(&accounts, &host);
            let site_passkeys = Self::related_passkeys(&passkeys, &host);
            let name = Self::site_name(&host, &login.title, &accounts);
            entries.push(Entry {
                kind: 0,
                id: login.id.clone(),
                name: name.clone(),
                sub: if login.username.is_empty() { texts::t(locale, "credentials.noUsername") } else { login.username.clone() },
                host,
                note: login.note.clone(),
                chip_2fa: !related.is_empty(),
                chip_passkey: !site_passkeys.is_empty(),
                standalone: true,
                used_at: login.usedAt.clone(),
            });
        }
        for passkey in &passkeys {
            let related = Self::related_accounts(&accounts, &passkey.rpId);
            let name = Self::site_name(&passkey.rpId, if passkey.rpName != passkey.rpId { &passkey.rpName } else { "" }, &accounts);
            entries.push(Entry {
                kind: 1,
                id: passkey.id.clone(),
                name: name.clone(),
                sub: if !passkey.userDisplayName.is_empty() { passkey.userDisplayName.clone() }
                    else if !passkey.userName.is_empty() { passkey.userName.clone() }
                    else { passkey.rpId.clone() },
                host: passkey.rpId.clone(),
                note: String::new(),
                chip_2fa: !related.is_empty(),
                chip_passkey: true,
                standalone: !login_sites.contains(&store::site_of(&passkey.rpId)),
                used_at: passkey.usedAt.clone(),
            });
        }

        // Comptes des onglets (avant recherche).
        ui.set_cred_count_all((entries.len()) as i32);
        ui.set_cred_count_logins(logins.len() as i32);
        ui.set_cred_count_passkeys(passkeys.len() as i32);

        // Onglet actif + recherche (web : `visible`).
        let query = inner.cred_query.trim().to_lowercase();
        let mut list: Vec<&Entry> = entries.iter()
            .filter(|e| match inner.cred_filter {
                1 => e.kind == 0,
                2 => e.kind == 1,
                _ => e.kind == 0 || e.standalone, // Tout : passkeys seules d'un site sans mot de passe
            })
            .filter(|e| query.is_empty() || [e.name.as_str(), e.host.as_str(), e.sub.as_str(), e.note.as_str()]
                .iter().any(|v| v.to_lowercase().contains(&query)))
            .collect();
        list.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

        // « Récemment utilisés » : logins touchés dans les 30 derniers jours,
        // seulement sur l'onglet Tout sans recherche (web : RECENT_MAX/DAYS).
        const RECENT_MAX: usize = 3;
        const RECENT_DAYS: i64 = 30;
        let since_ms = now_ms().saturating_sub(RECENT_DAYS as u64 * 86_400_000);
        let recent_ids: Vec<String> = if inner.cred_filter == 0 && query.is_empty() {
            let mut recent: Vec<&Entry> = entries.iter()
                .filter(|e| e.kind == 0 && e.used_at.as_deref()
                    .and_then(|iso| iso_ms(iso))
                    .map(|ms| ms > since_ms)
                    .unwrap_or(false))
                .collect();
            recent.sort_by(|a, b| b.used_at.cmp(&a.used_at));
            recent.into_iter().take(RECENT_MAX).map(|e| e.id.clone()).collect()
        } else {
            Vec::new()
        };

        let mut rows: Vec<CredentialRow> = Vec::new();
        let mut last_section = String::new();
        for entry in list.iter() {
            let section = if recent_ids.contains(&entry.id) {
                "recent".to_string()
            } else {
                match inner.cred_filter {
                    1 => "logins".to_string(),
                    2 => "passkeys".to_string(),
                    _ => "all".to_string(),
                }
            };
            if section != last_section {
                // Ligne de titre de section (kind -1), comme les `<h2>` du web.
                let label = match section.as_str() {
                    "recent" => texts::t(locale, "credentials.recent"),
                    _ => if !recent_ids.is_empty() { texts::t(locale, "credentials.allSites") }
                        else { texts::t(locale, &format!("credentials.section.{section}")) },
                };
                rows.push(CredentialRow {
                    id: "".into(),
                    kind: -1,
                    name: label.into(),
                    sub: "".into(),
                    host: "".into(),
                    chip_2fa: false,
                    chip_passkey: false,
                    tile_color: brand_color(&entry.name),
                    initials: "".into(),
                });
                last_section = section;
            }
            rows.push(CredentialRow {
                id: entry.id.clone().into(),
                kind: entry.kind,
                name: entry.name.clone().into(),
                sub: entry.sub.clone().into(),
                host: entry.host.clone().into(),
                chip_2fa: entry.chip_2fa,
                chip_passkey: entry.chip_passkey,
                tile_color: brand_color(&entry.name),
                initials: initials(if entry.name.is_empty() { "?" } else { &entry.name }).into(),
            });
        }
        ui.set_cred_entries(ModelRc::new(VecModel::from(rows)));
        ui.set_cred_has_entries(!entries.is_empty());
    }

    /// Détail du site choisi (web : `renderDetail`) : mot de passe, code 2FA
    /// lié, passkeys du site. Les codes sont recalculés à chaque tic.
    fn refresh_cred_detail(ui: &MainWindow, inner: &Inner, with_codes: bool) {
        let Some(selected) = inner.cred_selected.clone() else {
            ui.set_cred_detail_open(false);
            return;
        };
        let locale = Self::locale(&inner.prefs);
        let accounts = inner.store.list();
        let logins = inner.store.logins();
        let passkeys = inner.store.site_passkeys();
        let login = logins.iter().find(|l| l.id == selected.as_str());
        let passkey = passkeys.iter().find(|p| p.id == selected.as_str());
        let Some((name, host, origin, is_login)) = (match (login, passkey) {
            (Some(login), _) => {
                let host = store::host_of(&login.origin);
                Some((Self::site_name(&host, &login.title, &accounts), host, login.origin.clone(), true))
            }
            (_, Some(passkey)) => {
                let name = Self::site_name(&passkey.rpId, if passkey.rpName != passkey.rpId { &passkey.rpName } else { "" }, &accounts);
                Some((name, passkey.rpId.clone(), format!("https://{}", passkey.rpId), false))
            }
            _ => None,
        }) else {
            // Élément choisi introuvable (supprimé, coffre changé…) : retour à la liste.
            ui.set_cred_detail_open(false);
            return;
        };
        let meta = match login {
            Some(login) => if login.source == "extension" {
                texts::t(locale, "credentials.metaExtension")
            } else {
                texts::tf(locale, "credentials.meta", &[("date", &format_date(&login.updatedAt, locale))])
            },
            None => texts::t(locale, "credentials.passkeyOnly"),
        };
        ui.set_cred_detail_open(true);
        ui.set_cred_detail(CredentialDetail {
            id: selected.into(),
            name: name.into(),
            host: host.clone().into(),
            origin: origin.into(),
            is_login,
            username: login.map(|l| {
                if l.username.is_empty() { texts::t(locale, "credentials.noUsername") } else { l.username.clone() }
            }).unwrap_or_default().into(),
            password: login.map(|l| if inner.revealed_pw.contains(&l.id) { l.password.clone() } else { mask_password() })
                .unwrap_or_default().into(),
            revealed: login.map(|l| inner.revealed_pw.contains(&l.id)).unwrap_or(false),
            meta: meta.into(),
        });
        if !with_codes {
            return;
        }
        // Code 2FA du site, en direct (même compte que l'onglet Codes).
        let mut code_rows: Vec<CredCodeRow> = Vec::new();
        let now = now_ms();
        for account in Self::related_accounts(&accounts, &host) {
            let algorithm = Algorithm::parse(&account.algorithm).unwrap_or(Algorithm::Sha1);
            let code = otp::totp(&account.secret, account.period, account.digits, algorithm, now)
                .unwrap_or_else(|_| "—————".into());
            let remaining = otp::remaining_seconds(account.period, now);
            let label = [&account.issuer, &account.account].iter()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>().join(" · ");
            code_rows.push(CredCodeRow {
                id: account.id.clone().into(),
                label: label.into(),
                code: format_code(&code).into(),
                remaining: remaining as i32,
                progress: remaining as f32 / account.period as f32,
            });
        }
        ui.set_cred_codes(ModelRc::new(VecModel::from(code_rows)));
        // Passkeys du site ; celle choisie (entrée passkey) en premier.
        let mut site_passkeys = Self::related_passkeys(&passkeys, &host);
        if let Some(current) = passkey {
            site_passkeys.sort_by_key(|p| if p.id == current.id { 0 } else { 1 });
        }
        let passkey_rows: Vec<CredPasskeyRow> = site_passkeys.iter().map(|p| {
            let label = [p.userDisplayName.as_str(), p.userName.as_str()].iter()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect::<Vec<_>>().join(" · ");
            CredPasskeyRow {
                id: p.id.clone().into(),
                label: if label.is_empty() { p.rpId.clone().into() } else { label.into() },
                created: texts::tf(locale, "credentials.passkeyCreated",
                    &[("date", &format_date(&p.createdAt, locale)), ("site", &p.rpId)]).into(),
            }
        }).collect();
        ui.set_cred_passkeys(ModelRc::new(VecModel::from(passkey_rows)));
    }

    /* ───── Ticker : codes, verrouillage auto, compte à rebours ───── */

    fn start_ticker(ui: MainWindow, backend: Rc<RefCell<Inner>>) {
        let timer = slint::Timer::default();
        timer.start(slint::TimerMode::Repeated, Duration::from_secs(1), move || {
            let mut inner = backend.borrow_mut();
            // Anti force brute : compte à rebours affiché sur l'écran de déverrouillage.
            let waiting = inner.wait_until.map(|until| until.saturating_duration_since(Instant::now()));
            ui.set_unlock_wait(waiting.map(|d| d.as_secs() as i32).filter(|s| *s > 0).unwrap_or(0));
            // Verrouillage automatique (activité = actions utilisateur).
            if !inner.locked() && inner.prefs.auto_lock_min > 0 {
                let idle = inner.last_activity.elapsed();
                // auto_lock_min est en minutes (web : [1, 5, 15, 60, 0]).
                if idle > Duration::from_secs(inner.prefs.auto_lock_min as u64 * 60) {
                    Self::lock(&mut inner, &ui);
                    return;
                }
            }
            if inner.locked() {
                return;
            }
            Self::reload_accounts(&mut inner);
            Self::refresh(&ui, &inner);
            // Codes 2FA du détail Mots de passe, en direct (seconde par seconde).
            if ui.get_cred_detail_open() {
                Self::refresh_cred_detail(&ui, &inner, true);
            }
        });
        // Le timer doit survivre : il vit dans la closure du backend gardée par l'UI.
        std::mem::forget(timer);
    }

    fn bump_activity(inner: &mut Inner) {
        inner.last_activity = Instant::now();
    }

    /* ───── Câblage des callbacks ───── */

    fn wire(ui: &MainWindow, backend: &Rc<RefCell<Inner>>) {
        // i18n : les textes du cœur.
        {
            ui.global::<crate::I18n>().on_t_impl(move |key, locale| {
                let locale = Locale::parse(&locale).unwrap_or(Locale::Fr);
                texts::t(locale, &key).into()
            });
            ui.global::<crate::I18n>().on_tn_impl(move |key, n, locale| {
                let locale = Locale::parse(&locale).unwrap_or(Locale::Fr);
                texts::tn(locale, &key, n as i64).into()
            });
            ui.global::<crate::I18n>().on_t1_impl(move |key, param, locale| {
                let locale = Locale::parse(&locale).unwrap_or(Locale::Fr);
                // Un seul paramètre : substitue {version} et {name}.
                texts::tf(locale, &key, &[("version", param.as_str()), ("name", param.as_str()), ("param", param.as_str())]).into()
            });
        }

        let weak = ui.as_weak();
        let b1 = Rc::clone(&backend);
        ui.on_create_vault(move |password, confirm| {
            let mut inner = b1.borrow_mut();
            Self::bump_activity(&mut inner);
            if password != confirm {
                return "passwordMismatch".into();
            }
            let empty = DataMap::new();
            match vault::create(&password, &empty, vault::PBKDF2_ITERATIONS) {
                Err(error) => Self::error_text(&inner, &error),
                Ok((record, dek)) => {
                    inner.record = Some(record);
                    inner.dek = Some(dek);
                    inner.store = Store::new();
                    let persist_result = inner.persist();
                    Self::reload_accounts(&mut inner);
                    let ui = weak.unwrap();
                    if let Err(error) = persist_result {
                        ui.set_toast(Self::error_text(&inner, &error));
                    }
                    Self::refresh(&ui, &inner);
                    Self::refresh_cred(&ui, &inner);
                    ui.set_lock_mode(2);
                    "".into()
                }
            }
        });

        let weak = ui.as_weak();
        let b2 = Rc::clone(&backend);
        ui.on_unlock(move |password| {
            let mut inner = b2.borrow_mut();
            Self::bump_activity(&mut inner);
            if let Some(until) = inner.wait_until {
                if Instant::now() < until {
                    return "wait".into();
                }
            }
            let Some(record) = inner.record.clone() else { return "locked".into() };
            match vault::unlock_with_password(&record, &password) {
                Ok(dek) => {
                    let data = vault::decrypt_data(&dek, &record.data).unwrap_or_default();
                    inner.dek = Some(dek);
                    inner.failures = 0;
                    inner.wait_until = None;
                    inner.store = Store::from_map(data);
                    let _ = inner.persist(); // re-chiffre avec un IV frais, comme le web
                    Self::reload_accounts(&mut inner);
                    let ui = weak.unwrap();
                    Self::refresh(&ui, &inner);
                    Self::refresh_cred(&ui, &inner);
                    ui.set_lock_mode(2);
                    "".into()
                }
                Err(_) => {
                    inner.failures += 1;
                    if inner.failures >= 3 {
                        let seconds = 30u64.min(1u64 << (inner.failures - 3).min(5));
                        inner.wait_until = Some(Instant::now() + Duration::from_secs(seconds));
                    }
                    "wrongPassword".into()
                }
            }
        });

        let weak = ui.as_weak();
        let b3 = Rc::clone(&backend);
        ui.on_lock_now(move || {
            let mut inner = b3.borrow_mut();
            Self::lock(&mut inner, &weak.unwrap());
        });

        ui.on_password_strength(move |password| {
            vault::password_strength(&password).level as i32
        });

        let weak = ui.as_weak();
        let b5 = Rc::clone(&backend);
        ui.on_add_account(move |input| {
            let mut inner = b5.borrow_mut();
            Self::bump_activity(&mut inner);
            match Self::resolve_new_account(&input) {
                // Code d'erreur brut : l'UI préfixe avec « error. » (comme
                // create-vault/unlock) — un texte déjà traduit s'afficherait
                // « error.<traduction> ».
                Err(error) => error.code.into(),
                Ok(new) => {
                    if inner.store.find_duplicate(&new.secret, &new.issuer, &new.account).is_some() {
                        return "duplicate".into();
                    }
                    inner.store.add(&new, Some("key"));
                    if let Err(error) = inner.persist() {
                        return Self::error_text(&inner, &error);
                    }
                    Self::reload_accounts(&mut inner);
                    let ui = weak.unwrap();
                    Self::refresh(&ui, &inner);
                    Self::refresh_cred(&ui, &inner); // puces 2FA de la liste Mots de passe
                    "".into()
                }
            }
        });

        let b6 = Rc::clone(&backend);
        ui.on_preview(move |input| {
            let inner = b6.borrow();
            let locale = Self::locale(&inner.prefs);
            let name = if input.issuer.is_empty() { input.account.to_string() } else { input.issuer.to_string() };
            let name = name.as_str();
            let resolved = Self::resolve_preview(&input);
            let (code, summary) = match resolved {
                Err(_) => (String::new(), String::new()),
                Ok((secret, hotp, algorithm, digits, period, counter)) => {
                    let code = if hotp {
                        otp::hotp(&secret, counter as u64, digits, algorithm).unwrap_or_default()
                    } else {
                        otp::totp(&secret, period, digits, algorithm, now_ms()).unwrap_or_default()
                    };
                    let summary = if hotp {
                        texts::tf(locale, "new.summaryHotp", &[("algorithm", algorithm.name()), ("digits", &digits.to_string()), ("counter", &counter.to_string())])
                    } else {
                        texts::tf(locale, "new.summaryTotp", &[("algorithm", algorithm.name()), ("digits", &digits.to_string()), ("period", &period.to_string())])
                    };
                    (code, summary)
                }
            };
            PreviewResult {
                code: format_code(&code).into(),
                summary: summary.into(),
                initials: initials(if name.is_empty() { "?" } else { name }).into(),
                tile_color: brand_color(name),
            }
        });

        let weak = ui.as_weak();
        let b7 = Rc::clone(&backend);
        ui.on_card_tapped(move |id| {
            let mut inner = b7.borrow_mut();
            Self::bump_activity(&mut inner);
            let id = id.to_string();
            // Masqué : la première pression révèle (comme le web), la suivante copie.
            if inner.prefs.hide_codes && !inner.revealed.contains(&id) {
                inner.revealed.insert(id.clone());
                Self::reload_accounts(&mut inner);
                let ui = weak.unwrap();
                Self::refresh(&ui, &inner);
                return;
            }
            let Some(account) = inner.accounts.iter().find(|a| a.id == id).cloned() else { return };
            let code = Self::current_code(&account);
            if code.is_empty() {
                return;
            }
            let ui = weak.unwrap();
            Self::copy_text(&ui, &code);
            inner.store.touch_account(&id);
            let _ = inner.persist();
            inner.revealed.remove(&id);
            Self::reload_accounts(&mut inner);
            Self::refresh(&ui, &inner);
            let locale = Self::locale(&inner.prefs);
            let name = if account.issuer.is_empty() { &account.account } else { &account.issuer };
            ui.set_toast(texts::tf(locale, "toast.copied", &[("name", name)]).into());
        });

        let weak = ui.as_weak();
        let b8 = Rc::clone(&backend);
        ui.on_next_code(move |id| {
            let mut inner = b8.borrow_mut();
            Self::bump_activity(&mut inner);
            let id = id.to_string();
            let Some(account) = inner.accounts.iter().find(|a| a.id == id).cloned() else { return };
            let next = account.counter.saturating_add(1);
            let _ = inner.store.update(&id, &mymfa_core::store::AccountPatch {
                counter: Some(next),
                ..Default::default()
            });
            let _ = inner.persist();
            Self::reload_accounts(&mut inner);
            let ui = weak.unwrap();
            Self::refresh(&ui, &inner);
        });

        let weak = ui.as_weak();
        let b9 = Rc::clone(&backend);
        ui.on_toggle_favorite(move |id| {
            let mut inner = b9.borrow_mut();
            Self::bump_activity(&mut inner);
            let id = id.to_string();
            let Some(account) = inner.accounts.iter().find(|a| a.id == id).cloned() else { return };
            let _ = inner.store.update(&id, &mymfa_core::store::AccountPatch {
                favorite: Some(!account.favorite),
                ..Default::default()
            });
            let _ = inner.persist();
            Self::reload_accounts(&mut inner);
            let ui = weak.unwrap();
            Self::refresh(&ui, &inner);
        });

        let b10 = Rc::clone(&backend);
        ui.on_change_password(move |current, next, confirm| {
            let mut inner = b10.borrow_mut();
            Self::bump_activity(&mut inner);
            if next != confirm {
                return Self::error_text(&inner, &mymfa_core::AppError::new("passwordMismatch"));
            }
            let Some(record) = inner.record.clone() else { return "locked".into(); };
            let Some(dek) = inner.dek.clone() else { return "locked".into(); };
            if vault::unlock_with_password(&record, &current).is_err() {
                return Self::error_text(&inner, &mymfa_core::AppError::new("wrongPassword"));
            }
            match vault::change_password(&record, &dek, &next, vault::PBKDF2_ITERATIONS) {
                Err(error) => Self::error_text(&inner, &error),
                Ok(new_record) => {
                    inner.record = Some(new_record);
                    let _ = inner.persist();
                    "".into()
                }
            }
        });

        let weak = ui.as_weak();
        let b11 = Rc::clone(&backend);
        ui.on_set_theme(move |theme| {
            let mut inner = b11.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.prefs.theme = theme;
            inner.save_prefs();
            let ui = weak.unwrap();
            Self::apply_prefs(&ui, &inner.prefs);
        });

        let weak = ui.as_weak();
        let b12 = Rc::clone(&backend);
        ui.on_set_locale(move |locale| {
            let mut inner = b12.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.prefs.locale = locale.to_string();
            inner.save_prefs();
            let ui = weak.unwrap();
            Self::apply_prefs(&ui, &inner.prefs);
            Self::refresh(&ui, &inner);
            Self::refresh_cred(&ui, &inner);
            Self::refresh_cred_detail(&ui, &inner, false); // métadonnées traduites
        });

        let b13 = Rc::clone(&backend);
        ui.on_set_hide_codes(move |hide| {
            let mut inner = b13.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.prefs.hide_codes = hide;
            inner.save_prefs();
            inner.revealed.clear();
        });

        let weak = ui.as_weak();
        let b14 = Rc::clone(&backend);
        ui.on_apply_filter(move |query, mode, tag| {
            let mut inner = b14.borrow_mut();
            inner.query = query.to_string();
            inner.filter_mode = mode;
            inner.filter_tag = tag.to_string();
            Self::reload_accounts(&mut inner);
            Self::refresh(&weak.unwrap(), &inner);
        });

        let weak = ui.as_weak();
        let b15 = Rc::clone(&backend);
        ui.on_set_auto_lock(move |minutes| {
            let mut inner = b15.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.prefs.auto_lock_min = minutes;
            inner.save_prefs();
            let ui = weak.unwrap();
            Self::apply_prefs(&ui, &inner.prefs);
        });

        /* ── Vue Mots de passe ── */

        let weak = ui.as_weak();
        let b16 = Rc::clone(&backend);
        ui.on_cred_apply_filter(move |query, filter| {
            let mut inner = b16.borrow_mut();
            inner.cred_query = query.to_string();
            inner.cred_filter = filter;
            Self::refresh_cred(&weak.unwrap(), &inner);
        });

        let weak = ui.as_weak();
        let b17 = Rc::clone(&backend);
        ui.on_cred_select(move |id| {
            let mut inner = b17.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.cred_selected = Some(id.to_string());
            Self::refresh_cred_detail(&weak.unwrap(), &inner, true);
        });

        let weak = ui.as_weak();
        let b18 = Rc::clone(&backend);
        ui.on_cred_back(move || {
            let mut inner = b18.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.cred_selected = None;
            weak.unwrap().set_cred_detail_open(false);
        });

        let weak = ui.as_weak();
        let b19 = Rc::clone(&backend);
        ui.on_cred_toggle_reveal(move |id| {
            let mut inner = b19.borrow_mut();
            Self::bump_activity(&mut inner);
            let id = id.to_string();
            if !inner.store.logins().iter().any(|l| l.id == id) {
                return;
            }
            if inner.revealed_pw.contains(&id) {
                inner.revealed_pw.remove(&id);
            } else {
                inner.revealed_pw.insert(id);
            }
            Self::refresh_cred_detail(&weak.unwrap(), &inner, false);
        });

        let weak = ui.as_weak();
        let b20 = Rc::clone(&backend);
        ui.on_cred_copy_user(move |id| {
            let mut inner = b20.borrow_mut();
            Self::bump_activity(&mut inner);
            let locale = Self::locale(&inner.prefs);
            let Some(login) = inner.store.logins().into_iter().find(|l| l.id == id.to_string()) else { return };
            if login.username.is_empty() {
                return;
            }
            let ui = weak.unwrap();
            Self::copy_text(&ui, &login.username);
            ui.set_toast(texts::t(locale, "credentials.copiedUser").into());
        });

        let weak = ui.as_weak();
        let b21 = Rc::clone(&backend);
        ui.on_cred_copy_password(move |id| {
            let mut inner = b21.borrow_mut();
            Self::bump_activity(&mut inner);
            let locale = Self::locale(&inner.prefs);
            let Some(login) = inner.store.logins().into_iter().find(|l| l.id == id.to_string()) else { return };
            let ui = weak.unwrap();
            Self::copy_text(&ui, &login.password);
            // « Récemment utilisés » — comme le web (touchLogin).
            inner.store.touch_login(&login.id);
            let _ = inner.persist();
            Self::refresh_cred(&ui, &inner);
            ui.set_toast(texts::t(locale, "credentials.copiedPassword").into());
            // NB : le web vide le presse-papiers après 30 s — impossible sans
            // pont natif ; divergence v1 documentée.
        });

        let weak = ui.as_weak();
        let b22 = Rc::clone(&backend);
        ui.on_cred_copy_code(move |account_id| {
            let mut inner = b22.borrow_mut();
            Self::bump_activity(&mut inner);
            let locale = Self::locale(&inner.prefs);
            let Some(account) = inner.store.list().into_iter().find(|a| a.id == account_id.to_string()) else { return };
            let code = Self::current_code(&account);
            if code.is_empty() {
                return;
            }
            let ui = weak.unwrap();
            Self::copy_text(&ui, &code);
            inner.store.touch_account(&account.id);
            let _ = inner.persist();
            ui.set_toast(texts::t(locale, "credentials.copiedCode").into());
        });

        let weak = ui.as_weak();
        let b23 = Rc::clone(&backend);
        ui.on_cred_save_login(move |input| {
            let mut inner = b23.borrow_mut();
            Self::bump_activity(&mut inner);
            let result: Result<String, mymfa_core::AppError> = if input.id.is_empty() {
                inner.store.add_login(&store::NewLogin {
                    origin: input.url.to_string(),
                    username: input.username.to_string(),
                    password: input.password.to_string(),
                    title: input.title.to_string(),
                    ..store::NewLogin::default()
                }, Some("app")).map(|login| login.id)
            } else {
                inner.store.update_login(&input.id.to_string(), &store::LoginPatch {
                    origin: Some(input.url.to_string()),
                    username: Some(input.username.to_string()),
                    password: Some(input.password.to_string()),
                    title: Some(input.title.to_string()),
                    ..store::LoginPatch::default()
                }).map(|login| login.id)
            };
            match result {
                Err(error) => error.code.into(),
                Ok(id) => {
                    let _ = inner.persist();
                    inner.cred_selected = Some(id);
                    let ui = weak.unwrap();
                    Self::refresh_cred(&ui, &inner);
                    Self::refresh_cred_detail(&ui, &inner, true);
                    "".into()
                }
            }
        });

        let weak = ui.as_weak();
        let b24 = Rc::clone(&backend);
        ui.on_cred_remove_login(move |id| {
            let mut inner = b24.borrow_mut();
            Self::bump_activity(&mut inner);
            inner.store.remove_login(&id.to_string());
            let _ = inner.persist();
            inner.cred_selected = None;
            let ui = weak.unwrap();
            Self::refresh_cred(&ui, &inner);
            ui.set_cred_detail_open(false);
        });

        let weak = ui.as_weak();
        let b25 = Rc::clone(&backend);
        ui.on_cred_remove_passkey(move |id| {
            let mut inner = b25.borrow_mut();
            Self::bump_activity(&mut inner);
            let was_selected = inner.cred_selected.as_deref() == Some(id.as_str());
            inner.store.remove_passkey(&id.to_string());
            let _ = inner.persist();
            if was_selected {
                inner.cred_selected = None;
            }
            let ui = weak.unwrap();
            Self::refresh_cred(&ui, &inner);
            if was_selected {
                ui.set_cred_detail_open(false);
            } else {
                Self::refresh_cred_detail(&ui, &inner, true);
            }
        });

        ui.on_cred_generate(move |length, digits, symbols, words| {
            let options = GenOptions {
                length: length.max(1) as usize,
                digits,
                symbols,
                words,
            };
            passgen::generate_password(&options).into()
        });

        let b26 = Rc::clone(&backend);
        ui.on_cred_prefill(move |id| {
            let inner = b26.borrow();
            match inner.store.logins().into_iter().find(|l| l.id == id.to_string()) {
                Some(login) => CredLoginInput {
                    id: login.id.into(),
                    url: login.origin.into(),
                    username: login.username.into(),
                    password: login.password.into(),
                    title: login.title.into(),
                },
                None => CredLoginInput {
                    id: "".into(), url: "".into(), username: "".into(), password: "".into(), title: "".into(),
                },
            }
        });
    }

    fn current_code(account: &Account) -> String {
        let algorithm = Algorithm::parse(&account.algorithm).unwrap_or(Algorithm::Sha1);
        if account.type_ == "hotp" {
            otp::hotp(&account.secret, account.counter as u64, account.digits, algorithm).unwrap_or_default()
        } else {
            otp::totp(&account.secret, account.period, account.digits, algorithm, now_ms()).unwrap_or_default()
        }
    }

    /// Copie : par le TextInput interne de la fenêtre (voie officielle Slint,
    /// presse-papiers du backend — Android inclus). Le toast confirme toujours.
    fn copy_text(ui: &MainWindow, text: &str) {
        ui.invoke_copy_to_clipboard(text.into());
    }

    /// Champ « clé secrète ou URI » → paramètres validés (clé, algorithme, …).
    fn resolve_preview(input: &PreviewInput) -> Result<(String, bool, Algorithm, u32, u64, i64), mymfa_core::AppError> {
        let field = input.secret.trim();
        if field.len() >= 8 && field[..8].eq_ignore_ascii_case("otpauth:") {
            let auth = mymfa_core::otpauth::parse(field)?;
            let hotp = auth.type_ == mymfa_core::otpauth::OtpType::Hotp;
            return Ok((auth.secret, hotp, auth.algorithm, auth.digits, auth.period, auth.counter));
        }
        let secret = otp::normalize_secret(field);
        let algorithm = Algorithm::parse(&input.algorithm).ok_or_else(|| mymfa_core::AppError::new("unsupportedAlgorithm"))?;
        otp::base32_decode(&secret)?;
        Ok((secret, input.hotp, algorithm, input.digits as u32, input.period as u64, input.counter as i64))
    }

    fn resolve_new_account(
        input: &NewAccountInput,
    ) -> Result<mymfa_core::store::NewAccount, mymfa_core::AppError> {
        let field = input.secret_or_uri.trim();
        if field.len() >= 8 && field[..8].eq_ignore_ascii_case("otpauth:") {
            let auth = mymfa_core::otpauth::parse(field)?;
            return Ok(mymfa_core::store::NewAccount {
                type_: Some(auth.type_.as_str().into()),
                issuer: auth.issuer,
                account: auth.account,
                secret: auth.secret,
                algorithm: Some(auth.algorithm.name().into()),
                digits: Some(auth.digits),
                period: Some(auth.period),
                counter: Some(auth.counter),
                tag: input.tag.to_string(),
                description: input.description.to_string(),
                favorite: false,
            });
        }
        let secret = otp::normalize_secret(field);
        otp::base32_decode(&secret)?;
        Ok(mymfa_core::store::NewAccount {
            type_: Some(if input.hotp { "hotp".into() } else { "totp".into() }),
            issuer: input.issuer.to_string(),
            account: input.account.to_string(),
            secret,
            algorithm: Some(input.algorithm.to_string()),
            digits: Some(input.digits as u32),
            period: Some(input.period as u64),
            counter: Some(input.counter as i64),
            tag: input.tag.to_string(),
            description: input.description.to_string(),
            favorite: false,
        })
    }
}
