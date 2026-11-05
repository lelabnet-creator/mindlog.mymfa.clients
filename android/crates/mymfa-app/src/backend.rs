/*
 * Backend de l'app : état (coffre, comptes, préférences), persistance fichier,
 * ticker des codes, verrouillage automatique — miroir de web/js/{lock,app}.js
 * pour la part du socle (vues Codes, Nouveau compte, Réglages).
 */
use crate::storage;
use crate::{AccountRow, MainWindow, NewAccountInput, PreviewInput, PreviewResult};
use mymfa_core::otp::{self, Algorithm};
use mymfa_core::store::{Account, Store};
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

/// Initiales du service : « Google Cloud » → GC, « GitHub » → GH.
fn initials(name: &str) -> String {
    let words: Vec<&str> = name.trim().split(|c: char| c.is_whitespace() || c == '.' || c == '_' || c == '-')
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

/* ───── État ───── */

struct Inner {
    writer: std::sync::mpsc::Sender<(String, String)>,
    prefs: Prefs,
    record: Option<VaultRecord>, // coffre sur disque (texte du fichier)
    dek: Option<Dek>,            // présent = déverrouillé
    store: Store,
    revealed: HashSet<String>,   // codes révélés (masquage)
    accounts: Vec<Account>,      // cache pour les actions de carte
    query: String,               // filtres de la vue Codes
    filter_mode: i32,            // 0 tous, 1 favoris, >=2 tag
    filter_tag: String,
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
            accounts: Vec::new(),
            query: String::new(),
            filter_mode: 0,
            filter_tag: String::new(),
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
        inner.failures = 0;
        inner.wait_until = None;
        ui.set_lock_mode(if inner.record.is_some() { 1 } else { 0 });
        ui.set_accounts(ModelRc::new(VecModel::<AccountRow>::from(Vec::new())));
        ui.set_tags(ModelRc::new(VecModel::<SharedString>::from(Vec::new())));
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
                if idle > Duration::from_secs(inner.prefs.auto_lock_min as u64) {
                    Self::lock(&mut inner, &ui);
                    return;
                }
            }
            if inner.locked() {
                return;
            }
            Self::reload_accounts(&mut inner);
            Self::refresh(&ui, &inner);
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
                Err(error) => Self::error_text(&inner, &error),
                Ok(new) => {
                    if inner.store.find_duplicate(&new.secret, &new.issuer, &new.account).is_some() {
                        return Self::error_text(&inner, &mymfa_core::AppError::new("duplicate"));
                    }
                    inner.store.add(&new, Some("key"));
                    if let Err(error) = inner.persist() {
                        return Self::error_text(&inner, &error);
                    }
                    Self::reload_accounts(&mut inner);
                    let ui = weak.unwrap();
                    Self::refresh(&ui, &inner);
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
