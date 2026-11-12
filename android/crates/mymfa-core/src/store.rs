/*
 * Persistance des comptes OTP, de l'historique, des mots de passe et des
 * passkeys des sites — réplique de ../web/js/store.js.
 * Les données vivent dans une DataMap ({ clé localStorage → JSON en texte }),
 * texte en clair du coffre : le Store la lit et l'écrit, le coffre la chiffre.
 */
use crate::{now_iso, AppError, DataMap, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const ACCOUNTS_KEY: &str = "mymfa.accounts.v1";
pub const HISTORY_KEY: &str = "mymfa.history.v1";
/// Suppressions et vidage d'historique : nécessaires pour fusionner deux copies
/// sans faire réapparaître ce qui a été supprimé d'un côté.
pub const DELETED_KEY: &str = "mymfa.deleted.v1";
pub const LOGINS_KEY: &str = "mymfa.logins.v1";
pub const PASSKEYS_KEY: &str = "mymfa.passkeys.v1";
/// Réglages qui suivent le coffre (sauvegarde Drive, export, extension) :
/// { nom → { value, at } }.
pub const SETTINGS_KEY: &str = "mymfa.settings.v1";
pub const HISTORY_MAX: usize = 500;

/* ───── Synchro v2 (SYN-07) ─────
 * Avec une horloge (`Store.temps`), chaque modification tamponne ses champs au
 * format v2 (`h`, `t`) — celui que fusionne sync2.rs, comme web/js/store.js avec
 * `temps`. Sans horloge, la forme v1 historique (updatedAt seul, suppressions
 * dans mymfa.deleted.v1). Dans les deux cas, les tampons et champs inconnus sont
 * gardés, et seuls les éléments vivants sont servis. */

/// Tampons des champs d'un élément : { champ → tampon }.
pub type Tampons = std::collections::BTreeMap<String, String>;

const CHAMPS_COMPTE: [&str; 11] = ["type", "issuer", "account", "secret", "algorithm", "digits", "period", "counter", "tag", "description", "favorite"];
const CHAMPS_LOGIN: [&str; 8] = ["origin", "username", "password", "title", "note", "tag", "source", "favorite"];
const CHAMPS_PASSKEY: [&str; 9] = ["credentialId", "rpId", "rpName", "origin", "userHandle", "userName", "userDisplayName", "algorithm", "privateKey"];

/// Horloge de l'appareil qui écrit : identifiant, horloge hybride, et T() (ms)
/// au moment de l'écriture. L'appelant reprend `horloge` après coup (elle avance).
#[derive(Debug, Clone)]
pub struct TempsStore {
    pub horloge: crate::sync2::Horloge,
    pub appareil: String,
    pub maintenant: i64,
}

fn sommet(h: &Option<Tampons>) -> Option<&str> {
    h.as_ref().and_then(|h| h.values().map(String::as_str).max())
}

/// Un élément vit si le plus grand tampon de ses champs dépasse sa trace.
fn vivant(h: &Option<Tampons>, t: &Option<String>) -> bool {
    match t {
        None => true,
        Some(trace) => sommet(h).is_some_and(|s| s > trace.as_str()),
    }
}

fn tampons_de(champs: &[&str], tampon: &str) -> Tampons {
    champs.iter().map(|c| (c.to_string(), tampon.to_string())).collect()
}

/* ───── Modèle ───── */

#[allow(non_snake_case)] // champs camelCase : noms JSON du web
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u64,
    pub counter: i64,
    pub tag: String,
    pub description: String,
    pub favorite: bool,
    pub createdAt: String,
    pub updatedAt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usedAt: Option<String>,
    /// Synchro v2 : tampon de chaque champ (SYN-07), trace de suppression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<Tampons>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
    /// Champs inconnus de ce client, gardés tels quels à la réécriture.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Mot de passe d'un site (web : « logins », `mymfa.logins.v1`). Jamais hors coffre.
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Login {
    pub id: String,
    pub origin: String,
    pub username: String,
    pub password: String,
    pub title: String,
    pub note: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub source: String,
    pub createdAt: String,
    pub updatedAt: String,
    pub passwordChangedAt: String,
    // Ajoutés après coup côté web (patch favori, utilisation) : absents des vieux JSON.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub favorite: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usedAt: Option<String>,
    /// Synchro v2 : tampon de chaque champ (SYN-07), trace de suppression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<Tampons>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
    /// Champs inconnus de ce client, gardés tels quels à la réécriture.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

/// Passkey d'un site (myMFA fournisseur, `mymfa.passkeys.v1`) — pas celle qui
/// déverrouille le coffre (celle-ci vit dans les enveloppes du VaultRecord).
#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SitePasskey {
    pub id: String,
    pub credentialId: String,
    pub rpId: String,
    #[serde(default)]
    pub rpName: String,
    #[serde(default)]
    pub origin: String,
    #[serde(default)]
    pub userHandle: String,
    #[serde(default)]
    pub userName: String,
    #[serde(default)]
    pub userDisplayName: String,
    #[serde(default = "default_passkey_algorithm")]
    pub algorithm: i32,
    pub privateKey: String,
    pub createdAt: String,
    pub updatedAt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usedAt: Option<String>,
    /// Synchro v2 : tampon de chaque champ (SYN-07), trace de suppression.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub h: Option<Tampons>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub t: Option<String>,
    /// Champs inconnus de ce client, gardés tels quels à la réécriture.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

fn default_passkey_algorithm() -> i32 {
    -7 // ES256, défaut du web
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistoryEntry {
    pub id: String,
    pub at: String,
    pub action: String,
    pub accountId: Option<String>,
    pub label: Option<String>,
    pub tag: Option<String>,
    pub details: Option<Value>,
    /// Appareil auteur (SYN-09) : la source affichée par l'espace Synchro.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appareil: Option<String>,
    /// Champs inconnus de ce client, gardés tels quels : réécrire l'historique
    /// (chaque `log`) ne doit rien effacer de ce qu'un autre client y a mis.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Deleted {
    #[serde(default)]
    pub accounts: std::collections::BTreeMap<String, String>,
    pub historyClearedAt: Option<String>,
}

#[allow(non_snake_case)]
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExportPayload {
    pub app: String,
    pub version: u32,
    pub exportedAt: String,
    pub accounts: Vec<Account>,
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ImportStats {
    pub added: usize,
    pub skipped: usize,
}

/* ───── Aides ───── */

/// Identifiant unique : UUID v4, repli horodaté comme `uid()` côté web.
pub fn uid() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("getrandom");
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variante RFC 4122
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[0..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..32])
}

pub fn normalize_tag(tag: &str) -> String {
    tag.trim().split_whitespace().collect::<Vec<_>>().join("-").to_lowercase()
}

/// Libellé d'historique : « service — compte », parties vides omises.
pub fn describe(issuer: &str, account: &str) -> String {
    [issuer, account].iter().filter(|s| !s.is_empty()).cloned().collect::<Vec<_>>().join(" — ")
}

/* ───── Sites : adresses, hôtes, rattachement d'un compte à un site ───── */

/// Étiquettes sans signification pour le rattachement (web : IGNORED_LABELS).
const IGNORED_LABELS: &[&str] = &[
    "www", "app", "apps", "accounts", "account", "login", "signin", "auth", "id", "sso", "secure", "my", "mon", "portal", "admin",
    "mail", "webmail", "web", "cloud", "api", "mobile", "home", "online", "connect", "client", "clients", "user", "users",
    "espace", "compte", "service", "services", "com", "net", "org", "fr", "io", "dev",
];

/// Suffixes multi-parties (web : MULTI_SUFFIXES) : gouv.fr reste entier, etc.
const MULTI_SUFFIXES: &[&str] = &[
    "gouv.fr", "asso.fr", "nom.fr", "com.fr", "tm.fr", "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "co.jp", "ne.jp", "or.jp", "com.br", "com.mx",
    "co.in", "co.za", "com.cn", "com.tr", "co.kr", "com.sg", "com.hk", "co.il", "gv.at", "co.at",
    "github.io", "gitlab.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app",
    "firebaseapp.com", "appspot.com", "blogspot.com", "azurewebsites.net", "cloudfront.net", "s3.amazonaws.com",
    "onrender.com", "fly.dev", "glitch.me", "ngrok.io", "ngrok-free.app",
];

/// Origine d'une adresse (« https://exemple.fr/x » → « https://exemple.fr »),
/// ou « » si elle n'en a pas — réplique de `originOf` (new URL().origin).
pub fn origin_of(url: &str) -> String {
    match url::Url::parse(url.trim()) {
        Ok(parsed) if parsed.host().is_some() => format!("{}://{}", parsed.scheme(), {
            let mut authority = parsed.host_str().unwrap_or_default().to_string();
            if let Some(port) = parsed.port() {
                authority.push_str(&format!(":{port}"));
            }
            authority
        }),
        _ => String::new(),
    }
}

/// Hôte d'une origine, sans « www. » (web : `hostOf`), ou « » si pas d'hôte.
pub fn host_of(origin: &str) -> String {
    match url::Url::parse(origin.trim()) {
        Ok(parsed) => {
            let mut host = parsed.host_str().unwrap_or_default().to_string();
            if let Some(port) = parsed.port() {
                host.push_str(&format!(":{port}"));
            }
            host.strip_prefix("www.").unwrap_or(&host).to_string()
        }
        Err(_) => String::new(),
    }
}

/// Hôte comparable : minuscules, sans point final, sans « www. » ni suffixe
/// de développement « .localhost » (web : `plainHost`).
fn plain_host(host: &str) -> String {
    let mut value = host.trim().to_lowercase();
    if value.ends_with('.') {
        value.pop();
    }
    if let Some(stripped) = value.strip_prefix("www.") {
        value = stripped.to_string();
    }
    if let Some(stripped) = value.strip_suffix(".localhost") {
        value = stripped.to_string();
    }
    value
}

/// Service nommé par une adresse (« idp.exemple.fr ») : cet hôte, sinon « »
/// (web : `issuerHost`).
fn issuer_host(issuer: &str) -> Option<String> {
    let value: String = issuer.trim().to_lowercase()
        .trim_start_matches("https://").trim_start_matches("http://").to_string()
        .split(['/', ':']).next().unwrap_or("").to_string();
    let labels: Vec<&str> = value.split('.').collect();
    let looks_like_host = labels.len() >= 2
        && labels.iter().all(|l| l.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'))
        && !labels.iter().any(|l| l.is_empty())
        && !labels.last().map(|l| l.chars().all(|c| c.is_ascii_digit())).unwrap_or(false);
    if looks_like_host { Some(plain_host(&value)) } else { None }
}

/// Site d'un hôte : domaine registrable, façon `siteOf` du web — « a.b.gouv.fr »
/// → « b.gouv.fr », « accounts.google.com » → « google.com », hôtes IP et
/// « *.localhost » inchangés.
pub fn site_of(host: &str) -> String {
    let labels: Vec<String> = host.to_lowercase().trim_end_matches('.').split('.').map(str::to_string).collect();
    if labels.len() > 1 && labels.last().map(|l| l == "localhost").unwrap_or(false) {
        let parent = site_of(&labels[..labels.len() - 1].join("."));
        return format!("{parent}.localhost");
    }
    if labels.len() <= 2 || labels.last().map(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_digit())).unwrap_or(false) {
        return labels.join(".");
    }
    for n in [3, 2] {
        if labels.len() > n && MULTI_SUFFIXES.contains(&labels[labels.len() - n..].join(".").as_str()) {
            return labels[labels.len() - n - 1..].join(".");
        }
    }
    let top = labels[labels.len() - 1].clone();
    let second = labels[labels.len() - 2].clone();
    let depth = if top.len() == 2 && second.len() <= 3 { 3 } else { 2 };
    return labels[labels.len() - depth..].join(".");
}

/// Libellés significatifs d'un hôte (web : `hostLabels`).
fn host_labels(host: &str) -> Vec<String> {
    host.to_lowercase().split('.')
        .filter(|l| l.len() >= 3 && !IGNORED_LABELS.contains(l))
        .map(str::to_string)
        .collect()
}

/// Clés de rattachement d'un compte OTP : son seul service (issuer), jamais
/// l'identifiant ni la description (web : `accountKeys`).
fn account_keys(issuer: &str) -> Vec<String> {
    if let Some(host) = issuer_host(issuer) {
        return vec![format!("host:{host}")];
    }
    let issuer = issuer.to_lowercase();
    let mut words: Vec<String> = issuer.split(|c: char| !c.is_ascii_lowercase() && !c.is_ascii_digit())
        .filter(|w| w.len() >= 3 && !IGNORED_LABELS.contains(w))
        .map(str::to_string)
        .collect();
    let compact: String = issuer.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if compact.len() >= 3 && !words.contains(&compact) {
        words.push(compact);
    }
    words.iter().map(|w| format!("word:{w}")).collect()
}

/// Clés qu'un site présente : son hôte et ses domaines parents (« host:… »),
/// débuts de ses libellés significatifs (« word:… ») — web : `hostKeys`.
fn host_keys(host: &str) -> Vec<String> {
    let plain = plain_host(host);
    let labels: Vec<&str> = plain.split('.').collect();
    let mut keys: Vec<String> = Vec::new();
    for i in 0..labels.len().saturating_sub(1) {
        keys.push(format!("host:{}", labels[i..].join(".")));
    }
    for label in host_labels(&plain) {
        for n in 3..=label.len() {
            keys.push(format!("word:{}", &label[..n]));
        }
    }
    keys
}

/// Un compte OTP est-il celui d'un site ? Ses clés en croisent-elles une
/// (web : `accountMatchesHost`).
pub fn account_matches_host(account_issuer: &str, host: &str) -> bool {
    let host_set: std::collections::HashSet<String> = host_keys(host).into_iter().collect();
    account_keys(account_issuer).iter().any(|key| host_set.contains(key))
}

/* ───── Store ───── */

/// Compte à ajouter (champs bruts de saisie ou d'import) : `add` applique
/// trim/normalisation/défauts exacts de `Store.add` côté web.
#[derive(Debug, Clone, Default)]
pub struct NewAccount {
    pub type_: Option<String>,
    pub issuer: String,
    pub account: String,
    pub secret: String,
    pub algorithm: Option<String>,
    pub digits: Option<u32>,
    pub period: Option<u64>,
    pub counter: Option<i64>,
    pub tag: String,
    pub description: String,
    pub favorite: bool,
}

/// Patch de modification : chaque `Some` correspond à un champ présent dans le
/// patch JavaScript (`field in patch`).
#[derive(Debug, Clone, Default)]
pub struct AccountPatch {
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub tag: Option<String>,
    pub description: Option<String>,
    pub counter: Option<i64>,
    pub favorite: Option<bool>,
}

/// Nouveau mot de passe de site (web : `addLogin(data)`).
#[derive(Debug, Clone, Default)]
pub struct NewLogin {
    pub origin: String, // adresse saisie, brute : originOf la normalise
    pub username: String,
    pub password: String,
    pub title: String,
    pub note: String,
    pub tag: String,
}

/// Patch de modification d'un mot de passe (web : `updateLogin(id, patch)`).
#[derive(Debug, Clone, Default)]
pub struct LoginPatch {
    pub origin: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub title: Option<String>,
    pub note: Option<String>,
    pub tag: Option<String>,
    pub favorite: Option<bool>,
}

/// Nouvelle passkey de site (web : `addPasskey(data)`).
#[allow(non_snake_case)]
#[derive(Debug, Clone, Default)]
pub struct NewPasskey {
    pub credentialId: String,
    pub rpId: String,
    pub rpName: String,
    pub origin: String,
    pub userHandle: String,
    pub userName: String,
    pub userDisplayName: String,
    pub algorithm: Option<i32>,
    pub privateKey: String,
}

#[derive(Debug, Clone, Default)]
pub struct Store {
    pub data: DataMap,
    /// Identifiant de l'appareil qui écrit (SYN-09), noté dans l'historique.
    pub appareil: Option<String>,
    /// Horloge pour tamponner les écritures (synchro v2) ; None : forme v1.
    pub temps: Option<TempsStore>,
}

/// Objet libellé du journal (web : l'argument `account` de `log`, tel que le
/// produisent `loginLabel`/`passkeyLabel`).
struct LogLabel {
    id: String,
    issuer: String,
    account: String,
    tag: String,
}

impl LogLabel {
    fn of_account(account: &Account) -> Self {
        Self { id: account.id.clone(), issuer: account.issuer.clone(), account: account.account.clone(), tag: account.tag.clone() }
    }

    fn of_login(login: &Login) -> Self {
        Self { id: login.id.clone(), issuer: host_of(&login.origin), account: login.username.clone(), tag: String::new() }
    }

    fn of_passkey(passkey: &SitePasskey) -> Self {
        Self {
            id: passkey.id.clone(),
            issuer: if passkey.rpName.is_empty() { passkey.rpId.clone() } else { passkey.rpName.clone() },
            account: if passkey.userName.is_empty() { passkey.userDisplayName.clone() } else { passkey.userName.clone() },
            tag: String::new(),
        }
    }
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_map(data: DataMap) -> Self {
        Self { data, appareil: None, temps: None }
    }

    fn read_array<T: serde::de::DeserializeOwned>(&self, key: &str) -> Vec<T> {
        match self.data.get(key).and_then(|raw| serde_json::from_str::<Vec<T>>(raw).ok()) {
            Some(items) => items,
            None => Vec::new(),
        }
    }

    fn write<T: Serialize>(&mut self, key: &str, value: &T) {
        self.data.insert(key.to_string(), serde_json::to_string(value).expect("sérialisation interne"));
    }

    /// Un tampon pour une modification locale (plus grand que le plancher), si le
    /// Store a une horloge.
    fn tampon(&mut self, plancher: Option<&str>) -> Option<String> {
        let t = self.temps.as_mut()?;
        Some(t.horloge.apres(t.maintenant, plancher, &t.appareil))
    }

    fn comptes_bruts(&self) -> Vec<Account> {
        self.read_array(ACCOUNTS_KEY)
    }

    fn logins_bruts(&self) -> Vec<Login> {
        self.read_array(LOGINS_KEY)
    }

    fn passkeys_bruts(&self) -> Vec<SitePasskey> {
        self.read_array(PASSKEYS_KEY)
    }

    fn read_deleted(&self) -> Deleted {
        self.data
            .get(DELETED_KEY)
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default()
    }

    fn write_deleted(&mut self, deleted: &Deleted) {
        self.write(DELETED_KEY, deleted);
    }

    fn log(&mut self, action: &str, label: Option<LogLabel>, details: Option<Value>) {
        let mut history = self.read_array::<HistoryEntry>(HISTORY_KEY);
        let entry = HistoryEntry {
            id: uid(),
            at: now_iso(),
            action: action.into(),
            accountId: label.as_ref().map(|l| l.id.clone()),
            label: label.as_ref().map(|l| describe(&l.issuer, &l.account)),
            tag: label.as_ref().map(|l| l.tag.clone()),
            details,
            appareil: self.appareil.clone(),
            extra: serde_json::Map::new(),
        };
        history.insert(0, entry);
        history.truncate(HISTORY_MAX);
        self.write(HISTORY_KEY, &history);
    }

    /* ───── Comptes ───── */

    /// Comptes vivants (un compte supprimé en v2 reste dans la copie avec sa trace).
    pub fn list(&self) -> Vec<Account> {
        self.comptes_bruts().into_iter().filter(|a| vivant(&a.h, &a.t)).collect()
    }

    pub fn get(&self, id: &str) -> Option<Account> {
        self.list().into_iter().find(|a| a.id == id)
    }

    pub fn find_duplicate(&self, secret: &str, issuer: &str, account: &str) -> Option<Account> {
        self.list()
            .into_iter()
            .find(|a| a.secret == secret && a.issuer == issuer && a.account == account)
    }

    pub fn add(&mut self, data: &NewAccount, source: Option<&str>) -> Account {
        let now = now_iso();
        let account = Account {
            id: uid(),
            type_: data.type_.clone().unwrap_or_else(|| "totp".into()),
            issuer: data.issuer.trim().to_string(),
            account: data.account.trim().to_string(),
            secret: data.secret.clone(),
            algorithm: data.algorithm.clone().unwrap_or_else(|| "SHA1".into()),
            digits: data.digits.unwrap_or(6),
            period: data.period.unwrap_or(30),
            counter: data.counter.unwrap_or(0),
            tag: normalize_tag(&data.tag),
            description: data.description.trim().to_string(),
            favorite: data.favorite,
            createdAt: now.clone(),
            updatedAt: now,
            usedAt: None,
            h: None,
            t: None,
            extra: serde_json::Map::new(),
        };
        let mut account = account;
        if let Some(tampon) = self.tampon(None) {
            account.h = Some(tampons_de(&CHAMPS_COMPTE, &tampon));
            account.updatedAt = crate::sync2::iso_depuis_tampon(&tampon);
        }
        let mut accounts = self.comptes_bruts();
        accounts.push(account.clone());
        self.write(ACCOUNTS_KEY, &accounts);
        self.log("create", Some(LogLabel::of_account(&account)), source.map(|s| serde_json::json!({ "source": s })));
        account
    }

    /// Modification : seuls les changements réels touchent `updatedAt` et
    /// l'historique ; le favori n'est jamais journalisé.
    pub fn update(&mut self, id: &str, patch: &AccountPatch) -> Result<Account> {
        // Liste brute : modifier un élément supprimé le fait revivre (v2).
        let mut accounts = self.comptes_bruts();
        let idx = accounts.iter().position(|a| a.id == id).ok_or_else(|| AppError::new("accountNotFound"))?;
        let mut next = accounts[idx].clone();
        let mut changes: Vec<Value> = Vec::new();
        let text_fields: [(&str, &Option<String>); 4] = [
            ("issuer", &patch.issuer),
            ("account", &patch.account),
            ("tag", &patch.tag),
            ("description", &patch.description),
        ];
        let before = accounts[idx].clone();
        for (field, value) in text_fields {
            let Some(value) = value else { continue };
            let value = if field == "tag" { normalize_tag(value) } else { value.trim().to_string() };
            let before_value = match field {
                "issuer" => &before.issuer,
                "account" => &before.account,
                "tag" => &before.tag,
                _ => &before.description,
            };
            if &value != before_value {
                changes.push(serde_json::json!({ "field": field, "from": before_value, "to": value }));
                match field {
                    "issuer" => next.issuer = value,
                    "account" => next.account = value,
                    "tag" => next.tag = value,
                    _ => next.description = value,
                }
            }
        }
        if let Some(counter) = patch.counter {
            if counter != before.counter {
                next.counter = counter;
            }
        }
        if let Some(favorite) = patch.favorite {
            next.favorite = favorite;
        }
        if changes.is_empty() && next.counter == before.counter && next.favorite == before.favorite {
            return Ok(before);
        }
        if self.temps.is_some() {
            let mut champs: Vec<String> = changes.iter().filter_map(|c| c["field"].as_str().map(str::to_string)).collect();
            if next.counter != before.counter {
                champs.push("counter".into());
            }
            if next.favorite != before.favorite {
                champs.push("favorite".into());
            }
            let mut h = before.h.clone().unwrap_or_default();
            for champ in champs {
                let plancher = h.get(&champ).cloned();
                if let Some(t) = self.tampon(plancher.as_deref()) {
                    h.insert(champ, t);
                }
            }
            next.h = Some(h);
            next.updatedAt = sommet(&next.h).map(crate::sync2::iso_depuis_tampon).unwrap_or_else(now_iso);
        } else {
            next.updatedAt = now_iso();
        }
        accounts[idx] = next.clone();
        self.write(ACCOUNTS_KEY, &accounts);
        if !changes.is_empty() {
            self.log("update", Some(LogLabel::of_account(&next)), Some(serde_json::json!({ "changes": changes })));
        }
        Ok(next)
    }

    /// Élément utilisé (code copié) : pour « Récemment utilisés ». Ni modification ni historique.
    pub fn touch_account(&mut self, id: &str) {
        let mut accounts = self.comptes_bruts();
        if let Some(account) = accounts.iter_mut().find(|a| a.id == id) {
            account.usedAt = Some(now_iso());
            self.write(ACCOUNTS_KEY, &accounts);
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let Some(account) = self.list().into_iter().find(|a| a.id == id) else {
            return false;
        };
        if self.temps.is_some() {
            // v2 : l'élément reste, sa trace le tue — elle se propage par la fusion.
            let mut accounts = self.comptes_bruts();
            for a in accounts.iter_mut().filter(|a| a.id == id) {
                let plancher = sommet(&a.h).map(str::to_string);
                a.t = self.tampon(plancher.as_deref());
            }
            self.write(ACCOUNTS_KEY, &accounts);
        } else {
            let accounts: Vec<Account> = self.comptes_bruts().into_iter().filter(|a| a.id != id).collect();
            self.write(ACCOUNTS_KEY, &accounts);
            self.bury(id);
        }
        self.log("delete", Some(LogLabel::of_account(&account)), None);
        true
    }

    fn bury(&mut self, id: &str) {
        let mut deleted = self.read_deleted();
        deleted.accounts.insert(id.to_string(), now_iso());
        self.write_deleted(&deleted);
    }

    pub fn tombstones(&self) -> Deleted {
        self.read_deleted()
    }

    /* ───── Mots de passe des sites ───── */

    pub fn logins(&self) -> Vec<Login> {
        self.logins_bruts().into_iter().filter(|l| vivant(&l.h, &l.t)).collect()
    }

    pub fn find_login(&self, origin: &str, username: &str) -> Option<Login> {
        self.logins().into_iter()
            .find(|l| l.origin == origin && l.username == username)
    }

    pub fn add_login(&mut self, data: &NewLogin, source: Option<&str>) -> Result<Login> {
        let origin = origin_of(&data.origin);
        if origin.is_empty() {
            return Err(AppError::new("invalidUrl"));
        }
        if data.password.is_empty() {
            return Err(AppError::new("passwordEmpty"));
        }
        let now = now_iso();
        let login = Login {
            id: uid(),
            origin,
            username: data.username.trim().to_string(),
            password: data.password.clone(),
            title: data.title.trim().to_string(),
            note: data.note.trim().to_string(),
            tag: normalize_tag(&data.tag),
            source: source.unwrap_or_default().to_string(),
            createdAt: now.clone(),
            updatedAt: now.clone(),
            passwordChangedAt: now,
            favorite: false,
            usedAt: None,
            h: None,
            t: None,
            extra: serde_json::Map::new(),
        };
        let mut login = login;
        if let Some(tampon) = self.tampon(None) {
            login.h = Some(tampons_de(&CHAMPS_LOGIN, &tampon));
            login.updatedAt = crate::sync2::iso_depuis_tampon(&tampon);
            login.passwordChangedAt = login.updatedAt.clone();
        }
        let mut logins = self.logins_bruts();
        logins.push(login.clone());
        self.write(LOGINS_KEY, &logins);
        let mut details = serde_json::json!({ "kind": "login" });
        if let Some(source) = source {
            details["source"] = serde_json::json!(source);
        }
        self.log("create", Some(LogLabel::of_login(&login)), Some(details));
        Ok(login)
    }

    /// Modification : mêmes règles que le web — jamais de mot de passe dans le
    /// journal, seulement les champs modifiés ; le favori n'est pas journalisé.
    pub fn update_login(&mut self, id: &str, patch: &LoginPatch) -> Result<Login> {
        // Liste brute, comme update : une modification fait revivre (v2).
        let mut logins = self.logins_bruts();
        let idx = logins.iter().position(|l| l.id == id).ok_or_else(|| AppError::new("accountNotFound"))?;
        let mut next = logins[idx].clone();
        if let Some(username) = &patch.username { next.username = username.trim().to_string(); }
        if let Some(password) = &patch.password { next.password = password.clone(); }
        if let Some(title) = &patch.title { next.title = title.trim().to_string(); }
        if let Some(note) = &patch.note { next.note = note.trim().to_string(); }
        if let Some(tag) = &patch.tag { next.tag = normalize_tag(tag); }
        if let Some(origin) = &patch.origin {
            next.origin = origin_of(origin);
            if next.origin.is_empty() {
                return Err(AppError::new("invalidUrl"));
            }
        }
        if next.password.is_empty() {
            return Err(AppError::new("passwordEmpty"));
        }
        if let Some(favorite) = patch.favorite { next.favorite = favorite; }
        let before = logins[idx].clone();
        let changed: Vec<String> = ["origin", "username", "password", "title", "note", "tag"]
            .into_iter()
            .filter(|field| match *field {
                "origin" => next.origin != before.origin,
                "username" => next.username != before.username,
                "password" => next.password != before.password,
                "title" => next.title != before.title,
                "note" => next.note != before.note,
                _ => next.tag != before.tag,
            })
            .map(str::to_string)
            .collect();
        if changed.is_empty() && next.favorite == before.favorite {
            return Ok(before);
        }
        if self.temps.is_some() {
            let mut champs = changed.clone();
            if next.favorite != before.favorite {
                champs.push("favorite".into());
            }
            let mut h = before.h.clone().unwrap_or_default();
            for champ in champs {
                let plancher = h.get(&champ).cloned();
                if let Some(t) = self.tampon(plancher.as_deref()) {
                    h.insert(champ, t);
                }
            }
            if changed.contains(&"password".to_string()) {
                if let Some(t) = h.get("password") {
                    next.passwordChangedAt = crate::sync2::iso_depuis_tampon(t);
                }
            }
            next.h = Some(h);
            next.updatedAt = sommet(&next.h).map(crate::sync2::iso_depuis_tampon).unwrap_or_else(now_iso);
        } else {
            next.updatedAt = now_iso();
            if changed.contains(&"password".to_string()) {
                next.passwordChangedAt = next.updatedAt.clone();
            }
        }
        logins[idx] = next.clone();
        self.write(LOGINS_KEY, &logins);
        if !changed.is_empty() {
            self.log("update", Some(LogLabel::of_login(&next)), Some(serde_json::json!({ "kind": "login", "fields": changed })));
        }
        Ok(next)
    }

    /// Élément utilisé (rempli, copié) : pour « Récemment utilisés ». Ni modification ni historique.
    pub fn touch_login(&mut self, id: &str) {
        let mut logins = self.logins_bruts();
        if let Some(login) = logins.iter_mut().find(|l| l.id == id) {
            login.usedAt = Some(now_iso());
            self.write(LOGINS_KEY, &logins);
        }
    }

    pub fn remove_login(&mut self, id: &str) -> bool {
        let Some(login) = self.logins().into_iter().find(|l| l.id == id) else {
            return false;
        };
        if self.temps.is_some() {
            let mut logins = self.logins_bruts();
            for l in logins.iter_mut().filter(|l| l.id == id) {
                let plancher = sommet(&l.h).map(str::to_string);
                l.t = self.tampon(plancher.as_deref());
            }
            self.write(LOGINS_KEY, &logins);
        } else {
            let logins: Vec<Login> = self.logins_bruts().into_iter().filter(|l| l.id != id).collect();
            self.write(LOGINS_KEY, &logins);
            self.bury(id);
        }
        self.log("delete", Some(LogLabel::of_login(&login)), Some(serde_json::json!({ "kind": "login" })));
        true
    }

    /* ───── Passkeys des sites ───── */

    pub fn site_passkeys(&self) -> Vec<SitePasskey> {
        self.passkeys_bruts().into_iter().filter(|p| vivant(&p.h, &p.t)).collect()
    }

    /// Un même compte (rp + identifiant utilisateur) n'a qu'une passkey : la
    /// nouvelle remplace l'ancienne (enterrée), comme le web.
    pub fn add_passkey(&mut self, data: &NewPasskey, source: Option<&str>) -> SitePasskey {
        let now = now_iso();
        let passkey = SitePasskey {
            id: uid(),
            credentialId: data.credentialId.clone(),
            rpId: data.rpId.clone(),
            rpName: data.rpName.trim().to_string(),
            origin: data.origin.clone(),
            userHandle: data.userHandle.clone(),
            userName: data.userName.trim().to_string(),
            userDisplayName: data.userDisplayName.trim().to_string(),
            algorithm: data.algorithm.unwrap_or(-7),
            privateKey: data.privateKey.clone(),
            createdAt: now.clone(),
            updatedAt: now,
            usedAt: None,
            h: None,
            t: None,
            extra: serde_json::Map::new(),
        };
        let mut passkey = passkey;
        let mut current = self.passkeys_bruts();
        let replaced: Vec<String> = current.iter()
            .filter(|p| vivant(&p.h, &p.t) && p.rpId == passkey.rpId && !passkey.userHandle.is_empty() && p.userHandle == passkey.userHandle)
            .map(|p| p.id.clone())
            .collect();
        if let Some(tampon) = self.tampon(None) {
            passkey.h = Some(tampons_de(&CHAMPS_PASSKEY, &tampon));
            passkey.updatedAt = crate::sync2::iso_depuis_tampon(&tampon);
            // v2 : les remplacées restent, tuées par leur trace.
            for p in current.iter_mut().filter(|p| replaced.contains(&p.id)) {
                let plancher = sommet(&p.h).map(str::to_string);
                p.t = self.tampon(plancher.as_deref());
            }
            current.push(passkey.clone());
            self.write(PASSKEYS_KEY, &current);
        } else {
            current.retain(|p| !replaced.contains(&p.id));
            current.push(passkey.clone());
            self.write(PASSKEYS_KEY, &current);
            for id in &replaced {
                self.bury(id);
            }
        }
        let mut details = serde_json::json!({ "kind": "passkey" });
        if let Some(source) = source {
            details["source"] = serde_json::json!(source);
        }
        self.log("create", Some(LogLabel::of_passkey(&passkey)), Some(details));
        passkey
    }

    pub fn remove_passkey(&mut self, id: &str) -> bool {
        let Some(passkey) = self.site_passkeys().into_iter().find(|p| p.id == id) else {
            return false;
        };
        if self.temps.is_some() {
            let mut passkeys = self.passkeys_bruts();
            for p in passkeys.iter_mut().filter(|p| p.id == id) {
                let plancher = sommet(&p.h).map(str::to_string);
                p.t = self.tampon(plancher.as_deref());
            }
            self.write(PASSKEYS_KEY, &passkeys);
        } else {
            let passkeys: Vec<SitePasskey> = self.passkeys_bruts().into_iter().filter(|p| p.id != id).collect();
            self.write(PASSKEYS_KEY, &passkeys);
            self.bury(id);
        }
        self.log("delete", Some(LogLabel::of_passkey(&passkey)), Some(serde_json::json!({ "kind": "passkey" })));
        true
    }

    /// Élément utilisé (rempli, authentifié) : pour « Récemment utilisés ».
    pub fn touch_passkey(&mut self, id: &str) {
        let mut passkeys = self.passkeys_bruts();
        if let Some(passkey) = passkeys.iter_mut().find(|p| p.id == id) {
            passkey.usedAt = Some(now_iso());
            self.write(PASSKEYS_KEY, &passkeys);
        }
    }

    /* ───── Historique, tags, réglages, export ───── */

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.read_array(HISTORY_KEY)
    }

    pub fn clear_history(&mut self) {
        self.write(HISTORY_KEY, &Vec::<HistoryEntry>::new());
        if self.temps.is_some() {
            // v2 : vidage tamponné dans le marqueur (les entrées d'avant ne reviennent pas).
            let mut marqueur = match self.data.get(crate::sync2::SYNC_KEY).and_then(|raw| serde_json::from_str::<Value>(raw).ok()) {
                Some(Value::Object(m)) => m,
                _ => serde_json::Map::new(),
            };
            let avant = marqueur.get("historiqueVideLe").and_then(Value::as_str).map(str::to_string);
            if let Some(t) = self.tampon(avant.as_deref()) {
                marqueur.insert("historiqueVideLe".into(), Value::String(t));
            }
            self.write(crate::sync2::SYNC_KEY, &Value::Object(marqueur));
        } else {
            let mut deleted = self.read_deleted();
            deleted.historyClearedAt = Some(now_iso());
            self.write_deleted(&deleted);
        }
    }

    /// Tags distincts, triés.
    pub fn tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self.list().into_iter().map(|a| a.tag).filter(|t| !t.is_empty()).collect();
        tags.sort();
        tags.dedup();
        tags
    }

    pub fn settings(&self) -> serde_json::Map<String, Value> {
        match self.data.get(SETTINGS_KEY).and_then(|raw| serde_json::from_str::<Value>(raw).ok()) {
            Some(Value::Object(map)) => map,
            _ => serde_json::Map::new(),
        }
    }

    pub fn setting(&self, name: &str) -> Option<Value> {
        self.settings().get(name).and_then(|entry| entry.get("value")).cloned()
    }

    /// Réglage modifié : daté, pour que la fusion garde le plus récent.
    pub fn set_setting(&mut self, name: &str, value: &Value) {
        let mut all = self.settings();
        let unchanged = all.get(name).and_then(|e| e.get("value")).and_then(|v| {
            serde_json::to_string(v).ok().zip(serde_json::to_string(value).ok())
                .map(|(a, b)| a == b)
        }).unwrap_or(false);
        if unchanged {
            return;
        }
        let avant = all.get(name).and_then(|e| e.get("h")).and_then(Value::as_str).map(str::to_string);
        let entree = match self.tampon(avant.as_deref()) {
            Some(t) => serde_json::json!({ "value": value, "at": crate::sync2::iso_depuis_tampon(&t), "h": t }),
            None => serde_json::json!({ "value": value, "at": now_iso() }),
        };
        all.insert(name.to_string(), entree);
        self.write(SETTINGS_KEY, &Value::Object(all));
    }

    pub fn export_all(&self) -> ExportPayload {
        ExportPayload {
            app: "myMFA".into(),
            version: 1,
            exportedAt: now_iso(),
            accounts: self.list(),
            history: self.history(),
        }
    }

    /// Importe un export JSON : ajoute les comptes absents, ignore les doublons.
    pub fn import_all(&mut self, payload: &str) -> Result<ImportStats> {
        let payload: Value = serde_json::from_str(payload).map_err(|_| AppError::new("invalidImport"))?;
        let Value::Array(accounts) = payload.get("accounts").cloned().unwrap_or(Value::Null) else {
            return Err(AppError::new("invalidImport"));
        };
        let mut added = 0;
        let mut skipped = 0;
        for account in accounts {
            let secret = account.get("secret").and_then(Value::as_str).unwrap_or("");
            let issuer = account.get("issuer").and_then(Value::as_str).unwrap_or("");
            let name = account.get("account").and_then(Value::as_str).unwrap_or("");
            if secret.is_empty() || self.find_duplicate(secret, issuer, name).is_some() {
                skipped += 1;
                continue;
            }
            let new = NewAccount {
                type_: account.get("type").and_then(Value::as_str).map(str::to_string),
                issuer: issuer.into(),
                account: name.into(),
                secret: secret.into(),
                algorithm: account.get("algorithm").and_then(Value::as_str).map(str::to_string),
                digits: account.get("digits").and_then(Value::as_u64).map(|d| d as u32),
                period: account.get("period").and_then(Value::as_u64),
                counter: account.get("counter").and_then(Value::as_i64),
                tag: account.get("tag").and_then(Value::as_str).unwrap_or("").into(),
                description: account.get("description").and_then(Value::as_str).unwrap_or("").into(),
                favorite: account.get("favorite").and_then(Value::as_bool).unwrap_or(false),
            };
            self.add(&new, Some("import"));
            added += 1;
        }
        let stats = ImportStats { added, skipped };
        self.log("import", None, Some(serde_json::to_value(&stats).unwrap()));
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_account(issuer: &str, secret: &str, tag: &str) -> NewAccount {
        NewAccount {
            issuer: issuer.into(),
            account: "moi@example.net".into(),
            secret: secret.into(),
            tag: tag.into(),
            ..NewAccount::default()
        }
    }

    #[test]
    fn add_normalise_puis_journalise() {
        let mut store = Store::new();
        let account = store.add(&new_account("  GitHub ", "JBSWY3DPEHPK3PXP", "  Travail  Perso "), None);
        assert_eq!(account.issuer, "GitHub");
        assert_eq!(account.tag, "travail-perso");
        assert_eq!(account.type_, "totp");
        assert_eq!(account.algorithm, "SHA1");
        assert_eq!(account.period, 30);
        assert_eq!(account.digits, 6);
        let history = store.history();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].action, "create");
        assert_eq!(history[0].label.as_deref(), Some("GitHub — moi@example.net"));
    }

    #[test]
    fn update_sans_changement_reste_silencieux() {
        let mut store = Store::new();
        store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", "travail"), None);
        let before = store.list()[0].clone();
        let account = store.update(&before.id, &AccountPatch { issuer: Some("GitHub".into()), ..AccountPatch::default() }).unwrap();
        assert_eq!(account, before, "aucune écriture, updatedAt inchangé");
        assert_eq!(store.history().len(), 1);
        // Changement réel : journalisé avec avant → après.
        let updated = store.update(&before.id, &AccountPatch { tag: Some("Perso".into()), ..AccountPatch::default() }).unwrap();
        assert_eq!(updated.tag, "perso");
        assert!(updated.updatedAt >= before.updatedAt);
        let history = store.history();
        assert_eq!(history[0].action, "update");
        let changes = history[0].details.as_ref().unwrap()["changes"].as_array().unwrap().clone();
        assert_eq!(changes[0]["field"], "tag");
        assert_eq!(changes[0]["from"], "travail");
        assert_eq!(changes[0]["to"], "perso");
    }

    #[test]
    fn remove_enterre_le_compte() {
        let mut store = Store::new();
        let account = store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        assert!(store.remove(&account.id));
        assert!(store.list().is_empty());
        assert!(store.tombstones().accounts.contains_key(&account.id));
        assert_eq!(store.history()[0].action, "delete");
        assert!(!store.remove(&account.id));
    }

    #[test]
    fn touch_ne_journalise_pas() {
        let mut store = Store::new();
        let account = store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        store.touch_account(&account.id);
        assert!(store.list()[0].usedAt.is_some());
        assert_eq!(store.history().len(), 1);
    }

    #[test]
    fn tags_tries_sans_doublon() {
        let mut store = Store::new();
        store.add(&new_account("B", "JBSWY3DPEHPK3PXP", "perso"), None);
        store.add(&new_account("A", "JBSWY3DPEHPK3PXPZ", "travail"), None);
        store.add(&new_account("C", "JBSWY3DPEHPK3PXPZZ", "perso"), None);
        assert_eq!(store.tags(), vec!["perso", "travail"]);
    }

    #[test]
    fn historique_plafonne_a_500() {
        let mut store = Store::new();
        for i in 0..(HISTORY_MAX + 10) {
            store.add(&new_account(&format!("S{i}"), "JBSWY3DPEHPK3PXP", ""), None);
        }
        assert_eq!(store.history().len(), HISTORY_MAX);
    }

    #[test]
    fn reglages_datés_et_sans_écriture_inutile() {
        let mut store = Store::new();
        store.set_setting("prefs", &serde_json::json!({ "theme": "dark" }));
        let first = store.data.get(SETTINGS_KEY).unwrap().clone();
        let first_at: Value = serde_json::from_str(&first).unwrap();
        let first_at = first_at["prefs"]["at"].as_str().unwrap().to_string();
        store.set_setting("prefs", &serde_json::json!({ "theme": "dark" }));
        assert_eq!(store.data.get(SETTINGS_KEY), Some(&first), "valeur identique : pas de réécriture");
        store.set_setting("prefs", &serde_json::json!({ "theme": "light" }));
        let entry: Value = serde_json::from_str(store.data.get(SETTINGS_KEY).unwrap()).unwrap();
        assert_eq!(entry["prefs"]["value"]["theme"], "light");
        assert!(entry["prefs"]["at"].as_str().unwrap() >= first_at.as_str());
    }

    #[test]
    fn export_puis_import_ajoute_sans_doublon() {
        let mut store = Store::new();
        store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        let payload = serde_json::to_string(&store.export_all()).unwrap();
        let stats = store.import_all(&payload).unwrap();
        assert_eq!(stats, ImportStats { added: 0, skipped: 1 });
        let stats = store.import_all(r#"{"app":"myMFA","version":1,"accounts":[{"issuer":"OVH","secret":"JBSWY3DPEHPK3PXPZZ"}]}"#).unwrap();
        assert_eq!(stats, ImportStats { added: 1, skipped: 0 });
        assert_eq!(store.list().len(), 2);
        assert!(store.import_all("pas du json").is_err());
    }

    #[test]
    fn uid_format_uuid_v4() {
        let id = uid();
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
    }

    /* ───── Mots de passe et passkeys des sites (miroir de store.test.js) ───── */

    fn new_login(url: &str, username: &str, password: &str) -> NewLogin {
        NewLogin { origin: url.into(), username: username.into(), password: password.into(), ..NewLogin::default() }
    }

    #[test]
    fn logins_ajout_mise_a_jour_jamais_de_mot_de_passe_dans_le_journal() {
        let mut store = Store::new();
        let login = store.add_login(&new_login("https://exemple.fr/connexion?x=1", "  alice ", "s3cret"), None).unwrap();
        assert_eq!(login.origin, "https://exemple.fr");
        assert_eq!(login.username, "alice");
        assert_eq!(store.find_login("https://exemple.fr", "alice").unwrap().id, login.id);
        assert_eq!(store.history()[0].details.as_ref().unwrap()["kind"], "login");

        store.update_login(&login.id, &LoginPatch { password: Some("n0uveau".into()), ..LoginPatch::default() }).unwrap();
        assert_eq!(store.logins()[0].password, "n0uveau");
        let journal = serde_json::to_string(&store.history()).unwrap();
        assert!(!journal.contains("s3cret"));
        assert!(!journal.contains("n0uveau"));
        assert_eq!(store.history()[0].details.as_ref().unwrap()["fields"], serde_json::json!(["password"]));

        assert_eq!(store.add_login(&new_login("pas une adresse", "", "x"), None).unwrap_err().code, "invalidUrl");
        assert_eq!(store.add_login(&new_login("https://a.fr", "", ""), None).unwrap_err().code, "passwordEmpty");

        assert!(store.remove_login(&login.id));
        assert!(store.tombstones().accounts.contains_key(&login.id));
    }

    #[test]
    fn passkeys_une_seule_par_compte_du_site() {
        let mut store = Store::new();
        let mk = |credential: &str, handle: &str, name: &str| NewPasskey {
            credentialId: credential.into(),
            rpId: "exemple.fr".into(),
            userHandle: handle.into(),
            userName: name.into(),
            privateKey: "k".into(),
            ..NewPasskey::default()
        };
        let first = store.add_passkey(&mk("a", "u1", "alice"), None);
        store.add_passkey(&mk("b", "u2", "bob"), None);
        store.add_passkey(&mk("c", "u1", "alice"), None);
        let ids: Vec<String> = store.site_passkeys().into_iter().map(|p| p.credentialId).collect();
        assert_eq!(ids, vec!["b", "c"]);
        assert!(store.tombstones().accounts.contains_key(&first.id));
    }

    #[test]
    fn update_login_favori_sans_historique_champs_journalises() {
        let mut store = Store::new();
        let login = store.add_login(&new_login("https://exemple.fr/connexion", "moi", "secret"), None).unwrap();
        let before = store.history().len();
        let fav = store.update_login(&login.id, &LoginPatch { favorite: Some(true), ..LoginPatch::default() }).unwrap();
        assert!(fav.favorite);
        assert_eq!(store.history().len(), before, "favori : pas d'historique");
        let edited = store.update_login(&login.id, &LoginPatch {
            username: Some("autre".into()), password: Some("nouveau".into()), favorite: Some(true), ..LoginPatch::default()
        }).unwrap();
        assert_eq!(edited.username, "autre");
        assert_eq!(store.history()[0].details.as_ref().unwrap()["fields"], serde_json::json!(["username", "password"]));
        assert!(!serde_json::to_string(&store.history()).unwrap().contains("nouveau"));
    }

    #[test]
    fn touch_sans_historique_pour_logins_et_passkeys() {
        let mut store = Store::new();
        let login = store.add_login(&new_login("https://exemple.fr", "moi", "secret"), None).unwrap();
        let passkey = store.add_passkey(&NewPasskey {
            credentialId: "c".into(), rpId: "exemple.fr".into(), userHandle: "u".into(),
            privateKey: "k".into(), ..NewPasskey::default()
        }, None);
        let before = store.history().len();
        store.touch_login(&login.id);
        store.touch_passkey(&passkey.id);
        assert!(store.logins()[0].usedAt.is_some());
        assert!(store.site_passkeys()[0].usedAt.is_some());
        assert_eq!(store.history().len(), before);
    }

    #[test]
    fn login_tag_normalise_et_modifiable_tags_de_comptes_seulement() {
        let mut store = Store::new();
        let login = store.add_login(&NewLogin {
            origin: "https://exemple.fr".into(), username: "moi".into(), password: "secret".into(),
            tag: " Pro  Perso ".into(), ..NewLogin::default()
        }, None).unwrap();
        assert_eq!(login.tag, "pro-perso");
        store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", "banque"), None);
        assert_eq!(store.tags(), vec!["banque"], "tags() : ceux des comptes 2FA (filtres de l'accueil)");
        let next = store.update_login(&login.id, &LoginPatch { tag: Some("Travail".into()), ..LoginPatch::default() }).unwrap();
        assert_eq!(next.tag, "travail");
        assert_eq!(store.history()[0].details.as_ref().unwrap()["fields"], serde_json::json!(["tag"]));
    }

    #[test]
    fn json_des_logins_round_trip_avec_le_web() {
        let mut store = Store::new();
        store.add_login(&new_login("https://exemple.fr", "alice", "s3cret"), Some("app")).unwrap();
        // Re-lit le JSON qu'il a écrit : champs du web présents, rien de plus.
        let raw = store.data.get(LOGINS_KEY).unwrap().clone();
        let value: Value = serde_json::from_str(&raw).unwrap();
        let keys: Vec<&str> = value[0].as_object().unwrap().keys().map(|k| k.as_str()).collect();
        assert_eq!(keys, vec![
            "id", "origin", "username", "password", "title", "note", "tag", "source", "createdAt", "updatedAt", "passwordChangedAt"
        ]);
        // Un JSON web avec favorite/usedAt se lit aussi.
        let rich: Login = serde_json::from_str(r#"{
            "id": "x", "origin": "https://a.fr", "username": "u", "password": "p", "title": "", "note": "",
            "tag": "", "source": "", "createdAt": "2026-01-01T00:00:00.000Z", "updatedAt": "2026-01-01T00:00:00.000Z",
            "passwordChangedAt": "2026-01-01T00:00:00.000Z", "favorite": true, "usedAt": "2026-01-02T00:00:00.000Z"
        }"#).unwrap();
        assert!(rich.favorite);
        assert_eq!(rich.usedAt.as_deref(), Some("2026-01-02T00:00:00.000Z"));
    }

    /* ───── Sites : siteOf et rattachement (miroir de store.test.js) ───── */

    #[test]
    fn site_of_regroupe_les_sous_domaines() {
        assert_eq!(site_of("accounts.google.com"), "google.com");
        assert_eq!(site_of("www.notion.so"), "notion.so");
        assert_eq!(site_of("login.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site_of("impots.gouv.fr"), "impots.gouv.fr");
        assert_ne!(site_of("impots.gouv.fr"), site_of("ameli.gouv.fr"));
        assert_ne!(site_of("alice.github.io"), site_of("bob.github.io"));
        assert_eq!(site_of("bucket.s3.amazonaws.com"), "bucket.s3.amazonaws.com");
        assert_eq!(site_of("localhost"), "localhost");
        assert_eq!(site_of("192.168.1.10"), "192.168.1.10");
        assert_eq!(site_of("idp.mindlog.today.localhost"), "mindlog.today.localhost");
        assert_eq!(site_of("app.localhost"), "app.localhost");
    }

    #[test]
    fn rattachement_par_le_libelle_de_l_hote() {
        assert!(account_matches_host("GitHub", "github.com"));
        assert!(account_matches_host("Google", "accounts.google.com"));
        assert!(!account_matches_host("GitHub", "gitlab.com"));
        assert!(account_matches_host("OVH", "www.ovhcloud.com"));
        assert!(account_matches_host("Google Workspace", "accounts.google.com"));
        assert!(account_matches_host("ownCloud", "owncloud.jacques.fr"));
    }

    #[test]
    fn rattachement_ni_identifiant_ni_description() {
        assert!(!account_matches_host("Proton", "owncloud.jacques.fr"));
        assert!(!account_matches_host("GitHub", "hullu.fr"));
        assert!(!account_matches_host("Gmail", "mail.exemple.fr"));
        assert!(!account_matches_host("Nextcloud", "cloud.exemple.fr"));
        assert!(!account_matches_host("", "github.com"));
    }

    #[test]
    fn service_nomme_par_une_adresse_ne_vaut_que_cette_adresse() {
        let idp = "idp.mindlog.today";
        assert!(account_matches_host(idp, "idp.mindlog.today"));
        assert!(account_matches_host(idp, "idp.mindlog.today.localhost"));
        assert!(!account_matches_host(idp, "orp.mindlog.today"));
        assert!(!account_matches_host(idp, "orp.mindlog.today.localhost"));
    }

    #[test]
    fn origine_et_hote_des_adresses() {
        assert_eq!(origin_of("https://exemple.fr/connexion?x=1"), "https://exemple.fr");
        assert_eq!(origin_of("https://exemple.fr:8443/a"), "https://exemple.fr:8443");
        assert_eq!(origin_of("pas une adresse"), "");
        assert_eq!(host_of("https://www.exemple.fr/a"), "exemple.fr");
        assert_eq!(host_of("https://exemple.fr"), "exemple.fr");
        assert_eq!(host_of("n'importe quoi"), "");
    }

    #[test]
    fn historique_note_l_appareil_et_garde_les_champs_inconnus() {
        let mut store = Store::new();
        store.data.insert(
            HISTORY_KEY.into(),
            serde_json::json!([{ "id": "h0", "at": "2026-11-11T14:00:00.000Z", "action": "create", "accountId": null,
                "label": null, "tag": null, "details": null, "appareil": "tel", "futur": { "x": 1 } }]).to_string(),
        );
        store.appareil = Some("pc".into());
        store.add(&NewAccount { issuer: "GitHub".into(), secret: "JBSWY3DPEHPK3PXP".into(), ..Default::default() }, None);
        let brut: Vec<Value> = serde_json::from_str(&store.data[HISTORY_KEY]).unwrap();
        assert_eq!(brut[0]["appareil"], "pc", "le nouvel événement nomme son appareil");
        assert_eq!(brut[1]["appareil"], "tel", "l'appareil d'un autre client survit à la réécriture");
        assert_eq!(brut[1]["futur"]["x"], 1, "un champ inconnu aussi");
        let mut sans = Store::new();
        sans.add(&NewAccount { issuer: "GitHub".into(), secret: "JBSWY3DPEHPK3PXP".into(), ..Default::default() }, None);
        let brut: Vec<Value> = serde_json::from_str(&sans.data[HISTORY_KEY]).unwrap();
        assert!(brut[0].get("appareil").is_none(), "appareil inconnu : champ absent, comme le web");
    }

    /* ───── Mode v2 : écritures tamponnées (miroir de web/test/store-v2.test.js) ───── */

    const T0: i64 = 1_794_405_900_000;

    fn store_v2() -> Store {
        let mut store = Store::new();
        store.appareil = Some("pc".into());
        store.temps = Some(TempsStore { horloge: crate::sync2::Horloge::nouvelle(T0), appareil: "pc".into(), maintenant: T0 });
        store
    }

    fn brut(store: &Store, cle: &str) -> Vec<Value> {
        serde_json::from_str(&store.data[cle]).unwrap()
    }

    #[test]
    fn v2_ajout_tamponne_tous_les_champs() {
        let mut store = store_v2();
        let compte = store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        let h = compte.h.clone().unwrap();
        assert_eq!(h.len(), CHAMPS_COMPTE.len());
        assert!(h.values().all(|t| t == &h["issuer"]), "un seul tampon pour la création");
        assert!(h["issuer"].ends_with("pc"));
        assert_eq!(compte.updatedAt, crate::sync2::iso_depuis_tampon(&h["issuer"]));
    }

    #[test]
    fn v2_modification_ne_retamponne_que_les_champs_changes() {
        let mut store = store_v2();
        let compte = store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        let avant = compte.h.clone().unwrap();
        let apres = store.update(&compte.id, &AccountPatch { issuer: Some("GitHub Pro".into()), ..Default::default() }).unwrap();
        let h = apres.h.unwrap();
        assert!(h["issuer"] > avant["issuer"]);
        assert_eq!(h["secret"], avant["secret"], "champ inchangé : même tampon");
    }

    #[test]
    fn v2_suppression_garde_l_element_mort_et_une_modification_le_fait_revivre() {
        let mut store = store_v2();
        let compte = store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        assert!(store.remove(&compte.id));
        assert!(store.list().is_empty(), "invisible des lectures");
        let items = brut(&store, ACCOUNTS_KEY);
        assert_eq!(items.len(), 1, "gardé dans la copie pour propager la trace");
        assert!(items[0]["t"].is_string());
        assert!(!store.data.contains_key(DELETED_KEY), "pas de trace v1");
        store.update(&compte.id, &AccountPatch { issuer: Some("GitHub bis".into()), ..Default::default() }).unwrap();
        assert_eq!(store.list().len(), 1, "une modification postérieure à la trace le fait revivre");
    }

    #[test]
    fn v2_logins_mot_de_passe_date_par_son_tampon() {
        let mut store = store_v2();
        let login = store.add_login(&new_login("https://exemple.fr", "moi", "un"), None).unwrap();
        let apres = store.update_login(&login.id, &LoginPatch { password: Some("deux".into()), ..Default::default() }).unwrap();
        let h = apres.h.clone().unwrap();
        assert_eq!(apres.passwordChangedAt, crate::sync2::iso_depuis_tampon(&h["password"]));
        assert!(store.remove_login(&login.id));
        assert!(store.logins().is_empty());
        assert_eq!(brut(&store, LOGINS_KEY).len(), 1);
    }

    #[test]
    fn v2_vidage_d_historique_et_reglages_tamponnes() {
        let mut store = store_v2();
        store.add(&new_account("GitHub", "JBSWY3DPEHPK3PXP", ""), None);
        store.clear_history();
        let marqueur: Value = serde_json::from_str(&store.data[crate::sync2::SYNC_KEY]).unwrap();
        assert!(marqueur["historiqueVideLe"].as_str().unwrap().ends_with("pc"));
        store.set_setting("theme", &serde_json::json!("sombre"));
        let premier = store.settings()["theme"]["h"].as_str().unwrap().to_string();
        store.set_setting("theme", &serde_json::json!("clair"));
        assert!(store.settings()["theme"]["h"].as_str().unwrap() > premier.as_str());
    }

    #[test]
    fn v2_passkey_remplacee_tracee() {
        let mut store = store_v2();
        let nouvelle = |id: &str| NewPasskey {
            credentialId: id.into(),
            rpId: "exemple.fr".into(),
            userHandle: "u1".into(),
            privateKey: "k".into(),
            ..Default::default()
        };
        let premiere = store.add_passkey(&nouvelle("c1"), None);
        store.add_passkey(&nouvelle("c2"), None);
        let vivantes = store.site_passkeys();
        assert_eq!(vivantes.len(), 1);
        assert_eq!(vivantes[0].credentialId, "c2");
        let morte = brut(&store, PASSKEYS_KEY).into_iter().find(|p| p["id"] == premiere.id.as_str()).unwrap();
        assert!(morte["t"].is_string());
    }

    #[test]
    fn tampons_et_champs_inconnus_gardes_meme_sans_horloge() {
        let mut store = Store::new();
        store.data.insert(
            ACCOUNTS_KEY.into(),
            serde_json::json!([{ "id": "a1", "type": "totp", "issuer": "GitHub", "account": "", "secret": "JBSWY3DPEHPK3PXP",
                "algorithm": "SHA1", "digits": 6, "period": 30, "counter": 0, "tag": "", "description": "", "favorite": false,
                "createdAt": "2026-11-11T14:00:00.000Z", "updatedAt": "2026-11-11T14:00:00.000Z",
                "h": { "issuer": "1794405600000000000000tel" }, "futur": 1 }]).to_string(),
        );
        store.touch_account("a1");
        let item = &brut(&store, ACCOUNTS_KEY)[0];
        assert_eq!(item["h"]["issuer"], "1794405600000000000000tel", "tampon gardé");
        assert_eq!(item["futur"], 1, "champ inconnu gardé");
    }
}
