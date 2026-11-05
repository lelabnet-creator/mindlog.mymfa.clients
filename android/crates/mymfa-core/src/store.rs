/*
 * Persistance des comptes OTP et de l'historique — réplique de ../web/js/store.js.
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usedAt: Option<String>,
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

#[derive(Debug, Clone, Default)]
pub struct Store {
    pub data: DataMap,
}

impl Store {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_map(data: DataMap) -> Self {
        Self { data }
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

    fn read_deleted(&self) -> Deleted {
        self.data
            .get(DELETED_KEY)
            .and_then(|raw| serde_json::from_str(raw).ok())
            .unwrap_or_default()
    }

    fn write_deleted(&mut self, deleted: &Deleted) {
        self.write(DELETED_KEY, deleted);
    }

    fn log(&mut self, action: &str, account: Option<&Account>, details: Option<Value>) {
        let mut history = self.read_array::<HistoryEntry>(HISTORY_KEY);
        let entry = HistoryEntry {
            id: uid(),
            at: now_iso(),
            action: action.into(),
            accountId: account.map(|a| a.id.clone()),
            label: account.map(|a| describe(&a.issuer, &a.account)),
            tag: account.map(|a| a.tag.clone()),
            details,
        };
        history.insert(0, entry);
        history.truncate(HISTORY_MAX);
        self.write(HISTORY_KEY, &history);
    }

    /* ───── Comptes ───── */

    pub fn list(&self) -> Vec<Account> {
        self.read_array(ACCOUNTS_KEY)
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
        };
        let mut accounts = self.list();
        accounts.push(account.clone());
        self.write(ACCOUNTS_KEY, &accounts);
        self.log("create", Some(&account), source.map(|s| serde_json::json!({ "source": s })));
        account
    }

    /// Modification : seuls les changements réels touchent `updatedAt` et
    /// l'historique ; le favori n'est jamais journalisé.
    pub fn update(&mut self, id: &str, patch: &AccountPatch) -> Result<Account> {
        let mut accounts = self.list();
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
        next.updatedAt = now_iso();
        accounts[idx] = next.clone();
        self.write(ACCOUNTS_KEY, &accounts);
        if !changes.is_empty() {
            self.log("update", Some(&next), Some(serde_json::json!({ "changes": changes })));
        }
        Ok(next)
    }

    /// Élément utilisé (code copié) : pour « Récemment utilisés ». Ni modification ni historique.
    pub fn touch_account(&mut self, id: &str) {
        let mut accounts = self.list();
        if let Some(account) = accounts.iter_mut().find(|a| a.id == id) {
            account.usedAt = Some(now_iso());
            self.write(ACCOUNTS_KEY, &accounts);
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let Some(account) = self.list().into_iter().find(|a| a.id == id) else {
            return false;
        };
        let accounts: Vec<Account> = self.list().into_iter().filter(|a| a.id != id).collect();
        self.write(ACCOUNTS_KEY, &accounts);
        self.bury(id);
        self.log("delete", Some(&account), None);
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

    /* ───── Historique, tags, réglages, export ───── */

    pub fn history(&self) -> Vec<HistoryEntry> {
        self.read_array(HISTORY_KEY)
    }

    pub fn clear_history(&mut self) {
        self.write(HISTORY_KEY, &Vec::<HistoryEntry>::new());
        let mut deleted = self.read_deleted();
        deleted.historyClearedAt = Some(now_iso());
        self.write_deleted(&deleted);
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
        all.insert(name.to_string(), serde_json::json!({ "value": value, "at": now_iso() }));
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
}
