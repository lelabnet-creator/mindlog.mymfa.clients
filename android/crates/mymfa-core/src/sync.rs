/*
 * Fusion de deux copies des données myMFA (app ↔ extension ↔ Android).
 * Réplique de ../web/js/sync.js — entrées et sortie : { clé localStorage → JSON en texte }.
 */
use crate::store::{ACCOUNTS_KEY, DELETED_KEY, HISTORY_KEY, HISTORY_MAX, LOGINS_KEY, PASSKEYS_KEY, SETTINGS_KEY};
use crate::DataMap;
use serde_json::{Map, Value};

pub const TOMBSTONES_MAX: usize = 1000;

/// Clés fusionnées, dans l'ordre du web.
pub const KEYS: &[&str] =
    &[ACCOUNTS_KEY, HISTORY_KEY, DELETED_KEY, LOGINS_KEY, PASSKEYS_KEY, SETTINGS_KEY];

fn parse_json(raw: Option<&String>, fallback: Value) -> Value {
    match raw {
        Some(text) => serde_json::from_str(text).unwrap_or(fallback),
        None => fallback,
    }
}

fn list(map: &DataMap, key: &str) -> Vec<Value> {
    match parse_json(map.get(key), Value::Array(Vec::new())) {
        Value::Array(items) => items,
        _ => Vec::new(),
    }
}

struct Copy {
    history: Vec<Value>,
    deleted_accounts: Map<String, Value>,
    history_cleared_at: Option<String>,
}

fn read(map: &DataMap) -> Copy {
    let deleted = match parse_json(map.get(DELETED_KEY), Value::Object(Map::new())) {
        Value::Object(object) => object,
        _ => Map::new(),
    };
    Copy {
        history: match parse_json(map.get(HISTORY_KEY), Value::Array(Vec::new())) {
            Value::Array(items) => items,
            _ => Vec::new(),
        },
        deleted_accounts: match deleted.get("accounts") {
            Some(Value::Object(accounts)) => accounts.clone(),
            _ => Map::new(),
        },
        history_cleared_at: deleted
            .get("historyClearedAt")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    }
}

/// La date la plus récente (comparaison lexicographique, ISO 8601), comme `later` côté web.
fn later<'a>(x: Option<&'a str>, y: Option<&'a str>) -> Option<&'a str> {
    match (x, y) {
        (Some(a), Some(b)) => Some(if a > b { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

fn field<'a>(item: &'a Value, name: &str) -> Option<&'a str> {
    item.get(name).and_then(Value::as_str)
}

/// Identité « même élément ajouté des deux côtés » (separateur NUL, comme le web).
fn same_accounts(item: &Value) -> String {
    format!(
        "{}\0{}\0{}",
        field(item, "secret").unwrap_or(""),
        field(item, "issuer").unwrap_or(""),
        field(item, "account").unwrap_or("")
    )
}

fn same_logins(item: &Value) -> String {
    format!("{}\0{}", field(item, "origin").unwrap_or(""), field(item, "username").unwrap_or(""))
}

fn same_passkeys(item: &Value) -> String {
    field(item, "credentialId").unwrap_or("").to_string()
}

/// Fusionne deux copies : union par id (la version modifiée le plus récemment
/// gagne), les suppressions l'emportent toujours, les doublons par identité sont
/// enterrés, l'historique est plafonné, les réglages suivent `at`.
pub fn merge(left: &DataMap, right: &DataMap, now: &str) -> DataMap {
    let a = read(left);
    let b = read(right);

    let mut tombs: Map<String, Value> = a.deleted_accounts.clone();
    for (id, at) in &b.deleted_accounts {
        let merged = later(
            tombs.get(id).and_then(Value::as_str),
            at.as_str(),
        )
        .map(str::to_string)
        .unwrap_or_default();
        tombs.insert(id.clone(), Value::String(merged));
    }
    let history_cleared_at = later(a.history_cleared_at.as_deref(), b.history_cleared_at.as_deref())
        .map(str::to_string);

    let collections: &[(&str, fn(&Value) -> String)] = &[
        (ACCOUNTS_KEY, same_accounts),
        (LOGINS_KEY, same_logins),
        (PASSKEYS_KEY, same_passkeys),
    ];

    let mut merged: DataMap = DataMap::new();
    for &(key, identity) in collections {
        // Collections récentes : absentes des deux côtés, elles le restent.
        if key != ACCOUNTS_KEY && !left.contains_key(key) && !right.contains_key(key) {
            continue;
        }
        let mut by_id = Map::new(); // préserve l'ordre d'insertion (left puis right)
        for item in list(left, key).into_iter().chain(list(right, key)) {
            let Some(id) = field(&item, "id") else { continue };
            if tombs.get(id).is_some() {
                continue;
            }
            let current = by_id.get(id).cloned();
            let mut chosen = match &current {
                None => item.clone(),
                Some(current) => {
                    let current_at = field(current, "updatedAt").unwrap_or("");
                    let item_at = field(&item, "updatedAt").unwrap_or("");
                    if item_at > current_at { item.clone() } else { current.clone() }
                }
            };
            // Dernière utilisation : la plus récente des deux copies, sans
            // compter comme une modification.
            let used_at = later(
                current.as_ref().and_then(|c| field(c, "usedAt")),
                field(&item, "usedAt"),
            )
            .map(str::to_string);
            if let Some(used_at) = used_at {
                if field(&chosen, "usedAt") != Some(used_at.as_str()) {
                    chosen["usedAt"] = Value::String(used_at);
                }
            }
            by_id.insert(id.to_string(), chosen);
        }
        let mut ordered: Vec<Value> = by_id.into_values().collect();
        ordered.sort_by(|x, y| {
            field(x, "createdAt").unwrap_or("").cmp(field(y, "createdAt").unwrap_or(""))
        });
        let mut seen = std::collections::HashSet::new();
        let mut items = Vec::with_capacity(ordered.len());
        for item in ordered {
            let identity_key = identity(&item);
            if seen.contains(&identity_key) {
                // Doublon : l'autre côté le retirera aussi.
                if let Some(id) = field(&item, "id") {
                    tombs.insert(id.to_string(), Value::String(now.to_string()));
                }
                continue;
            }
            seen.insert(identity_key);
            items.push(item);
        }
        merged.insert(key.to_string(), serde_json::to_string(&items).unwrap_or_else(|_| "[]".into()));
    }

    // Historique : union par id (premier vu), sans ce qui précède le dernier
    // vidage, tri décroissant, plafonné.
    let mut entries: Map<String, Value> = Map::new();
    for entry in a.history.into_iter().chain(b.history) {
        let Some(id) = field(&entry, "id") else { continue };
        if entries.contains_key(id) {
            continue;
        }
        if let Some(cleared) = &history_cleared_at {
            if field(&entry, "at").unwrap_or("") <= cleared.as_str() {
                continue;
            }
        }
        entries.insert(id.to_string(), entry);
    }
    let mut history: Vec<Value> = entries.into_values().collect();
    history.sort_by(|x, y| field(y, "at").unwrap_or("").cmp(field(x, "at").unwrap_or("")));
    history.truncate(HISTORY_MAX);

    let mut kept_tombs: Vec<(String, String)> = tombs
        .into_iter()
        .filter_map(|(id, at)| at.as_str().map(|a| (id, a.to_string())))
        .collect();
    kept_tombs.sort_by(|x, y| y.1.cmp(&x.1));
    kept_tombs.truncate(TOMBSTONES_MAX);
    let mut kept = Map::new();
    for (id, at) in kept_tombs {
        kept.insert(id, Value::String(at));
    }

    if let Some(settings) = merge_settings(left, right) {
        merged.insert(SETTINGS_KEY.to_string(), settings);
    }
    merged.insert(HISTORY_KEY.to_string(), serde_json::to_string(&history).unwrap_or_else(|_| "[]".into()));
    merged.insert(
        DELETED_KEY.to_string(),
        serde_json::to_string(&serde_json::json!({
            "accounts": kept,
            "historyClearedAt": history_cleared_at,
        }))
        .unwrap_or_else(|_| "{}".into()),
    );
    merged
}

/// Réglages : union par nom, le plus récent (`at`) l'emporte. Absents des deux côtés : rien.
fn merge_settings(left: &DataMap, right: &DataMap) -> Option<String> {
    if !left.contains_key(SETTINGS_KEY) && !right.contains_key(SETTINGS_KEY) {
        return None;
    }
    let object = |map: &DataMap| -> Map<String, Value> {
        match parse_json(map.get(SETTINGS_KEY), Value::Object(Map::new())) {
            Value::Object(object) => object,
            _ => Map::new(),
        }
    };
    let mut out = object(left);
    for (name, entry) in object(right) {
        let is_entry = entry.is_object(); // comme `typeof entry === 'object'` (tableaux inclus)
        if !is_entry {
            continue;
        }
        let replace = match out.get(&name) {
            None => true,
            Some(current) => {
                let entry_at = entry.get("at").and_then(Value::as_str).unwrap_or("");
                let current_at = current.get("at").and_then(Value::as_str).unwrap_or("");
                entry_at > current_at
            }
        };
        if replace {
            out.insert(name, entry);
        }
    }
    Some(serde_json::to_string(&out).unwrap_or_else(|_| "{}".into()))
}

/// Sous-ensemble des clés de données d'une copie.
pub fn pick(map: &DataMap) -> DataMap {
    KEYS.iter().filter_map(|key| map.get(*key).map(|v| (key.to_string(), v.clone()))).collect()
}

/// Deux copies identiques, clé par clé (`?? null` côté web : absent ≡ null).
pub fn same(left: &DataMap, right: &DataMap) -> bool {
    KEYS.iter().all(|key| left.get(*key) == right.get(*key))
}

/// Les données contiennent-elles des mots de passe ou des passkeys de sites ?
pub fn has_credentials(map: &DataMap) -> bool {
    !list(map, LOGINS_KEY).is_empty() || !list(map, PASSKEYS_KEY).is_empty()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, String)]) -> DataMap {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    fn account(id: &str, secret: &str, issuer: &str, created: &str, updated: &str) -> String {
        serde_json::to_string(&serde_json::json!({
            "id": id, "type": "totp", "issuer": issuer, "account": "moi",
            "secret": secret, "algorithm": "SHA1", "digits": 6, "period": 30, "counter": 0,
            "tag": "", "description": "", "favorite": false,
            "createdAt": created, "updatedAt": updated,
        }))
        .unwrap()
    }

    fn accounts_json(items: &[String]) -> String {
        format!("[{}]", items.join(","))
    }

    const NOW: &str = "2026-11-05T12:00:00.000Z";

    #[test]
    fn conflit_par_updated_at_et_tombstone() {
        let left = map(&[
            (ACCOUNTS_KEY, accounts_json(&[account("a", "JBSWY3DP", "GitHub", "2026-01-01", "2026-02-01")])),
            (DELETED_KEY, r#"{"accounts":{"z":"2026-03-01"},"historyClearedAt":null}"#.into()),
        ]);
        // a réapparaît côté droit avec un updatedAt plus ancien : l'ancien doit gagner ;
        // z est enterré côté gauche : il ne doit pas réapparaître.
        let right = map(&[(
            ACCOUNTS_KEY,
            accounts_json(&[
                account("a", "JBSWY3DP", "GitHub", "2026-01-01", "2026-01-15"),
                account("z", "JBSWY3DPZ", "Old", "2025-12-01", "2025-12-01"),
            ]),
        )]);
        let out = merge(&left, &right, NOW);
        let accounts: Vec<Value> = serde_json::from_str(out.get(ACCOUNTS_KEY).unwrap()).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["updatedAt"], "2026-02-01");
        let deleted: Value = serde_json::from_str(out.get(DELETED_KEY).unwrap()).unwrap();
        assert!(deleted["accounts"].get("z").is_some());
    }

    #[test]
    fn doublon_par_identite_le_plus_ancien_gagne() {
        // Même (secret, issuer, account) sous deux id : le plus ancien est gardé, l'autre enterré.
        let left = map(&[(ACCOUNTS_KEY, accounts_json(&[account("new", "JBSWY3DP", "GitHub", "2026-06-01", "2026-06-01")]))]);
        let right = map(&[(ACCOUNTS_KEY, accounts_json(&[account("old", "JBSWY3DP", "GitHub", "2026-01-01", "2026-01-01")]))]);
        let out = merge(&left, &right, NOW);
        let accounts: Vec<Value> = serde_json::from_str(out.get(ACCOUNTS_KEY).unwrap()).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["id"], "old");
        let deleted: Value = serde_json::from_str(out.get(DELETED_KEY).unwrap()).unwrap();
        assert_eq!(deleted["accounts"]["new"], NOW);
    }

    #[test]
    fn historique_plafonne_et_filtre_vidage() {
        let entries: Vec<String> = (0..505)
            .map(|i| {
                serde_json::to_string(&serde_json::json!({
                    "id": format!("h{i}"), "at": format!("2026-10-{i:02}T00:00:00.000Z"),
                    "action": "create", "accountId": null, "label": null, "tag": null, "details": null,
                }))
                .unwrap()
            })
            .collect();
        let joined = format!("[{}]", entries.join(","));
        let left = map(&[(HISTORY_KEY, joined)]);
        let right = map(&[(DELETED_KEY, r#"{"accounts":{},"historyClearedAt":"2026-10-02T00:00:00.000Z"}"#.into())]);
        let out = merge(&left, &right, NOW);
        let history: Vec<Value> = serde_json::from_str(out.get(HISTORY_KEY).unwrap()).unwrap();
        assert!(history.len() <= HISTORY_MAX);
        assert!(history.iter().all(|e| e["at"].as_str().unwrap() > "2026-10-02T00:00:00.000Z"));
    }

    #[test]
    fn used_at_le_plus_recent_sans_compter_comme_modification() {
        let mut older = serde_json::from_str::<Value>(&account("a", "JBSWY3DP", "GitHub", "2026-01-01", "2026-02-01")).unwrap();
        older["usedAt"] = Value::String("2026-05-01".into());
        let mut newer = older.clone();
        newer["usedAt"] = Value::String("2026-04-01".into()); // plus ancien, mais updatedAt plus récent
        newer["updatedAt"] = Value::String("2026-03-01".into());
        let left = map(&[(ACCOUNTS_KEY, serde_json::to_string(&[older]).unwrap())]);
        let right = map(&[(ACCOUNTS_KEY, serde_json::to_string(&[newer]).unwrap())]);
        let out = merge(&left, &right, NOW);
        let accounts: Vec<Value> = serde_json::from_str(out.get(ACCOUNTS_KEY).unwrap()).unwrap();
        assert_eq!(accounts[0]["updatedAt"], "2026-03-01");
        assert_eq!(accounts[0]["usedAt"], "2026-05-01");
    }

    #[test]
    fn reglages_le_plus_recent_gagne() {
        let left = map(&[(
            SETTINGS_KEY,
            r#"{"policy":{"value":{"minLength":12},"at":"2026-01-01"},"prefs":{"value":{"theme":"dark"},"at":"2026-05-01"}}"#.into(),
        )]);
        let right = map(&[(
            SETTINGS_KEY,
            r#"{"policy":{"value":{"minLength":16},"at":"2026-06-01"},"prefs":{"value":{"theme":"light"},"at":"2026-03-01"}}"#.into(),
        )]);
        let out = merge(&left, &right, NOW);
        let settings: Value = serde_json::from_str(out.get(SETTINGS_KEY).unwrap()).unwrap();
        assert_eq!(settings["policy"]["value"]["minLength"], 16);
        assert_eq!(settings["prefs"]["value"]["theme"], "dark");
    }

    #[test]
    fn collections_absentes_des_deux_cotes_non_ecrites() {
        let left = map(&[(ACCOUNTS_KEY, "[]".into())]);
        let out = merge(&left, &DataMap::new(), NOW);
        assert!(!out.contains_key(LOGINS_KEY));
        assert!(!out.contains_key(PASSKEYS_KEY));
        assert!(out.contains_key(ACCOUNTS_KEY)); // toujours écrite
        assert_eq!(pick(&left), left);
        assert!(same(&left, &left));
        assert!(!has_credentials(&left));
    }
}
