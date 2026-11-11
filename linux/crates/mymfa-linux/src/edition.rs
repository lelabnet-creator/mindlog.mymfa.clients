/*
 * Contenu et modifications du coffre pour hyprdesk (LIN-05) : la même chose
 * que le web, par les mêmes règles (mymfa-core Store). Le contenu part en JSON
 * sans aucun secret (clé OTP, mot de passe de site, clé privée de passkey) ;
 * les opérations arrivent en JSON (`{"op": "...", ...}`) et rendent un JSON.
 *
 * Les erreurs portent le code i18n du web (`duplicate`, `invalidSecret`,
 * `invalidUri`…), que hyprdesk traduit.
 */
use mymfa_core::otp::{self, Algorithm};
use mymfa_core::otpauth::{self, OtpType};
use mymfa_core::passgen::{self, GenOptions};
use mymfa_core::store::{AccountPatch, LoginPatch, NewAccount, NewLogin, Store};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErreurOp {
    /// Saisie refusée : code i18n du web.
    Invalide(String),
    /// Élément absent (supprimé ailleurs entre-temps).
    Introuvable(String),
}

impl std::fmt::Display for ErreurOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ErreurOp::Invalide(c) => f.write_str(c),
            ErreurOp::Introuvable(id) => write!(f, "introuvable : {id}"),
        }
    }
}

fn invalide(code: &str) -> ErreurOp {
    ErreurOp::Invalide(code.to_string())
}

/* ───── Lecture des champs ───── */

fn texte(op: &Value, nom: &str) -> String {
    op.get(nom).and_then(Value::as_str).unwrap_or("").to_string()
}

fn texte_opt(op: &Value, nom: &str) -> Option<String> {
    op.get(nom).and_then(Value::as_str).map(str::to_string)
}

fn requis(op: &Value, nom: &str) -> Result<String, ErreurOp> {
    texte_opt(op, nom).filter(|s| !s.is_empty()).ok_or_else(|| invalide("missingField"))
}

/// Retire des objets d'une liste les champs secrets.
fn sans(valeur: Value, secrets: &[&str]) -> Value {
    match valeur {
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|mut v| {
                    if let Value::Object(o) = &mut v {
                        for s in secrets {
                            o.remove(*s);
                        }
                    }
                    v
                })
                .collect(),
        ),
        v => v,
    }
}

/* ───── Contenu ───── */

/// Tout le contenu du coffre, sans secret : comptes, logins (avec l'hôte et
/// la présence d'un mot de passe), passkeys, étiquettes, historique, réglages.
pub fn contenu(store: &Store) -> Value {
    let logins: Vec<Value> = store
        .logins()
        .into_iter()
        .map(|l| {
            let host = mymfa_core::store::host_of(&l.origin);
            let a_mdp = !l.password.is_empty();
            let longueur = l.password.chars().count();
            let mut v = serde_json::to_value(&l).unwrap_or(Value::Null);
            if let Value::Object(o) = &mut v {
                o.remove("password");
                o.insert("host".into(), json!(host));
                o.insert("hasPassword".into(), json!(a_mdp));
                o.insert("passwordLength".into(), json!(longueur));
            }
            v
        })
        .collect();
    json!({
        "accounts": sans(serde_json::to_value(store.list()).unwrap_or(Value::Null), &["secret"]),
        "logins": logins,
        "passkeys": sans(serde_json::to_value(store.site_passkeys()).unwrap_or(Value::Null), &["privateKey", "userHandle"]),
        "tags": store.tags(),
        "history": serde_json::to_value(store.history()).unwrap_or(Value::Null),
        "settings": Value::Object(store.settings()),
    })
}

/* ───── Comptes 2FA ───── */

/// Compte à ajouter, depuis une URI `otpauth://` (`uri`) ou des champs saisis.
fn nouveau_compte(op: &Value) -> Result<NewAccount, ErreurOp> {
    let mut n = if let Some(uri) = texte_opt(op, "uri").filter(|u| !u.trim().is_empty()) {
        let a = otpauth::parse(&uri).map_err(|e| invalide(e.code))?;
        NewAccount {
            type_: Some(a.type_.as_str().into()),
            issuer: a.issuer,
            account: a.account,
            secret: a.secret,
            algorithm: Some(a.algorithm.name().into()),
            digits: Some(a.digits),
            period: Some(a.period),
            counter: Some(a.counter),
            ..Default::default()
        }
    } else {
        let secret = otp::normalize_secret(&texte(op, "secret"));
        if secret.is_empty() {
            return Err(invalide("missingSecret"));
        }
        if !otp::is_valid_secret(&secret) {
            return Err(invalide("invalidSecret"));
        }
        let type_ = texte_opt(op, "type").unwrap_or_else(|| OtpType::Totp.as_str().into());
        if type_ != "totp" && type_ != "hotp" {
            return Err(invalide("unknownType"));
        }
        if let Some(a) = texte_opt(op, "algorithm") {
            Algorithm::parse(&a).ok_or_else(|| invalide("unsupportedAlgorithm"))?;
        }
        NewAccount {
            type_: Some(type_),
            issuer: texte(op, "issuer"),
            account: texte(op, "account"),
            secret,
            algorithm: texte_opt(op, "algorithm").map(|a| a.to_uppercase()),
            digits: op.get("digits").and_then(Value::as_u64).map(|d| d as u32),
            period: op.get("period").and_then(Value::as_u64),
            counter: op.get("counter").and_then(Value::as_i64),
            ..Default::default()
        }
    };
    // Les champs saisis l'emportent sur ceux de l'URI (vérification du service et du compte).
    if let Some(i) = texte_opt(op, "issuer").filter(|_| op.get("uri").is_some()) {
        n.issuer = i;
    }
    if let Some(a) = texte_opt(op, "account").filter(|_| op.get("uri").is_some()) {
        n.account = a;
    }
    if n.digits.is_some_and(|d| !(6..=8).contains(&d)) {
        return Err(invalide("unsupportedDigits"));
    }
    if n.period == Some(0) {
        return Err(invalide("invalidPeriod"));
    }
    n.tag = texte(op, "tag");
    n.description = texte(op, "description");
    n.favorite = op.get("favorite").and_then(Value::as_bool).unwrap_or(false);
    Ok(n)
}

/// Code du compte, maintenant (TOTP) ou au compteur enregistré (HOTP).
fn code_de(type_: &str, secret: &str, algorithme: &str, digits: u32, period: u64, counter: i64, maintenant_ms: u64) -> Option<String> {
    let algo = Algorithm::parse(algorithme).unwrap_or(Algorithm::Sha1);
    if type_ == "hotp" {
        otp::hotp(secret, counter.max(0) as u64, digits, algo).ok()
    } else {
        let p = if period == 0 { otp::DEFAULT_PERIOD } else { period };
        otp::totp(secret, p, digits, algo, maintenant_ms).ok()
    }
}

/// Aperçu d'un compte avant ajout (écran « Nouveau compte » du web) : champs
/// lus et code actuel, pour confirmer l'activation sur le site. Rien n'est écrit.
pub fn apercu(op: &Value, maintenant_ms: u64) -> Result<Value, ErreurOp> {
    let n = nouveau_compte(op)?;
    let type_ = n.type_.clone().unwrap_or_else(|| "totp".into());
    let algorithme = n.algorithm.clone().unwrap_or_else(|| "SHA1".into());
    let digits = n.digits.unwrap_or(6);
    let period = n.period.unwrap_or(30);
    let counter = n.counter.unwrap_or(0);
    let code = code_de(&type_, &n.secret, &algorithme, digits, period, counter, maintenant_ms).ok_or_else(|| invalide("invalidSecret"))?;
    Ok(json!({
        "type": type_, "issuer": n.issuer, "account": n.account, "algorithm": algorithme,
        "digits": digits, "period": period, "counter": counter, "code": code,
        "remaining": if type_ == "hotp" { 0 } else { otp::remaining_seconds(period, maintenant_ms) },
    }))
}

fn patch_compte(p: &Value) -> AccountPatch {
    AccountPatch {
        issuer: texte_opt(p, "issuer"),
        account: texte_opt(p, "account"),
        tag: texte_opt(p, "tag"),
        description: texte_opt(p, "description"),
        counter: p.get("counter").and_then(Value::as_i64),
        favorite: p.get("favorite").and_then(Value::as_bool),
    }
}

/* ───── Logins des sites ───── */

fn nouveau_login(op: &Value) -> NewLogin {
    NewLogin {
        origin: texte(op, "origin"),
        username: texte(op, "username"),
        password: texte(op, "password"),
        title: texte(op, "title"),
        note: texte(op, "note"),
        tag: texte(op, "tag"),
    }
}

fn patch_login(p: &Value) -> LoginPatch {
    LoginPatch {
        origin: texte_opt(p, "origin"),
        username: texte_opt(p, "username"),
        password: texte_opt(p, "password"),
        title: texte_opt(p, "title"),
        note: texte_opt(p, "note"),
        tag: texte_opt(p, "tag"),
        favorite: p.get("favorite").and_then(Value::as_bool),
    }
}

/* ───── Opérations ───── */

/// Applique une opération au magasin ; rend son résultat (JSON).
pub fn appliquer(store: &mut Store, op: &Value, maintenant_ms: u64) -> Result<Value, ErreurOp> {
    let nom = texte(op, "op");
    match nom.as_str() {
        "add_account" => {
            let n = nouveau_compte(op)?;
            if let Some(d) = store.find_duplicate(&n.secret, n.issuer.trim(), n.account.trim()) {
                return Err(ErreurOp::Invalide(format!("duplicate:{}", d.id)));
            }
            let source = texte_opt(op, "source").filter(|s| ["qr", "link", "key"].contains(&s.as_str()));
            let a = store.add(&n, source.as_deref());
            Ok(json!({ "id": a.id }))
        }
        "update_account" => {
            let id = requis(op, "id")?;
            let a = store
                .update(&id, &patch_compte(op.get("patch").unwrap_or(&Value::Null)))
                .map_err(|_| ErreurOp::Introuvable(id))?;
            Ok(json!({ "id": a.id }))
        }
        "remove_account" => {
            let id = requis(op, "id")?;
            if !store.remove(&id) {
                return Err(ErreurOp::Introuvable(id));
            }
            Ok(json!({}))
        }
        "next_hotp" => {
            let id = requis(op, "id")?;
            let a = store.get(&id).ok_or_else(|| ErreurOp::Introuvable(id.clone()))?;
            if a.type_ != "hotp" {
                return Err(invalide("notHotp"));
            }
            let suivant = a.counter + 1;
            let a = store
                .update(&id, &AccountPatch { counter: Some(suivant), ..Default::default() })
                .map_err(|_| ErreurOp::Introuvable(id))?;
            let code = code_de("hotp", &a.secret, &a.algorithm, a.digits, a.period, a.counter, maintenant_ms).unwrap_or_default();
            Ok(json!({ "counter": a.counter, "code": code }))
        }
        "touch_account" => {
            store.touch_account(&requis(op, "id")?);
            Ok(json!({}))
        }
        "add_login" => {
            let l = store.add_login(&nouveau_login(op), texte_opt(op, "source").as_deref()).map_err(|e| invalide(e.code))?;
            Ok(json!({ "id": l.id }))
        }
        "update_login" => {
            let id = requis(op, "id")?;
            let l = store
                .update_login(&id, &patch_login(op.get("patch").unwrap_or(&Value::Null)))
                .map_err(|e| if e.code == "loginNotFound" { ErreurOp::Introuvable(id.clone()) } else { invalide(e.code) })?;
            Ok(json!({ "id": l.id }))
        }
        "remove_login" => {
            let id = requis(op, "id")?;
            if !store.remove_login(&id) {
                return Err(ErreurOp::Introuvable(id));
            }
            Ok(json!({}))
        }
        "touch_login" => {
            store.touch_login(&requis(op, "id")?);
            Ok(json!({}))
        }
        "remove_passkey" => {
            let id = requis(op, "id")?;
            if !store.remove_passkey(&id) {
                return Err(ErreurOp::Introuvable(id));
            }
            Ok(json!({}))
        }
        "set_setting" => {
            let nom = requis(op, "name")?;
            store.set_setting(&nom, op.get("value").unwrap_or(&Value::Null));
            Ok(json!({}))
        }
        "clear_history" => {
            store.clear_history();
            Ok(json!({}))
        }
        "import" => {
            let payload = requis(op, "payload")?;
            let stats = store.import_all(&payload).map_err(|e| invalide(e.code))?;
            Ok(serde_json::to_value(stats).unwrap_or(Value::Null))
        }
        _ => Err(invalide("unknownOperation")),
    }
}

/// Mot de passe généré (générateur du web) : longueur, chiffres, symboles,
/// ou phrase de syllabes.
pub fn generer(options: &Value) -> String {
    let d = GenOptions::default();
    passgen::generate_password(&GenOptions {
        length: options.get("length").and_then(Value::as_u64).map(|n| n as usize).unwrap_or(d.length).clamp(4, 128),
        digits: options.get("digits").and_then(Value::as_bool).unwrap_or(d.digits),
        symbols: options.get("symbols").and_then(Value::as_bool).unwrap_or(d.symbols),
        words: options.get("words").and_then(Value::as_bool).unwrap_or(d.words),
    })
}

/// Export JSON du web (comptes et historique, en clair : à ranger à l'abri).
/* ───── Santé des mots de passe (tableau de bord, MLG-46) ───── */

/// Solidité heuristique partagée avec le web (passwordStrength) : 0-4.
fn solidite_niveau(mot: &str) -> u8 {
    mymfa_core::vault::password_strength(mot).level
}

/// Santé des mots de passe, pour le tableau de bord de hyprdesk : faibles
/// (solidité ≤ 2), réutilisés (même mot de passe sur plusieurs sites),
/// à renouveler (politique : un an). Jamais de mot de passe ni d'empreinte
/// dans la réponse : ids et libellés seulement. Les fuites (HIBP) restent
/// côté web en attendant leur port.
pub fn audit(store: &Store) -> Value {
    let an = 365.0 * 24.0 * 3600.0 * 1000.0;
    #[allow(clippy::unnecessary_cast)]
    let maintenant = crate::chemins::maintenant() as f64 * 1000.0;
    let mut empreintes: std::collections::BTreeMap<String, Vec<String>> = std::collections::BTreeMap::new();
    let mut faibles: Vec<Value> = Vec::new();
    let mut a_renouveller: Vec<Value> = Vec::new();
    for l in store.logins() {
        let id = l.id.clone();
        let site = if l.title.is_empty() { l.origin.clone() } else { l.title.clone() };
        let label = format!("{site} — {}", l.username);
        let niveau = solidite_niveau(&l.password);
        if niveau <= 2 {
            faibles.push(json!({ "id": id, "label": label, "niveau": niveau }));
        }
        let changement = &l.passwordChangedAt;
        if !changement.is_empty() {
            let t = mymfa_core::sync2::iso_vers_ms(changement).unwrap_or(0);
            if t > 0 && (maintenant as i64) - t > an as i64 {
                a_renouveller.push(json!({ "id": id, "label": label, "change_le": changement }));
            }
        }
        let empreinte = {
            use sha2::{Digest, Sha256};
            let h = Sha256::digest(l.password.as_bytes());
            h[..8].iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        empreintes.entry(empreinte).or_default().push(label);
    }
    let reutilises: Vec<Value> = empreintes
        .into_values()
        .filter(|sites| sites.len() > 1)
        .map(|sites| json!({ "sites": sites }))
        .collect();
    json!({
        "faibles": faibles,
        "reutilises": reutilises,
        "aRenouveler": a_renouveller,
    })
}

pub fn exporter(store: &Store) -> String {
    serde_json::to_string_pretty(&store.export_all()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn contenu_sans_secret() {
        let mut s = Store::new();
        appliquer(&mut s, &json!({"op":"add_account","secret":SECRET,"issuer":"GitHub","account":"moi","tag":"Travail"}), 0).unwrap();
        appliquer(&mut s, &json!({"op":"add_login","origin":"https://github.com","username":"moi","password":"hunter2-très-long"}), 0).unwrap();
        let c = contenu(&s);
        let texte = c.to_string();
        assert!(!texte.contains(SECRET), "clé OTP absente");
        assert!(!texte.contains("hunter2"), "mot de passe absent");
        assert_eq!(c["accounts"][0]["issuer"], "GitHub");
        assert_eq!(c["logins"][0]["host"], "github.com");
        assert_eq!(c["logins"][0]["hasPassword"], true);
        assert_eq!(c["history"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn ajout_par_uri_doublon_et_apercu() {
        let mut s = Store::new();
        let uri = format!("otpauth://totp/GitHub:moi?secret={SECRET}&issuer=GitHub&digits=8");
        let a = apercu(&json!({"uri": uri}), 59_000).unwrap();
        assert_eq!(a["code"], "94287082", "RFC 6238 : T = 59 s, 8 chiffres");
        appliquer(&mut s, &json!({"op":"add_account","uri":uri,"source":"qr"}), 0).unwrap();
        let e = appliquer(&mut s, &json!({"op":"add_account","uri":uri}), 0).unwrap_err();
        assert!(matches!(e, ErreurOp::Invalide(c) if c.starts_with("duplicate:")));
        assert_eq!(appliquer(&mut s, &json!({"op":"add_account","secret":"pas du base32 !"}), 0).unwrap_err(), invalide("invalidSecret"));
        assert_eq!(appliquer(&mut s, &json!({"op":"add_account","uri":"https://x"}), 0).unwrap_err(), invalide("notOtpauth"));
    }

    #[test]
    fn hotp_suivant_modification_suppression() {
        let mut s = Store::new();
        let id = appliquer(&mut s, &json!({"op":"add_account","secret":SECRET,"type":"hotp","issuer":"Banque","counter":0}), 0).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        let r = appliquer(&mut s, &json!({"op":"next_hotp","id":id}), 0).unwrap();
        assert_eq!((r["counter"].as_i64(), r["code"].as_str()), (Some(1), Some("287082")), "RFC 4226 : compteur 1");
        appliquer(&mut s, &json!({"op":"update_account","id":id,"patch":{"favorite":true,"tag":"Perso"}}), 0).unwrap();
        assert!(s.get(&id).unwrap().favorite);
        appliquer(&mut s, &json!({"op":"remove_account","id":id}), 0).unwrap();
        assert!(s.get(&id).is_none());
        assert_eq!(appliquer(&mut s, &json!({"op":"remove_account","id":id}), 0).unwrap_err(), ErreurOp::Introuvable(id));
    }

    #[test]
    fn logins_reglages_import_export() {
        let mut s = Store::new();
        let id = appliquer(&mut s, &json!({"op":"add_login","origin":"https://github.com","username":"moi","password":"a"}), 0).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        appliquer(&mut s, &json!({"op":"update_login","id":id,"patch":{"password":"bien plus long"}}), 0).unwrap();
        assert_eq!(s.logins()[0].password, "bien plus long");
        appliquer(&mut s, &json!({"op":"set_setting","name":"hideCodes","value":true}), 0).unwrap();
        assert_eq!(s.setting("hideCodes"), Some(json!(true)));
        appliquer(&mut s, &json!({"op":"add_account","secret":SECRET,"issuer":"GitHub"}), 0).unwrap();
        let export = exporter(&s);
        let mut autre = Store::new();
        let stats = appliquer(&mut autre, &json!({"op":"import","payload":export}), 0).unwrap();
        assert_eq!(stats["added"], 1);
        assert_eq!(appliquer(&mut s, &json!({"op":"nimporte"}), 0).unwrap_err(), invalide("unknownOperation"));
        assert_eq!(generer(&json!({"length": 32})).chars().count(), 32);
    }
}
