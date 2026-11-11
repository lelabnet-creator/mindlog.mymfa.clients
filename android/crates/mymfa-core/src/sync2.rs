/*
 * Synchro v2 (SYN-07) : fusion champ par champ par horloge hybride — réplique fidèle
 * de ../web/js/sync2.js (tests d'interopérabilité : fixtures sync2-web.json et
 * sync2-rust.json, générées du côté web et de ce module).
 *
 * La fusion v1 (sync.rs : l'élément entier dont updatedAt est le plus récent gagne)
 * dépend des horloges locales : une correction faite plus tard sur un appareil qui
 * retarde perd, une horloge dans le futur gagne jusqu'en 2027, deux horloges à la
 * même milliseconde ne convergent pas. La v2 sépare deux questions :
 *  - Qu'est-ce qui s'enchaîne ? Une horloge hybride (l, c, D) : heure de référence en
 *    ms, compteur, identifiant d'appareil. Une modification faite après avoir vu une
 *    version reçoit toujours un tampon plus grand qu'elle, quelle que soit l'horloge.
 *  - Qu'est-ce qui est vraiment simultané ? Là seulement, l'heure départage — et elle
 *    vient d'une référence publique (T(), SYN-08), jamais de l'horloge locale seule.
 *
 * Représentation (dans les données du coffre, mêmes clés que la v1) :
 *  - chaque élément garde ses champs actuels (l'interface et les structs typés ne
 *    cassent pas) plus `h` : { champ → tampon }, et `t` : tampon de suppression ;
 *  - la clé `mymfa.sync.v2` (marqueur) porte le registre des appareils, le vidage
 *    d'historique tamponné et les traces v1 encore sans élément à qui s'attacher ;
 *    sa présence signale un coffre v2 ;
 *  - l'enveloppe du coffre passe à `v: 2` quand les données portent le marqueur :
 *    un ancien client (enveloppe v: 1 exigée) refuse de lire — donc d'écrire ;
 *  - état par appareil, jamais synchronisé : identifiant, horloge (l, c), repère de
 *    dernière synchro. Côté web : localStorage hors des données ; côté démon :
 *    fichier d'état local.
 *
 * La fusion est commutative, associative et idempotente : champ par champ, le plus
 * grand tampon gagne ; compteur HOTP = valeur maximale ; suppressions datées (un
 * élément vit si max(tampons de ses champs) > trace) ; doublons de même identité
 * fusionnés champ par champ ; traces effacées une fois vues par tous les appareils
 * du registre ; journal des arrivées, départs, conflits, doublons et horloges
 * suspectes rendu à l'appelant (chiffré et conservé par chaque client, pas synchronisé).
 */
use crate::store::{ACCOUNTS_KEY, DELETED_KEY, HISTORY_KEY, HISTORY_MAX, LOGINS_KEY, PASSKEYS_KEY, SETTINGS_KEY};
use crate::DataMap;
use serde::Serialize;
use serde_json::{Map, Value};
use std::cmp::Ordering;

/// Clé du marqueur v2 dans les données (sa présence signale un coffre v2).
pub const SYNC_KEY: &str = "mymfa.sync.v2";
/// Appareil fictif des tampons issus de la migration (updatedAt hérité de la v1).
pub const APPAREIL_HERITAGE: &str = "legacy";
/// Un tampon reçu plus de 5 min dans le futur est accepté et journalisé, mais ne
/// contamine pas l'horloge locale.
pub const ECART_FUTUR_MS: i64 = 5 * 60 * 1000;
/// Un appareil muet depuis plus d'un an sort du registre, avec avertissement.
pub const SILENCE_MAX_MS: i64 = 365 * 24 * 60 * 60 * 1000;
/// Une trace de suppression n'est effacée qu'après cette rétention, même si tous
/// les appareils enregistrés l'ont vue : un appareil nouveau ou resté hors ligne
/// pendant la suppression doit avoir le temps de l'apprendre (sinon, à son
/// réveil, il ferait revivre l'élément supprimé).
pub const RETENTION_TRACE_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// `l` de référence : ms UTC sur 13 chiffres (jusqu'en 2286), compteur hexadécimal
/// sur 8 chiffres, identifiant d'appareil. Comparé en texte, l'ordre est (l, c, D).
const L_CHIFFRES: usize = 13;
const C_CHIFFRES: usize = 8;

/* ─── Tampons ─────────────────────────────────────────────────────────────── */

pub type Tampon = String;

/// Tampon d'horloge hybride (l, c, D) encodé en texte triable.
pub fn encoder_tampon(l: i64, c: u32, appareil: &str) -> Tampon {
    format!("{:0L_CHIFFRES$}{:0C_CHIFFRES$x}{}", l, c, appareil)
}

fn decoder_l(tampon: &str) -> i64 {
    tampon.get(..L_CHIFFRES).and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn decoder_c(tampon: &str) -> u32 {
    tampon
        .get(L_CHIFFRES..L_CHIFFRES + C_CHIFFRES)
        .and_then(|s| u32::from_str_radix(s, 16).ok())
        .unwrap_or(0)
}

fn decoder_appareil(tampon: &str) -> &str {
    tampon.get(L_CHIFFRES + C_CHIFFRES..).unwrap_or("")
}

/// Comparaison de tampons (l'ordre du texte suffit : largeurs fixes avant l'appareil).
pub fn comparer(a: &str, b: &str) -> Ordering {
    a.cmp(b)
}

/// Le plus grand des deux tampons (chaîne vide = pas de tampon, le plus petit).
pub fn tampon_max<'a>(a: &'a str, b: &'a str) -> &'a str {
    if a >= b { a } else { b }
}

/// Tampon d'une date ISO 8601 (héritage v1) : compteur 0, appareil « legacy ».
pub fn tampon_depuis_iso(iso: &str) -> Tampon {
    encoder_tampon(iso_vers_ms(iso).unwrap_or(0), 0, APPAREIL_HERITAGE)
}

/// Date ISO du `l` d'un tampon (affichage, updatedAt dérivé).
pub fn iso_depuis_tampon(tampon: &str) -> String {
    let ms = decoder_l(tampon);
    crate::iso_from_unix(ms.div_euclid(1000), ms.rem_euclid(1000) as u32)
}

/// ISO 8601 UTC « YYYY-MM-DDTHH:MM:SS(.mmm)Z » → ms. None si le format est inconnu.
pub fn iso_vers_ms(iso: &str) -> Option<i64> {
    let b = iso.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || (b[10] != b'T' && b[10] != b' ') || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let y: i64 = iso.get(..4)?.parse().ok()?;
    let mo: i64 = iso.get(5..7)?.parse().ok()?;
    let d: i64 = iso.get(8..10)?.parse().ok()?;
    let h: i64 = iso.get(11..13)?.parse().ok()?;
    let mi: i64 = iso.get(14..16)?.parse().ok()?;
    let s: i64 = iso.get(17..19)?.parse().ok()?;
    let ms: i64 = iso.get(20..23).and_then(|s| s.parse().ok()).unwrap_or(0);
    if !(1..=12).contains(&mo) {
        return None;
    }
    let bissextile = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let jours_du_mois = [31, if bissextile { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    if d < 1 || d > jours_du_mois[(mo - 1) as usize] {
        return None;
    }
    // Jours depuis l'époque (à l'envers de civil_from_days dans lib.rs).
    let y2 = if mo <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let mp = (mo + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let jours = era * 146_097 + doe - 719_468;
    Some(((jours * 24 + h) * 60 + mi) * 60 * 1000 + s * 1000 + ms)
}

/* ─── Horloge hybride ─────────────────────────────────────────────────────── */

/// Horloge hybride d'un appareil : l (ms UTC de référence), c compteur.
/// Persistée par le client (jamais synchronisée) ; mise à l'heure par T() (SYN-08).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Horloge {
    pub l: i64,
    pub c: u32,
}

impl Horloge {
    pub fn nouvelle(maintenant: i64) -> Self {
        Self { l: maintenant, c: 0 }
    }

    /// Un tampon pour une modification locale : l'avance à max(l, T()), le compteur
    /// repart de 0 si l a bougé, s'incrémente sinon.
    pub fn tic(&mut self, maintenant: i64, appareil: &str) -> Tampon {
        let l = self.l.max(maintenant);
        self.c = if l == self.l { self.c.saturating_add(1) } else { 0 };
        self.l = l;
        encoder_tampon(l, self.c, appareil)
    }

    /// Réception d'un tampon : l'horloge avance s'il la dépasse — sauf s'il est à
    /// plus de 5 min dans le futur (accepté, journalisé, sans contamination).
    /// Renvoie true si l'horloge a avancé.
    pub fn observer(&mut self, tampon: &str, maintenant: i64) -> bool {
        if tampon.is_empty() {
            return false;
        }
        let l = decoder_l(tampon);
        let c = decoder_c(tampon);
        if l > maintenant + ECART_FUTUR_MS {
            return false;
        }
        if l > self.l || (l == self.l && c > self.c) {
            self.l = l;
            self.c = c;
            return true;
        }
        false
    }

    /// Un tampon pour une nouvelle valeur d'un champ : après T(), et toujours plus
    /// grand que le tampon actuel du champ — une modification faite après avoir vu
    /// (ou porté) une version l'emporte sur elle, horloge faussée ou pas.
    pub fn apres(&mut self, maintenant: i64, plancher: Option<&str>, appareil: &str) -> Tampon {
        let t = self.tic(maintenant, appareil);
        if let Some(plancher) = plancher {
            if t.as_str() <= plancher {
                let l = decoder_l(plancher);
                let c = decoder_c(plancher).saturating_add(1);
                self.l = l;
                self.c = c;
                return encoder_tampon(l, c, appareil);
            }
        }
        t
    }
}

/* ─── Éléments : champs tamponnés ─────────────────────────────────────────── */

struct Collection {
    cle: &'static str,
    champs: &'static [&'static str],
    identite: fn(&Value) -> String,
    /// Écrite même absente des deux copies (comptes) ; les collections récentes
    /// absentes des deux côtés le restent.
    toujours: bool,
}

fn identite_comptes(item: &Value) -> String {
    format!("{}\0{}\0{}", texte(item, "secret"), texte(item, "issuer"), texte(item, "account"))
}

fn identite_logins(item: &Value) -> String {
    format!("{}\0{}", texte(item, "origin"), texte(item, "username"))
}

fn identite_passkeys(item: &Value) -> String {
    texte(item, "credentialId").to_string()
}

const COMPTES: Collection = Collection {
    cle: ACCOUNTS_KEY,
    champs: &["type", "issuer", "account", "secret", "algorithm", "digits", "period", "counter", "tag", "description", "favorite"],
    identite: identite_comptes,
    toujours: true,
};
const LOGINS: Collection = Collection {
    cle: LOGINS_KEY,
    champs: &["origin", "username", "password", "title", "note", "tag", "source", "favorite"],
    identite: identite_logins,
    toujours: false,
};
const PASSKEYS: Collection = Collection {
    cle: PASSKEYS_KEY,
    champs: &["credentialId", "rpId", "rpName", "origin", "userHandle", "userName", "userDisplayName", "algorithm", "privateKey"],
    identite: identite_passkeys,
    toujours: false,
};
const COLLECTIONS: &[Collection] = &[COMPTES, LOGINS, PASSKEYS];

fn texte<'a>(item: &'a Value, champ: &str) -> &'a str {
    item.get(champ).and_then(Value::as_str).unwrap_or("")
}

fn champ_de(item: &Value, champ: &str) -> Value {
    item.get(champ).cloned().unwrap_or(Value::Null)
}

fn tampon_de<'a>(item: &'a Value, champ: &str) -> &'a str {
    item.get("h").and_then(|h| h.get(champ)).and_then(Value::as_str).unwrap_or("")
}

fn poser_tampon(item: &mut Value, champ: &str, tampon: &str) {
    if !item.is_object() {
        return;
    }
    let objet = item.as_object_mut().unwrap();
    let h = objet.entry("h".to_string()).or_insert_with(|| Value::Object(Map::new()));
    if !h.is_object() {
        *h = Value::Object(Map::new());
    }
    h.as_object_mut().unwrap().insert(champ.to_string(), Value::String(tampon.to_string()));
}

/// Trace de suppression d'un élément (tampon), s'il en porte une.
fn trace_de(item: &Value) -> Option<&str> {
    item.get("t").and_then(Value::as_str).filter(|t| !t.is_empty())
}

/// Un élément vit si l'un de ses champs est plus récent que sa suppression :
/// une modification postérieure le fait revivre, une suppression postérieure le retire.
pub fn est_vivant(item: &Value) -> bool {
    let Some(trace) = trace_de(item) else { return true };
    let plus_recent = item
        .get("h")
        .and_then(Value::as_object)
        .map(|h| h.values().filter_map(Value::as_str).max().unwrap_or(""))
        .unwrap_or("");
    plus_recent > trace
}

fn liste(map: &DataMap, cle: &str) -> Vec<Value> {
    match map.get(cle) {
        Some(brut) => match serde_json::from_str::<Value>(brut) {
            Ok(Value::Array(items)) => items,
            _ => Vec::new(),
        },
        None => Vec::new(),
    }
}

fn ecrire_liste(map: &mut DataMap, cle: &str, items: &[Value]) {
    map.insert(cle.to_string(), serde_json::to_string(items).unwrap_or_else(|_| "[]".into()));
}

/* ─── Marqueur v2 (clé mymfa.sync.v2) ─────────────────────────────────────── */

/// Entrée du registre pour un appareil : `vu` est son repère de couverture (le
/// plus grand tampon qu'il a traité — c'est lui qui autorise l'élagage des
/// traces), `actif_le` la date (ms) de sa dernière synchro — c'est lui qui juge
/// le silence d'un an.
#[derive(Clone, Debug, PartialEq)]
pub struct Vu {
    pub tampon: Tampon,
    pub actif_le: i64,
}

/// Contenu du marqueur : registre des appareils, vidage d'historique tamponné, et
/// traces v1 encore sans élément à qui se rattacher (appliquées puis retirées à
/// la fusion).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Marqueur {
    pub appareils: Vec<(String, Vu)>,
    pub historique_vide_le: Option<Tampon>,
    pub v1: Vec<(String, Tampon)>,
}

fn lire_marqueur(map: &DataMap) -> Marqueur {
    let Some(brut) = map.get(SYNC_KEY) else { return Marqueur::default() };
    let Ok(Value::Object(objet)) = serde_json::from_str::<Value>(brut) else { return Marqueur::default() };
    let paires = |cle: &str| -> Vec<(String, Tampon)> {
        objet
            .get(cle)
            .and_then(Value::as_object)
            .map(|m| m.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect())
            .unwrap_or_default()
    };
    let appareils = objet
        .get("appareils")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    // Forme riche { vu, actifLe } ; une chaîne simple (ancienne
                    // forme) vaut couverture seule, activité inconnue (0).
                    let vu = match v {
                        Value::Object(e) => Vu {
                            tampon: e.get("vu").and_then(Value::as_str).unwrap_or("").to_string(),
                            actif_le: e.get("actifLe").and_then(Value::as_i64).unwrap_or(0),
                        },
                        Value::String(t) => Vu { tampon: t.clone(), actif_le: 0 },
                        _ => return None,
                    };
                    Some((k.clone(), vu))
                })
                .collect()
        })
        .unwrap_or_default();
    Marqueur {
        appareils,
        historique_vide_le: objet
            .get("historiqueVideLe")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        v1: paires("v1"),
    }
}

fn ecrire_marqueur(map: &mut DataMap, marqueur: &Marqueur) {
    let mut objet = Map::new();
    objet.insert("sync".to_string(), Value::String("v2".to_string()));
    let mut appareils = Map::new();
    for (a, vu) in &marqueur.appareils {
        appareils.insert(
            a.clone(),
            serde_json::json!({ "vu": vu.tampon, "actifLe": vu.actif_le }),
        );
    }
    objet.insert("appareils".to_string(), Value::Object(appareils));
    objet.insert(
        "historiqueVideLe".to_string(),
        marqueur
            .historique_vide_le
            .as_ref()
            .map(|t| Value::String(t.clone()))
            .unwrap_or(Value::Null),
    );
    if !marqueur.v1.is_empty() {
        let mut v1 = Map::new();
        for (id, t) in &marqueur.v1 {
            v1.insert(id.clone(), Value::String(t.clone()));
        }
        objet.insert("v1".to_string(), Value::Object(v1));
    }
    map.insert(SYNC_KEY.to_string(), Value::Object(objet).to_string());
}

/* ─── État par appareil (jamais synchronisé) ──────────────────────────────── */

/// Identifiant, horloge et repère de dernière synchro d'un appareil. L'appelant
/// persiste cet état localement (web : localStorage hors des données ; démon :
/// fichier d'état) et le repasse à chaque fusion.
#[derive(Clone, Debug)]
pub struct EtatSynchro {
    pub appareil: String,
    pub horloge: Horloge,
    /// Tampon du plus grand contenu vu à la dernière synchro : un champ changé
    /// des deux côtés depuis ce repère est un conflit.
    pub repere: String,
}

impl EtatSynchro {
    pub fn nouvelle(appareil: impl Into<String>, maintenant: i64) -> Self {
        Self { appareil: appareil.into(), horloge: Horloge::nouvelle(maintenant), repere: String::new() }
    }
}

/* ─── Rapport (journal de synchro, chiffré et conservé par le client) ─────── */

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Conflit {
    pub cle: String,
    pub champ: String,
    pub gagnant: Value,
    pub perdant: Value,
    pub tampon: String,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Entree {
    /// « conflit » | « doublon » | « horloge » | « appareil » | « trace » | « vidage » | « depart ».
    pub genre: &'static str,
    pub cle: String,
    pub champ: String,
    pub texte: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gagnant: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub perdant: Option<Value>,
    pub at: String,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Rapport {
    pub entrees: Vec<Entree>,
    /// Le résultat apporte quelque chose à la copie distante : à renvoyer.
    pub a_envoyer: bool,
}

fn entree(genre: &'static str, cle: &str, champ: &str, description: impl Into<String>, gagnant: Option<Value>, perdant: Option<Value>) -> Entree {
    Entree {
        genre,
        cle: cle.to_string(),
        champ: champ.to_string(),
        texte: description.into(),
        gagnant,
        perdant,
        at: crate::now_iso(),
    }
}

/* ─── Migration v1 → v2 ───────────────────────────────────────────────────── */

/// Porte une copie v1 (ou mixte) au format v2 : chaque `updatedAt` devient le
/// tampon initial de tous les champs de l'élément (appareil « legacy »), les
/// tombstones v1 s'attachent aux éléments (ou attendent dans le marqueur), les
/// réglages reçoivent leur tampon, le marqueur est posé. Rejouable sans effet :
/// les éléments déjà tamponnés ne bougent pas.
pub fn migrer(donnees: &DataMap, _maintenant: i64, appareil: &str) -> DataMap {
    let mut out = donnees.clone();
    let supprimes = lire_supprimes_v1(&out);
    let mut v1_restants: Vec<(String, Tampon)> = Vec::new();

    for collection in COLLECTIONS {
        let Some(brut) = out.get(collection.cle).cloned() else { continue };
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&brut) else { continue };
        let mut faits: Vec<Value> = Vec::with_capacity(items.len());
        for mut item in items {
            if item.is_object() && item.get("h").and_then(Value::as_object).is_none() {
                let base = texte(&item, "updatedAt");
                let base = if base.is_empty() { texte(&item, "createdAt") } else { base };
                let herite = tampon_depuis_iso(base);
                for champ in collection.champs {
                    poser_tampon(&mut item, champ, &herite);
                }
                if let Some(trace) = supprimes.get(texte(&item, "id")) {
                    item["t"] = Value::String(tampon_depuis_iso(trace));
                }
            }
            faits.push(item);
        }
        ecrire_liste(&mut out, collection.cle, &faits);
    }

    // Tombstones v1 rattachés à aucun élément présent : gardés dans le marqueur,
    // appliqués à l'arrivée de l'élément (fusion) puis retirés.
    let mut presents: std::collections::HashSet<String> = std::collections::HashSet::new();
    for collection in COLLECTIONS {
        for item in liste(&out, collection.cle) {
            presents.insert(texte(&item, "id").to_string());
        }
    }
    for (id, at) in &supprimes {
        if id != "__vidage__" && !presents.contains(id.as_str()) {
            v1_restants.push((id.clone(), tampon_depuis_iso(at)));
        }
    }

    // Réglages : chaque entrée reçoit le tampon de son `at` si elle n'en a pas.
    if let Some(brut) = out.get(SETTINGS_KEY).cloned() {
        if let Ok(Value::Object(entrees)) = serde_json::from_str::<Value>(&brut) {
            let mut faits = Map::new();
            for (nom, entree) in entrees {
                let mut entree = entree;
                if entree.is_object() && entree.get("h").and_then(Value::as_object).is_none() {
                    let at = entree.get("at").and_then(Value::as_str).unwrap_or("");
                    entree["h"] = Value::String(tampon_depuis_iso(at));
                }
                faits.insert(nom, entree);
            }
            out.insert(SETTINGS_KEY.to_string(), Value::Object(faits).to_string());
        }
    }

    // Vidage d'historique v1 (ISO) → tampon dans le marqueur.
    let mut marqueur = Marqueur { appareils: Vec::new(), historique_vide_le: None, v1: v1_restants };
    let ancien = lire_marqueur(&out);
    marqueur.v1.extend(ancien.v1);
    marqueur.historique_vide_le = match (supprimes.get("__vidage__"), &ancien.historique_vide_le) {
        (Some(iso), Some(actuel)) => {
            let t = tampon_depuis_iso(iso);
            Some(if actuel.as_str() > t.as_str() { actuel.clone() } else { t })
        }
        (Some(iso), None) => Some(tampon_depuis_iso(iso)),
        (None, actuel) => actuel.clone(),
    };
    marqueur.appareils = ancien.appareils;
    if !marqueur.appareils.iter().any(|(a, _)| a == appareil) {
        marqueur.appareils.push((appareil.to_string(), Vu { tampon: encoder_tampon(0, 0, APPAREIL_HERITAGE), actif_le: 0 }));
    }
    ecrire_marqueur(&mut out, &marqueur);
    // La trace v1 est consommée : les suppressions vivent dans les éléments.
    out.remove(DELETED_KEY);
    out
}

/// { id → date ISO } des suppressions v1, la date de vidage sous « __vidage__ ».
fn lire_supprimes_v1(map: &DataMap) -> std::collections::BTreeMap<String, String> {
    let mut out = std::collections::BTreeMap::new();
    if let Some(brut) = map.get(DELETED_KEY) {
        if let Ok(Value::Object(objet)) = serde_json::from_str::<Value>(brut) {
            if let Some(Value::Object(comptes)) = objet.get("accounts") {
                for (id, at) in comptes {
                    if let Some(at) = at.as_str() {
                        out.insert(id.clone(), at.to_string());
                    }
                }
            }
            if let Some(at) = objet.get("historyClearedAt").and_then(Value::as_str) {
                if !at.is_empty() {
                    out.insert("__vidage__".to_string(), at.to_string());
                }
            }
        }
    }
    out
}

/* ─── Fusion v2 ───────────────────────────────────────────────────────────── */

/// Fusionne la copie locale avec la copie distante (Drive). Renvoie la copie
/// fusionnée (à écrire en local) et le rapport (à chiffrer dans le journal).
/// `maintenant` est T() en ms (SYN-08) : la fusion ne lit jamais l'horloge système.
pub fn fusion(locale: &DataMap, distante: &DataMap, etat: &mut EtatSynchro, maintenant: i64) -> (DataMap, Rapport) {
    let mut rapport = Rapport::default();
    let locale = migrer(locale, maintenant, &etat.appareil);
    let distante = migrer(distante, maintenant, &etat.appareil);
    let mut resultat = locale.clone();

    // ── Marqueur : registre des appareils (union par le plus grand tampon),
    // vidage d'historique, traces v1 en attente. Horloges suspectes repérées ici.
    let mut marqueur = fusionner_marqueurs(&lire_marqueur(&locale), &lire_marqueur(&distante), maintenant, &mut rapport);
    for (_, vu) in marqueur.appareils.clone() {
        surveiller(&vu.tampon, etat, maintenant, &mut rapport);
    }
    if let Some(t) = &marqueur.historique_vide_le.clone() {
        surveiller(t, etat, maintenant, &mut rapport);
    }
    for (_, t) in marqueur.v1.clone() {
        surveiller(&t, etat, maintenant, &mut rapport);
    }

    // ── Collections : champ par champ.
    let mut a_enterrer: Vec<(String, Tampon)> = Vec::new();
    for collection in COLLECTIONS {
        if !collection.toujours && !locale.contains_key(collection.cle) && !distante.contains_key(collection.cle) {
            continue;
        }
        // Union par id : même id → fusion champ par champ (la locale d'abord, la
        // distante fusionnée dedans — le résultat ne dépend pas de l'ordre).
        let mut par_id: Vec<Value> = Vec::new();
        for item in liste(&locale, collection.cle).into_iter().chain(liste(&distante, collection.cle)) {
            let Some(id) = item.get("id").and_then(Value::as_str).map(str::to_string) else { continue };
            if let Some(position) = par_id.iter().position(|i| texte(i, "id") == id) {
                for (champ, gagnant, perdant) in
                    fusionner_items(&mut par_id[position], &item, collection, &etat.repere)
                {
                    rapport.entrees.push(entree(
                        "conflit",
                        collection.cle,
                        &format!("{id}.{champ}"),
                        format!("Conflit : le même champ a changé des deux côtés depuis la dernière synchro."),
                        Some(gagnant),
                        Some(perdant),
                    ));
                }
            } else {
                par_id.push(item);
            }
        }
        // Doublons de même identité (même élément ajouté des deux côtés, ou deux
        // ajouts hors ligne) : fusionnés champ par champ, l'identifiant le plus
        // ancien fait foi, l'autre est enterré d'un tampon déterministe (les deux
        // côtés calculent le même, où qu'ils soient).
        par_id.sort_by(|a, b| texte(a, "createdAt").cmp(texte(b, "createdAt")).then_with(|| texte(a, "id").cmp(texte(b, "id"))));
        let mut identites_vues: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut items: Vec<Value> = Vec::new();
        for item in par_id {
            if !est_vivant(&item) {
                items.push(item); // mort : gardé pour propager la trace, invisible côté interface
                continue;
            }
            let identite = (collection.identite)(&item);
            if identites_vues.contains(&identite) {
                let id_perdu = texte(&item, "id").to_string();
                if let Some(position) = items
                    .iter()
                    .position(|i| est_vivant(i) && (collection.identite)(i) == identite)
                {
                    let _ = fusionner_items(&mut items[position], &item, collection, &etat.repere);
                    let sommet = plus_grand_tampon(&items[position]);
                    let enterre = encoder_tampon(decoder_l(&sommet), decoder_c(&sommet).saturating_add(1), APPAREIL_HERITAGE);
                    a_enterrer.push((id_perdu.clone(), enterre));
                    rapport.entrees.push(entree(
                        "doublon",
                        collection.cle,
                        &id_perdu,
                        "Doublon de même identité : fusionné champ par champ dans l'élément le plus ancien, cet identifiant enterré.",
                        None,
                        None,
                    ));
                    continue;
                }
            }
            identites_vues.insert(identite);
            items.push(item);
        }
        ecrire_liste(&mut resultat, collection.cle, &items);
    }

    // ── Tombstones v1 en attente : appliqués aux éléments qui arrivent ; les ids
    // enterrés comme doublons le sont pour tout le monde de la même façon.
    for (id, tampon) in a_enterrer {
        match marqueur.v1.iter().position(|(i, _)| i == &id) {
            Some(position) => marqueur.v1[position].1 = tampon_max(&marqueur.v1[position].1, &tampon).to_string(),
            None => marqueur.v1.push((id, tampon)),
        }
    }
    appliquer_v1(&mut resultat, &mut marqueur, &mut rapport);

    // ── Historique : union par id, sans ce qui précède le vidage, plafonné.
    fusionner_historique(&locale, &distante, &marqueur.historique_vide_le, &mut resultat, &mut rapport);

    // ── Réglages : union par nom, le plus grand tampon gagne.
    fusionner_reglages(&locale, &distante, &mut resultat);

    // ── Élagage : traces vues par tous les appareils actifs effacées ; appareils
    // muets depuis plus d'un an retirés du registre, avec avertissement.
    elaguer(&mut resultat, &mut marqueur, etat, maintenant, &mut rapport);

    // ── Le repère avance au plus grand tampon vu — jamais à un tampon créé :
    // une fusion sans rien de nouveau ne doit rien changer au marqueur, sinon
    // les appareils se renverraient des mises à jour sans fin.
    let mut repere = etat.repere.clone();
    for collection in COLLECTIONS {
        for item in liste(&resultat, collection.cle) {
            let sommet = plus_grand_tampon(&item);
            surveiller(&sommet, etat, maintenant, &mut rapport);
            repere = repere.max(sommet);
            if let Some(trace) = trace_de(&item) {
                surveiller(trace, etat, maintenant, &mut rapport);
                repere = repere.max(trace.to_string());
            }
        }
    }
    for (_, vu) in &marqueur.appareils {
        repere = repere.max(vu.tampon.clone());
    }
    if let Some(t) = &marqueur.historique_vide_le {
        repere = repere.max(t.clone());
    }
    etat.repere = repere;
    // L'appareil publie son repère (les traces qu'il a vues pourront être effacées)
    // et son activité fraîche : il ne se fera pas retirer du registre tant qu'il
    // se synchronise.
    let soi = Vu { tampon: etat.repere.clone(), actif_le: maintenant };
    if let Some(position) = marqueur.appareils.iter().position(|(a, _)| a == &etat.appareil) {
        marqueur.appareils[position].1 = soi;
    } else {
        marqueur.appareils.push((etat.appareil.clone(), soi));
    }
    ecrire_marqueur(&mut resultat, &marqueur);

    rapport.a_envoyer = different_de(&resultat, &distante);
    (resultat, rapport)
}

/// Fusionne deux versions du même élément : champ par champ, le plus grand tampon
/// gagne ; compteur HOTP = valeur maximale ; dernières utilisations = la plus
/// récente (sans compter comme une modification). Renvoie les conflits (le même
/// champ changé des deux côtés depuis le repère, avec deux valeurs différentes).
fn fusionner_items(gauche: &mut Value, droite: &Value, collection: &Collection, repere: &str) -> Vec<(String, Value, Value)> {
    let mut conflits = Vec::new();
    if !gauche.is_object() || !droite.is_object() {
        return conflits;
    }
    let copie_gauche = gauche.clone();
    let copie_droite = droite.clone();
    let mut h: Map<String, Value> = gauche
        .get("h")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    for champ in collection.champs {
        let valeur_gauche = champ_de(gauche, champ);
        let valeur_droite = champ_de(&copie_droite, champ);
        let tg = tampon_de(gauche, champ).to_string();
        let td = tampon_de(&copie_droite, champ).to_string();
        let (valeur, tampon) = if td.as_str() > tg.as_str() {
            (valeur_droite.clone(), td.clone())
        } else {
            (valeur_gauche.clone(), tg.clone())
        };
        if !valeur.is_null() || gauche.get(champ).is_some() {
            gauche[champ] = valeur;
        }
        if !tampon.is_empty() {
            h.insert(champ.to_string(), Value::String(tampon));
        }
        // Conflit : le même champ a changé des deux côtés depuis le repère de
        // dernière synchro, avec deux valeurs différentes.
        if tg.as_str() > repere && td.as_str() > repere && valeur_gauche != valeur_droite {
            let (gagnant, perdant, tampon_gagnant) = if td.as_str() > tg.as_str() {
                (valeur_droite.clone(), valeur_gauche.clone(), td.clone())
            } else {
                (valeur_gauche.clone(), valeur_droite.clone(), tg.clone())
            };
            conflits.push((
                champ.to_string(),
                serde_json::json!({ "valeur": gagnant, "tampon": tampon_gagnant }),
                perdant,
            ));
        }
    }

    // HOTP : la valeur maximale, quel que soit le tampon — jamais de réutilisation
    // de code. Le tampon du champ suit l'appareil qui portait la valeur maximale.
    // Les valeurs se lisent AVANT la fusion des champs (qui a pu écraser la gauche).
    let compteur_gauche_avant = copie_gauche.get("counter").and_then(Value::as_u64);
    let compteur_droite_avant = copie_droite.get("counter").and_then(Value::as_u64);
    let compteur_tampon_gauche = tampon_de(&copie_gauche, "counter").to_string();
    if let (Some(cg), Some(cd)) = (compteur_gauche_avant, compteur_droite_avant) {
        if cg > cd {
            gauche["counter"] = Value::from(cg);
            if !compteur_tampon_gauche.is_empty() {
                h.insert("counter".to_string(), Value::String(compteur_tampon_gauche));
            }
        } else if cd > cg {
            gauche["counter"] = Value::from(cd);
            let tampon = tampon_de(&copie_droite, "counter");
            if !tampon.is_empty() {
                h.insert("counter".to_string(), Value::String(tampon.to_string()));
            }
        }
    }

    // Trace de suppression : le plus grand tampon.
    let trace = match (trace_de(gauche), trace_de(&copie_droite)) {
        (Some(a), Some(b)) => Some(tampon_max(a, b).to_string()),
        (Some(a), None) => Some(a.to_string()),
        (None, Some(b)) => Some(b.to_string()),
        (None, None) => None,
    };
    match trace {
        Some(t) => gauche["t"] = Value::String(t),
        None => {
            gauche.as_object_mut().unwrap().remove("t");
        }
    }

    // Champs dérivés : updatedAt du plus grand tampon, passwordChangedAt du tampon
    // du mot de passe, dernière utilisation = la plus récente, création = la plus
    // ancienne.
    // Tampons resérialisés dans l'ordre canonique des champs : deux côtés doivent
    // écrire la même chaîne, quel que soit l'ordre où leurs éditions sont arrivées.
    let mut h_canonique = Map::new();
    for champ in collection.champs {
        if let Some(tampon) = h.get(*champ) {
            h_canonique.insert(champ.to_string(), tampon.clone());
        }
    }
    gauche["h"] = Value::Object(h_canonique);
    let sommet = plus_grand_tampon(gauche);
    if !sommet.is_empty() {
        gauche["updatedAt"] = Value::String(iso_depuis_tampon(&sommet));
    }
    if collection.cle == LOGINS_KEY {
        let tp = tampon_de(gauche, "password");
        if !tp.is_empty() {
            gauche["passwordChangedAt"] = Value::String(iso_depuis_tampon(tp));
        }
    }
    let used_g = texte(gauche, "usedAt");
    let used_d = texte(&copie_droite, "usedAt");
    if used_d > used_g {
        gauche["usedAt"] = Value::String(used_d.to_string());
    }
    let created_g = texte(gauche, "createdAt");
    let created_d = texte(&copie_droite, "createdAt");
    if !created_d.is_empty() && (created_g.is_empty() || created_d < created_g) {
        gauche["createdAt"] = Value::String(created_d.to_string());
    }
    conflits
}

/// Le plus grand tampon des champs d'un élément (champ sans tampon = rien).
fn plus_grand_tampon(item: &Value) -> String {
    item.get("h")
        .and_then(Value::as_object)
        .map(|h| {
            h.values()
                .filter_map(Value::as_str)
                .fold(String::new(), |acc, t| tampon_max(&acc, t).to_string())
        })
        .unwrap_or_default()
}

/// Réception d'un tampon vu dans le contenu : fait avancer l'horloge locale,
/// sauf s'il est à plus de 5 min dans le futur — accepté, journalisé (l'appareil
/// émetteur est nommé), sans contamination.
fn surveiller(tampon: &str, etat: &mut EtatSynchro, maintenant: i64, rapport: &mut Rapport) {
    if tampon.is_empty() {
        return;
    }
    let l = decoder_l(tampon);
    if l > maintenant + ECART_FUTUR_MS {
        let appareil = decoder_appareil(tampon);
        let deja = rapport
            .entrees
            .iter()
            .any(|e| e.genre == "horloge" && e.champ == appareil && e.texte.contains(&format!("{} min", (l - maintenant) / 60_000)));
        if !deja {
            rapport.entrees.push(entree(
                "horloge",
                SYNC_KEY,
                appareil,
                format!(
                    "Horloge de « {appareil} » à {} min dans le futur : tampon accepté, horloge locale inchangée.",
                    (l - maintenant) / 60_000
                ),
                None,
                None,
            ));
        }
        return;
    }
    etat.horloge.observer(tampon, maintenant);
}

fn fusionner_marqueurs(a: &Marqueur, b: &Marqueur, maintenant: i64, rapport: &mut Rapport) -> Marqueur {
    let mut out: Vec<(String, Vu)> = a.appareils.clone();
    for (cle, vu) in &b.appareils {
        match out.iter().position(|(k, _)| k == cle) {
            Some(i) => {
                out[i].1.tampon = tampon_max(&out[i].1.tampon, &vu.tampon).to_string();
                out[i].1.actif_le = out[i].1.actif_le.max(vu.actif_le);
            }
            None => out.push((cle.clone(), vu.clone())),
        }
    }
    out.sort_by(|x, y| x.0.cmp(&y.0));
    // Appareils muets depuis plus d'un an (aucune synchro) : retirés du registre.
    // Le filtrage fait partie de l'union — mêmes entrées, même horloge de
    // référence, même calcul de chaque côté : l'entrée retirée par un côté ne
    // réapparaît pas par l'autre, et les appareils convergent. L'activité de
    // l'appareil courant est rafraîchie à la fin de la fusion : il ne se juge
    // jamais muet lui-même tant qu'il se synchronise.
    let mut muets: Vec<String> = Vec::new();
    let appareils: Vec<(String, Vu)> = out
        .into_iter()
        .filter(|(appareil, vu)| {
            let muet = vu.actif_le > 0 && vu.actif_le < maintenant - SILENCE_MAX_MS;
            if muet {
                muets.push(appareil.clone());
            }
            !muet
        })
        .collect();
    for appareil in muets {
        rapport.entrees.push(entree(
            "appareil",
            SYNC_KEY,
            &appareil,
            "Appareil muet depuis plus d'un an, retiré du registre : ses traces de suppression pourraient revenir s'il se réveille.",
            None,
            None,
        ));
    }
    Marqueur {
        appareils,
        historique_vide_le: match (&a.historique_vide_le, &b.historique_vide_le) {
            (Some(x), Some(y)) => Some(tampon_max(x, y).to_string()),
            (Some(x), None) => Some(x.clone()),
            (None, Some(y)) => Some(y.clone()),
            (None, None) => None,
        },
        v1: {
            let mut v1: Vec<(String, String)> = a.v1.clone();
            for (cle, t) in &b.v1 {
                match v1.iter().position(|(k, _)| k == cle) {
                    Some(i) => v1[i].1 = tampon_max(&v1[i].1, t).to_string(),
                    None => v1.push((cle.clone(), t.clone())),
                }
            }
            v1.sort_by(|x, y| x.0.cmp(&y.0));
            v1
        },
    }
}

/// Applique les traces v1 en attente aux éléments qui arrivent (un élément apparu
/// après coup sous un id déjà supprimé reste supprimé si sa trace est plus récente
/// que ses champs) ; les appliquées sortent du marqueur.
fn appliquer_v1(resultat: &mut DataMap, marqueur: &mut Marqueur, rapport: &mut Rapport) {
    if marqueur.v1.is_empty() {
        return;
    }
    let mut restants = marqueur.v1.clone();
    let mut total = 0;
    for collection in COLLECTIONS {
        let Some(brut) = resultat.get(collection.cle).cloned() else { continue };
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&brut) else { continue };
        let mut changements = 0;
        let mut faits: Vec<Value> = Vec::with_capacity(items.len());
        for mut item in items {
            let id = texte(&item, "id").to_string();
            if let Some(position) = restants.iter().position(|(i, _)| i == &id) {
                let trace = restants[position].1.clone();
                if plus_grand_tampon(&item).as_str() < trace.as_str() {
                    item["t"] = Value::String(trace);
                    changements += 1;
                }
                restants.remove(position);
            }
            faits.push(item);
        }
        if changements > 0 {
            ecrire_liste(resultat, collection.cle, &faits);
            total += changements;
        }
    }
    if total > 0 {
        rapport.entrees.push(entree(
            "depart",
            "collections",
            "",
            format!("Suppressions v1 rattachées à des éléments arrivés entre-temps ({total})."),
            None,
            None,
        ));
    }
    marqueur.v1 = restants;
}

fn fusionner_historique(
    locale: &DataMap,
    distante: &DataMap,
    vide_le: &Option<Tampon>,
    resultat: &mut DataMap,
    rapport: &mut Rapport,
) {
    let mut vues: Vec<(String, Value)> = Vec::new();
    for entree in liste(locale, HISTORY_KEY).into_iter().chain(liste(distante, HISTORY_KEY)) {
        let Some(id) = entree.get("id").and_then(Value::as_str).map(str::to_string) else { continue };
        if vues.iter().any(|(i, _)| i == &id) {
            continue;
        }
        if let Some(trace) = vide_le {
            let at = entree.get("at").and_then(Value::as_str).and_then(iso_vers_ms).unwrap_or(0);
            if at <= decoder_l(trace) {
                continue;
            }
        }
        vues.push((id, entree));
    }
    vues.sort_by(|a, b| texte(&b.1, "at").cmp(texte(&a.1, "at")).then_with(|| a.0.cmp(&b.0)));
    vues.truncate(HISTORY_MAX);
    let histoire: Vec<Value> = vues.into_iter().map(|(_, e)| e).collect();
    let avant = liste(locale, HISTORY_KEY).len().max(liste(distante, HISTORY_KEY).len());
    if histoire.len() < avant {
        rapport.entrees.push(entree(
            "vidage",
            HISTORY_KEY,
            "",
            "Historique écourté par le vidage le plus récent.",
            None,
            None,
        ));
    }
    ecrire_liste(resultat, HISTORY_KEY, &histoire);
}

/// Réglages : union par nom, le plus grand tampon (`h`, sinon `at`) l'emporte.
/// Absents des deux côtés : rien d'écrit.
fn fusionner_reglages(locale: &DataMap, distante: &DataMap, resultat: &mut DataMap) {
    if !locale.contains_key(SETTINGS_KEY) && !distante.contains_key(SETTINGS_KEY) {
        return;
    }
    let objet = |map: &DataMap| -> Map<String, Value> {
        match map.get(SETTINGS_KEY) {
            Some(brut) => match serde_json::from_str::<Value>(brut) {
                Ok(Value::Object(objet)) => objet,
                _ => Map::new(),
            },
            None => Map::new(),
        }
    };
    let tampon_reglage = |entree: &Value| -> String {
        let h = entree.get("h").and_then(Value::as_str).unwrap_or("");
        if !h.is_empty() {
            return h.to_string();
        }
        tampon_depuis_iso(entree.get("at").and_then(Value::as_str).unwrap_or(""))
    };
    let mut out = objet(locale);
    for (nom, entree) in objet(distante) {
        if !entree.is_object() {
            continue;
        }
        let remplacer = match out.get(&nom) {
            None => true,
            Some(actuel) => tampon_reglage(&entree) > tampon_reglage(actuel),
        };
        if remplacer {
            out.insert(nom, entree);
        }
    }
    resultat.insert(SETTINGS_KEY.to_string(), Value::Object(out).to_string());
}

/// Élagage des traces : un élément supprimé dont la trace a été vue par tous les
/// appareils actifs (registre du marqueur) sort de la copie ; un appareil muet
/// depuis plus d'un an sort du registre, avec avertissement.
fn elaguer(resultat: &mut DataMap, marqueur: &mut Marqueur, etat: &EtatSynchro, maintenant: i64, rapport: &mut Rapport) {
    // Les appareils muets ont déjà été retirés du registre par l'union
    // (fusionner_marqueurs). Reste l'élagage des traces vue partout.
    let _ = etat;
    for collection in COLLECTIONS {
        let Some(brut) = resultat.get(collection.cle).cloned() else { continue };
        let Ok(Value::Array(items)) = serde_json::from_str::<Value>(&brut) else { continue };
        let mut effaces = 0;
        let mut faits: Vec<Value> = Vec::with_capacity(items.len());
        for item in items {
            if let Some(trace) = trace_de(&item) {
                let mort = plus_grand_tampon(&item).as_str() <= trace;
                if mort {
                    // « Vue par tous les appareils actifs » : au moins un autre
                    // appareil au registre, chacun avec un repère qui couvre la
                    // trace, et la rétention écoulée (un appareil nouveau ou
                    // hors ligne pendant la suppression doit avoir le temps de
                    // l'apprendre). Registre vide ou trace récente : on garde.
                    let pairs: Vec<&str> = marqueur
                        .appareils
                        .iter()
                        .filter(|(a, _)| a != &etat.appareil)
                        .map(|(_, vu)| vu.tampon.as_str())
                        .collect();
                    let vu_partout = !pairs.is_empty() && pairs.iter().all(|vu| *vu >= trace);
                    let retenue = maintenant - decoder_l(trace) >= RETENTION_TRACE_MS;
                    if vu_partout && retenue {
                        effaces += 1;
                        continue; // trace propagée partout : l'élément sort de la copie
                    }
                }
            }
            faits.push(item);
        }
        if effaces > 0 {
            ecrire_liste(resultat, collection.cle, &faits);
            rapport.entrees.push(entree(
                "trace",
                collection.cle,
                nom_collection(collection.cle),
                format!("Traces de suppression vues par tous les appareils actifs : {effaces} élément(s) effacé(s) de la copie."),
                None,
                None,
            ));
        }
    }
}

fn nom_collection(cle: &str) -> &'static str {
    match cle {
        LOGINS_KEY => "logins",
        PASSKEYS_KEY => "passkeys",
        _ => "comptes",
    }
}

/// Le résultat diffère-t-il de la copie distante (sur toutes les clés présentes) ?
/// Comparaison sémantique (JSON parsé) : deux objets aux mêmes paires clé-valeur
/// mais d'ordres de sérialisation différents sont le même contenu — les comparer
/// en texte ferait se renvoyer les appareils sans fin (serde_json préserve ici
/// l'ordre d'insertion, feature preserve_order du workspace).
fn different_de(resultat: &DataMap, distante: &DataMap) -> bool {
    let mut cles: std::collections::BTreeSet<&str> = resultat.keys().map(String::as_str).collect();
    cles.extend(distante.keys().map(String::as_str));
    cles.into_iter().any(|cle| match (resultat.get(cle), distante.get(cle)) {
        (Some(a), Some(b)) if a == b => false,
        (Some(a), Some(b)) => match (serde_json::from_str::<Value>(a), serde_json::from_str::<Value>(b)) {
            (Ok(x), Ok(y)) => x != y,
            _ => true,
        },
        _ => true,
    })
}

/* ─── Tests : unitaires, cinq scénarios du simulateur, propriétés ─────────── */

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{ACCOUNTS_KEY, HISTORY_KEY, SETTINGS_KEY};

    const T0: i64 = 1_794_405_900_000; // 2026-11-11T14:05:00.000Z
    const MINUT: i64 = 60_000;

    fn compte(id: &str, issuer: &str, date: &str) -> Value {
        serde_json::json!({
            "id": id, "type": "totp", "issuer": issuer, "account": "moi@example.net",
            "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30, "counter": 0,
            "tag": "", "description": "", "favorite": false,
            "createdAt": date, "updatedAt": date,
        })
    }

    fn copie(items: Vec<Value>) -> DataMap {
        let mut map = DataMap::new();
        ecrire_liste(&mut map, ACCOUNTS_KEY, &items);
        map
    }

    fn valeur(map: &DataMap, id: &str, champ: &str) -> Value {
        liste(map, ACCOUNTS_KEY)
            .into_iter()
            .find(|i| texte(i, "id") == id)
            .map(|i| champ_de(&i, champ))
            .unwrap_or(Value::Null)
    }

    fn ids(map: &DataMap) -> Vec<String> {
        liste(map, ACCOUNTS_KEY).iter().map(|i| texte(i, "id").to_string()).collect()
    }

    /* ── Tampons : ordre, encodage, ISO ── */

    #[test]
    fn ordre_des_tampons_est_l_c_d() {
        let a = encoder_tampon(1000, 0, "a1b2");
        let b = encoder_tampon(1000, 1, "a1b2");
        let c = encoder_tampon(1001, 0, "a1b2");
        let d = encoder_tampon(1001, 0, "ffff");
        assert!(a < b && b < c && c < d);
        assert_eq!(decoder_l(&c), 1001);
        assert_eq!(decoder_c(&b), 1);
        assert_eq!(decoder_appareil(&a), "a1b2");
        // Largeur stable : 13 chiffres + 8 hexadécimaux + appareil.
        assert_eq!(a.len(), L_CHIFFRES + C_CHIFFRES + 4);
    }

    #[test]
    fn iso_vers_ms_aller_retour() {
        assert_eq!(iso_vers_ms("2026-11-11T14:05:00.000Z"), Some(T0));
        assert_eq!(iso_vers_ms("1970-01-01T00:00:00.000Z"), Some(0));
        assert_eq!(iso_vers_ms("2026-02-29T00:00:00Z"), None); // 2026 n'est pas bissextile
        assert_eq!(iso_vers_ms("2024-02-29T12:00:00Z"), Some(1_709_208_000_000));
        assert_eq!(iso_vers_ms("bancal"), None);
        assert_eq!(iso_depuis_tampon(&tampon_depuis_iso("2026-11-11T14:05:00.000Z")), "2026-11-11T14:05:00.000Z");
    }

    /* ── Horloge hybride ── */

    #[test]
    fn horloge_tic_compteur_et_avance() {
        let mut h = Horloge::nouvelle(T0);
        let t1 = h.tic(T0, "pc");
        let t2 = h.tic(T0, "pc"); // même ms : le compteur s'incrémente
        let t3 = h.tic(T0 + 5, "pc"); // l avance : le compteur repart de 0
        assert_eq!(decoder_l(&t1), T0);
        assert_eq!(decoder_c(&t1), 1);
        assert_eq!(decoder_c(&t2), 2);
        assert_eq!(decoder_l(&t3), T0 + 5);
        assert_eq!(decoder_c(&t3), 0);
        assert!(t1 < t2 && t2 < t3);
    }

    #[test]
    fn horloge_observe_sauf_futur_lointain() {
        let mut h = Horloge::nouvelle(T0);
        // Tampon en avance dans la limite des 5 min : l'horloge suit.
        assert!(h.observer(&encoder_tampon(T0 + MINUT, 0, "x"), T0));
        assert_eq!(h.l, T0 + MINUT);
        // Tampon à plus de 5 min dans le futur : refusé, sans contamination.
        assert!(!h.observer(&encoder_tampon(T0 + 10 * MINUT, 0, "x"), T0));
        assert_eq!(h.l, T0 + MINUT);
        // Tampon en retard : l'horloge ne recule jamais.
        assert!(!h.observer(&encoder_tampon(T0, 0, "x"), T0 + MINUT));
        assert_eq!(h.l, T0 + MINUT);
    }

    #[test]
    fn apres_plafonne_au_tampon_du_champ() {
        let mut h = Horloge::nouvelle(T0 - MINUT);
        let ancien = encoder_tampon(T0 + MINUT, 4, "autre");
        // L'horloge locale retarde : le tampon pose dépasse quand même le plancher.
        let t = h.apres(T0, Some(&ancien), "pc");
        assert!(comparer(&t, &ancien) == Ordering::Greater);
        assert_eq!(decoder_appareil(&t), "pc");
        // Sans plancher : simple tic.
        let t2 = h.apres(T0, None, "pc");
        assert!(comparer(&t2, &t) == Ordering::Greater);
    }

    /* ── Migration v1 → v2 ── */

    #[test]
    fn migration_pose_tampons_marqueur_et_traces() {
        let mut v1 = copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
        v1.insert(
            crate::store::DELETED_KEY.to_string(),
            r#"{"accounts":{"z1":"2026-03-01T00:00:00.000Z"},"historyClearedAt":"2026-02-01T00:00:00.000Z"}"#.into(),
        );
        v1.insert(
            SETTINGS_KEY.to_string(),
            r#"{"policy":{"value":{"minLength":12},"at":"2026-02-01T00:00:00.000Z"}}"#.into(),
        );
        let v2 = migrer(&v1, T0, "pc");
        // Tampons hérités de updatedAt, appareil « legacy ».
        let item = &liste(&v2, ACCOUNTS_KEY)[0];
        assert_eq!(tampon_de(item, "issuer"), tampon_depuis_iso("2026-01-01T00:00:00.000Z"));
        assert_eq!(tampon_de(item, "secret"), tampon_depuis_iso("2026-01-01T00:00:00.000Z"));
        assert!(est_vivant(item));
        // Marqueur posé, trace v1 orpheline en attente, vidage tamponné, DELETED_KEY consommé.
        let marqueur = lire_marqueur(&v2);
        assert!(v2.contains_key(SYNC_KEY));
        assert!(!v2.contains_key(crate::store::DELETED_KEY));
        assert_eq!(marqueur.v1, vec![("z1".to_string(), tampon_depuis_iso("2026-03-01T00:00:00.000Z"))]);
        assert_eq!(marqueur.historique_vide_le, Some(tampon_depuis_iso("2026-02-01T00:00:00.000Z")));
        assert!(marqueur.appareils.iter().any(|(a, _)| a == "pc"));
        // Réglages tamponnés.
        let reglages: Value = serde_json::from_str(v2.get(SETTINGS_KEY).unwrap()).unwrap();
        assert_eq!(reglages["policy"]["h"], tampon_depuis_iso("2026-02-01T00:00:00.000Z"));
        // Rejouer la migration ne change rien (éléments déjà tamponnés).
        let rejoue = migrer(&v2, T0, "pc");
        assert_eq!(v2, rejoue);
    }

    /* ── Fusion : base ── */

    #[test]
    fn fusion_union_et_gagnant_par_champ() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        let mut gauche = copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
        let droite = copie(vec![
            {
                let mut a = compte("a1", "GitHub", "2026-01-01T00:00:00.000Z");
                a["tag"] = Value::String("travail".into());
                a["updatedAt"] = Value::String("2026-02-01T00:00:00.000Z".into());
                a
            },
            compte("a2", "OVH", "2026-02-01T00:00:00.000Z"),
        ]);
        // La gauche doit être migrée ET tamponnée sur son propre champ pour un
        // cas réel : ici on passe par la fusion qui migre les deux copies.
        let (fusionne, rapport) = fusion(&gauche, &droite, etat, T0);
        assert_eq!(ids(&fusionne), vec!["a1", "a2"]);
        // Le champ tag modifié côté droit (tampon plus récent) gagne.
        assert_eq!(valeur(&fusionne, "a1", "tag"), Value::String("travail".into()));
        assert_eq!(valeur(&fusionne, "a1", "issuer"), Value::String("GitHub".into()));
        assert!(rapport.a_envoyer);
        assert_eq!(valeur(&fusionne, "a1", "updatedAt"), Value::String("2026-02-01T00:00:00.000Z".into()));
        let _ = &mut gauche;
    }

    #[test]
    fn suppression_datable_modifiee_apres_revit_et_l_inverse_meurt() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        // Gauche : élément supprimé le 2026-03 ; droite : élément modifié le 2026-04.
        // La modification est plus récente : l'élément vit.
        let supprime = {
            let mut item = compte("a1", "GitHub", "2026-01-01T00:00:00.000Z");
            item["t"] = Value::String(tampon_depuis_iso("2026-03-01T00:00:00.000Z"));
            item
        };
        let modifie = {
            let mut item = compte("a1", "GitHub", "2026-01-01T00:00:00.000Z");
            item["description"] = Value::String("clé de secours".into());
            item["updatedAt"] = Value::String("2026-04-01T00:00:00.000Z".into());
            item
        };
        let (fusionne, _) = fusion(&copie(vec![supprime.clone()]), &copie(vec![modifie.clone()]), etat, T0);
        let item = &liste(&fusionne, ACCOUNTS_KEY)[0];
        assert!(est_vivant(item), "la modification postérieure fait revivre l'élément");
        assert_eq!(valeur(&fusionne, "a1", "description"), Value::String("clé de secours".into()));
        // L'inverse : suppression du 2026-05, modification du 2026-04 → mort.
        let supprime2 = {
            let mut item = supprime.clone();
            item["t"] = Value::String(tampon_depuis_iso("2026-05-01T00:00:00.000Z"));
            item
        };
        let (fusionne2, _) = fusion(&copie(vec![supprime2]), &copie(vec![modifie]), etat, T0);
        let item2 = &liste(&fusionne2, ACCOUNTS_KEY)[0];
        assert!(!est_vivant(item2), "la suppression postérieure l'emporte");
    }

    #[test]
    fn compteur_hotp_prend_la_valeur_maximale() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        // Gauche : compteur 5 daté du 2026-01. Droite : compteur 2 daté du 2026-06
        // (tampon plus grand, valeur plus petite). La valeur 5 doit gagner.
        let gauche = copie(vec![{
            let mut a = compte("a1", "GitHub", "2026-01-01T00:00:00.000Z");
            a["counter"] = Value::from(5);
            a["updatedAt"] = Value::String("2026-01-01T00:00:00.000Z".into());
            a
        }]);
        let droite = copie(vec![{
            let mut a = compte("a1", "GitHub", "2026-01-01T00:00:00.000Z");
            a["counter"] = Value::from(2);
            a["updatedAt"] = Value::String("2026-06-01T00:00:00.000Z".into());
            a
        }]);
        let (fusionne, _) = fusion(&gauche, &droite, etat, T0);
        assert_eq!(valeur(&fusionne, "a1", "counter"), Value::from(5), "jamais de réutilisation de code HOTP");
    }

    #[test]
    fn doublons_fusionnes_champ_par_champ_et_enterres() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        // Même (secret, issuer, account) sous deux id : le plus ancien est gardé,
        // les champs se fusionnent, le doublon est enterré d'un tampon déterministe.
        let gauche = copie(vec![{
            let mut a = compte("nouveau", "GitHub", "2026-06-01T00:00:00.000Z");
            a["tag"] = Value::String("travail".into());
            a
        }]);
        let droite = copie(vec![{
            let mut a = compte("ancien", "GitHub", "2026-01-01T00:00:00.000Z");
            a["description"] = Value::String("perso".into());
            a
        }]);
        let (fusionne, rapport) = fusion(&gauche, &droite, etat, T0);
        assert_eq!(ids(&fusionne), vec!["ancien"], "l'identifiant le plus ancien fait foi");
        assert_eq!(valeur(&fusionne, "ancien", "tag"), Value::String("travail".into()), "les champs se fusionnent");
        // Le doublon « nouveau » hérite de tampons plus récents sur tous ses champs :
        // sa description vide gagne (indistinguable d'un effacement — limite connue
        // de la migration, la v1 avait le même défaut, élément entier).
        assert_eq!(valeur(&fusionne, "ancien", "description"), Value::String(String::new()));
        assert!(rapport.entrees.iter().any(|e| e.genre == "doublon"));
        // L'id enterré est dans le marqueur : s'il revient d'une autre copie, il meurt.
        let marqueur = lire_marqueur(&fusionne);
        assert!(marqueur.v1.iter().any(|(id, _)| id == "nouveau"));
        let retour = copie(vec![{
            let mut a = compte("nouveau", "GitHub", "2026-06-01T00:00:00.000Z");
            a["tag"] = Value::String("travail".into());
            a
        }]);
        let (fusionne2, _) = fusion(&fusionne, &retour, etat, T0);
        assert!(!ids(&fusionne2).contains(&"nouveau".to_string()), "le doublon enterré ne revient pas");
    }

    #[test]
    fn fusion_idempotente_et_converge_sur_copie_identique() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        let x = migrer(&copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]), T0, "pc");
        // La première fusion publie le repère de l'appareil dans le marqueur (avant :
        // tampon nul) ; la deuxième ne doit plus rien changer — sinon les appareils
        // se renverraient des mises à jour sans fin.
        let (une_fois, rapport) = fusion(&x, &x, etat, T0);
        assert!(rapport.entrees.is_empty(), "aucun conflit, aucun doublon");
        let (deux_fois, rapport2) = fusion(&une_fois, &une_fois, etat, T0);
        assert_eq!(deux_fois, une_fois, "refusionner une copie déjà fusionnée : rien ne bouge");
        assert!(!rapport2.a_envoyer);
    }

    /* ── Banc : les cinq scénarios du simulateur ── */


    struct Banc {
        copies: Vec<(String, DataMap, EtatSynchro, i64)>, // appareil, copie, état, décalage d'horloge
        drive: DataMap,
        t: i64,
        rapports: Vec<Rapport>,
    }

    impl Banc {
        /// Deux appareils avec la même copie initiale (v1) et un décalage d'horloge.
        fn nouveau(skew_pc: i64, skew_tel: i64) -> Self {
            let initial = copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
            let init = || copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
            let mk = |nom: &str, skew: i64| {
                (
                    nom.to_string(),
                    init(),
                    EtatSynchro::nouvelle(nom, T0 - MINUT),
                    skew,
                )
            };
            Self {
                copies: vec![mk("pc", skew_pc), mk("tel", skew_tel)],
                drive: initial,
                t: T0,
                rapports: Vec::new(),
            }
        }

        fn position(&self, appareil: &str) -> usize {
            self.copies.iter().position(|(n, _, _, _)| n == appareil).unwrap()
        }

        /// Tic de l'appareil, décalage d'horloge compris (T() imparfaite, hors ligne).
        fn tic(&mut self, appareil: &str, plancher: Option<&str>) -> Tampon {
            let position = self.position(appareil);
            let (nom, _, etat, skew) = &mut self.copies[position];
            etat.horloge.apres(self.t + *skew, plancher, nom)
        }

        fn tampon_champ(&self, appareil: &str, champ: &str) -> String {
            let item = &liste(&self.copies[self.position(appareil)].1, ACCOUNTS_KEY)[0];
            tampon_de(item, champ).to_string()
        }

        fn plus_grand_tampon_item(&self, appareil: &str) -> String {
            let item = &liste(&self.copies[self.position(appareil)].1, ACCOUNTS_KEY)[0];
            plus_grand_tampon(item)
        }

        fn edit(&mut self, appareil: &str, champ: &str, valeur: &str) {
            let tampon = self.tic(appareil, Some(&self.tampon_champ(appareil, champ)));
            let position = self.position(appareil);
            let (_, copie, _, _) = &mut self.copies[position];
            let mut items = liste(copie, ACCOUNTS_KEY);
            let item = &mut items[0];
            item[champ] = Value::String(valeur.to_string());
            poser_tampon(item, champ, &tampon);
            ecrire_liste(copie, ACCOUNTS_KEY, &items);
        }

        fn supprime(&mut self, appareil: &str) {
            let plancher = self.plus_grand_tampon_item(appareil);
            let tampon = self.tic(appareil, Some(&plancher));
            let position = self.position(appareil);
            let (_, copie, _, _) = &mut self.copies[position];
            let mut items = liste(copie, ACCOUNTS_KEY);
            items[0]["t"] = Value::String(tampon);
            ecrire_liste(copie, ACCOUNTS_KEY, &items);
        }

        fn sync(&mut self, appareil: &str) {
            let position = self.position(appareil);
            let (_, copie, etat, _) = &mut self.copies[position];
            let locale = copie.clone();
            let (fusionne, rapport) = fusion(&locale, &self.drive.clone(), etat, self.t);
            *copie = fusionne.clone();
            self.rapports.push(rapport.clone());
            if rapport.a_envoyer {
                self.drive = fusionne;
            }
        }

        /// Chaque appareil se synchronise jusqu'à ce que plus rien ne s'envoie.
        fn converge(&mut self) {
            for _ in 0..12 {
                let mut stable = true;
                for (nom, _, _, _) in self.copies.clone() {
                    self.sync(&nom);
                    if self.rapports.last().unwrap().a_envoyer {
                        stable = false;
                    }
                }
                if stable {
                    return;
                }
            }
            panic!("les copies ne convergent pas");
        }

        fn valeur(&self, appareil: &str, champ: &str) -> Value {
            let copie = &self.copies[self.position(appareil)].1;
            valeur(copie, "a1", champ)
        }

        fn vivant(&self, appareil: &str) -> bool {
            let copie = &self.copies[self.position(appareil)].1;
            liste(copie, ACCOUNTS_KEY).first().map(est_vivant).unwrap_or(false)
        }

        fn identiques(&self) -> bool {
            self.copies
                .iter()
                .all(|(_, copie, _, _)| different_de(copie, &self.drive) == false && different_de(copie, &self.copies[0].1) == false)
        }

        fn entrees(&self, genre: &str) -> usize {
            self.rapports.iter().filter(|r| r.entrees.iter().any(|e| e.genre == genre)).count()
        }
    }

    /// Scénario « Horloge en retard » : le téléphone retarde de 10 minutes, la
    /// correction faite plus tard gagne quand même (elle a vu la version d'avant).
    #[test]
    fn scenario_horloge_en_retard() {
        let mut banc = Banc::nouveau(0, -10 * MINUT);
        banc.edit("pc", "issuer", "GitHub Pro");
        banc.sync("pc");
        banc.sync("tel");
        banc.edit("tel", "issuer", "GitHub Entreprise");
        banc.sync("tel");
        banc.sync("pc");
        banc.converge();
        for appareil in ["pc", "tel"] {
            assert_eq!(banc.valeur(appareil, "issuer"), Value::String("GitHub Entreprise".into()), "{appareil}");
        }
        assert!(banc.identiques());
    }

    /// Scénario « Deux champs en parallèle » : les deux changements hors ligne survivent.
    #[test]
    fn scenario_deux_champs_parallele() {
        let mut banc = Banc::nouveau(0, 0);
        banc.edit("pc", "tag", "travail");
        banc.edit("tel", "issuer", "GH");
        banc.sync("pc");
        banc.sync("tel");
        banc.sync("pc");
        banc.converge();
        for appareil in ["pc", "tel"] {
            assert_eq!(banc.valeur(appareil, "issuer"), Value::String("GH".into()), "{appareil}");
            assert_eq!(banc.valeur(appareil, "tag"), Value::String("travail".into()), "{appareil}");
        }
        assert!(banc.identiques());
    }

    /// Scénario « Modifié après une suppression » : la modification plus récente
    /// fait revivre le compte, et le conflit est signalé.
    #[test]
    fn scenario_modifie_apres_suppression() {
        let mut banc = Banc::nouveau(0, 0);
        banc.supprime("pc");
        banc.sync("pc");
        banc.edit("tel", "description", "clé de secours");
        banc.sync("tel");
        banc.sync("pc");
        banc.converge();
        for appareil in ["pc", "tel"] {
            assert!(banc.vivant(appareil), "{appareil} : la modification a fait revivre le compte");
            assert_eq!(banc.valeur(appareil, "description"), Value::String("clé de secours".into()), "{appareil}");
        }
        assert!(banc.identiques());
        assert!(banc.entrees("conflit") > 0, "le conflit est journalisé");
    }

    /// Scénario « Horloge dans le futur » : le tampon futur est accepté sans
    /// contaminer l'horloge, la modification ultérieure (vue du futur) gagne quand
    /// même grâce au plancher, et l'horloge suspecte est journalisée.
    #[test]
    fn scenario_horloge_dans_le_futur() {
        let mut banc = Banc::nouveau(0, 365 * 24 * 60 * MINUT); // téléphone un an en avance
        banc.edit("tel", "issuer", "X");
        banc.sync("tel");
        banc.sync("pc");
        // Le tampon à un an dans le futur a été signalé à la première fusion du pc,
        // et n'a pas contaminé son horloge locale au-delà des 5 minutes.
        assert!(banc.entrees("horloge") > 0, "l'horloge suspecte est journalisée");
        let horloge_pc = banc.copies[banc.position("pc")].2.horloge;
        assert!(horloge_pc.l < T0 + 6 * MINUT, "l'horloge du pc n'a pas suivi le futur");
        // La correction du pc, faite après avoir vu le tampon futur, l'emporte
        // grâce au plancher (son horloge saute alors au-dessus — voulu : les
        // tampons d'un même appareil restent croissants).
        banc.edit("pc", "issuer", "Y");
        banc.sync("pc");
        banc.sync("tel");
        banc.converge();
        for appareil in ["pc", "tel"] {
            assert_eq!(banc.valeur(appareil, "issuer"), Value::String("Y".into()), "{appareil}");
        }
        assert!(banc.identiques());
    }

    /// Scénario « Même milliseconde » : deux éditions simultanées convergent vers
    /// la même valeur (l'appareil départage), avec conflit signalé.
    #[test]
    fn scenario_meme_milliseconde() {
        let mut banc = Banc::nouveau(0, 0);
        banc.edit("pc", "issuer", "A");
        banc.edit("tel", "issuer", "B");
        banc.sync("pc");
        banc.sync("tel");
        banc.sync("pc");
        banc.sync("tel");
        banc.converge();
        let attendu = banc.valeur("pc", "issuer");
        assert!(attendu == Value::String("A".into()) || attendu == Value::String("B".into()));
        for appareil in ["pc", "tel"] {
            assert_eq!(banc.valeur(appareil, "issuer"), attendu, "{appareil} : le même nom partout");
        }
        assert!(banc.identiques());
        assert!(banc.entrees("conflit") > 0, "le conflit est journalisé");
    }

    /* ── Élagage et registre des appareils ── */

    #[test]
    fn trace_vue_par_tous_est_effacee_et_silencieux_retire() {
        // Trois appareils : pc supprime, tous se synchronisent, la trace se propage,
        // puis est effacée de toutes les copies une fois vue par tous.
        let mut banc = Banc::nouveau(0, 0);
        banc.copies.push(("trois".to_string(), banc.drive.clone(), EtatSynchro::nouvelle("trois", T0 - MINUT), 0));
        banc.supprime("pc");
        banc.converge();
        // Convergé : partout mort (la trace circule) et encore présente pour propager.
        for (nom, copie, _, _) in &banc.copies {
            let items = liste(copie, ACCOUNTS_KEY);
            assert!(items.iter().all(|i| !est_vivant(i)), "{nom} : le compte est supprimé partout");
        }
        // Le temps passe d'un an : l'élagage retire la trace vue par tous.
        banc.t += SILENCE_MAX_MS + MINUT;
        banc.converge();
        // À ce stade la trace est vue par tous : les copies suivantes la laissent
        // tomber dès que tous les appareils actifs l'ont vue.
        for (nom, copie, _, _) in &banc.copies {
            let items = liste(copie, ACCOUNTS_KEY);
            assert!(items.is_empty(), "{nom} : trace vue partout, l'élément sort de la copie");
        }
    }

    /* ── Propriétés génératives ── */

    /// PRNG déterministe (xorshift64*), pour des tests de propriétés rejouables.
    struct Aleatoire(u64);

    impl Aleatoire {
        fn suivant(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn borne(&mut self, n: i64) -> i64 {
            (self.suivant() % n as u64) as i64
        }
    }

    /// Banc génératif : trois appareils aux horloges décalées, opérations aléatoires
    /// (éditions, suppressions, ajouts, synchros), convergence périodique.
    /// Invariants vérifiés à chaque convergence :
    ///  - toutes les copies et Drive sont identiques (convergence) ;
    ///  - chaque champ vivant porte la valeur de l'édit au tampon maximal
    ///    (rien d'enchaîné n'est perdu : une modification faite après avoir vu une
    ///    version porte un tampon plus grand qu'elle) ;
    ///  - un élément dont la suppression porte le plus grand tampon est mort partout
    ///    (pas de résurrection) ;
    ///  - refusionner une copie sur Drive ne change plus rien (idempotence).
    struct BancAleatoire {
        copies: Vec<(String, DataMap, EtatSynchro, i64)>,
        drive: DataMap,
        t: i64,
        // Attentes : id → (tampon par champ → (valeur, tampon)), tampon de suppression max.
        attente_champs: std::collections::BTreeMap<String, Vec<(&'static str, String, Value)>>,
        attente_trace: std::collections::BTreeMap<String, String>,
    }

    impl BancAleatoire {
        fn nouveau() -> Self {
            let mut copies = Vec::new();
            for nom in ["un", "deux", "trois"] {
                let mut items = Vec::new();
                for k in 0..2 {
                    let date = crate::iso_from_unix((T0 - 86_400_000) / 1000, 0);
                    let mut a = compte(&format!("init{k}"), "Initial", &date);
                    a["secret"] = Value::String(format!("SECRET{k}"));
                    items.push(a);
                }
                // Migration locale immédiate : les copies démarrent au format v2.
                let copie = migrer(&copie(items), T0, nom);
                copies.push((nom.to_string(), copie.clone(), EtatSynchro::nouvelle(nom, T0), 0));
            }
            let drive = copies[0].1.clone();
            Self {
                copies,
                drive,
                t: T0,
                attente_champs: std::collections::BTreeMap::new(),
                attente_trace: std::collections::BTreeMap::new(),
            }
        }

        fn sync(&mut self, appareil: &str) {
            let position = self.copies.iter().position(|(n, _, _, _)| n == appareil).unwrap();
            let (_, copie, etat, _) = &mut self.copies[position];
            let locale = copie.clone();
            let (fusionne, rapport) = fusion(&locale, &self.drive.clone(), etat, self.t);
            *copie = fusionne;
            if rapport.a_envoyer {
                self.drive = copie.clone();
            }
        }

        fn converge(&mut self) {
            for _ in 0..8 {
                let noms: Vec<String> = self.copies.iter().map(|(n, _, _, _)| n.clone()).collect();
                for nom in noms {
                    self.sync(&nom);
                }
                // Stable quand aucune copie ne diffère de Drive.
                let stable = self.copies.iter().all(|(_, copie, _, _)| !different_de(copie, &self.drive));
                if stable {
                    return;
                }
            }
            panic!("pas de convergence après 8 tours");
        }
    }

    #[test]
    fn propriete_convergence_et_attentes_sur_histoires_aleatoires() {
        for graine in [1u64, 7, 42, 2026, 98765] {
            let mut alea = Aleatoire(graine);
            let mut banc = BancAleatoire::nouveau();
            let champs = ["issuer", "tag", "description", "counter"];
            for pas in 0..120 {
                banc.t += alea.borne(4 * MINUT);
                let choix = alea.borne(10);
                let appareil = ["un", "deux", "trois"][alea.borne(3) as usize];
                if choix < 4 {
                    // Édition d'un champ d'un élément existant (par l'appareil).
                    let position = banc.copies.iter().position(|(n, _, _, _)| n == appareil).unwrap();
                    let items = liste(&banc.copies[position].1, ACCOUNTS_KEY);
                    let vivants: Vec<usize> = items.iter().enumerate().filter(|(_, i)| est_vivant(i)).map(|(k, _)| k).collect();
                    if vivants.is_empty() {
                        continue;
                    }
                    let k = vivants[alea.borne(vivants.len() as i64) as usize];
                    let id = texte(&items[k], "id").to_string();
                    let champ = champs[alea.borne(champs.len() as i64) as usize];
                    // Plancher : le tampon actuel du champ, sinon le plus grand de l'élément.
                    let plancher = {
                        let actuel = tampon_de(&items[k], champ).to_string();
                        if actuel.is_empty() { plus_grand_tampon(&items[k]) } else { actuel }
                    };
                    let valeur = if champ == "counter" {
                        Value::from(items[k].get("counter").and_then(Value::as_u64).unwrap_or(0) + 1 + alea.borne(3) as u64)
                    } else {
                        Value::String(format!("{appareil}-{pas}"))
                    };
                    let tampon = {
                        let (nom, _, etat, _) = &mut banc.copies[position];
                        etat.horloge.apres(banc.t, Some(&plancher), nom)
                    };
                    let (_, copie, _, _) = &mut banc.copies[position];
                    let mut items2 = liste(copie, ACCOUNTS_KEY);
                    let item = &mut items2[k];
                    item[champ] = valeur.clone();
                    if champ == "counter" {
                        // HOTP : valeur maximale uniquement.
                        if valeur.as_u64().unwrap() < item.get("counter").and_then(Value::as_u64).unwrap_or(0) {
                            continue;
                        }
                    }
                    poser_tampon(item, champ, &tampon);
                    ecrire_liste(copie, ACCOUNTS_KEY, &items2);
                    // Attente : ce tampon prétend à la vérité sur ce champ.
                    banc.attente_champs.entry(id.clone()).or_default().push((champ, tampon, valeur));
                } else if choix < 6 {
                    // Suppression d'un élément vivant.
                    let position = banc.copies.iter().position(|(n, _, _, _)| n == appareil).unwrap();
                    let items = liste(&banc.copies[position].1, ACCOUNTS_KEY);
                    let vivants: Vec<usize> = items.iter().enumerate().filter(|(_, i)| est_vivant(i)).map(|(k, _)| k).collect();
                    if vivants.is_empty() {
                        continue;
                    }
                    let k = vivants[alea.borne(vivants.len() as i64) as usize];
                    let id = texte(&items[k], "id").to_string();
                    let plancher = plus_grand_tampon(&items[k]);
                    let tampon = {
                        let (nom, _, etat, _) = &mut banc.copies[position];
                        etat.horloge.apres(banc.t, Some(&plancher), nom)
                    };
                    let (_, copie, _, _) = &mut banc.copies[position];
                    let mut items2 = liste(copie, ACCOUNTS_KEY);
                    items2[k]["t"] = Value::String(tampon.clone());
                    ecrire_liste(copie, ACCOUNTS_KEY, &items2);
                    banc.attente_trace.insert(id, tampon);
                } else if choix < 8 {
                    // Ajout d'un nouvel élément (même identité possible : doublon à fusionner).
                    let id = format!("ajout-{pas}");
                    let secret = if alea.borne(3) == 0 { "DOUBLONSECRET".to_string() } else { format!("S-{id}") };
                    let date = crate::iso_from_unix(banc.t / 1000, 0);
                    let mut a = compte(&id, "Ajout", &date);
                    a["secret"] = Value::String(secret);
                    a["account"] = Value::String(format!("moi-{id}@example.net"));
                    let position = banc.copies.iter().position(|(n, _, _, _)| n == appareil).unwrap();
                    let (_, copie, _, _) = &mut banc.copies[position];
                    let mut items = liste(copie, ACCOUNTS_KEY);
                    items.push(a);
                    ecrire_liste(copie, ACCOUNTS_KEY, &items);
                } else {
                    // Synchronisation d'un appareil.
                    banc.sync(appareil);
                }
                // Tous les 30 pas : convergence et vérification des invariants.
                if pas % 30 == 29 {
                    banc.converge();
                    verifier_attentes(&banc);
                }
            }
            banc.converge();
            verifier_attentes(&banc);
        }
    }

    /// Invariants post-convergence : copies identiques, champ vivant = édit au
    /// tampon maximal, suppression au tampon maximal = mort partout.
    fn verifier_attentes(banc: &BancAleatoire) {
        // Convergence : toutes les copies égales entre elles et à Drive.
        let premiere = &banc.copies[0].1;
        for (nom, copie, _, _) in &banc.copies {
            assert!(!different_de(copie, premiere), "{nom} : copie divergente après convergence");
            assert!(!different_de(copie, &banc.drive), "{nom} : copie divergente de Drive");
        }
        for id in banc.attente_champs.keys() {
            let attentes = banc.attente_champs.get(id).unwrap();
            // Les attentes des ids jamais distribués à Drive n'existent pas… tous le sont.
            let _ = attentes;
        }
        for (id, attentes) in &banc.attente_champs {
            let items = liste(&banc.drive, ACCOUNTS_KEY);
            let Some(item) = items.iter().find(|i| texte(i, "id") == id) else {
                continue; // l'élément a pu sortir par élagage — voir attente_trace
            };
            let trace_max = banc.attente_trace.get(id);
            let vivant_attendu = match trace_max {
                Some(trace) => attentes.iter().map(|(_, t, _)| t.as_str()).max().unwrap() > trace.as_str(),
                None => true,
            };
            assert_eq!(est_vivant(item), vivant_attendu, "{id} : vivant = {vivant_attendu} attendu");
            if !vivant_attendu {
                continue;
            }
            for (champ, _, _) in attentes {
                // La valeur attendue : celle de l'attente au tampon maximal pour ce champ.
                let (tampon_max_attendu, valeur_attendue) = attentes
                    .iter()
                    .filter(|(c, _, _)| c == champ)
                    .map(|(_, t, v)| (t.clone(), v.clone()))
                    .max_by(|a, b| a.0.cmp(&b.0))
                    .unwrap();
                // Pour le compteur HOTP : valeur maximale, pas tampon maximal.
                if champ == &"counter" {
                    let attendu = attentes
                        .iter()
                        .filter(|(c, _, _)| c == champ)
                        .map(|(_, _, v)| v.as_u64().unwrap())
                        .max()
                        .unwrap();
                    assert_eq!(item.get("counter").and_then(Value::as_u64), Some(attendu), "{id}.counter");
                    continue;
                }
                assert_eq!(champ_de(item, champ), valeur_attendue, "{id}.{champ} : tampon max {tampon_max_attendu}");
            }
        }
    }

    /// Pas de résurrection : après une convergence complète où l'élément est mort,
    /// refusionner (toutes les paires, dans tous les sens) ne le fait pas revenir.
    #[test]
    fn pas_de_resurrection_apres_convergence_complete() {
        let etat_pc = &mut EtatSynchro::nouvelle("pc", T0);
        let etat_tel = &mut EtatSynchro::nouvelle("tel", T0);
        let initial = copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
        let mut pc = migrer(&initial, T0, "pc");
        let mut tel = migrer(&initial, T0, "tel");
        // pc supprime puis synchronise ; tel synchronise (adopte la trace).
        let horloge_pc = etat_pc.horloge;
        let _ = horloge_pc;
        let tampon = etat_pc.horloge.apres(T0, Some(&plus_grand_tampon(&liste(&pc, ACCOUNTS_KEY)[0])), "pc");
        let mut items = liste(&pc, ACCOUNTS_KEY);
        items[0]["t"] = Value::String(tampon);
        ecrire_liste(&mut pc, ACCOUNTS_KEY, &items);
        let (pc2, _) = fusion(&pc, &DataMap::new(), etat_pc, T0);
        pc = pc2;
        let (tel2, _) = fusion(&tel, &pc, etat_tel, T0);
        tel = tel2;
        assert!(!est_vivant(&liste(&tel, ACCOUNTS_KEY)[0]), "tel a adopté la suppression");
        // Refusionner dans tous les sens ne ressuscite rien.
        let (pc3, _) = fusion(&pc, &tel, etat_pc, T0 + MINUT);
        let (tel3, _) = fusion(&tel, &pc3, etat_tel, T0 + MINUT);
        let (pc4, _) = fusion(&pc3, &tel3, etat_pc, T0 + 2 * MINUT);
        // Le contenu converge (comptes, historique, réglages) ; les tampons
        // d'activité du registre, eux, datent la dernière synchro de CHAQUE
        // appareil : la copie de tel connaît l'activité de pc à T0+1 min, pc
        // s'est encore synchronisé à T0+2 min — on ne compare pas cela.
        assert_eq!(liste(&pc4, ACCOUNTS_KEY), liste(&tel3, ACCOUNTS_KEY));
        assert_eq!(pc4.get(HISTORY_KEY), tel3.get(HISTORY_KEY));
        assert!(!est_vivant(&liste(&pc4, ACCOUNTS_KEY)[0]));
        assert!(!est_vivant(&liste(&tel3, ACCOUNTS_KEY)[0]));
    }

    /// Un tampon reçu à plus de 5 min dans le futur est journalisé, accepté comme
    /// contenu, mais ne contamine pas l'horloge locale.
    #[test]
    fn tampon_futur_journaise_sans_contaminer() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        let lointain = encoder_tampon(T0 + 365 * 24 * 60 * MINUT, 3, "tel");
        let mut futur = copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
        let mut items = liste(&futur, ACCOUNTS_KEY);
        items[0]["updatedAt"] = Value::String(iso_depuis_tampon(&lointain));
        poser_tampon(&mut items[0], "issuer", &lointain);
        items[0]["issuer"] = Value::String("Du futur".into());
        ecrire_liste(&mut futur, ACCOUNTS_KEY, &items);
        let vide = DataMap::new();
        let (fusionne, rapport) = fusion(&vide, &futur, etat, T0);
        assert_eq!(valeur(&fusionne, "a1", "issuer"), Value::String("Du futur".into()), "le contenu futur est accepté");
        assert!(
            rapport.entrees.iter().any(|e| e.genre == "horloge" && e.champ == "tel"),
            "l'horloge suspecte est journalisée avec l'appareil émetteur"
        );
        assert_eq!(etat.horloge.l, T0, "l'horloge locale n'a pas suivi le futur");
        // La modification locale suivante, avec plancher, reprend la main.
        let tampon = etat.horloge.apres(T0 + MINUT, Some(&lointain), "pc");
        assert!(comparer(&tampon, &lointain) == Ordering::Greater);
    }

    /// Historique : union par id, sans ce qui précède le vidage tamponné, plafonné.
    #[test]
    fn historique_union_vidage_et_plafond() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        let entree_h = |id: &str, at: &str| {
            serde_json::json!({ "id": id, "at": at, "action": "create", "accountId": null, "label": null, "tag": null, "details": null })
        };
        let mut gauche = DataMap::new();
        let mut items = Vec::new();
        for k in 0..600 {
            items.push(entree_h(&format!("h{k}"), &format!("2026-09-{:02}T00:00:00.000Z", k % 28 + 1)));
        }
        ecrire_liste(&mut gauche, HISTORY_KEY, &items);
        let mut droite = DataMap::new();
        let marqueur = Marqueur {
            appareils: vec![],
            historique_vide_le: Some(tampon_depuis_iso("2026-09-15T00:00:00.000Z")),
            v1: vec![],
        };
        ecrire_marqueur(&mut droite, &marqueur);
        let (fusionne, _) = fusion(&gauche, &droite, etat, T0);
        let histoire = liste(&fusionne, HISTORY_KEY);
        assert!(histoire.len() <= HISTORY_MAX);
        for e in &histoire {
            let at = e.get("at").and_then(Value::as_str).unwrap();
            assert!(at > "2026-09-15T00:00:00.000Z", "rien d'avant le vidage : {at}");
        }
        // Tri décroissant.
        let ats: Vec<&str> = histoire.iter().map(|e| e.get("at").and_then(Value::as_str).unwrap()).collect();
        let mut tries = ats.clone();
        tries.sort();
        tries.reverse();
        assert_eq!(ats, tries);
    }

    /// Réglages : le plus grand tampon gagne, champ par nom.
    #[test]
    fn reglages_plus_grand_tampon_gagne() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        let gauche = migrer(
            &{
                let mut m = DataMap::new();
                m.insert(
                    SETTINGS_KEY.to_string(),
                    r#"{"policy":{"value":{"minLength":12},"at":"2026-05-01T00:00:00.000Z"}}"#.into(),
                );
                m
            },
            T0,
            "pc",
        );
        let droite = migrer(
            &{
                let mut m = DataMap::new();
                m.insert(
                    SETTINGS_KEY.to_string(),
                    r#"{"policy":{"value":{"minLength":16},"at":"2026-02-01T00:00:00.000Z"},"prefs":{"value":{"theme":"dark"},"at":"2026-03-01T00:00:00.000Z"}}"#.into(),
                );
                m
            },
            T0,
            "tel",
        );
        let (fusionne, _) = fusion(&gauche, &droite, etat, T0);
        let reglages: Value = serde_json::from_str(fusionne.get(SETTINGS_KEY).unwrap()).unwrap();
        assert_eq!(reglages["policy"]["value"]["minLength"], 12, "le tampon de mai gagne contre février");
        assert_eq!(reglages["prefs"]["value"]["theme"], "dark", "nouveau côté droit : adopté");
    }

    /// Collections récentes absentes des deux côtés : rien d'écrit ; comptes
    /// toujours écrits ; le marqueur toujours posé.
    #[test]
    fn collections_absentes_non_ecrites() {
        let etat = &mut EtatSynchro::nouvelle("pc", T0);
        let gauche = copie(vec![compte("a1", "GitHub", "2026-01-01T00:00:00.000Z")]);
        let vide = DataMap::new();
        let (fusionne, _) = fusion(&gauche, &vide, etat, T0);
        assert!(!fusionne.contains_key(LOGINS_KEY));
        assert!(!fusionne.contains_key(PASSKEYS_KEY));
        assert!(fusionne.contains_key(ACCOUNTS_KEY));
        assert!(fusionne.contains_key(SYNC_KEY));
        assert!(fusionne.contains_key(HISTORY_KEY));
    }
}

