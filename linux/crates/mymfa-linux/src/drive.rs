/*
 * Google Drive pour le démon Linux (LIN-06) : la couche transport de la
 * synchronisation v2 (SYN-07). Le fichier de rendez-vous est le même que celui
 * du web — `mymfa-vault.json` dans `appDataFolder` (portée drive.appdata),
 * invisible dans l'interface de Drive, chiffré de bout en bout.
 *
 * OAuth « Application de bureau » (du même projet Google Cloud que le web,
 * identifiant client distinct) : boucle locale + PKCE, RFC 8252 — le démon ouvre
 * le navigateur, Google revient sur http://127.0.0.1:<port>/?code=…, le démon
 * échange le code contre ses jetons. Le jeton de rafraîchissement est conservé
 * chiffré par la DEK du coffre (AAD propre) dans `mymfa-drive.json` : coffre
 * verrouillé ou absent, plus aucun jeton — déverrouiller le coffre reconnecte.
 *
 * Le transport HTTP est injecté (`Transport`) : les tests conduisent un faux
 * Google sans réseau ; reqwest (rustls) n'est utilisé que par le vrai.
 */
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use mymfa_core::vault::{from_b64, random_bytes, to_b64, DataBlob, Dek};
use mymfa_core::AppError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::chemins::maintenant;

pub const AAD_JETONS: &str = "mymfa:linux:drive:v1";
/// Identifiant client OAuth « Application de bureau » du projet Google Cloud
/// de myMFA (distinct de l'identifiant du client web).
pub const ID_CLIENT: &str = "399049616505-ct9hd12gpivd4feht1811dk8st78lb15.apps.googleusercontent.com";
/// Portée réservée au dossier caché de l'app : Drive ne voit que ses propres fichiers.
pub const PORTEE: &str = "https://www.googleapis.com/auth/drive.appdata";
pub const FICHIER: &str = "mymfa-vault.json";
const API: &str = "https://www.googleapis.com/drive/v3/files";
const TELEVERSEMENT: &str = "https://www.googleapis.com/upload/drive/v3/files";
const JETON_URL: &str = "https://oauth2.googleapis.com/token";

/* ─── PKCE (RFC 7636, S256) ───────────────────────────────────────────────── */

pub fn b64url(donnees: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(donnees.len().div_ceil(3) * 4);
    for paquet in donnees.chunks(3) {
        let b = [paquet[0], *paquet.get(1).unwrap_or(&0), *paquet.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if paquet.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if paquet.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// Couple vérificateur/défi PKCE : le défi part dans l'URL d'autorisation, le
/// vérificateur reste pour l'échange du code.
pub struct Pkce {
    pub verifier: Zeroizing<String>,
    pub challenge: String,
}

impl Pkce {
    pub fn nouveau() -> Self {
        let octets = random_bytes(64);
        let verifier = Zeroizing::new(b64url(&octets));
        let empreinte = Sha256::digest(verifier.as_bytes());
        Self { challenge: b64url(&empreinte), verifier }
    }
}

/* ─── Jetons ──────────────────────────────────────────────────────────────── */

#[derive(Clone, Debug)]
pub struct Jetons {
    /// Jeton d'accès (Authorization: Bearer …).
    pub acces: Zeroizing<String>,
    /// Instant (s) où il cesse d'être fiable (avec une minute de marge).
    pub acces_expire_le: u64,
    /// Jeton de rafraîchissement : Google le renvoie à la connexion ; il reste
    /// le même ensuite (rarement renouvelé — on garde alors l'ancien).
    pub rafraichissement: Zeroizing<String>,
}

/// Persiste les jetons chiffrés par la DEK dans `mymfa-drive.json` (0600).
/// Renvoie le texte du fichier à écrire de façon atomique.
pub fn jetons_en_texte(jetons: &Jetons, dek: &Dek) -> Result<String, AppError> {
    #[derive(serde::Serialize)]
    #[serde(rename_all = "camelCase")]
    struct JetonsClairs {
        acces: String,
        acces_expire_le: u64,
        rafraichissement: String,
    }
    let clairs = serde_json::to_vec(&JetonsClairs {
        acces: jetons.acces.to_string(),
        acces_expire_le: jetons.acces_expire_le,
        rafraichissement: jetons.rafraichissement.to_string(),
    })
    .map_err(|_| AppError::new("corrupted"))?;
    let iv = random_bytes(12);
    let cle = aes_gcm::Key::<Aes256Gcm>::from_slice(&dek.0).to_owned();
    let ct = Aes256Gcm::new(&cle)
        .encrypt(
            Nonce::from_slice(&iv),
            Payload { msg: &clairs, aad: AAD_JETONS.as_bytes() },
        )
        .map_err(|_| AppError::new("corrupted"))?;
    Ok(serde_json::json!({
        "v": 1,
        "data": DataBlob { iv: to_b64(&iv), ct: to_b64(&ct) },
    })
    .to_string())
}

/// Relit des jetons chiffrés (None si la connexion n'existe pas encore, erreur
/// si le fichier ne s'ouvre plus avec cette DEK — coffre recréé ailleurs).
pub fn jetons_depuis_texte(texte: &str, dek: &Dek) -> Result<Option<Jetons>, AppError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct JetonsClairs {
        acces: String,
        acces_expire_le: u64,
        rafraichissement: String,
    }
    let Some(blob) = texte
        .trim()
        .is_empty()
        .then_some(None)
        .unwrap_or_else(|| serde_json::from_str::<serde_json::Value>(texte).ok().and_then(|v| {
            Some(DataBlob { iv: v["data"]["iv"].as_str()?.to_string(), ct: v["data"]["ct"].as_str()?.to_string() })
        }))
    else {
        return Ok(None);
    };
    let iv = from_b64(&blob.iv).map_err(|_| AppError::new("corrupted"))?;
    let ct = from_b64(&blob.ct).map_err(|_| AppError::new("corrupted"))?;
    let cle = aes_gcm::Key::<Aes256Gcm>::from_slice(&dek.0).to_owned();
    let clairs = Aes256Gcm::new(&cle)
        .decrypt(Nonce::from_slice(&iv), Payload { msg: &ct, aad: AAD_JETONS.as_bytes() })
        .map_err(|_| AppError::new("driveAuth"))?;
    let j: JetonsClairs = serde_json::from_slice(&clairs).map_err(|_| AppError::new("corrupted"))?;
    Ok(Some(Jetons {
        acces: Zeroizing::new(j.acces),
        acces_expire_le: j.acces_expire_le,
        rafraichissement: Zeroizing::new(j.rafraichissement),
    }))
}

/* ─── Transport HTTP (injection) ──────────────────────────────────────────── */

pub struct Reponse {
    pub statut: u16,
    pub corps: String,
}

pub trait Transport {
    /// Requête HTTP porteuse du jeton d'accès : POST form (OAuth), GET/POST/PATCH
    /// Drive. `corps` = (type de contenu, corps). Renvoie le statut et le corps.
    async fn envoyer(&self, jeton_acces: &str, methode: &str, url: &str, corps: Option<(&str, String)>) -> Result<Reponse, AppError>;
}

/// Le vrai transport : reqwest + rustls (aucune bibliothèque système).
pub struct TransportReel(pub reqwest::Client);

/// Un client réutilisable (connexions keep-alive partagées).
pub fn transport_reel() -> TransportReel {
    TransportReel(reqwest::Client::new())
}

impl Transport for TransportReel {
    async fn envoyer(&self, jeton_acces: &str, methode: &str, url: &str, corps: Option<(&str, String)>) -> Result<Reponse, AppError> {
        let requete = match methode {
            "POST" => self.0.post(url),
            "PATCH" => self.0.patch(url),
            _ => self.0.get(url),
        };
        let requete = requete
            .bearer_auth(jeton_acces)
            .header("Accept", "application/json");
        let requete = if let Some((type_contenu, corps)) = corps {
            requete.header("Content-Type", type_contenu).body(corps)
        } else {
            requete
        };
        let reponse = requete.send().await.map_err(|_| AppError::new("driveUnavailable"))?;
        let statut = reponse.status().as_u16();
        let corps = reponse.text().await.map_err(|_| AppError::new("driveUnavailable"))?;
        Ok(Reponse { statut, corps })
    }
}

/* ─── OAuth : boucle locale + PKCE ────────────────────────────────────────── */

/// URL d'autorisation à ouvrir dans le navigateur (le port est celui du
/// serveur de boucle locale déjà lié sur 127.0.0.1).
pub fn url_autorisation(challenge: &str, port: u16, etat: &str) -> String {
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={ID_CLIENT}&redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}&response_type=code&scope={PORTEE}&code_challenge={challenge}&code_challenge_method=S256&state={etat}&prompt=consent&access_type=offline"
    )
}

/// Le corps de la page renvoyée au navigateur après le retour de Google.
pub const PAGE_RETOUR: &str = "<!doctype html><meta charset=utf-8><title>myMFA</title><p style=\"font-family:sans-serif;font-size:1.2rem;text-align:center;margin-top:20vh\">myMFA : connexion Drive établie — tu peux fermer cet onglet.</p>";

/// Échange le code d'autorisation contre les jetons (PKCE : le vérificateur
/// prouve que c'est bien nous qui avons lancé la connexion).
pub async fn echanger_code(t: &impl Transport, code: &str, verifier: &str, port: u16) -> Result<Jetons, AppError> {
    let corps = format!(
        "code={}&client_id={ID_CLIENT}&code_verifier={}&grant_type=authorization_code&redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}",
        url_encoder(code),
        url_encoder(verifier)
    );
    let reponse = t.envoyer("", "POST", JETON_URL, Some(("application/x-www-form-urlencoded", corps))).await?;
    if reponse.statut != 200 {
        return Err(AppError::new("driveAuth"));
    }
    jetons_de_reponse(&reponse.corps)
}

/// Rafraîchit le jeton d'accès (Google renvoie parfois un nouveau jeton de
/// rafraîchissement : on le garde, sinon l'ancien reste valable).
pub async fn rafraichir(t: &impl Transport, ancien: &Jetons) -> Result<Jetons, AppError> {
    let corps = format!(
        "client_id={ID_CLIENT}&refresh_token={}&grant_type=refresh_token",
        url_encoder(&ancien.rafraichissement)
    );
    let reponse = t.envoyer("", "POST", JETON_URL, Some(("application/x-www-form-urlencoded", corps))).await?;
    if reponse.statut != 200 {
        return Err(AppError::new("driveAuth"));
    }
    #[derive(Deserialize)]
    struct ReponseJeton {
        #[serde(default)]
        access_token: String,
        #[serde(default)]
        expires_in: u64,
        #[serde(default)]
        refresh_token: String,
    }
    let j: ReponseJeton = serde_json::from_str(&reponse.corps).map_err(|_| AppError::new("driveHttp"))?;
    if j.access_token.is_empty() {
        return Err(AppError::new("driveAuth"));
    }
    Ok(Jetons {
        acces: Zeroizing::new(j.access_token),
        acces_expire_le: maintenant() + j.expires_in.saturating_sub(60),
        rafraichissement: if j.refresh_token.is_empty() {
            ancien.rafraichissement.clone()
        } else {
            Zeroizing::new(j.refresh_token)
        },
    })
}

/// Échappement x-www-form-urlencoded minimal (seulement ce que nous envoyons :
/// codes, vérificateurs et jetons alphanumériques et quelques signes).
fn url_encoder(texte: &str) -> String {
    let mut out = String::with_capacity(texte.len());
    for c in texte.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            autre => out.push_str(&autre.to_string().bytes().map(|b| format!("%{b:02X}")).collect::<String>()),
        }
    }
    out
}

fn jetons_de_reponse(corps: &str) -> Result<Jetons, AppError> {
    #[derive(Deserialize)]
    struct ReponseJeton {
        access_token: String,
        expires_in: u64,
        #[serde(default)]
        refresh_token: String,
    }
    let j: ReponseJeton = serde_json::from_str(corps).map_err(|_| AppError::new("driveHttp"))?;
    if j.refresh_token.is_empty() {
        // Sans jeton de rafraîchissement, la connexion ne survit pas à l'heure :
        // refus (prompt=consent + access_type=offline les garantissent côté URL).
        return Err(AppError::new("driveAuth"));
    }
    Ok(Jetons {
        acces: Zeroizing::new(j.access_token),
        acces_expire_le: maintenant() + j.expires_in.saturating_sub(60),
        rafraichissement: Zeroizing::new(j.refresh_token),
    })
}

/* ─── Client Drive appDataFolder ──────────────────────────────────────────── */

/// La sauvegarde trouvée sur Drive : identifiant du fichier, révision (le
/// repère de version du cycle v2), date de modification (heure des serveurs
/// Google — la référence T() du web, consignée au journal côté démon).
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SauvegardeDrive {
    pub id: String,
    pub revision: String,
    pub modifiee_le: String,
}

/// Cherche mymfa-vault.json dans appDataFolder. 403 avec « appNotAuthorized »
/// ou 404 : aucune sauvegarde. Autre statut : erreur porteuse du code HTTP.
pub async fn trouver(t: &impl Transport, jetons: &Jetons) -> Result<Option<SauvegardeDrive>, AppError> {
    let url = format!(
        "{API}?spaces=appDataFolder&q={}&fields=files(id,headRevisionId,modifiedTime)&orderBy=modifiedTime%20desc&pageSize=1",
        url_encoder(&format!("name = '{FICHIER}' and trashed = false"))
    );
    let reponse = t.envoyer(&jetons.acces, "GET", &url, None).await?;
    if reponse.statut == 401 || reponse.statut == 403 {
        return Err(AppError::new("driveAuth"));
    }
    if reponse.statut != 200 {
        return Err(AppError::with("driveHttp", vec![("status", reponse.statut.to_string())]));
    }
    #[derive(Deserialize)]
    struct ReponseListe {
        #[serde(default)]
        files: Vec<Fichier>,
    }
    #[derive(Deserialize)]
    struct Fichier {
        id: String,
        #[serde(rename = "headRevisionId", default)]
        revision: String,
        #[serde(rename = "modifiedTime", default)]
        modifiee_le: String,
    }
    let liste: ReponseListe = serde_json::from_str(&reponse.corps).map_err(|_| AppError::new("driveHttp"))?;
    Ok(liste.files.into_iter().next().map(|f| SauvegardeDrive { id: f.id, revision: f.revision, modifiee_le: f.modifiee_le }))
}

/// Lit le contenu chiffré de la sauvegarde.
pub async fn lire(t: &impl Transport, jetons: &Jetons, id: &str) -> Result<String, AppError> {
    let reponse = t.envoyer(&jetons.acces, "GET", &format!("{API}/{id}?alt=media"), None).await?;
    if reponse.statut == 401 || reponse.statut == 403 {
        return Err(AppError::new("driveAuth"));
    }
    if reponse.statut != 200 {
        return Err(AppError::with("driveHttp", vec![("status", reponse.statut.to_string())]));
    }
    Ok(reponse.corps)
}

/// La révision actuelle de la sauvegarde (revérification avant envoi : si
/// quelqu'un a écrit entre-temps, relire et refusionner).
pub async fn revision_actuelle(t: &impl Transport, jetons: &Jetons, id: &str) -> Result<String, AppError> {
    let reponse = t.envoyer(&jetons.acces, "GET", &format!("{API}/{id}?fields=headRevisionId"), None).await?;
    if reponse.statut == 401 || reponse.statut == 403 {
        return Err(AppError::new("driveAuth"));
    }
    if reponse.statut != 200 {
        return Err(AppError::with("driveHttp", vec![("status", reponse.statut.to_string())]));
    }
    let valeur: serde_json::Value = serde_json::from_str(&reponse.corps).map_err(|_| AppError::new("driveHttp"))?;
    Ok(valeur["headRevisionId"].as_str().unwrap_or_default().to_string())
}

/// Envoie le coffre fusionné : PATCH media sur le fichier existant, création
/// multipart sinon. Renvoie la révision nouvellement posée.
pub async fn envoyer(t: &impl Transport, jetons: &Jetons, id: Option<&str>, contenu: &str) -> Result<String, AppError> {
    let (url, type_contenu, corps) = match id {
        Some(id) => (
            format!("{TELEVERSEMENT}/{id}?uploadType=media&fields=headRevisionId"),
            "application/json".to_string(),
            contenu.to_string(),
        ),
        None => {
            let borne = "mymfa-demon-3f8a";
            let metadonnees = serde_json::json!({ "name": FICHIER, "parents": ["appDataFolder"], "mimeType": "application/json" });
            (
                format!("{TELEVERSEMENT}?uploadType=multipart&fields=headRevisionId"),
                format!("multipart/related; boundary={borne}"),
                format!(
                    "--{borne}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n{}\r\n--{borne}\r\nContent-Type: application/json\r\n\r\n{contenu}\r\n--{borne}--",
                    metadonnees
                ),
            )
        }
    };
    let reponse = t
        .envoyer(&jetons.acces, if id.is_some() { "PATCH" } else { "POST" }, &url, Some((&type_contenu, corps)))
        .await?;
    if reponse.statut == 401 || reponse.statut == 403 {
        return Err(AppError::new("driveAuth"));
    }
    if reponse.statut != 200 {
        return Err(AppError::with("driveHttp", vec![("status", reponse.statut.to_string())]));
    }
    let valeur: serde_json::Value = serde_json::from_str(&reponse.corps).map_err(|_| AppError::new("driveHttp"))?;
    Ok(valeur["headRevisionId"].as_str().unwrap_or_default().to_string())
}

/* ─── Boucle locale (RFC 8252) : Google revient sur 127.0.0.1 ────────────── */

/// Attend le retour du navigateur sur le serveur de boucle locale déjà lié :
/// une seule requête GET, `code` extrait, `state` vérifié (une page d'un autre
/// onglet ne peut pas nous imposer un code), page de confirmation renvoyée.
/// Renvoie le code d'autorisation.
pub async fn attendre_code(ecouteur: tokio::net::TcpListener, etat_attendu: &str, patience: std::time::Duration) -> Result<String, AppError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (mut flux, _) = tokio::time::timeout(patience, ecouteur.accept())
        .await
        .map_err(|_| AppError::new("driveCancelled"))?
        .map_err(|_| AppError::new("driveCancelled"))?;
    // Lire la requête (en-têtes compris) : quelques kilo-octets suffisent.
    let mut tampon = [0u8; 8192];
    let n = tokio::time::timeout(patience, flux.read(&mut tampon))
        .await
        .map_err(|_| AppError::new("driveCancelled"))?
        .map_err(|_| AppError::new("driveCancelled"))?;
    let requete = String::from_utf8_lossy(&tampon[..n]);
    let ligne = requete.lines().next().unwrap_or("");
    let cible = ligne.split_whitespace().nth(1).unwrap_or("");
    let (chemin, requete_cible) = cible.split_once('?').unwrap_or((cible, ""));
    if chemin != "/" {
        return Err(AppError::new("driveCancelled"));
    }
    let mut code = String::new();
    let mut etat = String::new();
    let mut erreur = String::new();
    for paire in requete_cible.split('&') {
        let (cle, valeur) = paire.split_once('=').unwrap_or((paire, ""));
        match cle {
            "code" => code = url_decoder(valeur),
            "state" => etat = url_decoder(valeur),
            "error" => erreur = url_decoder(valeur),
            _ => {}
        }
    }
    let reponse = if erreur.is_empty() && !code.is_empty() && etat == etat_attendu {
        ("HTTP/1.1 200 OK", PAGE_RETOUR)
    } else {
        ("HTTP/1.1 400 Bad Request", "<!doctype html><meta charset=utf-8><title>myMFA</title><p>myMFA : connexion Drive interrompue.</p>")
    };
    let corps = format!(
        "{}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        reponse.0,
        reponse.1.len(),
        reponse.1
    );
    let _ = flux.write_all(corps.as_bytes()).await;
    let _ = flux.flush().await;
    if erreur.is_empty() && !code.is_empty() && etat == etat_attendu {
        Ok(code)
    } else {
        Err(AppError::new("driveCancelled"))
    }
}

fn url_decoder(texte: &str) -> String {
    let octets = texte.as_bytes();
    let mut out = Vec::with_capacity(octets.len());
    let mut k = 0;
    while k < octets.len() {
        match octets[k] {
            b'%' if k + 2 < octets.len() => match u8::from_str_radix(std::str::from_utf8(&octets[k + 1..k + 3]).unwrap_or(""), 16) {
                Ok(b) => {
                    out.push(b);
                    k += 3;
                }
                Err(_) => {
                    out.push(octets[k]);
                    k += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                k += 1;
            }
            b => {
                out.push(b);
                k += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/* ─── Tests : PKCE, jetons, faux Google ──────────────────────────────────── */

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn base64url_sans_rempadding_et_conforme_rfc4648() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        // Alphabet URL : aucun + ni / ni =.
        let long = b64url(&random_bytes(64));
        assert_eq!(long.len(), 86);
        assert!(!long.contains('+') && !long.contains('/') && !long.contains('='));
    }

    #[test]
    fn pkce_verifier_et_defi_correspondent() {
        let pkce = Pkce::nouveau();
        assert_eq!(pkce.verifier.len(), 86);
        let empreinte = Sha256::digest(pkce.verifier.as_bytes());
        assert_eq!(pkce.challenge, b64url(&empreinte), "le défi est S256 du vérificateur");
        // Deux tirages : jamais le même couple.
        let autre = Pkce::nouveau();
        assert_ne!(pkce.verifier, autre.verifier);
    }

    #[test]
    fn url_d_autorisation_porte_toutes_les_exigences() {
        let pkce = Pkce::nouveau();
        let url = url_autorisation(&pkce.challenge, 45_123, "etat123");
        assert!(url.contains(&format!("client_id={ID_CLIENT}")));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A45123"));
        assert!(url.contains(&format!("scope={PORTEE}")));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains(&format!("code_challenge={}", pkce.challenge)));
        assert!(url.contains("state=etat123"));
        assert!(url.contains("access_type=offline"), "jeton de rafraîchissement exigé");
        assert!(url.contains("prompt=consent"));
    }

    #[test]
    fn jetons_aller_retour_chiffres_par_la_dek() {
        let dek = Dek(random_bytes(32).try_into().unwrap());
        let jetons = Jetons {
            acces: Zeroizing::new("ACCESS".into()),
            acces_expire_le: 1234,
            rafraichissement: Zeroizing::new("RAFRAICHISSEMENT".into()),
        };
        let texte = jetons_en_texte(&jetons, &dek).unwrap();
        assert!(!texte.contains("ACCESS") && !texte.contains("RAFRAICHISSEMENT"), "jamais de jeton en clair");
        let relus = jetons_depuis_texte(&texte, &dek).unwrap().unwrap();
        assert_eq!(relus.acces, jetons.acces);
        assert_eq!(relus.acces_expire_le, 1234);
        assert_eq!(relus.rafraichissement, jetons.rafraichissement);
        // Une autre DEK refuse (coffre recréé ailleurs).
        let autre = Dek(random_bytes(32).try_into().unwrap());
        assert!(jetons_depuis_texte(&texte, &autre).is_err());
        // Fichier vide : pas encore de connexion.
        assert!(jetons_depuis_texte("", &dek).unwrap().is_none());
    }

    /// Un faux Google : réponses par méthode + URL, compteur d'appels.
    struct Faux {
        reponses: BTreeMap<(String, String), Reponse>,
        appels: std::sync::Mutex<Vec<(String, String)>>,
    }

    impl Faux {
        fn avec(methode: &str, url_contient: &str, statut: u16, corps: &str) -> Self {
            let mut reponses = BTreeMap::new();
            reponses.insert(
                (methode.to_string(), url_contient.to_string()),
                Reponse { statut, corps: corps.to_string() },
            );
            Self { reponses, appels: std::sync::Mutex::new(Vec::new()) }
        }
    }

    impl Transport for Faux {
        async fn envoyer(&self, _jeton: &str, methode: &str, url: &str, _corps: Option<(&str, String)>) -> Result<Reponse, AppError> {
            self.appels.lock().unwrap().push((methode.to_string(), url.to_string()));
            for ((m, fragment), reponse) in &self.reponses {
                if m == methode && url.contains(fragment.as_str()) {
                    return Ok(Reponse { statut: reponse.statut, corps: reponse.corps.clone() });
                }
            }
            Ok(Reponse { statut: 404, corps: "{}".into() })
        }
    }

    fn jetons_fait() -> Jetons {
        Jetons {
            acces: Zeroizing::new("jeton-d-acces".into()),
            acces_expire_le: u64::MAX,
            rafraichissement: Zeroizing::new("jeton-de-rafraichissement".into()),
        }
    }

    #[tokio::test]
    async fn echanger_code_poste_le_verificateur_et_lit_les_jetons() {
        let corps = r#"{"access_token":"ACC","expires_in":3600,"refresh_token":"REF"}"#;
        let faux = Faux::avec("POST", JETON_URL, 200, corps);
        let pkce = Pkce::nouveau();
        let jetons = echanger_code(&faux, "CODE-123", &pkce.verifier, 45_123).await.unwrap();
        assert_eq!(jetons.acces.as_str(), "ACC");
        assert_eq!(jetons.rafraichissement.as_str(), "REF");
        {
            let appels = faux.appels.lock().unwrap();
            assert_eq!(appels[0].0, "POST");
            assert!(appels[0].1.contains(JETON_URL));
            // Le corps envoyé porte code, vérificateur, identifiant et
            // redirection (vérifié par le transport réel, non testé ici).
        }
    }

    #[tokio::test]
    async fn echanger_code_refuse_une_erreur_google() {
        let faux = Faux::avec("POST", JETON_URL, 400, r#"{"error":"invalid_grant"}"#);
        assert!(echanger_code(&faux, "x", "y", 1).await.is_err());
    }

    #[tokio::test]
    async fn rafraichir_conserve_l_ancien_jeton_si_google_n_en_renvoie_pas() {
        let corps = r#"{"access_token":"NouvelAcces","expires_in":1800}"#;
        let faux = Faux::avec("POST", JETON_URL, 200, corps);
        let ancien = jetons_fait();
        let nouveau = rafraichir(&faux, &ancien).await.unwrap();
        assert_eq!(nouveau.acces.as_str(), "NouvelAcces");
        assert_eq!(nouveau.rafraichissement, ancien.rafraichissement);
    }

    #[tokio::test]
    async fn trouver_lire_envoyer_font_le_tour_d_un_faux_drive() {
        let mut faux = Faux::avec(
            "GET",
            "spaces=appDataFolder",
            200,
            r#"{"files":[{"id":"ABC123","headRevisionId":"REV1","modifiedTime":"2026-11-11T14:05:00.000Z"}]}"#,
        );
        faux.reponses.insert(
            ("GET".into(), "alt=media".into()),
            Reponse { statut: 200, corps: r#"{"v":1,"password":{},"data":{}}"#.into() },
        );
        faux.reponses.insert(
            ("PATCH".into(), "uploadType=media".into()),
            Reponse { statut: 200, corps: r#"{"headRevisionId":"REV2"}"#.into() },
        );
        let jetons = jetons_fait();
        let sauvegarde = trouver(&faux, &jetons).await.unwrap().expect("fichier trouvé");
        assert_eq!(sauvegarde.id, "ABC123");
        assert_eq!(sauvegarde.revision, "REV1");
        assert_eq!(sauvegarde.modifiee_le, "2026-11-11T14:05:00.000Z");
        let contenu = lire(&faux, &jetons, &sauvegarde.id).await.unwrap();
        assert!(contenu.contains("\"v\":1"));
        let revision = envoyer(&faux, &jetons, Some(&sauvegarde.id), "{}").await.unwrap();
        assert_eq!(revision, "REV2");
        // 401 : jeton périmé → driveAuth (le démon rafraîchit puis retente).
        faux.reponses.insert(
            ("GET".into(), "spaces=appDataFolder".into()),
            Reponse { statut: 401, corps: "{}".into() },
        );
        assert!(matches!(trouver(&faux, &jetons).await, Err(e) if e.code == "driveAuth"));
    }

    #[tokio::test]
    async fn boucle_locale_rend_le_code_et_refuse_un_mauvais_etat() {
        use tokio::io::AsyncWriteExt;
        let ecouteur = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ecouteur.local_addr().unwrap().port();
        // Bon retour : code rendu, page de confirmation.
        let client = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut flux = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            flux.write_all(b"GET /?code=CODE-99&state=etat1 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n").await.unwrap();
            let mut tampon = Vec::new();
            let _ = flux.read_to_end(&mut tampon).await;
            String::from_utf8_lossy(&tampon).into_owned()
        });
        let code = attendre_code(ecouteur, "etat1", std::time::Duration::from_secs(5)).await.unwrap();
        assert_eq!(code, "CODE-99");
        let page = client.await.unwrap();
        assert!(page.contains("200 OK") && page.contains("fermer cet onglet"));

        // Mauvais état (page tiers) : refusé.
        let ecouteur = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = ecouteur.local_addr().unwrap().port();
        let client = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut flux = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            flux.write_all(b"GET /?code=CODE-X&state=autre HTTP/1.1\r\n\r\n").await.unwrap();
            let mut tampon = Vec::new();
            let _ = flux.read_to_end(&mut tampon).await;
            String::from_utf8_lossy(&tampon).into_owned()
        });
        assert!(attendre_code(ecouteur, "etat1", std::time::Duration::from_secs(5)).await.is_err());
        let page = client.await.unwrap();
        assert!(page.contains("400 Bad Request"));
    }

    #[tokio::test]
    async fn creation_multipart_pose_le_nom_et_le_parent() {
        let faux = Faux::avec("POST", "uploadType=multipart", 200, r#"{"headRevisionId":"REV9"}"#);
        let jetons = jetons_fait();
        let revision = envoyer(&faux, &jetons, None, "{}").await.unwrap();
        assert_eq!(revision, "REV9");
        {
            let appels = faux.appels.lock().unwrap();
            assert!(appels[0].1.contains("uploadType=multipart"));
            // Le fichier de création n'est pas un PATCH.
            assert_eq!(appels[0].0, "POST");
        }
    }
}
