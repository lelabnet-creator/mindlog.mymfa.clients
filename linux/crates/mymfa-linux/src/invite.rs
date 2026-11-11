/*
 * Invite de déverrouillage de repli : pinentry (protocole Assuan), le temps
 * que hyprdesk tienne la sienne (LIN-04). Quand une application demande le
 * coffre verrouillé, le démon émet MyMfa1.UnlockRequested ET, si l'invite de
 * repli est active, ouvre pinentry ; le premier déverrouillage l'emporte.
 *
 * `MYMFA_PINENTRY` : programme à lancer (défaut `pinentry` s'il est dans le
 * PATH) ; `none` le désactive — hyprdesk seul répond alors.
 */
use crate::demon::{Partage, Refus};
use crate::coffre::ErreurCoffre;
use std::process::Stdio;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use zeroize::Zeroizing;

const ESSAIS: usize = 3;

fn programme() -> Option<String> {
    match std::env::var("MYMFA_PINENTRY") {
        Ok(v) if v == "none" || v.is_empty() => None,
        Ok(v) => Some(v),
        Err(_) => {
            let chemin = std::env::var_os("PATH")?;
            std::env::split_paths(&chemin).any(|d| d.join("pinentry").is_file()).then(|| "pinentry".to_string())
        }
    }
}

pub fn active() -> bool {
    programme().is_some()
}

/// Échappement Assuan : %, CR et LF.
fn echapper(texte: &str) -> String {
    texte.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn desechapper(texte: &str) -> Zeroizing<String> {
    let octets = texte.as_bytes();
    let mut sortie = Zeroizing::new(Vec::with_capacity(octets.len()));
    let mut i = 0;
    while i < octets.len() {
        if octets[i] == b'%' && i + 2 < octets.len() {
            let hex = std::str::from_utf8(&octets[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                sortie.push(v);
                i += 3;
                continue;
            }
        }
        sortie.push(octets[i]);
        i += 1;
    }
    Zeroizing::new(String::from_utf8_lossy(&sortie).into_owned())
}

/// Ouvre pinentry et tente de déverrouiller. `true` : déverrouillé ;
/// `false` : annulé, échoué ou indisponible.
pub async fn demander(d: &Partage, application: &str) -> bool {
    match dialogue(d, application).await {
        Ok(ouvert) => ouvert,
        Err(e) => {
            crate::journal!("invite pinentry indisponible : {e}");
            false
        }
    }
}

async fn dialogue(d: &Partage, application: &str) -> std::io::Result<bool> {
    let Some(prog) = programme() else { return Ok(false) };
    let env = crate::presse_papiers::environnement_graphique(d.connexion.get()).await;
    let mut enfant = Command::new(prog)
        .envs(env.iter().map(|(n, v)| (n.as_str(), v.as_str())))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let mut entree = enfant.stdin.take().expect("stdin");
    let mut sortie = BufReader::new(enfant.stdout.take().expect("stdout")).lines();

    async fn reponse(sortie: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>) -> std::io::Result<(bool, Option<Zeroizing<String>>)> {
        let mut donnees = None;
        while let Some(ligne) = sortie.next_line().await? {
            let ligne = Zeroizing::new(ligne);
            if ligne.starts_with("OK") {
                return Ok((true, donnees));
            }
            if ligne.starts_with("ERR") {
                return Ok((false, None));
            }
            if let Some(d) = ligne.strip_prefix("D ") {
                donnees = Some(desechapper(d));
            }
        }
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    }

    reponse(&mut sortie).await?; // « OK Pleased to meet you »
    let description = if application.is_empty() {
        "Une application demande l'accès au trousseau.%0ASaisissez le mot de passe de votre coffre myMFA.".to_string()
    } else {
        format!(
            "« {} » demande l'accès au trousseau.%0ASaisissez le mot de passe de votre coffre myMFA.",
            echapper(application)
        )
    };
    for commande in [
        "SETTITLE myMFA".to_string(),
        format!("SETDESC {description}"),
        "SETPROMPT Mot de passe :".to_string(),
        "SETOK Déverrouiller".to_string(),
        "SETCANCEL Annuler".to_string(),
    ] {
        entree.write_all(format!("{commande}\n").as_bytes()).await?;
        reponse(&mut sortie).await?;
    }
    for essai in 0..ESSAIS {
        if !d.verrouille() {
            return Ok(true);
        }
        if essai > 0 {
            entree.write_all(b"SETERROR Mot de passe incorrect\n").await?;
            reponse(&mut sortie).await?;
        }
        entree.write_all(b"GETPIN\n").await?;
        let (ok, mdp) = reponse(&mut sortie).await?;
        let Some(mdp) = mdp.filter(|_| ok) else { break }; // annulé
        match d.deverrouiller(mdp).await {
            Ok(()) => {
                let _ = entree.write_all(b"BYE\n").await;
                return Ok(true);
            }
            Err(Refus::Coffre(ErreurCoffre::MauvaisMotDePasse)) => continue,
            Err(e) => {
                crate::journal!("déverrouillage impossible : {e}");
                break;
            }
        }
    }
    let _ = entree.write_all(b"BYE\n").await;
    Ok(!d.verrouille())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assuan() {
        assert_eq!(echapper("a%b\nc"), "a%25b%0Ac");
        assert_eq!(desechapper("mot%25de%20passe").as_str(), "mot%de passe");
        assert_eq!(desechapper("fin%").as_str(), "fin%");
        assert_eq!(desechapper("%4").as_str(), "%4");
        assert_eq!(desechapper("%C3%A9t%C3%A9").as_str(), "été");
    }
}
