/*
 * Presse-papiers Wayland (wl-clipboard). Un mot de passe copié est marqué
 * sensible (les gestionnaires d'historique l'ignorent) et effacé au bout de
 * 30 s s'il est toujours là — comme l'app web.
 */
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use zeroize::Zeroizing;

pub const EFFACEMENT: Duration = Duration::from_secs(30);

/// Variables d'affichage qui manquent au démon (lancé par systemd avant la
/// session graphique) : relues dans l'environnement du gestionnaire systemd
/// de l'utilisateur, où le compositeur les importe
/// (`systemctl --user import-environment` / dbus-update-activation-environment).
pub async fn environnement_graphique(conn: Option<&zbus::Connection>) -> Vec<(String, String)> {
    const NOMS: [&str; 4] = ["WAYLAND_DISPLAY", "DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"];
    if std::env::var_os("WAYLAND_DISPLAY").is_some() {
        return Vec::new();
    }
    let Some(conn) = conn else { return Vec::new() };
    let Ok(systemd) = zbus::Proxy::new(conn, "org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager").await
    else {
        return Vec::new();
    };
    let Ok(env) = systemd.get_property::<Vec<String>>("Environment").await else { return Vec::new() };
    env.iter()
        .filter_map(|l| l.split_once('='))
        .filter(|(n, _)| NOMS.contains(n) && std::env::var_os(n).is_none())
        .map(|(n, v)| (n.to_string(), v.to_string()))
        .collect()
}

pub async fn copier(conn: Option<&zbus::Connection>, valeur: Zeroizing<String>, sensible: bool) -> Result<(), String> {
    let env = environnement_graphique(conn).await;
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && !env.iter().any(|(n, _)| n == "WAYLAND_DISPLAY") {
        return Err("presse-papiers indisponible : WAYLAND_DISPLAY inconnu du démon \
                    (systemctl --user import-environment WAYLAND_DISPLAY)"
            .into());
    }
    let mut commande = Command::new("wl-copy");
    commande.envs(env.iter().map(|(n, v)| (n.as_str(), v.as_str())));
    commande.arg("--type").arg("text/plain");
    if sensible {
        commande.arg("--sensitive");
    }
    let mut enfant = commande
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("wl-copy introuvable : {e}"))?;
    if let Some(mut entree) = enfant.stdin.take() {
        entree.write_all(valeur.as_bytes()).await.map_err(|e| e.to_string())?;
    }
    let statut = enfant.wait().await.map_err(|e| e.to_string())?;
    if !statut.success() {
        return Err("wl-copy a échoué".into());
    }
    if sensible {
        tokio::spawn(async move {
            tokio::time::sleep(EFFACEMENT).await;
            if contenu_actuel(&env).await.as_deref().map(|c| c.as_bytes()) == Some(valeur.as_bytes()) {
                let _ = Command::new("wl-copy").arg("--clear").envs(env.iter().map(|(n, v)| (n.as_str(), v.as_str()))).status().await;
            }
        });
    }
    Ok(())
}

async fn contenu_actuel(env: &[(String, String)]) -> Option<Zeroizing<String>> {
    let mut enfant = Command::new("wl-paste")
        .args(["--no-newline", "--type", "text/plain"])
        .envs(env.iter().map(|(n, v)| (n.as_str(), v.as_str())))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut texte = Zeroizing::new(String::new());
    enfant.stdout.take()?.read_to_string(&mut texte).await.ok()?;
    enfant.wait().await.ok()?;
    Some(texte)
}
