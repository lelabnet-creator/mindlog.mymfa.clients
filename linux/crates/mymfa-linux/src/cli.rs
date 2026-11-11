/*
 * Ligne de commande `mymfa` : le démon, et les commandes qui lui parlent par
 * today.mindlog.MyMfa1 (la même interface que hyprdesk).
 */
use crate::chemins::{self, Chemins};
use crate::demon::Demon;
use crate::interface::{self, CodeDbus, LoginDbus, MyMfa};
use crate::{import_gnome, journal, service};
use futures_util::StreamExt;
use std::io::{BufRead, Write};
use std::os::fd::AsRawFd;
use zbus::fdo::{DBusProxy, RequestNameFlags, RequestNameReply};
use zbus::Connection;
use zeroize::Zeroizing;

const AIDE: &str = "\
mymfa — trousseau du bureau, sur le coffre myMFA

Usage : mymfa <commande>

  status                  état du coffre, du sceau de session et du Secret Service
  unlock                  déverrouille (mot de passe du coffre, celui du web)
  lock                    verrouille : coffre et trousseau quittent la mémoire
  codes [filtre]          codes 2FA en cours
  logins [recherche]      logins des sites (sans mot de passe)
  copy <id>               copie le code d'un compte
  copy-login <id> [champ] copie le mot de passe (défaut, effacé après 30 s) ou l'identifiant (username)
  seal                    scelle le mot de passe du coffre par la session (pam_mymfa)
  seal --forget           renonce au déverrouillage à la connexion
  init [--from FICHIER]   crée le coffre, ou installe une sauvegarde mymfa-vault.json
  import-gnome-keyring    reprend les secrets de gnome-keyring (avant de le couper)
  daemon                  lance le démon (systemd --user ou activation D-Bus)

Données : $XDG_DATA_HOME/mymfa (défaut ~/.local/share/mymfa).";

pub async fn executer(args: Vec<String>) -> Result<(), String> {
    let commande = args.first().map(String::as_str).unwrap_or("help");
    let reste = &args[args.len().min(1)..];
    match commande {
        "daemon" => demon().await,
        "init" => init(reste),
        "status" => status().await,
        "unlock" => {
            let mdp = lire_mot_de_passe("Mot de passe du coffre myMFA : ").map_err(|e| e.to_string())?;
            appeler::<()>("Unlock", &(mdp.as_str(),)).await?;
            println!("Coffre déverrouillé.");
            Ok(())
        }
        "lock" => {
            appeler::<()>("Lock", &()).await?;
            println!("Coffre verrouillé.");
            Ok(())
        }
        "codes" => codes(reste.first().map(String::as_str).unwrap_or("")).await,
        "logins" => logins(reste.first().map(String::as_str).unwrap_or("")).await,
        "copy" => {
            let id = reste.first().ok_or("usage : mymfa copy <id> (voir mymfa codes)")?;
            appeler::<()>("CopyCode", &(id.as_str(),)).await?;
            println!("Code copié.");
            Ok(())
        }
        "copy-login" => {
            let id = reste.first().ok_or("usage : mymfa copy-login <id> [password|username]")?;
            let champ = reste.get(1).map(String::as_str).unwrap_or("password");
            appeler::<()>("CopyLogin", &(id.as_str(), champ)).await?;
            println!("{} copié{}.", if champ == "username" { "Identifiant" } else { "Mot de passe" }, if champ == "username" { "" } else { " (effacé dans 30 s)" });
            Ok(())
        }
        "seal" => seal(reste).await,
        "import-gnome-keyring" => import_gnome::importer().await,
        "help" | "--help" | "-h" => {
            println!("{AIDE}");
            Ok(())
        }
        autre => Err(format!("commande inconnue : {autre}\n\n{AIDE}")),
    }
}

/* ───── Démon ───── */

/// Durcissement : pas de vidage mémoire (core dump) ni de ptrace par un
/// autre processus de l'utilisateur ; fichiers créés en 0600.
fn durcir() {
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        libc::umask(0o077);
    }
}

async fn demon() -> Result<(), String> {
    durcir();
    let d = Demon::nouveau(Chemins::depuis_environnement());
    let conn = Connection::session().await.map_err(|e| format!("bus de session : {e}"))?;
    let _ = d.connexion.set(conn.clone());
    let serveur = conn.object_server();
    // Objets publiés avant les noms : un client activé appelle aussitôt.
    serveur.at(interface::CHEMIN, MyMfa { d: d.clone() }).await.map_err(|e| e.to_string())?;
    service::publier(&d, serveur).await.map_err(|e| e.to_string())?;
    match conn.request_name_with_flags(interface::NOM, RequestNameFlags::DoNotQueue.into()).await {
        Ok(RequestNameReply::PrimaryOwner) | Ok(RequestNameReply::AlreadyOwner) => {}
        _ => return Err(format!("{} est déjà tenu : un démon mymfa tourne déjà", interface::NOM)),
    }
    // org.freedesktop.secrets : en file s'il est tenu (gnome-keyring), repris
    // dès qu'il se libère.
    match conn.request_name_with_flags(service::NOM, enumflags2::BitFlags::empty()).await {
        Ok(RequestNameReply::PrimaryOwner) | Ok(RequestNameReply::AlreadyOwner) => {
            d.etat().secret_service = true;
            journal!("Secret Service tenu (org.freedesktop.secrets)");
        }
        Ok(_) => journal!("org.freedesktop.secrets tenu par un autre service (gnome-keyring ?) : en file d'attente"),
        Err(e) => journal!("org.freedesktop.secrets refusé : {e}"),
    }
    let bus = DBusProxy::new(&conn).await.map_err(|e| e.to_string())?;
    // Fin des flux de signaux = bus perdu (fin de session) : le démon s'arrête.
    let bus_perdu = std::sync::Arc::new(tokio::sync::Notify::new());
    {
        let d = d.clone();
        let bus_perdu = bus_perdu.clone();
        let mut acquis = bus.receive_name_acquired().await.map_err(|e| e.to_string())?;
        let mut perdus = bus.receive_name_lost().await.map_err(|e| e.to_string())?;
        tokio::spawn(async move {
            loop {
                let (signal, tenu) = tokio::select! {
                    Some(s) = acquis.next() => (s.args().ok().map(|a| a.name.to_string()), true),
                    Some(s) = perdus.next() => (s.args().ok().map(|a| a.name.to_string()), false),
                    else => break,
                };
                if signal.as_deref() == Some(service::NOM) {
                    d.etat().secret_service = tenu;
                    journal!("org.freedesktop.secrets {}", if tenu { "repris" } else { "perdu" });
                    interface::annoncer_proprietes(&d).await;
                }
            }
            bus_perdu.notify_one();
        });
    }
    // Chaque changement de verrou : objets du coffre et annonces sur le bus.
    {
        let d = d.clone();
        let mut verrou = d.verrou.subscribe();
        tokio::spawn(async move {
            while verrou.changed().await.is_ok() {
                service::apres_changement_de_verrou(&d).await;
            }
        });
    }
    // Remises PAM et coffre remplacé : une passe par seconde (un stat).
    {
        let d = d.clone();
        tokio::spawn(async move {
            let mut cadence = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                cadence.tick().await;
                let avant = (d.scelle(), d.etat().cle_session.is_some());
                d.surveiller_une_fois().await;
                if (d.scelle(), d.etat().cle_session.is_some()) != avant {
                    interface::annoncer_proprietes(&d).await;
                }
            }
        });
    }
    journal!("démon prêt ({})", d.chemins.donnees.display());
    let mut terme = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    tokio::select! {
        _ = terme.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
        _ = bus_perdu.notified() => journal!("bus de session perdu"),
    }
    d.verrouiller();
    journal!("arrêt");
    Ok(())
}

/* ───── Client ───── */

async fn proxy() -> Result<zbus::Proxy<'static>, String> {
    let conn = Connection::session().await.map_err(|e| format!("bus de session : {e}"))?;
    zbus::Proxy::new(&conn, interface::NOM, interface::CHEMIN, interface::NOM).await.map_err(message)
}

fn message(e: zbus::Error) -> String {
    match e {
        zbus::Error::MethodError(nom, detail, _) => {
            let court = nom.as_str().rsplit('.').next().unwrap_or("").to_string();
            match (court.as_str(), detail) {
                ("ServiceUnknown", _) => "démon mymfa injoignable (systemctl --user start mymfa)".into(),
                (_, Some(d)) => d,
                (c, None) => c.into(),
            }
        }
        e => e.to_string(),
    }
}

async fn appeler<R>(methode: &str, corps: &(impl serde::Serialize + zbus::zvariant::DynamicType)) -> Result<R, String>
where
    R: for<'d> zbus::zvariant::DynamicDeserialize<'d>,
{
    proxy().await?.call(methode, corps).await.map_err(message)
}

async fn propriete<T>(p: &zbus::Proxy<'_>, nom: &str) -> Result<T, String>
where
    T: TryFrom<zbus::zvariant::OwnedValue>,
    T::Error: Into<zbus::Error>,
{
    p.get_property::<T>(nom).await.map_err(message)
}

async fn status() -> Result<(), String> {
    let p = proxy().await?;
    let present: bool = propriete(&p, "VaultPresent").await?;
    let verrouille: bool = propriete(&p, "Locked").await?;
    let scelle: bool = propriete(&p, "Sealed").await?;
    let cle: bool = propriete(&p, "SessionKey").await?;
    let ss: bool = propriete(&p, "SecretService").await?;
    let version: String = propriete(&p, "Version").await?;
    println!("mymfa {version}");
    println!(
        "Coffre          : {}",
        if !present {
            "absent (mymfa init)"
        } else if verrouille {
            "verrouillé"
        } else {
            "déverrouillé"
        }
    );
    println!(
        "Connexion       : {}",
        match (scelle, cle) {
            (true, _) => "déverrouillage à la connexion actif (sceau de session)",
            (false, true) => "clé de session reçue : le prochain déverrouillage la scellera",
            (false, false) => "pas de sceau (pam_mymfa absent ou mymfa seal --forget)",
        }
    );
    println!(
        "Secret Service  : {}",
        if ss { "tenu par mymfa" } else { "tenu par un autre service (gnome-keyring ?) — mymfa en file d'attente" }
    );
    Ok(())
}

/// Code par groupes de trois chiffres, comme l'app.
fn grouper(code: &str) -> String {
    let chiffres: Vec<char> = code.chars().collect();
    let taille = if chiffres.len().is_multiple_of(3) || chiffres.len() > 6 { 3 } else { chiffres.len().div_ceil(2) };
    chiffres.chunks(taille.max(1)).map(|c| c.iter().collect::<String>()).collect::<Vec<_>>().join(" ")
}

async fn codes(filtre: &str) -> Result<(), String> {
    let codes: Vec<CodeDbus> = appeler("Codes", &()).await?;
    let f = filtre.to_lowercase();
    for (id, issuer, account, _tag, code, restant, periode, favori) in codes {
        if !f.is_empty() && !issuer.to_lowercase().contains(&f) && !account.to_lowercase().contains(&f) {
            continue;
        }
        let temps = if periode == 0 { "HOTP".to_string() } else { format!("{restant:>2} s") };
        let etoile = if favori { "★ " } else { "" };
        let nom = if account.is_empty() { issuer } else { format!("{issuer} ({account})") };
        println!("{:<11} {temps}  {etoile}{nom}  [{id}]", grouper(&code));
    }
    Ok(())
}

async fn logins(recherche: &str) -> Result<(), String> {
    let logins: Vec<LoginDbus> = appeler("SearchLogins", &(recherche,)).await?;
    for (id, titre, hote, _origine, identifiant) in logins {
        let titre = if titre.is_empty() { hote.clone() } else { titre };
        println!("{titre:<24} {identifiant:<28} {hote}  [{id}]");
    }
    Ok(())
}

async fn seal(reste: &[String]) -> Result<(), String> {
    if reste.iter().any(|a| a == "--forget") {
        appeler::<()>("ForgetSeal", &()).await?;
        println!("Sceau oublié : le coffre ne s'ouvrira plus à la connexion.");
        return Ok(());
    }
    let mdp = lire_mot_de_passe("Mot de passe du coffre myMFA : ").map_err(|e| e.to_string())?;
    appeler::<()>("Seal", &(mdp.as_str(),)).await?;
    println!("Mot de passe du coffre scellé : la prochaine connexion ouvrira le coffre.");
    Ok(())
}

/* ───── init ───── */

fn init(reste: &[String]) -> Result<(), String> {
    let chemins = Chemins::depuis_environnement();
    let cible = chemins.coffre();
    if cible.exists() {
        return Err(format!("un coffre existe déjà : {}", cible.display()));
    }
    let texte = if let Some(i) = reste.iter().position(|a| a == "--from") {
        let source = reste.get(i + 1).ok_or("usage : mymfa init --from <mymfa-vault.json>")?;
        let texte = std::fs::read_to_string(source).map_err(|e| format!("{source} : {e}"))?;
        mymfa_core::vault::parse(&texte).ok_or("ce fichier n'est pas un coffre myMFA (mymfa-vault.json)")?;
        texte
    } else {
        let mdp = lire_mot_de_passe("Nouveau mot de passe du coffre : ").map_err(|e| e.to_string())?;
        mymfa_core::vault::validate_password(&mdp)
            .map_err(|_| format!("mot de passe trop court ({} caractères au moins)", mymfa_core::vault::PASSWORD_MIN_LENGTH))?;
        let confirmation = lire_mot_de_passe("Confirmation : ").map_err(|e| e.to_string())?;
        if *mdp != *confirmation {
            return Err("les deux saisies diffèrent".into());
        }
        let (record, _) = mymfa_core::vault::create(&mdp, &Default::default(), mymfa_core::vault::PBKDF2_ITERATIONS)
            .map_err(|e| e.to_string())?;
        serde_json::to_string(&record).map_err(|e| e.to_string())?
    };
    chemins::ecrire_prive(&cible, texte.as_bytes()).map_err(|e| e.to_string())?;
    println!("Coffre installé : {}", cible.display());
    Ok(())
}

/* ───── Saisie ───── */

/// Mot de passe sans écho sur le terminal ; sur une entrée redirigée, une ligne.
pub fn lire_mot_de_passe(invite: &str) -> std::io::Result<Zeroizing<String>> {
    let mut ligne = Zeroizing::new(String::new());
    if let Ok(mut tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
        let fd = tty.as_raw_fd();
        let mut ancien: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::isatty(0) } == 1 && unsafe { libc::tcgetattr(fd, &mut ancien) } == 0 {
            let mut muet = ancien;
            muet.c_lflag &= !libc::ECHO;
            muet.c_lflag |= libc::ECHONL;
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &muet) };
            let _ = tty.write_all(invite.as_bytes());
            let _ = tty.flush();
            let lu = std::io::BufReader::new(&tty).read_line(&mut ligne);
            unsafe { libc::tcsetattr(fd, libc::TCSANOW, &ancien) };
            lu?;
            retirer_fin_de_ligne(&mut ligne);
            return Ok(ligne);
        }
    }
    eprint!("{invite}");
    std::io::stdin().lock().read_line(&mut ligne)?;
    eprintln!();
    retirer_fin_de_ligne(&mut ligne);
    Ok(ligne)
}

fn retirer_fin_de_ligne(ligne: &mut Zeroizing<String>) {
    while ligne.ends_with('\n') || ligne.ends_with('\r') {
        ligne.pop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groupes_de_chiffres() {
        assert_eq!(grouper("123456"), "123 456");
        assert_eq!(grouper("12345678"), "123 456 78");
        assert_eq!(grouper("12345"), "123 45");
    }
}
