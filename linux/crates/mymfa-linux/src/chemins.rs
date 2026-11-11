/*
 * Emplacements du client Linux.
 *
 *  - Données : `$XDG_DATA_HOME/mymfa/` (défaut `~/.local/share/mymfa/`), le
 *    même dossier que l'app Slint lancée sur le bureau (`mymfa-vault.json`,
 *    même contenu que la sauvegarde Drive du web).
 *  - Remise PAM : `/run/user/UID/mymfa/` (voir mymfa_sceau::remise).
 *
 * `MYMFA_DATA_DIR` et `MYMFA_RUNTIME_DIR` remplacent ces deux racines — pour
 * les essais (bus privé, dossier jetable), jamais nécessaires en usage normal.
 */
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Coffre : même nom et même contenu que la sauvegarde Drive du web.
pub const COFFRE: &str = "mymfa-vault.json";
/// Secrets des applications (Secret Service) : local, jamais synchronisé.
pub const TROUSSEAU: &str = "mymfa-keyring.json";
/// Mot de passe du coffre scellé par la clé de session.
pub const SCEAU: &str = "session-seal.json";
/// Présent : l'utilisateur a renoncé au déverrouillage à la connexion.
pub const SANS_SCEAU: &str = "no-seal";

#[derive(Debug, Clone)]
pub struct Chemins {
    pub donnees: PathBuf,
    /// Racine de la remise PAM (`/run/user/UID`).
    pub execution: PathBuf,
}

impl Chemins {
    pub fn depuis_environnement() -> Self {
        let donnees = std::env::var_os("MYMFA_DATA_DIR").map(PathBuf::from).unwrap_or_else(|| {
            let base = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from).unwrap_or_else(|| {
                let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."));
                home.join(".local/share")
            });
            base.join("mymfa")
        });
        let execution = std::env::var_os("MYMFA_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| mymfa_sceau::remise::dossier_execution(unsafe { libc::getuid() }));
        Chemins { donnees, execution }
    }

    pub fn coffre(&self) -> PathBuf {
        self.donnees.join(COFFRE)
    }

    pub fn trousseau(&self) -> PathBuf {
        self.donnees.join(TROUSSEAU)
    }

    pub fn sceau(&self) -> PathBuf {
        self.donnees.join(SCEAU)
    }

    pub fn sans_sceau(&self) -> PathBuf {
        self.donnees.join(SANS_SCEAU)
    }
}

/// Lecture d'un petit fichier texte ; `None` s'il n'existe pas ou est illisible.
pub fn lire(chemin: &Path) -> Option<String> {
    std::fs::read_to_string(chemin).ok()
}

/// Écriture atomique en 0600 (fichier temporaire, fsync, renommage) : jamais
/// de fichier à moitié écrit, jamais lisible par un autre utilisateur.
pub fn ecrire_prive(chemin: &Path, contenu: &[u8]) -> std::io::Result<()> {
    let dossier = chemin.parent().unwrap_or(Path::new("."));
    std::fs::create_dir_all(dossier)?;
    let _ = std::fs::set_permissions(dossier, std::fs::Permissions::from_mode(0o700));
    let nom = chemin.file_name().and_then(|n| n.to_str()).unwrap_or("fichier");
    let temporaire = dossier.join(format!(".{nom}.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&temporaire);
    let resultat = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporaire)?;
        f.write_all(contenu)?;
        f.sync_all()?;
        std::fs::rename(&temporaire, chemin)
    })();
    if resultat.is_err() {
        let _ = std::fs::remove_file(&temporaire);
    }
    resultat
}

/// Date de modification (ns), pour repérer un coffre remplacé sur le disque.
pub fn modification(chemin: &Path) -> Option<u128> {
    let meta = std::fs::metadata(chemin).ok()?;
    meta.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok().map(|d| d.as_nanos())
}

pub fn maintenant() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
