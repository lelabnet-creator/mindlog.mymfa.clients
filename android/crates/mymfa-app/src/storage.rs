/* Emplacement des données de l'app : répertoire interne Android (via
 * android-activity), dossier de données utilisateur sur le bureau.
 */
use crate::AppHandle;
use std::path::PathBuf;

pub const PREFS_FILE: &str = "prefs.json";
pub const VAULT_FILE: &str = "mymfa-vault.json"; // même nom et contenu que la sauvegarde Drive du web

/// Paquet Android (manifest.yaml de xbuild) : repli quand NativeActivity ne
/// fournit pas de chemin de données (internalDataPath vide, fréquent).
#[cfg(target_os = "android")]
const PACKAGE: &str = "today.mindlog.mymfa";

pub fn data_dir(app: &AppHandle) -> PathBuf {
    #[cfg(target_os = "android")]
    {
        // internal_data_path : /data/user/0/<paquet>/files — privé à l'app.
        let candidates = [
            app.internal_data_path(),
            Some(PathBuf::from(format!("/data/data/{PACKAGE}/files"))),
        ];
        for dir in candidates.into_iter().flatten() {
            if std::fs::create_dir_all(&dir).is_ok() && probe_writable(&dir) {
                return dir;
            }
        }
        PathBuf::from(".") // dernier recours (ne devrait jamais servir)
    }
    #[cfg(not(target_os = "android"))]
    {
        let _ = app;
        let base = std::env::var("XDG_DATA_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
                PathBuf::from(home).join(".local/share")
            });
        base.join("mymfa")
    }
}

/// L'écriture doit réussir : un chemin lisible mais non inscriptible ne sert à rien.
#[cfg(target_os = "android")]
fn probe_writable(dir: &std::path::Path) -> bool {
    let probe = dir.join(".probe");
    match std::fs::write(&probe, b"ok") {
        Ok(()) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

pub fn read_text(dir: &std::path::Path, name: &str) -> Option<String> {
    let path = dir.join(name);
    if !path.exists() {
        return None;
    }
    std::fs::read_to_string(path).ok()
}

pub fn write_text(dir: &std::path::Path, name: &str, content: &str) {
    let _ = std::fs::create_dir_all(dir);
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.tmp"));
    // Écriture atomique : jamais de coffre à moitié écrit.
    if std::fs::write(&tmp, content).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}
