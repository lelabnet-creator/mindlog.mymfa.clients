/*
 * Remise de la clé de session du module PAM au démon.
 *
 * Le module (root, dans la pile PAM du gestionnaire de connexion) dépose un
 * fichier 0600, propriété de l'utilisateur, dans `/run/user/UID/mymfa/` ; le
 * démon (l'utilisateur) le lit, l'efface aussitôt, puis l'exploite. Le
 * fichier ne contient que des clés dérivées, jamais le mot de passe de
 * session, et vit sur un tmpfs propre à l'utilisateur, détruit à la
 * déconnexion.
 *
 * Deux fichiers :
 *  - `session-key` (ouverture de session) :
 *        mymfa-session-key v1\niterations=<n>\nkey=<hex>\n
 *  - `rekey` (changement du mot de passe de session, pam_sm_chauthtok) :
 *        mymfa-rekey v1\niterations=<n>\nold=<hex>\nnew=<hex>\n
 *
 * Écriture sûre pour root dans un dossier que l'utilisateur contrôle : tout
 * passe par des descripteurs (openat, O_NOFOLLOW, O_EXCL), jamais par un
 * chemin qu'un lien symbolique pourrait détourner.
 */
use crate::{cle_de_hex, hex, Cle};
use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const DOSSIER: &str = "mymfa";
pub const FICHIER_CLE: &str = "session-key";
pub const FICHIER_RENOUVELLEMENT: &str = "rekey";
/// Aucun fichier de remise légitime n'approche cette taille.
const TAILLE_MAX: usize = 4096;

/// Dossier d'exécution de l'utilisateur (logind) : `/run/user/UID`.
pub fn dossier_execution(uid: u32) -> PathBuf {
    PathBuf::from(format!("/run/user/{uid}"))
}

/// Clé de session remise à l'ouverture de session.
pub struct Remise {
    pub iterations: u32,
    pub cle: Cle,
}

/// Ancienne et nouvelle clés, remises au changement de mot de passe.
pub struct Renouvellement {
    pub iterations: u32,
    pub ancienne: Cle,
    pub nouvelle: Cle,
}

impl Remise {
    pub fn encoder(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            format!("mymfa-session-key v1\niterations={}\nkey={}\n", self.iterations, hex(self.cle.as_ref()))
                .into_bytes(),
        )
    }

    pub fn decoder(octets: &[u8]) -> Option<Self> {
        let champs = champs(octets, "mymfa-session-key v1")?;
        Some(Remise { iterations: champ(&champs, "iterations")?.parse().ok()?, cle: cle_de_hex(champ(&champs, "key")?)? })
    }
}

impl Renouvellement {
    pub fn encoder(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(
            format!(
                "mymfa-rekey v1\niterations={}\nold={}\nnew={}\n",
                self.iterations,
                hex(self.ancienne.as_ref()),
                hex(self.nouvelle.as_ref())
            )
            .into_bytes(),
        )
    }

    pub fn decoder(octets: &[u8]) -> Option<Self> {
        let champs = champs(octets, "mymfa-rekey v1")?;
        Some(Renouvellement {
            iterations: champ(&champs, "iterations")?.parse().ok()?,
            ancienne: cle_de_hex(champ(&champs, "old")?)?,
            nouvelle: cle_de_hex(champ(&champs, "new")?)?,
        })
    }
}

/// Lignes `nom=valeur` après l'en-tête attendu.
fn champs<'a>(octets: &'a [u8], entete: &str) -> Option<Vec<(&'a str, &'a str)>> {
    let texte = std::str::from_utf8(octets).ok()?;
    let mut lignes = texte.lines();
    if lignes.next()? != entete {
        return None;
    }
    Some(lignes.filter_map(|l| l.split_once('=')).collect())
}

fn champ<'a>(champs: &[(&'a str, &'a str)], nom: &str) -> Option<&'a str> {
    champs.iter().find(|(n, _)| *n == nom).map(|(_, v)| *v)
}

/* ───── Système de fichiers, par descripteurs ───── */

fn cstr(nom: &str) -> io::Result<CString> {
    CString::new(nom).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

fn verifier(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn ouvrir_dossier(chemin: &Path) -> io::Result<OwnedFd> {
    let c = CString::new(chemin.as_os_str().as_bytes()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let fd = verifier(unsafe { libc::open(c.as_ptr(), libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn ouvrir_dans(dossier: &OwnedFd, nom: &str, drapeaux: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;
    let c = cstr(nom)?;
    let fd = verifier(unsafe { libc::openat(dossier.as_raw_fd(), c.as_ptr(), drapeaux | libc::O_NOFOLLOW | libc::O_CLOEXEC, mode as libc::c_uint) })?;
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn etat(fd: &OwnedFd) -> io::Result<libc::stat> {
    use std::os::fd::AsRawFd;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    verifier(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(st)
}

/// `base/mymfa/`, créé au besoin (0700) et rendu à `uid` si root l'a créé.
/// Refuse un dossier qui n'appartient pas à `uid`.
fn sous_dossier(base: &Path, uid: u32, gid: u32) -> io::Result<OwnedFd> {
    use std::os::fd::AsRawFd;
    let racine = ouvrir_dossier(base)?;
    let racine_st = etat(&racine)?;
    if racine_st.st_uid != uid {
        // /run/user/UID appartient à l'utilisateur : sinon, ce n'est pas le bon.
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let nom = cstr(DOSSIER)?;
    let cree = unsafe { libc::mkdirat(racine.as_raw_fd(), nom.as_ptr(), 0o700) };
    if cree < 0 {
        let e = io::Error::last_os_error();
        if e.raw_os_error() != Some(libc::EEXIST) {
            return Err(e);
        }
    }
    let sous = ouvrir_dans(&racine, DOSSIER, libc::O_DIRECTORY | libc::O_RDONLY, 0)?;
    let st = etat(&sous)?;
    if st.st_uid != uid {
        if st.st_uid == unsafe { libc::geteuid() } && cree == 0 {
            verifier(unsafe { libc::fchown(sous.as_raw_fd(), uid, gid) })?;
        } else {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
    }
    verifier(unsafe { libc::fchmod(sous.as_raw_fd(), 0o700) })?;
    Ok(sous)
}

/// Dépose `contenu` dans `base/mymfa/nom` (0600, propriété de `uid`),
/// atomiquement : un fichier temporaire exclusif, puis un renommage.
pub fn deposer(base: &Path, uid: u32, gid: u32, nom: &str, contenu: &[u8]) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let dossier = sous_dossier(base, uid, gid)?;
    let temporaire = format!(".{nom}.{}", std::process::id());
    let c_tmp = cstr(&temporaire)?;
    let c_nom = cstr(nom)?;
    unsafe { libc::unlinkat(dossier.as_raw_fd(), c_tmp.as_ptr(), 0) };
    let fd = ouvrir_dans(&dossier, &temporaire, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)?;
    let resultat = (|| {
        if unsafe { libc::geteuid() } != uid {
            verifier(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) })?;
        }
        verifier(unsafe { libc::fchmod(fd.as_raw_fd(), 0o600) })?;
        let mut fichier = std::fs::File::from(fd);
        fichier.write_all(contenu)?;
        drop(fichier);
        verifier(unsafe { libc::renameat(dossier.as_raw_fd(), c_tmp.as_ptr(), dossier.as_raw_fd(), c_nom.as_ptr()) })?;
        Ok(())
    })();
    if resultat.is_err() {
        unsafe { libc::unlinkat(dossier.as_raw_fd(), c_tmp.as_ptr(), 0) };
    }
    resultat
}

/// Lit puis efface `base/mymfa/nom`. `Ok(None)` s'il n'y a rien. Le fichier
/// doit être un fichier ordinaire appartenant au processus courant.
pub fn consommer(base: &Path, nom: &str) -> io::Result<Option<Zeroizing<Vec<u8>>>> {
    use std::os::fd::AsRawFd;
    let racine = match ouvrir_dossier(base) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let dossier = match ouvrir_dans(&racine, DOSSIER, libc::O_DIRECTORY | libc::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let fd = match ouvrir_dans(&dossier, nom, libc::O_RDONLY, 0) {
        Ok(fd) => fd,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let c_nom = cstr(nom)?;
    // Effacé avant toute autre chose : un fichier de remise ne sert qu'une fois.
    unsafe { libc::unlinkat(dossier.as_raw_fd(), c_nom.as_ptr(), 0) };
    let st = etat(&fd)?;
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG || st.st_uid != unsafe { libc::geteuid() } {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    let mut contenu = Zeroizing::new(Vec::with_capacity(256));
    std::fs::File::from(fd).take(TAILLE_MAX as u64 + 1).read_to_end(&mut contenu)?;
    if contenu.len() > TAILLE_MAX {
        return Err(io::Error::from(io::ErrorKind::InvalidData));
    }
    Ok(Some(contenu))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn dossier_temporaire(nom: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("mymfa-sceau-{nom}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn moi() -> (u32, u32) {
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    #[test]
    fn remise_encodage() {
        let r = Remise { iterations: 42, cle: Zeroizing::new([9u8; 32]) };
        let lu = Remise::decoder(&r.encoder()).unwrap();
        assert_eq!(lu.iterations, 42);
        assert_eq!(*lu.cle, [9u8; 32]);
        assert!(Remise::decoder(b"autre chose\nkey=00").is_none());
        assert!(Remise::decoder(b"mymfa-session-key v1\niterations=1\nkey=00\n").is_none(), "clé trop courte");
        let n = Renouvellement { iterations: 7, ancienne: Zeroizing::new([1u8; 32]), nouvelle: Zeroizing::new([2u8; 32]) };
        let lu = Renouvellement::decoder(&n.encoder()).unwrap();
        assert_eq!((*lu.ancienne, *lu.nouvelle, lu.iterations), ([1u8; 32], [2u8; 32], 7));
        assert!(Remise::decoder(&n.encoder()).is_none(), "en-têtes distincts");
    }

    #[test]
    fn deposer_puis_consommer() {
        let base = dossier_temporaire("depot");
        let (uid, gid) = moi();
        deposer(&base, uid, gid, FICHIER_CLE, b"contenu").unwrap();
        let fichier = base.join(DOSSIER).join(FICHIER_CLE);
        let meta = std::fs::metadata(&fichier).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(meta.uid(), uid);
        assert_eq!(std::fs::metadata(base.join(DOSSIER)).unwrap().permissions().mode() & 0o777, 0o700);
        // Un second dépôt remplace le premier.
        deposer(&base, uid, gid, FICHIER_CLE, b"second").unwrap();
        assert_eq!(consommer(&base, FICHIER_CLE).unwrap().unwrap().as_slice(), b"second");
        assert!(!fichier.exists(), "consommé = effacé");
        assert!(consommer(&base, FICHIER_CLE).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn rien_a_consommer() {
        let base = dossier_temporaire("vide");
        assert!(consommer(&base, FICHIER_CLE).unwrap().is_none());
        assert!(consommer(&base.join("absent"), FICHIER_CLE).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn lien_symbolique_refuse() {
        let base = dossier_temporaire("lien");
        let (uid, gid) = moi();
        let cible = base.join("ailleurs");
        std::fs::create_dir_all(&cible).unwrap();
        std::os::unix::fs::symlink(&cible, base.join(DOSSIER)).unwrap();
        assert!(deposer(&base, uid, gid, FICHIER_CLE, b"x").is_err(), "dossier mymfa en lien : refusé");
        std::fs::remove_file(base.join(DOSSIER)).unwrap();
        std::fs::create_dir_all(base.join(DOSSIER)).unwrap();
        std::os::unix::fs::symlink(cible.join("f"), base.join(DOSSIER).join(FICHIER_CLE)).unwrap();
        assert!(consommer(&base, FICHIER_CLE).is_err(), "fichier en lien : refusé");
        assert!(!cible.join("f").exists());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn dossier_d_un_autre_refuse() {
        let base = dossier_temporaire("autre");
        let (uid, gid) = moi();
        // La base doit appartenir à l'utilisateur visé.
        assert!(deposer(&base, uid.wrapping_add(1), gid, FICHIER_CLE, b"x").is_err());
        let _ = std::fs::remove_dir_all(&base);
    }
}
