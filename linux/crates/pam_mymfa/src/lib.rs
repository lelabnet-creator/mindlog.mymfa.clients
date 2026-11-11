/*
 * pam_mymfa.so — déverrouillage du coffre myMFA à la connexion.
 *
 *   auth      optional  pam_mymfa.so       garde le mot de passe de session
 *   session   optional  pam_mymfa.so       en dérive la clé, la remet au démon
 *   password  optional  pam_mymfa.so       nouveau mot de passe : nouveau sceau
 *
 * Règle d'or : ce module ne fait JAMAIS échouer une connexion. Toutes les
 * fonctions rendent PAM_IGNORE (ou PAM_SUCCESS quand la remise a eu lieu),
 * avalent leurs erreurs, attrapent toute panique, et ne demandent rien à
 * l'utilisateur (sauf option `ask`, pour les essais).
 *
 * Le mot de passe de session ne quitte jamais la pile PAM : il est gardé
 * (pam_set_data, effacé de la mémoire au nettoyage) entre l'authentification
 * et l'ouverture de session, qui en dérive une clé (PBKDF2-SHA256, sel propre
 * à la machine et à l'utilisateur, cf. mymfa_sceau) ; seule cette clé est
 * déposée dans /run/user/UID/mymfa/session-key (0600, propriété de
 * l'utilisateur), que le démon consomme puis efface.
 *
 * Options : `ask` (demander le mot de passe s'il n'est pas déjà dans la pile),
 * `rundir=CHEMIN` (remplace /run/user/UID : essais), `iterations=N` (essais),
 * `debug` (une ligne syslog par étape, jamais un secret).
 */
use mymfa_sceau::remise::{self, Remise, Renouvellement};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use zeroize::Zeroizing;

#[repr(C)]
pub struct PamHandle {
    _prive: [u8; 0],
}

const PAM_SUCCESS: c_int = 0;
const PAM_IGNORE: c_int = 25;
const PAM_AUTHTOK: c_int = 6;
const PAM_OLDAUTHTOK: c_int = 7;
const PAM_UPDATE_AUTHTOK: c_int = 0x2000;

/// Nom de la donnée gardée entre auth et session.
const DONNEE: &CStr = c"today.mindlog.mymfa.authtok";

type Nettoyage = unsafe extern "C" fn(*mut PamHandle, *mut c_void, c_int);

#[link(name = "pam")]
extern "C" {
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_authtok(pamh: *mut PamHandle, item: c_int, authtok: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_set_data(pamh: *mut PamHandle, name: *const c_char, data: *mut c_void, cleanup: Option<Nettoyage>) -> c_int;
    fn pam_get_data(pamh: *const PamHandle, name: *const c_char, data: *mut *const c_void) -> c_int;
}

/* ───── Options ───── */

struct Options {
    ask: bool,
    debug: bool,
    rundir: Option<PathBuf>,
    iterations: u32,
}

impl Options {
    unsafe fn lire(argc: c_int, argv: *const *const c_char) -> Self {
        let mut o = Options { ask: false, debug: false, rundir: None, iterations: mymfa_sceau::ITERATIONS };
        if argv.is_null() {
            return o;
        }
        for i in 0..argc.max(0) as usize {
            let p = *argv.add(i);
            if p.is_null() {
                continue;
            }
            let Ok(a) = CStr::from_ptr(p).to_str() else { continue };
            match a {
                "ask" => o.ask = true,
                "debug" => o.debug = true,
                _ => {
                    if let Some(v) = a.strip_prefix("rundir=") {
                        o.rundir = Some(PathBuf::from(v));
                    } else if let Some(v) = a.strip_prefix("iterations=") {
                        if let Ok(n) = v.parse::<u32>() {
                            o.iterations = n.max(1);
                        }
                    }
                }
            }
        }
        o
    }

    fn journal(&self, message: &str) {
        if !self.debug {
            return;
        }
        if let Ok(m) = CString::new(format!("pam_mymfa: {message}")) {
            unsafe { libc::syslog(libc::LOG_AUTHPRIV | libc::LOG_DEBUG, c"%s".as_ptr(), m.as_ptr()) };
        }
    }
}

/* ───── Aides PAM ───── */

/// Copie d'un jeton de la pile (PAM_AUTHTOK / PAM_OLDAUTHTOK), demandé
/// seulement avec `ask`.
unsafe fn jeton(pamh: *mut PamHandle, element: c_int, demander: bool) -> Option<Zeroizing<Vec<u8>>> {
    let mut p: *const c_void = std::ptr::null();
    if pam_get_item(pamh, element, &mut p) == PAM_SUCCESS && !p.is_null() {
        return Some(Zeroizing::new(CStr::from_ptr(p as *const c_char).to_bytes().to_vec()));
    }
    if demander {
        let mut t: *const c_char = std::ptr::null();
        if pam_get_authtok(pamh, element, &mut t, std::ptr::null()) == PAM_SUCCESS && !t.is_null() {
            return Some(Zeroizing::new(CStr::from_ptr(t).to_bytes().to_vec()));
        }
    }
    None
}

unsafe extern "C" fn nettoyer(_pamh: *mut PamHandle, donnee: *mut c_void, _statut: c_int) {
    if !donnee.is_null() {
        // Zeroizing : le mot de passe est effacé en mémoire à la libération.
        drop(Box::from_raw(donnee as *mut Zeroizing<Vec<u8>>));
    }
}

/// Utilisateur cible : (nom, uid, gid).
unsafe fn utilisateur(pamh: *mut PamHandle) -> Option<(String, u32, u32)> {
    let mut u: *const c_char = std::ptr::null();
    if pam_get_user(pamh, &mut u, std::ptr::null()) != PAM_SUCCESS || u.is_null() {
        return None;
    }
    let nom = CStr::from_ptr(u);
    let mut pw: libc::passwd = std::mem::zeroed();
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    let mut tampon = vec![0 as c_char; 16 * 1024];
    let r = libc::getpwnam_r(nom.as_ptr(), &mut pw, tampon.as_mut_ptr(), tampon.len(), &mut res);
    if r != 0 || res.is_null() {
        return None;
    }
    Some((nom.to_str().ok()?.to_string(), pw.pw_uid, pw.pw_gid))
}

fn cle(mot_de_passe: &[u8], nom: &str, uid: u32, iterations: u32) -> mymfa_sceau::Cle {
    mymfa_sceau::deriver(mot_de_passe, &mymfa_sceau::sel(&mymfa_sceau::machine_id(), uid, nom), iterations)
}

/// Exécute `corps` sans jamais laisser passer une panique dans libpam.
fn protege(corps: impl FnOnce() -> c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(corps)).unwrap_or(PAM_IGNORE)
}

/* ───── Points d'entrée ───── */

/// # Safety
/// Appelée par libpam avec un `pamh` valide.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(pamh: *mut PamHandle, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    protege(|| {
        let o = Options::lire(argc, argv);
        if let Some(t) = jeton(pamh, PAM_AUTHTOK, o.ask).filter(|t| !t.is_empty()) {
            let boite = Box::into_raw(Box::new(t)) as *mut c_void;
            if pam_set_data(pamh, DONNEE.as_ptr(), boite, Some(nettoyer)) != PAM_SUCCESS {
                nettoyer(pamh, boite, 0);
            } else {
                o.journal("mot de passe de session gardé pour l'ouverture de session");
            }
        } else {
            o.journal("aucun mot de passe dans la pile : rien à garder");
        }
        PAM_IGNORE
    })
}

/// # Safety
/// Appelée par libpam.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(_pamh: *mut PamHandle, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_IGNORE
}

/// # Safety
/// Appelée par libpam.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(_pamh: *mut PamHandle, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_IGNORE
}

/// # Safety
/// Appelée par libpam avec un `pamh` valide.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_open_session(pamh: *mut PamHandle, _flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    protege(|| {
        let o = Options::lire(argc, argv);
        let mut p: *const c_void = std::ptr::null();
        if pam_get_data(pamh, DONNEE.as_ptr(), &mut p) != PAM_SUCCESS || p.is_null() {
            o.journal("pas de mot de passe gardé (authentification sans mot de passe ?) : rien à remettre");
            return PAM_IGNORE;
        }
        let mot_de_passe = (*(p as *const Zeroizing<Vec<u8>>)).clone();
        // Le mot de passe gardé est libéré (et effacé) dès maintenant.
        pam_set_data(pamh, DONNEE.as_ptr(), std::ptr::null_mut(), None);
        let Some((nom, uid, gid)) = utilisateur(pamh) else { return PAM_IGNORE };
        let base = o.rundir.clone().unwrap_or_else(|| remise::dossier_execution(uid));
        let r = Remise { iterations: o.iterations, cle: cle(&mot_de_passe, &nom, uid, o.iterations) };
        drop(mot_de_passe);
        match remise::deposer(&base, uid, gid, remise::FICHIER_CLE, &r.encoder()) {
            Ok(()) => {
                o.journal("clé de session remise au démon");
                PAM_SUCCESS
            }
            Err(e) => {
                o.journal(&format!("remise impossible ({}) : {e}", base.display()));
                PAM_IGNORE
            }
        }
    })
}

/// # Safety
/// Appelée par libpam.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_close_session(_pamh: *mut PamHandle, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_IGNORE
}

/// Changement du mot de passe de session : ancienne et nouvelle clés remises
/// au démon, qui rescelle (si l'utilisateur est connecté ; sinon, le sceau
/// périmé se refait au prochain déverrouillage manuel).
///
/// # Safety
/// Appelée par libpam avec un `pamh` valide.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_chauthtok(pamh: *mut PamHandle, flags: c_int, argc: c_int, argv: *const *const c_char) -> c_int {
    protege(|| {
        if flags & PAM_UPDATE_AUTHTOK == 0 {
            return PAM_IGNORE; // phase PAM_PRELIM_CHECK
        }
        let o = Options::lire(argc, argv);
        let (Some(ancien), Some(nouveau)) = (jeton(pamh, PAM_OLDAUTHTOK, o.ask), jeton(pamh, PAM_AUTHTOK, o.ask)) else {
            o.journal("ancien ou nouveau mot de passe absent (changé par root ?) : sceau à refaire au prochain déverrouillage");
            return PAM_IGNORE;
        };
        let Some((nom, uid, gid)) = utilisateur(pamh) else { return PAM_IGNORE };
        let base = o.rundir.clone().unwrap_or_else(|| remise::dossier_execution(uid));
        if !base.is_dir() {
            o.journal("utilisateur non connecté : sceau à refaire au prochain déverrouillage");
            return PAM_IGNORE;
        }
        let r = Renouvellement {
            iterations: o.iterations,
            ancienne: cle(&ancien, &nom, uid, o.iterations),
            nouvelle: cle(&nouveau, &nom, uid, o.iterations),
        };
        drop((ancien, nouveau));
        match remise::deposer(&base, uid, gid, remise::FICHIER_RENOUVELLEMENT, &r.encoder()) {
            Ok(()) => o.journal("clés de renouvellement remises au démon"),
            Err(e) => o.journal(&format!("renouvellement non remis : {e}")),
        }
        PAM_IGNORE
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options() {
        let args = [c"ask".as_ptr(), c"rundir=/tmp/x".as_ptr(), c"iterations=12".as_ptr(), c"inconnue".as_ptr()];
        let o = unsafe { Options::lire(args.len() as c_int, args.as_ptr()) };
        assert!(o.ask && !o.debug);
        assert_eq!(o.rundir, Some(PathBuf::from("/tmp/x")));
        assert_eq!(o.iterations, 12);
        let o = unsafe { Options::lire(0, std::ptr::null()) };
        assert_eq!(o.iterations, mymfa_sceau::ITERATIONS);
        assert!(o.rundir.is_none() && !o.ask);
    }

    #[test]
    fn panique_avalee() {
        assert_eq!(protege(|| panic!("jamais dans libpam")), PAM_IGNORE);
    }

    #[test]
    fn cle_identique_a_celle_du_demon() {
        // Le démon descelle avec la clé que le module a dérivée : même formule.
        let a = cle(b"session", "jacques", 1000, 10);
        let b = mymfa_sceau::deriver(b"session", &mymfa_sceau::sel(&mymfa_sceau::machine_id(), 1000, "jacques"), 10);
        assert_eq!(*a, *b);
    }
}
