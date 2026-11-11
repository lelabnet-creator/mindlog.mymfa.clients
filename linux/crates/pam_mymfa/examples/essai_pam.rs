/*
 * Banc d'essai du module : joue une vraie pile PAM (libpam, pam_start_confdir)
 * sur un dossier de configuration jetable — sans root, sans toucher /etc/pam.d.
 *
 *   essai_pam <confdir> <service> <utilisateur> session <mot de passe>
 *   essai_pam <confdir> <service> <utilisateur> chauthtok <ancien> <nouveau>
 *
 * La conversation répond le mot de passe à chaque invite (l'ancien à
 * « Current », le nouveau sinon). Rend le code PAM de chaque étape.
 */
use std::ffi::{c_char, c_int, c_void, CStr, CString};

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start_confdir(service: *const c_char, user: *const c_char, conv: *const PamConv, confdir: *const c_char, pamh: *mut *mut c_void) -> c_int;
    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_open_session(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_close_session(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_chauthtok(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
}

struct Reponses {
    ancien: CString,
    nouveau: CString,
}

extern "C" fn conversation(n: c_int, msgs: *mut *const PamMessage, resp: *mut *mut PamResponse, data: *mut c_void) -> c_int {
    unsafe {
        let r = &*(data as *const Reponses);
        let tableau = libc::calloc(n as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        for i in 0..n as usize {
            let m = &**msgs.add(i);
            let texte = if m.msg.is_null() { "" } else { CStr::from_ptr(m.msg).to_str().unwrap_or("") };
            let valeur = if texte.contains("Current") || texte.contains("current") { &r.ancien } else { &r.nouveau };
            (*tableau.add(i)).resp = libc::strdup(valeur.as_ptr());
        }
        *resp = tableau;
    }
    0
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 6 {
        eprintln!("usage : essai_pam <confdir> <service> <utilisateur> session|chauthtok <mot de passe> [nouveau]");
        std::process::exit(2);
    }
    let c = |s: &str| CString::new(s).unwrap();
    let (confdir, service, user) = (c(&a[1]), c(&a[2]), c(&a[3]));
    let reponses = Box::new(Reponses { ancien: c(&a[5]), nouveau: c(a.get(6).unwrap_or(&a[5])) });
    let conv = PamConv { conv: conversation, appdata_ptr: &*reponses as *const Reponses as *mut c_void };
    let mut h: *mut c_void = std::ptr::null_mut();
    unsafe {
        let r = pam_start_confdir(service.as_ptr(), user.as_ptr(), &conv, confdir.as_ptr(), &mut h);
        println!("pam_start_confdir = {r}");
        let fin = if a[4] == "chauthtok" {
            let r = pam_chauthtok(h, 0);
            println!("pam_chauthtok = {r}");
            r
        } else {
            let r = pam_authenticate(h, 0);
            println!("pam_authenticate = {r}");
            let s = pam_open_session(h, 0);
            println!("pam_open_session = {s}");
            println!("pam_close_session = {}", pam_close_session(h, 0));
            s
        };
        pam_end(h, fin);
    }
}
