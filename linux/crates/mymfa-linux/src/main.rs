/*
 * mymfa — client Linux de myMFA : le trousseau du bureau.
 *
 *   mymfa daemon   démon utilisateur (systemd --user / activation D-Bus) :
 *                  org.freedesktop.secrets + today.mindlog.MyMfa1
 *   mymfa <cmd>    CLI, cliente du démon (voir `mymfa help`)
 *
 * Même coffre que le web et Android (android/crates/mymfa-core) ; secrets
 * des applications dans un trousseau local chiffré par la clé du coffre ;
 * déverrouillage à la connexion par pam_mymfa (crates/pam_mymfa).
 */
mod chemins;
mod cli;
mod coffre;
mod demon;
mod import_gnome;
mod interface;
mod invite;
mod presse_papiers;
mod service;
mod session;
mod trousseau;

use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let runtime = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("mymfa: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(cli::executer(args)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("mymfa: {message}");
            ExitCode::FAILURE
        }
    }
}
