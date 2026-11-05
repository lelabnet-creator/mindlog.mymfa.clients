/*
 * Application Android myMFA — interface Slint sur le cœur mymfa-core.
 * Cible bureau conservée (cargo run) pour itérer l'UI sans émulateur.
 */
mod backend;
mod storage;

slint::include_modules!();

/// Poignée native : AndroidApp côté Android, () sur les autres cibles.
#[cfg(target_os = "android")]
pub type AppHandle = slint::android::android_activity::AndroidApp;
#[cfg(not(target_os = "android"))]
pub type AppHandle = ();

pub fn run(app: AppHandle) -> Result<(), slint::PlatformError> {
    let ui = MainWindow::new()?;
    backend::Backend::start(ui.clone_strong(), app);
    ui.run()
}

#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: slint::android::AndroidApp) {
    slint::android::init(app.clone()).expect("init du backend Android de Slint");
    run(app).expect("myMFA");
}

