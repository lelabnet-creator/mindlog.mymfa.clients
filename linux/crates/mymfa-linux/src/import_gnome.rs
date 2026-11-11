/*
 * Reprise du trousseau gnome-keyring : tant que gnome-keyring tient
 * org.freedesktop.secrets (le démon mymfa attend alors en file), on lit ses
 * collections par le Secret Service lui-même — déverrouillage par sa propre
 * invite au besoin — et on recopie chaque élément dans le trousseau local de
 * mymfa (MyMfa1.ImportSecret). Relançable : un élément aux mêmes attributs
 * est remplacé, pas dupliqué. Le fichier ~/.local/share/keyrings n'est pas
 * touché.
 */
use crate::interface;
use futures_util::StreamExt;
use std::collections::HashMap;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};
use zeroize::Zeroizing;

const SS: &str = "org.freedesktop.secrets";

fn err(e: zbus::Error) -> String {
    e.to_string()
}

async fn proxy<'a>(conn: &Connection, chemin: &'a str, iface: &'a str) -> Result<Proxy<'a>, String> {
    zbus::proxy::Builder::new(conn)
        .destination(SS)
        .map_err(err)?
        .path(chemin)
        .map_err(err)?
        .interface(iface)
        .map_err(err)?
        .cache_properties(zbus::proxy::CacheProperties::No)
        .build()
        .await
        .map_err(err)
}

pub async fn importer() -> Result<(), String> {
    let conn = Connection::session().await.map_err(err)?;
    let mymfa = Proxy::new(&conn, interface::NOM, interface::CHEMIN, interface::NOM)
        .await
        .map_err(|_| "démon mymfa injoignable (systemctl --user start mymfa)".to_string())?;
    if mymfa.get_property::<bool>("SecretService").await.map_err(err)? {
        return Err("mymfa tient déjà org.freedesktop.secrets : l'import se fait pendant que gnome-keyring \
                    tourne encore (voir linux/README.md, « Reprise de gnome-keyring »)"
            .into());
    }
    if mymfa.get_property::<bool>("Locked").await.map_err(err)? {
        return Err("coffre myMFA verrouillé : mymfa unlock, puis relancer l'import".into());
    }
    let service = proxy(&conn, "/org/freedesktop/secrets", "org.freedesktop.Secret.Service").await?;
    let (_, session): (OwnedValue, OwnedObjectPath) =
        service.call("OpenSession", &("plain", Value::from(""))).await.map_err(err)?;
    let collections: Vec<OwnedObjectPath> = service.get_property("Collections").await.map_err(err)?;
    let (_, invite): (Vec<OwnedObjectPath>, OwnedObjectPath) =
        service.call("Unlock", &(collections.clone(),)).await.map_err(err)?;
    if invite.as_str() != "/" {
        println!("gnome-keyring demande son mot de passe…");
        let p = proxy(&conn, invite.as_str(), "org.freedesktop.Secret.Prompt").await?;
        let mut fin = p.receive_signal("Completed").await.map_err(err)?;
        p.call_method("Prompt", &("",)).await.map_err(err)?;
        let message = fin.next().await.ok_or("invite gnome-keyring interrompue")?;
        let (annule, _): (bool, OwnedValue) = message.body().deserialize().map_err(err)?;
        if annule {
            return Err("déverrouillage de gnome-keyring annulé".into());
        }
    }
    let mut total = 0usize;
    for c in &collections {
        let id = c.as_str().rsplit('/').next().unwrap_or("import").to_string();
        if id == "session" {
            continue; // collection éphémère de gnome-keyring, en mémoire seulement
        }
        let pc = proxy(&conn, c.as_str(), "org.freedesktop.Secret.Collection").await?;
        let label: String = pc.get_property("Label").await.unwrap_or_default();
        let elements: Vec<OwnedObjectPath> = pc.get_property("Items").await.map_err(err)?;
        let mut n = 0usize;
        for e in elements {
            let pe = proxy(&conn, e.as_str(), "org.freedesktop.Secret.Item").await?;
            let label_e: String = pe.get_property("Label").await.unwrap_or_default();
            let attributs: HashMap<String, String> = pe.get_property("Attributes").await.unwrap_or_default();
            let ((_, _, valeur, type_contenu),): ((OwnedObjectPath, Vec<u8>, Vec<u8>, String),) =
                match pe.call("GetSecret", &(session.clone(),)).await {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("  élément ignoré ({label_e}) : {e}");
                        continue;
                    }
                };
            let valeur = Zeroizing::new(valeur);
            let _: OwnedObjectPath = mymfa
                .call(
                    "ImportSecret",
                    &(id.as_str(), label.as_str(), label_e.as_str(), attributs, valeur.as_slice(), type_contenu.as_str()),
                )
                .await
                .map_err(err)?;
            n += 1;
        }
        println!("{label} ({id}) : {n} élément(s) repris");
        total += n;
    }
    if let Ok(s) = proxy(&conn, session.as_str(), "org.freedesktop.Secret.Session").await {
        let _ = s.call_method("Close", &()).await;
    }
    println!("{total} secret(s) repris dans le trousseau mymfa. Étape suivante : couper gnome-keyring (README).");
    Ok(())
}
