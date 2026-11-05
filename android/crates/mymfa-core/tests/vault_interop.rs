/*
 * Interopérabilité coffre, sens web → Rust : les fixtures sont chiffrées par
 * web/js/vault.js (scripts/make-fixtures.mjs) et doivent s'ouvrir ici.
 * Le sens inverse (Rust → web) est couvert par tests/interop_out.rs + scripts/interop-check.mjs.
 */
use mymfa_core::vault::{self, VaultRecord};
use mymfa_core::DataMap;
use serde_json::Value;

fn fixtures() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-web.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixtures absentes : lancer `npm run gen`"))
        .expect("fixtures illisibles")
}

fn data_map(value: &Value) -> DataMap {
    value
        .as_object()
        .expect("données de fixture")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("texte JSON").to_string()))
        .collect()
}

#[test]
fn coffre_web_deverrouille_par_mot_de_passe() {
    let fixture = fixtures();
    let data = data_map(fixture.get("data").unwrap());
    for name in ["simple", "decomposed"] {
        let record: VaultRecord =
            serde_json::from_value(fixture["records"][name].clone()).expect("enregistrement");
        let password = if name == "decomposed" {
            fixture["decomposedPassword"].as_str().unwrap()
        } else {
            "correct horse battery"
        };
        let dek = vault::unlock_with_password(&record, password)
            .unwrap_or_else(|e| panic!("{name} : {e}"));
        assert_eq!(vault::decrypt_data(&dek, &record.data).unwrap(), data, "{name} : données intactes");
    }
}

#[test]
fn coffre_web_mauvais_mot_de_passe_refuse() {
    let fixture = fixtures();
    let record: VaultRecord =
        serde_json::from_value(fixture["records"]["simple"].clone()).unwrap();
    assert_eq!(
        vault::unlock_with_password(&record, "mauvais mot de passe").unwrap_err().code,
        "wrongPassword"
    );
}

#[test]
fn coffre_web_deverrouille_par_passkey_prf() {
    let fixture = fixtures();
    let record: VaultRecord =
        serde_json::from_value(fixture["records"]["withPasskey"].clone()).unwrap();
    let prf_output = vault::from_b64(fixture["prfOutput"].as_str().unwrap()).unwrap();
    let dek = vault::unlock_with_prf(&record, "cred-fixture", &prf_output).unwrap();
    let data = data_map(fixture.get("data").unwrap());
    assert_eq!(vault::decrypt_data(&dek, &record.data).unwrap(), data);
    // Mauvaise sortie PRF : refusée.
    assert_eq!(
        vault::unlock_with_prf(&record, "cred-fixture", &[0u8; 32]).unwrap_err().code,
        "passkeyRejected"
    );
}

#[test]
fn re_chiffrement_rust_reste_ouvrable_au_format_web() {
    let fixture = fixtures();
    let record: VaultRecord =
        serde_json::from_value(fixture["records"]["withPasskey"].clone()).unwrap();
    let dek = vault::unlock_with_password(&record, "correct horse battery").unwrap();
    // Les données re-chiffrées par Rust doivent reprendre la même forme (v, data.iv/ct base64).
    let data = data_map(fixture.get("data").unwrap());
    let reblob = vault::encrypt_data(&dek, &data).unwrap();
    assert_eq!(vault::decrypt_data(&dek, &reblob).unwrap(), data);
    // Les itérations de la fixture sont réduites, mais le format de l'enveloppe est intact.
    assert_eq!(record.password.kdf, "PBKDF2-SHA256");
    assert_eq!(record.password.iterations, fixture["iterations"].as_u64().unwrap() as u32);
    assert_eq!(record.passkeys.len(), 1);
    assert_eq!(record.passkeys[0].id, "cred-fixture");
}
