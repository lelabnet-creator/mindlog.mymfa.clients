/*
 * Interopérabilité coffre, sens Rust → web : crée ici un coffre complet
 * (mot de passe + passkey à sortie PRF fixe), l'écrit en fixture, puis
 * scripts/interop-check.mjs vérifie que web/js/vault.js l'ouvre.
 */
use mymfa_core::vault;
use mymfa_core::DataMap;

fn data() -> DataMap {
    [
        (
            "mymfa.accounts.v1",
            r#"[{"id":"a1","type":"totp","issuer":"GitHub","account":"moi@example.net","secret":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30,"counter":0,"tag":"travail","description":"","favorite":false,"createdAt":"2026-01-01T00:00:00.000Z","updatedAt":"2026-01-01T00:00:00.000Z"}]"#,
        ),
        ("mymfa.history.v1", "[]"),
        ("mymfa.deleted.v1", r#"{"accounts":{},"historyClearedAt":null}"#),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

#[test]
fn ecrit_un_coffre_pour_le_web() {
    let iterations = 1000;
    let password = "correct horse battery";
    let prf_output = vec![11u8; 32];
    let (record, dek) = vault::create(password, &data(), iterations).unwrap();
    let record = vault::add_passkey(&record, &dek, "cred-rust", "Clé Rust", &[5u8; 32], &prf_output).unwrap();

    // Cohérence interne d'abord : le coffre s'ouvre ici-même.
    let dek2 = vault::unlock_with_password(&record, password).unwrap();
    assert_eq!(vault::decrypt_data(&dek2, &record.data).unwrap(), data());
    let dek3 = vault::unlock_with_prf(&record, "cred-rust", &prf_output).unwrap();
    assert_eq!(vault::decrypt_data(&dek3, &record.data).unwrap(), data());

    // Puis fixture pour la vérification côté web (Node).
    let fixture = serde_json::json!({
        "password": password,
        "iterations": iterations,
        "prfOutput": vault::to_b64(&prf_output),
        "record": record,
        "data": data(),
    });
    let path =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/vault-rust.json");
    std::fs::write(path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();
}
