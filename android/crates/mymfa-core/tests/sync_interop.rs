/*
 * Interopérabilité fusion : chaque cas a été fusionné par web/js/sync.js
 * (fixtures sync-web.json) ; la fusion Rust doit rendre le même résultat,
 * clé par clé, sémantiquement (les deux côtés parsent le JSON, l'ordre des
 * propriétés n'engage rien).
 */
use mymfa_core::sync;
use mymfa_core::DataMap;
use serde_json::Value;

struct Fixture {
    now: String,
    cases: Vec<Value>,
}

fn fixtures() -> Fixture {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sync-web.json");
    let raw: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("fixtures absentes : lancer `npm run gen`"))
            .expect("fixtures illisibles");
    Fixture {
        now: raw["now"].as_str().unwrap().to_string(),
        cases: raw["cases"].as_array().unwrap().clone(),
    }
}

fn to_map(value: &Value) -> DataMap {
    value
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().unwrap().to_string()))
        .collect()
}

/// Compare sémantiquement deux sorties : mêmes clés, mêmes valeurs JSON parsées.
fn assert_same_merge(name: &str, expected: &Value, actual: &DataMap) {
    let expected_map = expected.as_object().unwrap();
    let expected_keys: std::collections::BTreeSet<&String> = expected_map.keys().collect();
    let actual_keys: std::collections::BTreeSet<&String> = actual.keys().collect();
    assert_eq!(expected_keys, actual_keys, "{name} : clés de sortie différentes");
    for (key, expected_raw) in expected_map {
        let actual_raw = actual.get(key).unwrap();
        let expected_value: Value = serde_json::from_str(expected_raw.as_str().unwrap()).unwrap();
        let actual_value: Value = serde_json::from_str(actual_raw).unwrap();
        assert_eq!(expected_value, actual_value, "{name} : « {key} » différent");
    }
}

#[test]
fn chaque_cas_de_fusion_web_est_reproduit() {
    let fixture = fixtures();
    assert!(!fixture.cases.is_empty());
    for case in &fixture.cases {
        let name = case["name"].as_str().unwrap();
        let left = to_map(&case["left"]);
        let right = to_map(&case["right"]);
        let out = sync::merge(&left, &right, &fixture.now);
        assert_same_merge(name, &case["expected"], &out);
    }
}

#[test]
fn fusion_idempotente_et_symetrique_pour_l_essentiel() {
    let fixture = fixtures();
    let case = fixture.cases.iter().find(|c| c["name"] == "doublon-par-identite").unwrap();
    let left = to_map(&case["left"]);
    let right = to_map(&case["right"]);
    // Fusionner à nouveau le résultat avec une copie vide ne change rien (tombstones posées).
    let once = sync::merge(&left, &right, &fixture.now);
    let twice = sync::merge(&once, &DataMap::new(), &fixture.now);
    assert_same_merge("doublon une fois", &serde_json::to_value(&once).unwrap(), &twice);
}
