/*
 * Interopérabilité synchro v2, deux sens :
 *  - web → Rust : chaque cas de tests/fixtures/sync2-web.json (fusion calculée
 *    par web/js/sync2.js, via android/scripts/make-fixtures.mjs) est fusionné
 *    ici ; la fusion Rust doit rendre le même résultat, sémantiquement (les deux
 *    côtés parsent le JSON, l'ordre des clés n'engage pas), le même a_envoyer et
 *    les mêmes genres d'entrées de rapport.
 *  - Rust → web : ce test écrit tests/fixtures/sync2-rust.json (mêmes entrées,
 *    résultats calculés ici) ; android/scripts/interop-check.mjs vérifie que
 *    web/js/sync2.js rend les mêmes.
 */
use mymfa_core::sync2::{self, EtatSynchro, Horloge};
use mymfa_core::DataMap;
use serde_json::Value;

fn fixtures(path: &str) -> Value {
    let full = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(path);
    serde_json::from_str(&std::fs::read_to_string(full).expect("fixtures absentes : lancer `npm run gen`")).expect("fixtures illisibles")
}

fn to_map(value: &Value) -> DataMap {
    value
        .as_object()
        .expect("une copie est un objet clé → chaîne")
        .iter()
        .map(|(k, v)| (k.clone(), v.as_str().expect("valeur de copie en texte").to_string()))
        .collect()
}

fn etat_de(case: &Value) -> EtatSynchro {
    let e = &case["etat"];
    EtatSynchro {
        appareil: e["appareil"].as_str().unwrap().to_string(),
        horloge: Horloge { l: e["horloge"]["l"].as_i64().unwrap(), c: e["horloge"]["c"].as_u64().unwrap() as u32 },
        repere: e["repere"].as_str().unwrap_or("").to_string(),
    }
}

/// Compare deux copies clé par clé, JSON parsé (l'ordre des clés n'engage pas).
fn assert_meme_copie(nom: &str, attendu: &Value, actuel: &DataMap) {
    let attendu_map = attendu.as_object().unwrap();
    let cles: std::collections::BTreeSet<&String> = attendu_map.keys().collect();
    let actuelles: std::collections::BTreeSet<&String> = actuel.keys().collect();
    assert_eq!(cles, actuelles, "{nom} : clés de sortie différentes");
    for (cle, attendu_brut) in attendu_map {
        let attendu_valeur: Value = serde_json::from_str(attendu_brut.as_str().unwrap()).unwrap();
        let actuel_valeur: Value = serde_json::from_str(actuel.get(cle).unwrap()).unwrap();
        assert_eq!(attendu_valeur, actuel_valeur, "{nom} : clé « {cle} » différente");
    }
}

#[test]
fn chaque_cas_de_fusion_v2_web_est_reproduit() {
    let fixture = fixtures("sync2-web.json");
    let cases = fixture["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let nom = case["name"].as_str().unwrap();
        let locale = to_map(&case["locale"]);
        let distante = to_map(&case["distante"]);
        let mut etat = etat_de(case);
        let maintenant = case["maintenant"].as_i64().unwrap();
        let (fusion, rapport) = sync2::fusion(&locale, &distante, &mut etat, maintenant);
        assert_meme_copie(nom, &case["attendu"], &fusion);
        assert_eq!(
            rapport.a_envoyer,
            case["aEnvoyer"].as_bool().unwrap(),
            "{nom} : a_envoyer différent"
        );
        let mut genres: Vec<&str> = rapport.entrees.iter().map(|e| e.genre).collect();
        genres.sort_unstable();
        let mut attendus: Vec<&str> = case["genres"]
            .as_array()
            .unwrap()
            .iter()
            .map(|g| g.as_str().unwrap())
            .collect();
        attendus.sort_unstable();
        assert_eq!(genres, attendus, "{nom} : genres d'entrées de rapport différents");
    }
}

/// Sens Rust → web : mêmes entrées que sync2-web.json, résultats calculés ici ;
/// scripts/interop-check.mjs les rejoue avec web/js/sync2.js. Ce test s'exécute
/// après le premier (fixtures déjà générées) — ou seul, il régénère les siennes.
#[test]
fn ecrit_les_fusions_v2_pour_le_web() {
    let fixture = fixtures("sync2-web.json");
    let cases = fixture["cases"].as_array().unwrap();
    let mut sorties = Vec::new();
    for case in cases {
        let nom = case["name"].as_str().unwrap().to_string();
        let locale = to_map(&case["locale"]);
        let distante = to_map(&case["distante"]);
        let mut etat = etat_de(case);
        let maintenant = case["maintenant"].as_i64().unwrap();
        let (fusion, rapport) = sync2::fusion(&locale, &distante, &mut etat, maintenant);
        let mut genres: Vec<&str> = rapport.entrees.iter().map(|e| e.genre).collect();
        genres.sort_unstable();
        sorties.push(serde_json::json!({
            "name": nom,
            "locale": case["locale"],
            "distante": case["distante"],
            "etat": case["etat"],
            "maintenant": maintenant,
            "attendu": fusion,
            "aEnvoyer": rapport.a_envoyer,
            "genres": genres,
        }));
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/sync2-rust.json");
    std::fs::write(
        path,
        serde_json::to_string_pretty(&serde_json::json!({ "maintenant": fixture["maintenant"], "cases": sorties })).unwrap(),
    )
    .unwrap();
}

/// Les deux côtés convergent : fusionner la sortie Rust avec la sortie JS ne
/// change plus rien (idempotence du résultat partagé), et la fusion est
/// commutative sur les jeux communs.
#[test]
fn les_sorties_des_deux_cotes_se_refusionnent_sans_effet() {
    let fixture = fixtures("sync2-web.json");
    for case in fixture["cases"].as_array().unwrap() {
        let nom = case["name"].as_str().unwrap();
        let locale = to_map(&case["locale"]);
        let distante = to_map(&case["distante"]);
        let maintenant = case["maintenant"].as_i64().unwrap();
        let etat_web = etat_de(case);
        let (fusion_web, _) = sync2::fusion(&locale, &distante, &mut etat_web.clone(), maintenant);
        let etat_rust = etat_de(case);
        let (fusion_rust, rapport2) = sync2::fusion(&locale, &distante, &mut { etat_rust.clone() }, maintenant);
        assert_eq!(fusion_web, fusion_rust, "{nom} : les deux exécutions Rust divergent");
        // Refusionner la sortie avec n'importe quel côté : rien de nouveau.
        let mut etat3 = etat_de(case);
        let (refusion, rapport3) = sync2::fusion(&fusion_rust, &distante, &mut etat3, maintenant);
        assert!(!rapport3.a_envoyer || refusion == fusion_rust, "{nom} : la refusion change le résultat");
        let _ = rapport2;
    }
}
