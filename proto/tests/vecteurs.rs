//! `proto/vectors.json` est à jour (regénéré à l'identique par
//! `examples/vectors.rs`) et se relit par l'API publique, comme un portage le
//! ferait. La vérification indépendante (Python, OpenSSL) est
//! `scripts/verifier_vecteurs.py`.

#[path = "../examples/vectors.rs"]
#[allow(dead_code)]
mod generator;

use brocolis_proto::{KeyBundle, Token, cle_protegee, jetons};
use serde_json::Value;

fn file() -> Value {
    let path = format!("{}/vectors.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn le_fichier_est_a_jour() {
    assert!(
        generator::generate() == file(),
        "vectors.json n'est plus à jour : cargo run --example vectors"
    );
}

#[test]
fn cles_protegees_et_anciens_jetons() {
    let v = file();
    let p = &v["protected_key"];
    let key = unhex(&p["key"]);
    let k = cle_protegee::unprotect_key(p["v1"]["token"].as_str().unwrap(), "brocoli vert 2026")
        .unwrap();
    assert_eq!(k.to_vec(), key);
    for c in p["v2"].as_array().unwrap() {
        let token = c["token"].as_str().unwrap();
        assert_eq!(
            cle_protegee::unprotect_key(token, c["phrase"].as_str().unwrap())
                .unwrap()
                .to_vec(),
            key
        );
        assert!(cle_protegee::unprotect_key(token, c["wrong_phrase"].as_str().unwrap()).is_err());
    }
    let l = &v["legacy_tokens"];
    let keys: Vec<[u8; 32]> = l["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| unhex(k).try_into().unwrap())
        .collect();
    assert_eq!(
        jetons::open(l["v1"]["token"].as_str().unwrap(), &keys).text,
        "Salut 🥦"
    );
    assert_eq!(
        jetons::open(l["v2"]["token"].as_str().unwrap(), &keys[1..]).text,
        "À tous"
    );
    assert_eq!(
        jetons::open(l["marked"]["sealed"].as_str().unwrap(), &keys).text,
        l["marked"]["opened"].as_str().unwrap()
    );
}

#[test]
fn paquets_et_jetons_v3_se_relisent() {
    let v = file();
    for case in v["sessions"].as_array().unwrap() {
        if let Some(alice) = case["setup"].get("alice") {
            for who in [alice, &case["setup"]["bob"]] {
                let b = KeyBundle::from_bytes(&unhex(&who["bundle"])).unwrap();
                assert_eq!(
                    b.identity.fingerprint(),
                    who["fingerprint"].as_str().unwrap()
                );
            }
        }
        for step in case["steps"].as_array().unwrap() {
            if let Some(t) = step.get("token") {
                let token = Token::decode(t.as_str().unwrap()).unwrap();
                assert_eq!(token.encode(), t.as_str().unwrap());
                assert_eq!(token.to_bytes()[0], step["type"].as_u64().unwrap() as u8);
            }
        }
    }
}
