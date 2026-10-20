//! Les vecteurs Wycheproof (C2SP/wycheproof, `testvectors_v1`, Apache 2.0 :
//! `tests/wycheproof/LICENSE`) des primitives du protocole, passés aux
//! fonctions de `brocolis_proto::kdf` et `paquet` elles-mêmes. Chaque cas
//! « invalid » doit être refusé ; un cas « acceptable » peut l'être (notre
//! politique est dite pour chacun).

use brocolis_proto::kdf::{
    aes_gcm_open, aes_gcm_seal, ed25519_verify, hkdf_sha256, hmac_sha256, x25519, x25519_public,
};
use brocolis_proto::paquet::{mlkem_decapsulate, mlkem_public};
use serde_json::Value;

fn load(name: &str) -> Value {
    let path = format!("{}/tests/wycheproof/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn hex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap();
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn tests(v: &Value) -> impl Iterator<Item = (&Value, &Value)> {
    v["testGroups"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|g| g["tests"].as_array().unwrap().iter().map(move |t| (g, t)))
}

fn flags(t: &Value) -> Vec<&str> {
    t["flags"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f.as_str().unwrap())
        .collect()
}

#[test]
fn aes_256_gcm() {
    let mut n = 0;
    for (g, t) in tests(&load("aes_gcm_test.json")) {
        // Le protocole n'utilise qu'AES-256, nonce 96 bits, tag 128 bits.
        if g["keySize"] != 256 || g["ivSize"] != 96 || g["tagSize"] != 128 {
            continue;
        }
        let key: [u8; 32] = hex(&t["key"]).try_into().unwrap();
        let iv: [u8; 12] = hex(&t["iv"]).try_into().unwrap();
        let (aad, msg) = (hex(&t["aad"]), hex(&t["msg"]));
        let ct = [hex(&t["ct"]), hex(&t["tag"])].concat();
        let id = &t["tcId"];
        match t["result"].as_str().unwrap() {
            "valid" => {
                assert_eq!(
                    aes_gcm_seal(&key, &iv, &aad, &msg).unwrap(),
                    ct,
                    "tcId {id}"
                );
                assert_eq!(
                    *aes_gcm_open(&key, &iv, &aad, &ct).unwrap(),
                    msg,
                    "tcId {id}"
                );
            }
            _ => assert!(aes_gcm_open(&key, &iv, &aad, &ct).is_err(), "tcId {id}"),
        }
        n += 1;
    }
    assert!(n >= 60, "{n}");
}

#[test]
fn x25519_wycheproof() {
    let mut n = 0;
    for (_, t) in tests(&load("x25519_test.json")) {
        let private: [u8; 32] = hex(&t["private"]).try_into().unwrap();
        let public: [u8; 32] = hex(&t["public"]).try_into().unwrap();
        let shared = hex(&t["shared"]);
        let f = flags(t);
        let id = &t["tcId"];
        let r = x25519(&private, &public);
        // Notre politique : refuser un secret nul (petit ordre) et une clé
        // publique non canonique (bit 255 levé ou u ≥ p). Tout le reste
        // doit donner exactement le secret attendu.
        if f.contains(&"ZeroSharedSecret") || f.contains(&"NonCanonicalPublic") {
            assert!(r.is_err(), "tcId {id} {f:?}");
        } else if t["result"] == "invalid" {
            assert!(r.is_err() || r.unwrap().to_vec() != shared, "tcId {id}");
        } else {
            assert_eq!(r.unwrap().to_vec(), shared, "tcId {id} {f:?}");
        }
        n += 1;
    }
    assert!(n > 500);
    // La clé publique de base : RFC 7748 §6.1.
    let a: [u8; 32] = hex(&Value::from(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ))
    .try_into()
    .unwrap();
    assert_eq!(
        x25519_public(&a).to_vec(),
        hex(&Value::from(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        ))
    );
}

#[test]
fn hkdf_sha256_wycheproof() {
    let mut n = 0;
    for (_, t) in tests(&load("hkdf_sha256_test.json")) {
        let size = t["size"].as_u64().unwrap() as usize;
        let r = hkdf_sha256(&hex(&t["salt"]), &hex(&t["ikm"]), &hex(&t["info"]), size);
        match t["result"].as_str().unwrap() {
            "valid" => assert_eq!(r.unwrap(), hex(&t["okm"]), "tcId {}", t["tcId"]),
            _ => assert!(r.is_err(), "tcId {}", t["tcId"]),
        }
        n += 1;
    }
    assert!(n > 80);
}

#[test]
fn hmac_sha256_wycheproof() {
    for (g, t) in tests(&load("hmac_sha256_test.json")) {
        let bits = g["tagSize"].as_u64().unwrap() as usize;
        let tag = hmac_sha256(&hex(&t["key"]), &hex(&t["msg"]));
        let expected = hex(&t["tag"]);
        let same = tag[..bits / 8] == expected[..];
        assert_eq!(same, t["result"] == "valid", "tcId {}", t["tcId"]);
    }
}

#[test]
fn ed25519_wycheproof() {
    let mut n = 0;
    for (g, t) in tests(&load("ed25519_test.json")) {
        let pk: [u8; 32] = hex(&g["publicKey"]["pk"]).try_into().unwrap();
        let sig = hex(&t["sig"]);
        let ok = match <[u8; 64]>::try_from(sig.as_slice()) {
            Ok(sig) => ed25519_verify(&pk, &hex(&t["msg"]), &sig).is_ok(),
            Err(_) => false,
        };
        assert_eq!(
            ok,
            t["result"] == "valid",
            "tcId {} {:?}",
            t["tcId"],
            t["comment"]
        );
        n += 1;
    }
    assert!(n > 140);
}

#[test]
fn mlkem_768_wycheproof() {
    let mut n = 0;
    for (_, t) in tests(&load("mlkem_768_test.json")) {
        let id = &t["tcId"];
        let Ok(seed) = <[u8; 64]>::try_from(hex(&t["seed"]).as_slice()) else {
            // Graine de mauvaise longueur : refusée par le type.
            assert_eq!(t["result"], "invalid", "tcId {id}");
            n += 1;
            continue;
        };
        if t.get("ek").is_some() {
            assert_eq!(mlkem_public(&seed), hex(&t["ek"]), "tcId {id}");
        }
        let r = mlkem_decapsulate(&seed, &hex(&t["c"]));
        match t["result"].as_str().unwrap() {
            "valid" => assert_eq!(r.unwrap().to_vec(), hex(&t["K"]), "tcId {id}"),
            _ => assert!(r.is_err(), "tcId {id}"),
        }
        n += 1;
    }
    assert!(n > 190);
}
