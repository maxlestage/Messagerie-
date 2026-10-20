//! Produit `reference-rust.json` avec la référence Rust, pour les tests
//! d'interopérabilité de BrocolisProto (ReferenceRustTests.swift). Hors de
//! toute compilation du dépôt ; pour le relancer, un projet Cargo jetable :
//!
//! ```toml
//! [package]
//! name = "reference-rust"
//! version = "0.0.0"
//! edition = "2024"
//! [workspace]
//! [dependencies]
//! brocolis-proto = { path = "<dépôt>/proto" }
//! serde_json = "1"
//! curve25519-dalek = "5"
//! argon2 = { version = "0.6", default-features = false, features = ["alloc"] }
//! ```
//!
//! puis `reference-rust ed25519`, `argon2`, `phase1` (assemblés dans le JSON
//! : 100 points tirés et les cas particuliers, Argon2id, états) et, pour le
//! sens Swift → Rust, `reference-rust phase3 <fichier écrit par les tests
//! Swift avec BROCOLIS_INTEROP_OUT>`. `reference-rust echanges` rejoue le
//! scénario aléatoire de ProtocoleTests.testEchangesAleatoires (mêmes
//! graines, mêmes tirages) et dit où un rejeu n'est pas reconnu comme tel.

use brocolis_proto::groupe::{SenderKeyState, new_group_id};
use brocolis_proto::hasard::Deterministic;
use brocolis_proto::kdf::sha256;
use brocolis_proto::{Content, Device, ReceivedSenderKey, ReplayGuard, Session, Token};
use curve25519_dalek::edwards::CompressedEdwardsY;
use serde_json::{Value, json};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

fn text(c: Content) -> String {
    match c {
        Content::Text(t) => t,
        _ => panic!("distribution"),
    }
}

fn ed25519() {
    let mut cases = Vec::new();
    let mut encs: Vec<[u8; 32]> = Vec::new();
    for i in 0..3000u32 {
        encs.push(sha256(&i.to_be_bytes()));
    }
    // y petits, p - k, p + k, avec et sans signe.
    for k in 0..64u8 {
        let mut a = [0u8; 32];
        a[0] = k;
        encs.push(a);
        let mut p = [0xffu8; 32];
        p[31] = 0x7f;
        p[0] = 0xed_u8.wrapping_sub(k);
        encs.push(p);
        let mut q = [0xffu8; 32];
        q[31] = 0x7f;
        q[0] = 0xed_u8.wrapping_add(k);
        if 0xed_u16 + (k as u16) < 0x100 {
            encs.push(q);
        }
    }
    let n = encs.len();
    for i in 0..n {
        let mut e = encs[i];
        e[31] |= 0x80;
        encs.push(e);
    }
    for e in encs {
        let d = CompressedEdwardsY(e).decompress();
        cases.push(json!({ "enc": hex(&e), "point": d.is_some(),
            "small": d.map(|p| p.is_small_order()).unwrap_or(false) }));
    }
    println!("{}", serde_json::to_string(&cases).unwrap());
}

fn argon() {
    use argon2::{Algorithm, Argon2, Params, Version};
    let mut out = Vec::new();
    for (m, t, p, len) in [(64u32, 2u32, 2u32, 100usize), (48, 1, 3, 64), (96, 3, 1, 1025), (32, 4, 4, 4)] {
        let params = Params::new(m, t, p, Some(len)).unwrap();
        let mut o = vec![0u8; len];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(b"brocoli", &[0x55; 16], &mut o)
            .unwrap();
        out.push(json!({ "m": m, "t": t, "p": p, "len": len, "out": hex(&o) }));
    }
    println!("{}", serde_json::to_string(&out).unwrap());
}

const T0: u64 = 1_790_000_000;

/// Phase 1 : la référence ouvre des sessions et écrit ses états.
fn phase1() {
    let mut rng = Deterministic::new(b"interop");
    let alice = Device::generate(&mut rng, T0, true);
    let bob = Device::generate(&mut rng, T0, true);
    let bundle = bob.bundle().unwrap();
    let mut a = alice.initiate(&bundle, true, &mut rng).unwrap();
    let t1 = a.encrypt("Rust → Swift 1 🥦").unwrap();
    let t2 = a.encrypt("Rust → Swift 2").unwrap();
    // PSK
    let key = [0x42u8; 32];
    let mut p = Session::initiate_psk(&key, &mut rng).unwrap();
    let p1 = p.encrypt("PSK de Rust").unwrap();
    // Groupe
    let gid = new_group_id(&mut rng);
    let mut chain = SenderKeyState::generate(gid, &mut rng);
    let dist = a.encrypt_distribution(&chain.distribution()).unwrap();
    let g1 = chain.encrypt("groupe 1").unwrap();
    let g2 = chain.encrypt("groupe 2").unwrap();
    let recv = ReceivedSenderKey::from_distribution(&chain.distribution()).unwrap();
    let mut guard = ReplayGuard::default();
    guard.insert([9u8; 32], T0);
    // Une session riche : clés sautées et cliquets passés.
    let carol = Device::generate(&mut rng, T0, false);
    let mut dave = Device::generate(&mut rng, T0, false);
    let mut c = carol.initiate(&dave.bundle().unwrap(), false, &mut rng).unwrap();
    let c0 = c.encrypt_token("c0").unwrap();
    let Token::Initial(ci) = &c0 else { panic!() };
    let (mut d, _) = dave.accept(ci, T0, &mut rng).unwrap();
    c.decrypt_text(&d.encrypt("d0").unwrap(), T0, &mut rng).unwrap();
    let pending_c1 = c.encrypt("c1 en retard").unwrap();
    let _lost = c.encrypt("c2 perdu").unwrap();
    d.decrypt_text(&c.encrypt("c3").unwrap(), T0, &mut rng).unwrap();
    c.decrypt_text(&d.encrypt("d1").unwrap(), T0, &mut rng).unwrap();
    d.decrypt_text(&c.encrypt("c4").unwrap(), T0, &mut rng).unwrap();
    assert!(d.skipped_len() == 2);
    let mut rchain = SenderKeyState::generate([7u8; 16], &mut rng);
    let mut rrecv = ReceivedSenderKey::from_distribution(&rchain.distribution()).unwrap();
    let late_group = rchain.encrypt("groupe en retard").unwrap();
    let Token::Group(g) = Token::decode(&rchain.encrypt("groupe à l'heure").unwrap()).unwrap() else { panic!() };
    rrecv.decrypt(&g, T0).unwrap();
    let v = json!({
        "alice_device": serde_json::from_str::<Value>(&alice.to_json()).unwrap(),
        "bob_device": serde_json::from_str::<Value>(&bob.to_json()).unwrap(),
        "bob_bundle": bundle.to_base64(),
        "alice_session": serde_json::from_str::<Value>(&a.to_json()).unwrap(),
        "tokens": [t1, t2], "texts": ["Rust → Swift 1 🥦", "Rust → Swift 2"],
        "psk_key": hex(&key), "psk_session": serde_json::from_str::<Value>(&p.to_json()).unwrap(),
        "psk_token": p1,
        "chain": serde_json::from_str::<Value>(&chain.to_json()).unwrap(),
        "received": serde_json::from_str::<Value>(&recv.to_json()).unwrap(),
        "distribution": dist, "group_tokens": [g1, g2],
        "replay_guard": serde_json::to_value(&guard).unwrap(),
        "rich": { "c": serde_json::from_str::<Value>(&c.to_json()).unwrap(),
            "d": serde_json::from_str::<Value>(&d.to_json()).unwrap(),
            "dave_device": serde_json::from_str::<Value>(&dave.to_json()).unwrap(),
            "pending": pending_c1, "pending_text": "c1 en retard",
            "received": serde_json::from_str::<Value>(&rrecv.to_json()).unwrap(),
            "late_group": late_group, "late_group_text": "groupe en retard" },
    });
    println!("{}", serde_json::to_string_pretty(&v).unwrap());
}

/// Phase 3 : la référence relit les états écrits par Swift et continue.
fn phase3(path: &str) {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let s = |k: &str| v[k].as_str().unwrap().to_string();
    let mut rng = Deterministic::new(b"phase3");
    let mut checks = 0;
    // Alice (session écrite par Swift après la réponse de Bob) lit les
    // réponses Swift et répond.
    let mut alice = Session::from_json(&s("alice_session")).unwrap();
    let mut bob = Session::from_json(&s("bob_session")).unwrap();
    for (t, expected) in v["to_alice"].as_array().unwrap().iter().zip(v["to_alice_texts"].as_array().unwrap()) {
        assert_eq!(text(alice.decrypt_text(t.as_str().unwrap(), T0, &mut rng).unwrap()), expected.as_str().unwrap());
        checks += 1;
    }
    let r = alice.encrypt("Rust relit Swift").unwrap();
    assert_eq!(text(bob.decrypt_text(&r, T0, &mut rng).unwrap()), "Rust relit Swift");
    checks += 1;
    let r = bob.encrypt("et réciproquement").unwrap();
    assert_eq!(text(alice.decrypt_text(&r, T0, &mut rng).unwrap()), "et réciproquement");
    checks += 1;
    // Un appareil écrit par Swift : son paquet se vérifie, il accepte un
    // premier message.
    let mut dev = Device::from_json(&s("swift_device")).unwrap();
    let b = dev.bundle().unwrap();
    let parsed = brocolis_proto::KeyBundle::from_base64(&s("swift_bundle")).unwrap();
    assert_eq!(parsed.identity, b.identity);
    assert_eq!(parsed.spk, b.spk);
    checks += 1;
    let initial = Token::decode(&s("swift_initial")).unwrap();
    let Token::Initial(i) = initial else { panic!() };
    // Le premier message vient d'un initiateur Swift (hybride, encapsulation
    // de CryptoKit/BoringSSL).
    let (mut sb, c) = dev.accept(&i, T0, &mut rng).unwrap();
    assert_eq!(text(c), s("swift_initial_text"));
    assert_eq!(sb.is_post_quantum(), v["swift_initial_pq"].as_bool().unwrap());
    checks += 1;
    let reply = sb.encrypt("réponse de Rust").unwrap();
    // Groupe : la chaîne Swift.
    let mut recv = ReceivedSenderKey::from_json(&s("received")).unwrap();
    let Token::Group(g) = Token::decode(&s("group_token")).unwrap() else { panic!() };
    assert_eq!(recv.decrypt(&g, T0).unwrap(), s("group_text"));
    checks += 1;
    let mut chain = SenderKeyState::from_json(&s("chain")).unwrap();
    let t = chain.encrypt("Rust dans le groupe Swift").unwrap();
    let g: ReplayGuard = serde_json::from_str(&s("replay_guard")).unwrap();
    assert_eq!(g.len(), 1);
    checks += 1;
    println!("{}", serde_json::to_string(&json!({ "checks": checks, "reply": reply, "group_reply": t,
        "session_from_swift_initial": serde_json::from_str::<Value>(&sb.to_json()).unwrap() })).unwrap());
}

fn below(rng: &mut Deterministic, n: usize) -> usize {
    use brocolis_proto::hasard::Rng;
    (rng.next_u32() as usize) % n
}

fn echanges(seed: u32) {
    let pq = seed % 2 == 0;
    let mut rng = Deterministic::new(format!("échanges/{seed}").as_bytes());
    let alice = Device::generate(&mut rng, T0, pq);
    let mut bob = Device::generate(&mut rng, T0, pq);
    let mut a = alice.initiate(&bob.bundle().unwrap(), pq, &mut rng).unwrap();
    let Token::Initial(i) = a.encrypt_token("bonjour").unwrap() else { panic!() };
    let (mut b, _) = bob.accept(&i, T0, &mut rng).unwrap();
    let r = b.encrypt_token("re").unwrap();
    a.decrypt(&r, T0, &mut rng).unwrap();
    let mut in_flight: Vec<(bool, Token, String)> = Vec::new();
    let mut delivered: Vec<(bool, Token)> = Vec::new();
    let mut now = T0;
    for step in 0..300 {
        now += 7;
        match below(&mut rng, 10) {
            0..=3 => {
                let from_a = below(&mut rng, 2) == 0;
                let msg = format!("{seed}/{step} {}", "é".repeat(below(&mut rng, 200)));
                let s = if from_a { &mut a } else { &mut b };
                in_flight.push((from_a, s.encrypt_token(&msg).unwrap(), msg));
            }
            4..=7 if !in_flight.is_empty() => {
                let k = below(&mut rng, in_flight.len());
                let (from_a, token, msg) = in_flight.remove(k);
                let r = if from_a { &mut b } else { &mut a };
                assert_eq!(text(r.decrypt(&token, now, &mut rng).unwrap()), msg);
                delivered.push((from_a, token));
            }
            8 if !in_flight.is_empty() => {
                let k = below(&mut rng, in_flight.len());
                in_flight.remove(k);
            }
            9 if !delivered.is_empty() => {
                let k = below(&mut rng, delivered.len());
                let (from_a, token) = &delivered[k];
                let r = if *from_a { &mut b } else { &mut a };
                let e = r.decrypt(token, now, &mut rng).err();
                if e != Some(brocolis_proto::Erreur::Rejoue) {
                    println!("graine {seed} étape {step} : {:?}", e);
                }
            }
            _ => {
                a = Session::from_json(&a.to_json()).unwrap();
                b = Session::from_json(&b.to_json()).unwrap();
            }
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args[1].as_str() {
        "ed25519" => ed25519(),
        "argon2" => argon(),
        "phase1" => phase1(),
        "phase3" => phase3(&args[2]),
        "echanges" => for seed in 0..24 { echanges(seed) },
        _ => panic!(),
    }
    let _ = unhex("");
}
