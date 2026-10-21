//! Robustesse du protocole v4 (§9), toujours exécutée par `cargo test` :
//! entrées aléatoires, altération de chaque octet d'un jeton, sauts trop
//! grands, désordre aléatoire sur de longues conversations. Aucune entrée
//! ne doit faire paniquer, aucune altération ne doit être acceptée, et un
//! échec laisse la session telle qu'elle était.

use brocolis_proto::hasard::{Deterministic, Rng};
use brocolis_proto::jeton_v4::{HEADER_LEN, HEADER_LEN_CT};
use brocolis_proto::{Content, Device, Erreur, ReplayGuard, Session4, Token4};

fn text(c: Content) -> String {
    match c {
        Content::Text(t) => t,
        Content::Distribution(_) => panic!("distribution"),
    }
}

/// Alice et Bob, session établie et confirmée (un aller-retour).
fn duo(seed: &[u8]) -> (Session4, Session4, Device, Deterministic) {
    let mut rng = Deterministic::new(seed);
    let alice = Device::generate(&mut rng, 0, true);
    let mut bob = Device::generate(&mut rng, 0, true);
    let mut a = alice.initiate4(&bob.bundle().unwrap(), &mut rng).unwrap();
    let t = a.encrypt_token("bonjour").unwrap();
    let (mut b, _) = bob.accept4(&t, 0, &mut rng).unwrap();
    let r = b.encrypt_token("re").unwrap();
    a.decrypt(&r, 0, &mut rng).unwrap();
    (a, b, bob, rng)
}

#[test]
fn entrees_aleatoires() {
    let (a, b, bob, mut rng) = duo(b"aleatoire4");
    for i in 0..3_000u32 {
        let n = (rng.next_u32() % 3_000) as usize;
        let mut data = vec![0u8; n];
        rng.fill_bytes(&mut data);
        if !data.is_empty() {
            data[0] = 1 + (i % 2) as u8;
        }
        // Une longueur d'en-tête plausible pour atteindre le déchiffrement.
        if data.len() > 15 && i % 3 == 0 {
            let len = if i % 2 == 0 {
                HEADER_LEN + 16
            } else {
                HEADER_LEN_CT + 16
            };
            data[13..15].copy_from_slice(&(len as u16).to_be_bytes());
        }
        let _ = Token4::decode(&String::from_utf8_lossy(&data));
        let _ = Session4::from_json(&String::from_utf8_lossy(&data));
        let Ok(t) = Token4::from_bytes(&data) else {
            continue;
        };
        for s in [&a, &b] {
            let mut s = s.clone();
            let before = s.to_json();
            assert!(s.decrypt(&t, 0, &mut rng).is_err());
            assert_eq!(*s.to_json(), *before);
        }
        let _ = bob.clone().accept4(&t, 0, &mut rng);
        let _ = Session4::accept_psk(&[[1; 32]], &t, &mut ReplayGuard::default(), 0, &mut rng);
    }
}

#[test]
fn chaque_octet_altere_est_refuse() {
    let (mut a, b, _, mut rng) = duo(b"alteration4");
    // Un message avec encapsulation (nouvelle chaîne d'Alice).
    let t = a.encrypt_token("secret").unwrap().to_bytes();
    let step = 7; // tout l'en-tête et le chiffré, sans 4 000 essais ML-KEM
    for i in (0..t.len()).step_by(step) {
        let mut m = t.clone();
        m[i] ^= 0x01;
        let Ok(tok) = Token4::from_bytes(&m) else {
            continue;
        };
        let mut s = b.clone();
        let before = s.to_json();
        let r = s.decrypt(&tok, 0, &mut rng);
        assert!(r.is_err(), "octet {i} altéré accepté");
        assert_eq!(*s.to_json(), *before, "octet {i} : état modifié");
    }
    let mut s = b.clone();
    assert_eq!(
        text(
            s.decrypt(&Token4::from_bytes(&t).unwrap(), 0, &mut rng)
                .unwrap()
        ),
        "secret"
    );
}

#[test]
fn premier_message_altere_ou_rejoue() {
    let mut rng = Deterministic::new(b"premier4");
    let alice = Device::generate(&mut rng, 0, true);
    let bob = Device::generate(&mut rng, 0, true);
    let mut a = alice.initiate4(&bob.bundle().unwrap(), &mut rng).unwrap();
    let t = a.encrypt_token("x").unwrap().to_bytes();
    // EK, CT, préambule, en-tête, chiffré : un octet de chaque.
    for i in [1, 40, 1_200, 1_170, 1_190, 1_250, t.len() - 1] {
        let mut m = t.clone();
        m[i] ^= 0x01;
        let Ok(tok) = Token4::from_bytes(&m) else {
            continue;
        };
        let mut b = bob.clone();
        assert!(b.accept4(&tok, 0, &mut rng).is_err(), "octet {i}");
    }
    // Un appareil tiers : aucune clé n'ouvre le préambule.
    let mut carole = Device::generate(&mut rng, 0, true);
    assert_eq!(
        carole
            .accept4(&Token4::from_bytes(&t).unwrap(), 0, &mut rng)
            .err(),
        Some(Erreur::CleInconnue)
    );
}

#[test]
fn trop_de_sauts() {
    let (mut a, mut b, _, mut rng) = duo(b"sauts4");
    let mut last = None;
    for i in 0..1_002 {
        last = Some(a.encrypt_token(&format!("{i}")).unwrap());
    }
    assert_eq!(
        b.decrypt(&last.unwrap(), 0, &mut rng),
        Err(Erreur::TropDeClesSautees)
    );
}

#[test]
fn longue_conversation_dans_le_desordre() {
    let (mut a, mut b, _, mut rng) = duo(b"desordre4");
    for round in 0..12u32 {
        let (from, to) = if round % 2 == 0 {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        let n = 1 + (rng.next_u32() % 5);
        let mut batch: Vec<(String, Token4)> = (0..n)
            .map(|i| {
                let t = format!("r{round}m{i}");
                let tok = from.encrypt_token(&t).unwrap();
                (t, tok)
            })
            .collect();
        // Mélange (Fisher-Yates déterministe).
        for i in (1..batch.len()).rev() {
            let j = (rng.next_u32() as usize) % (i + 1);
            batch.swap(i, j);
        }
        for (t, tok) in &batch {
            assert_eq!(text(to.decrypt(tok, 0, &mut rng).unwrap()), *t);
            assert_eq!(to.decrypt(tok, 0, &mut rng), Err(Erreur::Rejoue));
        }
        assert_eq!(to.skipped_len(), 0);
    }
}

#[test]
fn un_retardataire_d_une_chaine_passee() {
    let (mut a, mut b, _, mut rng) = duo(b"retard4");
    let x1 = a.encrypt_token("x1").unwrap();
    let x2 = a.encrypt_token("x2").unwrap();
    assert_eq!(text(b.decrypt(&x2, 0, &mut rng).unwrap()), "x2");
    let y = b.encrypt_token("y").unwrap();
    assert_eq!(text(a.decrypt(&y, 0, &mut rng).unwrap()), "y");
    // Nouvelle chaîne d'Alice (encapsulation vers la clé ML-KEM de Bob).
    let x3 = a.encrypt_token("x3").unwrap();
    assert_eq!(text(b.decrypt(&x3, 0, &mut rng).unwrap()), "x3");
    // x1, de la chaîne d'avant, arrive enfin.
    assert_eq!(text(b.decrypt(&x1, 0, &mut rng).unwrap()), "x1");
    assert_eq!(b.decrypt(&x1, 0, &mut rng), Err(Erreur::Rejoue));
    assert_eq!(b.skipped_len(), 0);
}
