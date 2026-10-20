//! Tests de propriétés du protocole v3 : aller-retour, désordre, pertes,
//! rejeu, sessions croisées, altérations d'un bit, MAX_SKIP, persistance.
//! Les scénarios sont tirés par un générateur déterministe (graines fixes) :
//! un échec se rejoue à l'identique.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use brocolis_proto::groupe::{SenderKeyState, new_group_id};
use brocolis_proto::hasard::{Deterministic, Rng};
use brocolis_proto::paquet::{PREKEY_GRACE, PREKEY_ROTATION};
use brocolis_proto::{
    Content, Device, Erreur, MAX_SKIP, MAX_SKIP_AGE, ReceivedSenderKey, ReplayGuard, Session, Token,
};

const T0: u64 = 1_790_000_000;

fn text(c: Content) -> String {
    match c {
        Content::Text(t) => t,
        Content::Distribution(_) => panic!("distribution inattendue"),
    }
}

/// Une session établie et confirmée (B a répondu), en mode `pq`.
fn established(seed: &[u8], pq: bool) -> (Session, Session, Deterministic) {
    let mut rng = Deterministic::new(seed);
    let alice = Device::generate(&mut rng, T0, pq);
    let mut bob = Device::generate(&mut rng, T0, pq);
    let mut a = alice
        .initiate(&bob.bundle().unwrap(), pq, &mut rng)
        .unwrap();
    let Token::Initial(i) = a.encrypt_token("bonjour").unwrap() else {
        panic!()
    };
    let (mut b, c) = bob.accept(&i, T0, &mut rng).unwrap();
    assert_eq!(text(c), "bonjour");
    let r = b.encrypt_token("re").unwrap();
    assert_eq!(text(a.decrypt(&r, T0, &mut rng).unwrap()), "re");
    (a, b, rng)
}

fn below(rng: &mut Deterministic, n: usize) -> usize {
    (rng.next_u32() as usize) % n
}

/// Un échange au hasard : envois des deux côtés, livraisons dans le
/// désordre, pertes, rejeux et sauvegardes JSON. Chaque message livré est lu
/// une fois, exactement ; un rejeu ne l'est jamais.
#[test]
fn echanges_aleatoires() {
    for seed in 0..24u32 {
        let pq = seed % 2 == 0;
        let (mut a, mut b, mut rng) = established(&seed.to_be_bytes(), pq);
        // (de A ?, jeton, texte, déjà livré)
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
                    assert_eq!(
                        text(r.decrypt(&token, now, &mut rng).unwrap()),
                        msg,
                        "graine {seed}"
                    );
                    delivered.push((from_a, token));
                }
                8 if !in_flight.is_empty() => {
                    // Perdu.
                    let k = below(&mut rng, in_flight.len());
                    in_flight.remove(k);
                }
                9 if !delivered.is_empty() => {
                    let k = below(&mut rng, delivered.len());
                    let (from_a, token) = &delivered[k];
                    let r = if *from_a { &mut b } else { &mut a };
                    let before = r.to_json();
                    assert_eq!(r.decrypt(token, now, &mut rng), Err(Erreur::Rejoue));
                    assert_eq!(r.to_json(), before);
                }
                _ => {
                    a = Session::from_json(&a.to_json()).unwrap();
                    b = Session::from_json(&b.to_json()).unwrap();
                }
            }
            assert!(a.skipped_len() <= MAX_SKIP as usize && b.skipped_len() <= MAX_SKIP as usize);
        }
        // Tout ce qui reste en vol arrive encore.
        while let Some((from_a, token, msg)) = in_flight.pop() {
            let r = if from_a { &mut b } else { &mut a };
            assert_eq!(text(r.decrypt(&token, now, &mut rng).unwrap()), msg);
        }
    }
}

/// Un bit modifié n'importe où dans un jeton : refusé, et la session est
/// exactement celle d'avant.
#[test]
fn alterations_d_un_bit() {
    let (mut a, mut b, mut rng) = established(b"bits", true);
    let token = a.encrypt_token("un message à ne pas modifier").unwrap();
    let bytes = token.to_bytes();
    let before = b.to_json();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut x = bytes.clone();
            x[i] ^= 1 << bit;
            if let Ok(t) = Token::from_bytes(&x) {
                assert!(b.decrypt(&t, T0, &mut rng).is_err(), "octet {i} bit {bit}");
            }
            assert_eq!(b.to_json(), before);
        }
    }
    assert_eq!(
        text(b.decrypt(&token, T0, &mut rng).unwrap()),
        "un message à ne pas modifier"
    );
}

/// Un bit modifié dans un premier message (préambule, CT ML-KEM compris) :
/// aucune session n'est ouverte, et l'appareil ne retient rien.
#[test]
fn alterations_du_premier_message() {
    let mut rng = Deterministic::new(b"premier");
    let alice = Device::generate(&mut rng, T0, true);
    let mut bob = Device::generate(&mut rng, T0, true);
    let mut a = alice
        .initiate(&bob.bundle().unwrap(), true, &mut rng)
        .unwrap();
    let token = a.encrypt_token("établir").unwrap();
    let bytes = token.to_bytes();
    let before = bob.to_json();
    // Un octet sur trois, tous les bits : couvre chaque champ.
    for i in (0..bytes.len()).step_by(3) {
        for bit in 0..8 {
            let mut x = bytes.clone();
            x[i] ^= 1 << bit;
            if let Ok(Token::Initial(m)) = Token::from_bytes(&x) {
                assert!(bob.accept(&m, T0, &mut rng).is_err(), "octet {i} bit {bit}");
            }
        }
    }
    assert_eq!(bob.to_json(), before);
    let Token::Initial(m) = token else { panic!() };
    assert_eq!(text(bob.accept(&m, T0, &mut rng).unwrap().1), "établir");
}

#[test]
fn max_skip_et_age_des_cles_sautees() {
    let (mut a, mut b, mut rng) = established(b"skip", false);
    let tokens: Vec<Token> = (0..=MAX_SKIP + 1)
        .map(|i| a.encrypt_token(&i.to_string()).unwrap())
        .collect();
    // Le message n = MAX_SKIP + 1 demanderait 1 001 clés sautées : refusé.
    let before = b.to_json();
    assert_eq!(
        b.decrypt(&tokens[MAX_SKIP as usize + 1], T0, &mut rng),
        Err(Erreur::TropDeClesSautees)
    );
    assert_eq!(b.to_json(), before);
    // n = MAX_SKIP passe : 1 000 clés gardées.
    assert_eq!(
        text(b.decrypt(&tokens[MAX_SKIP as usize], T0, &mut rng).unwrap()),
        "1000"
    );
    assert_eq!(b.skipped_len(), MAX_SKIP as usize);
    assert_eq!(
        text(
            b.decrypt(&tokens[MAX_SKIP as usize + 1], T0, &mut rng)
                .unwrap()
        ),
        "1001"
    );
    // Un retardataire, encore dans les 30 jours.
    assert_eq!(
        text(
            b.decrypt(&tokens[5], T0 + MAX_SKIP_AGE - 1, &mut rng)
                .unwrap()
        ),
        "5"
    );
    assert_eq!(b.decrypt(&tokens[5], T0, &mut rng), Err(Erreur::Rejoue));
    // Après 30 jours, les clés sautées sont effacées : le message est perdu.
    assert!(b.decrypt(&tokens[6], T0 + MAX_SKIP_AGE, &mut rng).is_err());
    b.purge(T0 + MAX_SKIP_AGE);
    assert_eq!(b.skipped_len(), 0);
}

#[test]
fn le_plafond_de_cles_sautees_efface_les_plus_vieilles() {
    let (mut a, mut b, mut rng) = established(b"plafond", false);
    let first: Vec<Token> = (0..600)
        .map(|i| a.encrypt_token(&i.to_string()).unwrap())
        .collect();
    let second: Vec<Token> = (600..1200)
        .map(|i| a.encrypt_token(&i.to_string()).unwrap())
        .collect();
    b.decrypt(&first[599], T0, &mut rng).unwrap();
    b.decrypt(&second[599], T0, &mut rng).unwrap();
    assert_eq!(b.skipped_len(), MAX_SKIP as usize);
    // Les plus vieilles (0..198) sont parties ; 198 et suivantes restent.
    assert!(b.decrypt(&first[0], T0, &mut rng).is_err());
    assert_eq!(text(b.decrypt(&first[198], T0, &mut rng).unwrap()), "198");
}

#[test]
fn sessions_croisees() {
    let (mut a1, mut b1, mut rng) = established(b"croise-1", true);
    let (mut a2, mut b2, _) = established(b"croise-2", true);
    let t1 = a1.encrypt_token("pour b1").unwrap();
    let t2 = a2.encrypt_token("pour b2").unwrap();
    let before = b2.to_json();
    assert_eq!(b2.decrypt(&t1, T0, &mut rng), Err(Erreur::SessionInconnue));
    assert_eq!(b2.to_json(), before);
    // Même identifiant forcé : la clé ne correspond pas.
    let Token::Message(mut e) = t1.clone() else {
        panic!()
    };
    e.session_id = b2.session_id();
    assert!(b2.decrypt(&Token::Message(e), T0, &mut rng).is_err());
    assert_eq!(b2.to_json(), before);
    assert_eq!(text(b1.decrypt(&t1, T0, &mut rng).unwrap()), "pour b1");
    assert_eq!(text(b2.decrypt(&t2, T0, &mut rng).unwrap()), "pour b2");
    // Ses propres messages renvoyés : ignorés.
    let own = a1.encrypt_token("à moi").unwrap();
    assert_eq!(a1.decrypt(&own, T0, &mut rng), Err(Erreur::Rejoue));
}

#[test]
fn nouvelle_session_meme_identifiant() {
    let mut rng = Deterministic::new(b"nouvelle");
    let alice = Device::generate(&mut rng, T0, true);
    let mut bob = Device::generate(&mut rng, T0, true);
    let bundle = bob.bundle().unwrap();
    let mut a1 = alice.initiate(&bundle, true, &mut rng).unwrap();
    let Token::Initial(i1) = a1.encrypt_token("un").unwrap() else {
        panic!()
    };
    let (mut b1, _) = bob.accept(&i1, T0, &mut rng).unwrap();
    // Alice a perdu sa session et en ouvre une autre : même AD, même id.
    let mut a2 = alice.initiate(&bundle, true, &mut rng).unwrap();
    let t = a2.encrypt_token("deux").unwrap();
    assert_eq!(t.session_id(), Some(b1.session_id()));
    assert_eq!(b1.decrypt(&t, T0, &mut rng), Err(Erreur::NouvelleSession));
    let Token::Initial(i2) = t else { panic!() };
    let (mut b2, c) = bob.accept(&i2, T0, &mut rng).unwrap();
    assert_eq!(text(c), "deux");
    let r = b2.encrypt_token("ok").unwrap();
    assert_eq!(text(a2.decrypt(&r, T0, &mut rng).unwrap()), "ok");
}

#[test]
fn sans_pq_et_paquet_sans_mlkem() {
    let mut rng = Deterministic::new(b"sans-pq");
    let alice = Device::generate(&mut rng, T0, true);
    let mut bob = Device::generate(&mut rng, T0, false);
    let bundle = bob.bundle().unwrap();
    assert_eq!(
        alice.initiate(&bundle, true, &mut rng).err(),
        Some(Erreur::PqIndisponible)
    );
    let mut a = alice.initiate(&bundle, false, &mut rng).unwrap();
    assert!(!a.is_post_quantum());
    let Token::Initial(i) = a.encrypt_token("classique").unwrap() else {
        panic!()
    };
    let (b, _) = bob.accept(&i, T0, &mut rng).unwrap();
    assert!(!b.is_post_quantum());
    assert_eq!(b.peer_identity(), Some(alice.identity().dh));
}

#[test]
fn ancienne_spk_gardee_un_mois() {
    let mut rng = Deterministic::new(b"spk");
    let alice = Device::generate(&mut rng, T0, true);
    let mut bob = Device::generate(&mut rng, T0, true);
    let old = bob.bundle().unwrap();
    let mut a = alice.initiate(&old, true, &mut rng).unwrap();
    let late = a.encrypt_token("en retard").unwrap();
    bob.rotate(&mut rng, T0 + PREKEY_ROTATION);
    assert_ne!(bob.bundle().unwrap().spk_id, old.spk_id);
    let Token::Initial(i) = late else { panic!() };
    // Encore acceptée pendant le mois de grâce…
    let mut copy = Device::from_json(&bob.to_json()).unwrap();
    assert!(copy.accept(&i, T0 + PREKEY_ROTATION + 1, &mut rng).is_ok());
    // … puis effacée.
    bob.purge(T0 + PREKEY_ROTATION + PREKEY_GRACE);
    assert_eq!(
        bob.accept(&i, T0, &mut rng).err(),
        Some(Erreur::CleInconnue)
    );
}

#[test]
fn psk_aller_retour_et_confidentialite_apres_reponse() {
    let mut rng = Deterministic::new(b"psk");
    let key = [9u8; 32];
    let mut a = Session::initiate_psk(&key, &mut rng).unwrap();
    let mut guard = ReplayGuard::default();
    let t1 = a.encrypt_token("un").unwrap();
    let t2 = a.encrypt_token("deux").unwrap();
    let Token::Initial(i2) = &t2 else { panic!() };
    let (mut b, c) = Session::accept_psk(&[key], i2, &mut guard, T0, &mut rng).unwrap();
    assert_eq!(text(c), "deux");
    assert_eq!(text(b.decrypt(&t1, T0, &mut rng).unwrap()), "un");
    let r = b.encrypt_token("trois").unwrap();
    assert_eq!(text(a.decrypt(&r, T0, &mut rng).unwrap()), "trois");
    assert!(a.is_confirmed());
    // Après la réponse, quelqu'un qui n'a que la clé partagée (et a tout
    // vu passer) ne lit plus rien : le message suivant ne s'ouvre pas avec
    // une session refaite à partir de la clé.
    let next = a.encrypt_token("quatre").unwrap();
    let Token::Initial(i1) = &t1 else { panic!() };
    let mut g2 = ReplayGuard::default();
    let (mut spy, _) =
        Session::accept_psk(&[key], i1, &mut g2, T0, &mut Deterministic::new(b"espion")).unwrap();
    assert!(spy.decrypt(&next, T0, &mut rng).is_err());
    assert_eq!(text(b.decrypt(&next, T0, &mut rng).unwrap()), "quatre");
}

#[test]
fn groupe_par_sessions_a_deux() {
    let (mut a, mut b, mut rng) = established(b"groupe", true);
    let gid = new_group_id(&mut rng);
    let mut chain = SenderKeyState::generate(gid, &mut rng);
    // Distribution par la session à deux (type 0x03).
    let dist = a.encrypt_distribution(&chain.distribution()).unwrap();
    assert!(Token::decode(&dist).is_ok_and(|t| matches!(t, Token::Distribution(_))));
    let Content::Distribution(d) = b.decrypt_text(&dist, T0, &mut rng).unwrap() else {
        panic!()
    };
    let mut recv = ReceivedSenderKey::from_distribution(&d).unwrap();
    // Un 0x03 relu comme 0x02 (ou l'inverse) est refusé : le type est
    // authentifié.
    let tok = a.encrypt_token("texte").unwrap();
    let Token::Message(e) = tok else { panic!() };
    let before = b.to_json();
    assert!(
        b.decrypt(&Token::Distribution(e.clone()), T0, &mut rng)
            .is_err()
    );
    assert_eq!(b.to_json(), before);
    assert_eq!(
        text(b.decrypt(&Token::Message(e), T0, &mut rng).unwrap()),
        "texte"
    );
    let msgs: Vec<String> = (0..50)
        .map(|i| chain.encrypt(&format!("g{i}")).unwrap())
        .collect();
    let mut order: Vec<usize> = (0..50).collect();
    for i in (1..order.len()).rev() {
        order.swap(i, below(&mut rng, i + 1));
    }
    for (k, &i) in order.iter().enumerate() {
        if k % 7 == 3 {
            continue; // perdu
        }
        let Token::Group(g) = Token::decode(&msgs[i]).unwrap() else {
            panic!()
        };
        assert_eq!(recv.decrypt(&g, T0).unwrap(), format!("g{i}"));
        assert_eq!(recv.decrypt(&g, T0), Err(Erreur::Rejoue));
    }
    // Un membre qui n'a que l'ancienne chaîne ne lit pas la nouvelle.
    let mut renewed = SenderKeyState::generate(gid, &mut rng);
    let Token::Group(g) = renewed.encrypt_token("après départ").unwrap() else {
        panic!()
    };
    assert_eq!(recv.decrypt(&g, T0), Err(Erreur::ExpediteurInconnu));
}

#[test]
fn groupe_alterations_et_saut() {
    let mut rng = Deterministic::new(b"groupe-bits");
    let mut chain = SenderKeyState::generate([3; 16], &mut rng);
    let mut recv = ReceivedSenderKey::from_distribution(&chain.distribution()).unwrap();
    let t = chain.encrypt_token("signé").unwrap();
    let bytes = t.to_bytes();
    for i in 0..bytes.len() {
        let mut x = bytes.clone();
        x[i] ^= 0x40;
        if let Ok(Token::Group(g)) = Token::from_bytes(&x) {
            assert!(recv.decrypt(&g, T0).is_err(), "octet {i}");
        }
    }
    let Token::Group(g) = t else { panic!() };
    assert_eq!(recv.decrypt(&g, T0).unwrap(), "signé");
    for _ in 0..=MAX_SKIP {
        chain.encrypt_token("x").unwrap();
    }
    let Token::Group(far) = chain.encrypt_token("trop loin").unwrap() else {
        panic!()
    };
    assert_eq!(recv.decrypt(&far, T0), Err(Erreur::TropDeClesSautees));
}

#[test]
fn texte_trop_long_refuse() {
    let (mut a, _, _) = established(b"long", false);
    let long = "x".repeat(brocolis_proto::session::MAX_PLAINTEXT + 1);
    assert_eq!(a.encrypt(&long).err(), Some(Erreur::TropGrand));
    let max = "x".repeat(brocolis_proto::session::MAX_PLAINTEXT);
    let t = a.encrypt(&max).unwrap();
    assert!(Token::decode(&t).is_ok());
    // Le jeton reste du base64 standard strict.
    let inner = t
        .trim_start_matches("[[BROCOLIS:v3:")
        .trim_end_matches("]]");
    assert!(STANDARD.decode(inner).is_ok());
}
