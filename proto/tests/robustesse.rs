//! Fuzzing « du pauvre », toujours exécuté par `cargo test` (les cibles
//! `cargo fuzz` sont dans `proto/fuzz`) : des milliers d'entrées aléatoires
//! et de mutations de jetons valides passent par chaque décodeur et par le
//! déchiffrement v3. Aucune ne doit faire paniquer ni boucler, et aucune
//! entrée mutée ne doit être acceptée par le déchiffrement.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use brocolis_proto::groupe::{SenderKeyDistribution, SenderKeyState};
use brocolis_proto::hasard::{Deterministic, Rng};
use brocolis_proto::{
    Device, KeyBundle, ReceivedSenderKey, ReplayGuard, Session, Token, cle_protegee, jetons,
    remplissage,
};

const T0: u64 = 1_790_000_000;

fn random_bytes(rng: &mut Deterministic, max: usize) -> Vec<u8> {
    let n = (rng.next_u32() as usize) % (max + 1);
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

/// Une mutation : bits, octets, coupe, insertion, duplication.
fn mutate(rng: &mut Deterministic, data: &[u8]) -> Vec<u8> {
    let mut v = data.to_vec();
    for _ in 0..1 + rng.next_u32() % 4 {
        let len = v.len().max(1);
        let i = (rng.next_u32() as usize) % len;
        match rng.next_u32() % 6 {
            0 if !v.is_empty() => v[i] ^= 1 << (rng.next_u32() % 8),
            1 if !v.is_empty() => v[i] = rng.next_u32() as u8,
            2 => v.truncate(i),
            3 => v.insert(i.min(v.len()), rng.next_u32() as u8),
            4 if !v.is_empty() => {
                let j = (rng.next_u32() as usize) % v.len();
                let (a, b) = (i.min(j), i.max(j));
                let chunk = v[a..b].to_vec();
                v.splice(a..a, chunk);
            }
            _ => v.extend(random_bytes(rng, 8)),
        }
    }
    v
}

#[test]
fn decodeurs_entrees_aleatoires() {
    let mut rng = Deterministic::new(b"aleatoire");
    for i in 0..20_000 {
        let data = random_bytes(&mut rng, 2_000);
        // Forcer de temps en temps un type valide en tête.
        let mut data = data;
        if !data.is_empty() && i % 2 == 0 {
            data[0] = 1 + (i % 4) as u8;
        }
        let _ = Token::from_bytes(&data);
        let _ = KeyBundle::from_bytes(&data);
        let _ = SenderKeyDistribution::from_bytes(&data);
        let _ = remplissage::unpad(&data);
        let text = String::from_utf8_lossy(&data);
        let _ = Token::decode(&text);
        let _ = jetons::open(&text, &[[1u8; 32]]);
        let _ = jetons::masked(&text);
        let _ = jetons::find_key(&text);
        let _ = cle_protegee::v2_params(&text);
        let b64 = STANDARD.encode(&data);
        let _ = Token::decode(&format!("[[BROCOLIS:v3:{b64}]]"));
        let _ = jetons::open(
            &format!("[[BROCOLIS:v1:{b64}]] [[BROCOLIS:v2:{b64}]]"),
            &[[1u8; 32]],
        );
        let _ = cle_protegee::v2_params(&format!("[[BROCOLIS-CLE:v2:{b64}]]"));
        let _ = Session::from_json(&text);
        let _ = Device::from_json(&text);
    }
}

#[test]
fn mutations_de_jetons_v3() {
    let mut rng = Deterministic::new(b"mutations");
    let alice = Device::generate(&mut rng, T0, true);
    let mut bob = Device::generate(&mut rng, T0, true);
    let mut a = alice
        .initiate(&bob.bundle().unwrap(), true, &mut rng)
        .unwrap();
    let first = a.encrypt_token("premier").unwrap();
    let Token::Initial(i) = &first else { panic!() };
    let (mut b, _) = bob.accept(i, T0, &mut rng).unwrap();
    let reply = b.encrypt_token("réponse").unwrap();
    let mut chain = SenderKeyState::generate([5; 16], &mut rng);
    let mut recv = ReceivedSenderKey::from_distribution(&chain.distribution()).unwrap();
    let group = chain.encrypt_token("groupe").unwrap();
    let dist = b.encrypt_distribution(&chain.distribution()).unwrap();
    let dist = Token::decode(&dist).unwrap();
    let samples = [
        first.to_bytes(),
        reply.to_bytes(),
        group.to_bytes(),
        dist.to_bytes(),
    ];
    let bob_before = bob.to_json();
    let a_before = a.to_json();
    let mut decoded = 0;
    for k in 0..6_000 {
        let base = &samples[k % samples.len()];
        let m = mutate(&mut rng, base);
        if &m == base {
            continue;
        }
        let Ok(t) = Token::from_bytes(&m) else {
            continue;
        };
        decoded += 1;
        // Le jeton muté peut rester bien formé : il ne doit jamais être lu.
        if t.to_bytes() == *base {
            continue;
        }
        match &t {
            Token::Initial(i) => {
                assert!(bob.accept(i, T0, &mut rng).is_err());
                let mut g = ReplayGuard::default();
                assert!(Session::accept_psk(&[[1u8; 32]], i, &mut g, T0, &mut rng).is_err());
                assert!(b.decrypt(&t, T0, &mut rng).is_err());
            }
            Token::Message(_) | Token::Distribution(_) => {
                assert!(a.decrypt(&t, T0, &mut rng).is_err());
            }
            Token::Group(g) => assert!(recv.decrypt(g, T0).is_err()),
        }
    }
    assert!(decoded > 100, "{decoded}");
    assert_eq!(bob.to_json(), bob_before);
    assert_eq!(a.to_json(), a_before);
    // Les originaux passent toujours.
    assert!(a.decrypt(&reply, T0, &mut rng).is_ok());
    let Token::Group(g) = &group else { panic!() };
    assert!(recv.decrypt(g, T0).is_ok());
}

#[test]
fn mutations_d_etats_json() {
    let mut rng = Deterministic::new(b"json");
    let alice = Device::generate(&mut rng, T0, false);
    let mut bob = Device::generate(&mut rng, T0, false);
    let mut a = alice
        .initiate(&bob.bundle().unwrap(), false, &mut rng)
        .unwrap();
    let Token::Initial(i) = a.encrypt_token("x").unwrap() else {
        panic!()
    };
    let (b, _) = bob.accept(&i, T0, &mut rng).unwrap();
    let texts = [b.to_json().to_string(), bob.to_json().to_string()];
    for k in 0..3_000 {
        let base = texts[k % 2].as_bytes();
        let m = mutate(&mut rng, base);
        let text = String::from_utf8_lossy(&m);
        if let Ok(mut s) = Session::from_json(&text) {
            // Un état relu, même altéré, ne fait jamais paniquer.
            let _ = s.encrypt("y");
            let _ = s.decrypt_text("[[BROCOLIS:v3:AAAA]]", T0, &mut rng);
        }
        if let Ok(d) = Device::from_json(&text) {
            let _ = d.bundle();
        }
    }
}

#[test]
fn mutations_de_cles_protegees_et_jetons_v1_v2() {
    let mut rng = Deterministic::new(b"anciens");
    let key = [3u8; 32];
    let v1 = jetons::seal_with("ancien", &[key], &mut rng);
    let v2 = jetons::seal_with("ancien", &[key, [4u8; 32]], &mut rng);
    for k in 0..4_000 {
        let base = if k % 2 == 0 { &v1 } else { &v2 };
        let m = mutate(&mut rng, base.as_bytes());
        let text = String::from_utf8_lossy(&m);
        let o = jetons::open(&text, &[key]);
        // Une altération qui garde l'enveloppe ne s'ouvre jamais en un autre
        // texte.
        if o.opened > 0 {
            assert!(o.text.contains("ancien"));
        }
    }
    let protected = cle_protegee::protect_key_v2_with(
        &key,
        "phrase longue",
        cle_protegee::Argon2Params::MINIMUM,
        &[1; 16],
        &[2; 12],
    )
    .unwrap();
    for _ in 0..2_000 {
        let m = mutate(&mut rng, protected.as_bytes());
        let _ = cle_protegee::v2_params(&String::from_utf8_lossy(&m));
    }
}
