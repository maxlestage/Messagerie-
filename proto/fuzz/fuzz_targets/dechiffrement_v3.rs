//! Le déchiffrement v3 : une session établie (graines fixes) reçoit des
//! jetons arbitraires. Rien ne doit paniquer, et un échec laisse la session
//! inchangée.
#![no_main]

use std::sync::OnceLock;

use brocolis_proto::hasard::Deterministic;
use brocolis_proto::{Device, ReplayGuard, Session, Token};
use libfuzzer_sys::fuzz_target;

struct Etat {
    bob: Device,
    a: Session,
    b: Session,
}

fn etat() -> &'static Etat {
    static E: OnceLock<Etat> = OnceLock::new();
    E.get_or_init(|| {
        let mut rng = Deterministic::new(b"fuzz");
        let alice = Device::generate(&mut rng, 0, true);
        let mut bob = Device::generate(&mut rng, 0, true);
        let mut a = alice.initiate(&bob.bundle().unwrap(), true, &mut rng).unwrap();
        let Token::Initial(i) = a.encrypt_token("x").unwrap() else { unreachable!() };
        let (b, _) = bob.accept(&i, 0, &mut rng).unwrap();
        Etat { bob, a, b }
    })
}

fuzz_target!(|data: &[u8]| {
    let e = etat();
    let mut rng = Deterministic::new(data);
    // Les octets bruts, et les mêmes avec l'identifiant de la session pour
    // atteindre le cliquet.
    let mut forced = data.to_vec();
    if forced.len() > 9 && (2..=3).contains(&forced[0]) {
        forced[1..9].copy_from_slice(&e.b.session_id());
    }
    for bytes in [data, &forced[..]] {
        let Ok(t) = Token::from_bytes(bytes) else { continue };
        for s in [&e.a, &e.b] {
            let mut s = s.clone();
            let before = s.to_json();
            if s.decrypt(&t, 0, &mut rng).is_err() {
                assert_eq!(s.to_json(), before);
            }
        }
        if let Token::Initial(i) = &t {
            let mut bob = e.bob.clone();
            let _ = bob.accept(i, 0, &mut rng);
            let _ = Session::accept_psk(&[[1u8; 32]], i, &mut ReplayGuard::default(), 0, &mut rng);
        }
    }
});
