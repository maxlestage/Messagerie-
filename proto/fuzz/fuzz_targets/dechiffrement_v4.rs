//! Le déchiffrement v4 (§9) : une session établie (graines fixes) reçoit des
//! jetons arbitraires, avec ou sans longueur d'en-tête plausible. Rien ne
//! doit paniquer, et un échec laisse la session inchangée.
#![no_main]

use std::sync::OnceLock;

use brocolis_proto::hasard::Deterministic;
use brocolis_proto::{Device, ReplayGuard, Session4, Token4};
use libfuzzer_sys::fuzz_target;

struct Etat {
    bob: Device,
    a: Session4,
    b: Session4,
}

fn etat() -> &'static Etat {
    static E: OnceLock<Etat> = OnceLock::new();
    E.get_or_init(|| {
        let mut rng = Deterministic::new(b"fuzz4");
        let alice = Device::generate(&mut rng, 0, true);
        let mut bob = Device::generate(&mut rng, 0, true);
        let mut a = alice.initiate4(&bob.bundle().unwrap(), &mut rng).unwrap();
        let t = a.encrypt_token("x").unwrap();
        let (mut b, _) = bob.accept4(&t, 0, &mut rng).unwrap();
        let r = b.encrypt_token("y").unwrap();
        a.decrypt(&r, 0, &mut rng).unwrap();
        Etat { bob, a, b }
    })
}

fuzz_target!(|data: &[u8]| {
    let e = etat();
    let mut rng = Deterministic::new(data);
    let mut forced = data.to_vec();
    if forced.len() > 15 {
        forced[0] = 2;
        forced[13..15].copy_from_slice(&1_241u16.to_be_bytes());
    }
    for bytes in [data, &forced[..]] {
        let Ok(t) = Token4::from_bytes(bytes) else { continue };
        for s in [&e.a, &e.b] {
            let mut s = s.clone();
            let before = s.to_json();
            if s.decrypt(&t, 0, &mut rng).is_err() {
                assert_eq!(*s.to_json(), *before);
            }
        }
        let _ = e.bob.clone().accept4(&t, 0, &mut rng);
        let _ = Session4::accept_psk(&[[1u8; 32]], &t, &mut ReplayGuard::default(), 0, &mut rng);
    }
});
