//! Les messages de groupe (type 0x04) reçus par une chaîne connue.
#![no_main]

use brocolis_proto::groupe::SenderKeyState;
use brocolis_proto::hasard::Deterministic;
use brocolis_proto::{ReceivedSenderKey, Token};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut rng = Deterministic::new(b"fuzz-groupe");
    let chain = SenderKeyState::generate([1; 16], &mut rng);
    let mut recv = ReceivedSenderKey::from_distribution(&chain.distribution()).unwrap();
    let mut forced = data.to_vec();
    if forced.len() > 25 {
        forced[0] = 0x04;
        forced[1..17].copy_from_slice(&[1; 16]);
        forced[17..25].copy_from_slice(&chain.sender_id());
    }
    for bytes in [data, &forced[..]] {
        if let Ok(Token::Group(g)) = Token::from_bytes(bytes) {
            // Sans la clé de signature, rien ne passe.
            assert!(recv.decrypt(&g, 0).is_err());
        }
    }
});
