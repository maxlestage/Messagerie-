//! Tous les lecteurs de jetons et de formats binaires : aucune entrée ne
//! doit faire paniquer ni boucler.
#![no_main]

use brocolis_proto::groupe::SenderKeyDistribution;
use brocolis_proto::{KeyBundle, Token, cle_protegee, jeton_v3, jetons, remplissage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = Token::from_bytes(data) {
        // Un jeton décodé se réencode à l'identique (encodage strict).
        assert_eq!(t.to_bytes(), data);
        assert_eq!(Token::decode(&t.encode()).as_ref(), Ok(&t));
    }
    let _ = KeyBundle::from_bytes(data);
    let _ = SenderKeyDistribution::from_bytes(data);
    let _ = remplissage::unpad(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = Token::decode(text);
        let _ = jeton_v3::find_all(text);
        let _ = jetons::open(text, &[[7u8; 32]]);
        let _ = jetons::masked(text);
        let _ = jetons::find_key(text);
        let _ = cle_protegee::v2_params(text);
        let _ = brocolis_proto::Session::from_json(text);
        let _ = brocolis_proto::Device::from_json(text);
    }
});
