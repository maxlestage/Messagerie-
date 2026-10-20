//! Écrit `proto/vectors.json` : les vecteurs de test de référence, que les
//! implémentations Swift, Kotlin et WebAssembly doivent retrouver octet pour
//! octet. Déterministe : toutes les graines sont fixes, et chaque secret
//! tiré au hasard est écrit dans le fichier.
//!
//! ```sh
//! cargo run --release --example vectors
//! ```
//!
//! Conventions : octets en hexadécimal minuscule, jetons tels quels, heures
//! en secondes Unix. `h32("étiquette")` = SHA-256 de l'étiquette UTF-8.

#![forbid(unsafe_code)]

use core::convert::Infallible;

use brocolis_proto::cle_protegee::{self, Argon2Params};
use brocolis_proto::groupe::SenderKeyState;
use brocolis_proto::hasard::Deterministic;
use brocolis_proto::jeton_v3::{TYPE_DISTRIBUTION, Token};
use brocolis_proto::kdf;
use brocolis_proto::paquet::{IdentitySecret, mlkem_encapsulate, mlkem_public};
use brocolis_proto::remplissage::pad;
use brocolis_proto::{Content, Device, Session, jetons};
use rand_core::{TryCryptoRng, TryRng};
use serde_json::{Value, json};

/// Un générateur qui note tout ce qu'il donne (pour écrire les secrets
/// tirés pendant le cliquet).
pub struct Recorder {
    inner: Deterministic,
    pub drawn: Vec<u8>,
}

impl Recorder {
    pub fn new(seed: &[u8]) -> Self {
        Recorder {
            inner: Deterministic::new(seed),
            drawn: Vec::new(),
        }
    }

    pub fn take(&mut self) -> String {
        hex(&std::mem::take(&mut self.drawn))
    }
}

impl TryRng for Recorder {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_be_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_be_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        self.inner.try_fill_bytes(dst)?;
        self.drawn.extend_from_slice(dst);
        Ok(())
    }
}

impl TryCryptoRng for Recorder {}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn h32(label: &str) -> [u8; 32] {
    kdf::sha256(label.as_bytes())
}

pub fn h64(label: &str) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h32(&format!("{label}/0")));
    out[32..].copy_from_slice(&h32(&format!("{label}/1")));
    out
}

const NOW: u64 = 1_790_000_000;

fn primitives() -> Value {
    let rk = h32("kdf_rk/rk");
    let dh = h32("kdf_rk/dh");
    let (rk2, ck) = kdf::kdf_rk(&rk, &dh);
    let (ck2, mk) = kdf::kdf_ck(&ck);
    let (key, nonce) = kdf::message_key(&mk);
    let (dh1, dh2, dh3, ss) = (h32("sk/dh1"), h32("sk/dh2"), h32("sk/dh3"), h32("sk/ss"));
    let psk = h32("psk/cle");
    let sk_psk = kdf::sk_psk(&psk);
    let r = kdf::psk_ratchet_secret(&sk_psk);
    let ad = [h32("ad/ik_a"), h32("ad/ik_b")].concat();
    json!({
        "kdf_rk": { "rk": hex(&rk), "dh": hex(&dh), "rk_out": hex(rk2.as_ref()), "ck_out": hex(ck.as_ref()) },
        "kdf_ck": { "ck": hex(ck.as_ref()), "ck_out": hex(ck2.as_ref()), "mk": hex(mk.as_ref()) },
        "message_key": { "mk": hex(mk.as_ref()), "key": hex(key.as_ref()), "nonce": hex(&nonce) },
        "sk_classic": { "dh1": hex(&dh1), "dh2": hex(&dh2), "dh3": hex(&dh3),
            "sk": hex(kdf::sk_x3dh(&dh1, &dh2, &dh3, None).as_ref()) },
        "sk_hybrid": { "dh1": hex(&dh1), "dh2": hex(&dh2), "dh3": hex(&dh3), "ss": hex(&ss),
            "sk": hex(kdf::sk_x3dh(&dh1, &dh2, &dh3, Some(&ss)).as_ref()) },
        "sk_psk": { "key": hex(&psk), "sk": hex(sk_psk.as_ref()),
            "psk_ratchet_secret": hex(r.as_ref()), "psk_ratchet_public": hex(&kdf::x25519_public(&r)) },
        "session_id": { "ad": hex(&ad), "id": hex(&kdf::session_id(&ad)) },
        "fingerprint": { "data": hex(&[7u8; 32]), "fingerprint": kdf::fingerprint(&[7u8; 32]) },
        "x25519": { "secret": hex(&h32("x25519/a")), "public": hex(&kdf::x25519_public(&h32("x25519/a"))),
            "peer_secret": hex(&h32("x25519/b")), "peer_public": hex(&kdf::x25519_public(&h32("x25519/b"))),
            "shared": hex(kdf::x25519(&h32("x25519/a"), &kdf::x25519_public(&h32("x25519/b"))).unwrap().as_ref()) },
        "mlkem768": {
            "seed": hex(&h64("mlkem/seed")),
            "encapsulation_key": hex(&mlkem_public(&h64("mlkem/seed"))),
            "m": hex(&h32("mlkem/m")),
            "ciphertext": hex(&mlkem_encapsulate(&mlkem_public(&h64("mlkem/seed")), &h32("mlkem/m")).unwrap().0),
            "shared": hex(mlkem_encapsulate(&mlkem_public(&h64("mlkem/seed")), &h32("mlkem/m")).unwrap().1.as_ref()),
        },
    })
}

fn padding() -> Value {
    let cases: Vec<Value> = [0usize, 1, 5, 158, 159, 160, 161]
        .iter()
        .map(|&n| {
            let data: Vec<u8> = (0..n).map(|i| (i % 251) as u8 + 1).collect();
            json!({ "data": hex(&data), "padded": hex(&pad(&data)) })
        })
        .collect();
    json!({ "block": 160, "cases": cases,
        "invalid": [hex(&[0u8; 160]), hex(&[0x41; 160]), hex(&[0x80; 159]), ""] })
}

fn protected_keys() -> Value {
    let key: [u8; 32] = core::array::from_fn(|i| i as u8);
    let v1 = cle_protegee::protect_key_v1_with(&key, "brocoli vert 2026", &[0x11; 16], &[0x22; 12])
        .unwrap();
    let mut v2 = Vec::new();
    for (name, p) in [
        ("minimum", Argon2Params::MINIMUM),
        ("default", Argon2Params::DEFAULT),
    ] {
        let salt = [0x33u8; 16];
        let nonce = [0x44u8; 12];
        let phrase = "brocoli vert 2026";
        let k = cle_protegee::argon2id_key(phrase, &salt, p).unwrap();
        let token = cle_protegee::protect_key_v2_with(&key, phrase, p, &salt, &nonce).unwrap();
        v2.push(
            json!({ "name": name, "m_kib": p.m_kib, "t": p.t, "p": p.p, "salt": hex(&salt),
            "nonce": hex(&nonce), "phrase": phrase, "argon2id_key": hex(k.as_ref()), "token": token,
            "wrong_phrase": "brocoli vert 2025" }),
        );
    }
    json!({
        "key": hex(&key),
        "v1": { "salt": hex(&[0x11; 16]), "nonce": hex(&[0x22; 12]), "phrase": "brocoli vert 2026",
            "token": v1, "wrong_phrase": "brocoli vert 2025" },
        "v2": v2,
        "v2_rejected_params": [
            { "m_kib": 19_455, "t": 2, "p": 1 }, { "m_kib": 19_456, "t": 1, "p": 1 },
            { "m_kib": 1_048_577, "t": 3, "p": 1 }, { "m_kib": 65_536, "t": 3, "p": 0 },
            { "m_kib": 65_536, "t": 17, "p": 1 }
        ],
    })
}

fn legacy_tokens() -> Value {
    let k1 = h32("jetons/k1");
    let k2 = h32("jetons/k2");
    let mut rng = Deterministic::new(b"jetons");
    let v1 = jetons::seal_with("Salut 🥦", &[k1], &mut rng);
    let v2 = jetons::seal_with("À tous", &[k1, k2], &mut rng);
    let marked = jetons::seal_with("Rendez-vous ((au parc)) à ((18 h)) !", &[k1], &mut rng);
    json!({
        "keys": [hex(&k1), hex(&k2)],
        "rng_seed": "jetons",
        "v1": { "text": "Salut 🥦", "token": v1 },
        "v2": { "text": "À tous", "token": v2 },
        "marked": { "input": "Rendez-vous ((au parc)) à ((18 h)) !", "sealed": marked,
            "opened": "Rendez-vous au parc à 18 h !" },
    })
}

fn device(name: &str, pq: bool) -> (Device, Value) {
    let identity = IdentitySecret {
        dh: h32(&format!("{name}/ik")),
        sign: h32(&format!("{name}/ed25519")),
    };
    let spk_id = if name == "alice" { 1 } else { 2 };
    let spk = h32(&format!("{name}/spk"));
    let pq_seed = h64(&format!("{name}/pqpk"));
    let d = Device::from_secrets(
        identity.clone(),
        (spk_id, spk),
        pq.then_some((100 + spk_id, pq_seed)),
        NOW,
    );
    let b = d.bundle().unwrap();
    let v = json!({
        "ik_x25519_secret": hex(&identity.dh),
        "ik_ed25519_seed": hex(&identity.sign),
        "ik_x25519_public": hex(&b.identity.dh),
        "ik_ed25519_public": hex(&b.identity.sign),
        "spk_id": spk_id,
        "spk_secret": hex(&spk),
        "spk_public": hex(&b.spk),
        "spk_signature": hex(&b.spk_signature),
        "pq_id": b.pq.as_ref().map(|p| p.id),
        "pq_seed": pq.then(|| hex(&pq_seed)),
        "pq_public": b.pq.as_ref().map(|p| hex(&p.key)),
        "pq_signature": b.pq.as_ref().map(|p| hex(&p.signature)),
        "bundle": hex(&b.to_bytes()),
        "fingerprint": b.identity.fingerprint(),
    });
    (d, v)
}

/// Ce que fait Bob d'un premier message : accepter la session.
type Accept = Box<dyn FnMut(&Token, &mut Recorder) -> (Session, Content)>;

/// Les clés du prochain message envoyé par `s`.
fn next_keys(s: &Session) -> Value {
    let (cks, _) = s.debug_chain_keys();
    let ck = cks.unwrap();
    let (ck2, mk) = kdf::kdf_ck(&ck);
    let (key, nonce) = kdf::message_key(&mk);
    json!({ "ck": hex(&ck), "mk": hex(mk.as_ref()), "ck_next": hex(ck2.as_ref()),
        "key": hex(key.as_ref()), "nonce": hex(&nonce) })
}

fn header(t: &Token) -> Value {
    let e = match t {
        Token::Initial(i) => &i.envelope,
        Token::Message(e) | Token::Distribution(e) => e,
        Token::Group(_) => unreachable!(),
    };
    json!({ "dh": hex(&e.header.dh), "pn": e.header.pn, "n": e.header.n,
        "header": hex(&e.header.to_bytes()), "ciphertext": hex(&e.ciphertext) })
}

fn send(s: &mut Session, from: &str, text: &str) -> (Token, Value) {
    let keys = next_keys(s);
    let t = s.encrypt_token(text).unwrap();
    let mut aad = s.associated_data().to_vec();
    if let Token::Initial(i) = &t {
        aad.extend_from_slice(&i.envelope.header.to_bytes());
    } else if let Token::Message(e) | Token::Distribution(e) = &t {
        aad.extend_from_slice(&e.header.to_bytes());
    }
    if matches!(t, Token::Distribution(_)) {
        aad.push(TYPE_DISTRIBUTION);
    }
    let v = json!({ "from": from, "text": text, "type": t.to_bytes()[0],
        "padded": hex(&pad(text.as_bytes())), "aad": hex(&aad),
        "keys": keys, "header": header(&t), "token": t.encode() });
    (t, v)
}

fn session_case(name: &str, pq: Option<bool>) -> Value {
    let mut steps = Vec::new();
    let mut rng_a = Recorder::new(format!("{name}/alice/cliquet").as_bytes());
    let mut rng_b = Recorder::new(format!("{name}/bob/cliquet").as_bytes());
    let (mut a, mut bob_side, setup): (Session, Accept, Value) = match pq {
        Some(pq) => {
            let (alice, alice_v) = device("alice", pq);
            let (mut bob, bob_v) = device("bob", pq);
            let bundle = bob.bundle().unwrap();
            let ek = h32(&format!("{name}/ek"));
            let ratchet = h32(&format!("{name}/alice/cliquet0"));
            let m = h32(&format!("{name}/mlkem_m"));
            let s = Session::initiate_with(
                alice.identity_secret(),
                &bundle,
                &ek,
                &ratchet,
                pq.then_some(&m),
            )
            .unwrap();
            let ika = alice.identity_secret();
            let dh1 = kdf::x25519(&ika.dh, &bundle.spk).unwrap();
            let dh2 = kdf::x25519(&ek, &bundle.identity.dh).unwrap();
            let dh3 = kdf::x25519(&ek, &bundle.spk).unwrap();
            let (ct, ss) = if pq {
                let (ct, ss) = mlkem_encapsulate(&bundle.pq.as_ref().unwrap().key, &m).unwrap();
                (Some(hex(&ct)), Some(*ss))
            } else {
                (None, None)
            };
            let sk = kdf::sk_x3dh(&dh1, &dh2, &dh3, ss.as_ref());
            let first_dh = kdf::x25519(&ratchet, &bundle.spk).unwrap();
            let (rk, ck) = kdf::kdf_rk(&sk, &first_dh);
            let setup = json!({
                "alice": alice_v, "bob": bob_v,
                "ek_secret": hex(&ek), "ek_public": hex(&kdf::x25519_public(&ek)),
                "alice_ratchet_secret": hex(&ratchet), "alice_ratchet_public": hex(&kdf::x25519_public(&ratchet)),
                "mlkem_m": pq.then(|| hex(&m)), "mlkem_ciphertext": ct, "mlkem_shared": ss.map(|s| hex(&s)),
                "dh1": hex(dh1.as_ref()), "dh2": hex(dh2.as_ref()), "dh3": hex(dh3.as_ref()),
                "sk": hex(sk.as_ref()), "ad": hex(s.associated_data()), "session_id": hex(&s.session_id()),
                "alice_first_dh": hex(first_dh.as_ref()), "alice_root_key": hex(rk.as_ref()),
                "alice_sending_chain": hex(ck.as_ref()),
            });
            let accept = Box::new(move |t: &Token, rng: &mut Recorder| {
                let Token::Initial(i) = t else { unreachable!() };
                bob.accept(i, NOW, rng).unwrap()
            });
            (s, accept, setup)
        }
        None => {
            let key = h32(&format!("{name}/cle"));
            let ek = h32(&format!("{name}/ek"));
            let s = Session::initiate_psk_with(&key, &ek).unwrap();
            let sk = kdf::sk_psk(&key);
            let r = kdf::psk_ratchet_secret(&sk);
            let first_dh = kdf::x25519(&ek, &kdf::x25519_public(&r)).unwrap();
            let (rk, ck) = kdf::kdf_rk(&sk, &first_dh);
            let setup = json!({
                "key": hex(&key), "key_b64": base64_std(&key),
                "ek_secret": hex(&ek), "ek_public": hex(&kdf::x25519_public(&ek)),
                "sk": hex(sk.as_ref()), "psk_ratchet_secret": hex(r.as_ref()),
                "psk_ratchet_public": hex(&kdf::x25519_public(&r)),
                "ad": hex(s.associated_data()), "session_id": hex(&s.session_id()),
                "alice_first_dh": hex(first_dh.as_ref()), "alice_root_key": hex(rk.as_ref()),
                "alice_sending_chain": hex(ck.as_ref()),
            });
            let accept = Box::new(move |t: &Token, rng: &mut Recorder| {
                let Token::Initial(i) = t else { unreachable!() };
                let mut guard = brocolis_proto::ReplayGuard::default();
                Session::accept_psk(&[key], i, &mut guard, NOW, rng).unwrap()
            });
            (s, accept, setup)
        }
    };

    // A → B : deux premiers messages (0x01), le second reçu d'abord.
    let (t1, v1) = send(&mut a, "alice", "Salut Bob 🥦");
    let (t2, v2) = send(&mut a, "alice", "Tu me lis ?");
    steps.push(v1);
    steps.push(v2);
    let (mut b, c) = bob_side(&t2, &mut rng_b);
    assert_eq!(c, Content::Text("Tu me lis ?".into()));
    let bob_drawn = rng_b.take();
    assert_eq!(
        b.decrypt(&t1, NOW, &mut rng_b).unwrap(),
        Content::Text("Salut Bob 🥦".into())
    );
    steps.push(
        json!({ "event": "bob reçoit le message 2 puis le 1 (désordre)",
        "bob_ratchet_secret_drawn": bob_drawn, "bob_ratchet_public": hex(&b.ratchet_public()),
        "bob_root_key": hex(&b.debug_root_key()) }),
    );
    // B → A (0x02) : A fait tourner le cliquet.
    let (t3, v3) = send(&mut b, "bob", "Oui, cinq sur cinq.");
    steps.push(v3);
    assert_eq!(
        a.decrypt(&t3, NOW, &mut rng_a).unwrap(),
        Content::Text("Oui, cinq sur cinq.".into())
    );
    steps.push(json!({ "event": "alice reçoit la réponse : session confirmée",
        "alice_ratchet_secret_drawn": rng_a.take(), "alice_ratchet_public": hex(&a.ratchet_public()),
        "alice_root_key": hex(&a.debug_root_key()) }));
    // A → B (0x02), puis B → A sans réponse intermédiaire.
    let (t4, v4) = send(&mut a, "alice", "Parfait.");
    steps.push(v4);
    assert_eq!(
        b.decrypt(&t4, NOW, &mut rng_b).unwrap(),
        Content::Text("Parfait.".into())
    );
    steps.push(json!({ "event": "bob reçoit",
        "bob_ratchet_secret_drawn": rng_b.take(), "bob_ratchet_public": hex(&b.ratchet_public()),
        "bob_root_key": hex(&b.debug_root_key()) }));
    let (t5, v5) = send(&mut b, "bob", "");
    steps.push(v5);
    assert_eq!(
        a.decrypt(&t5, NOW, &mut rng_a).unwrap(),
        Content::Text(String::new())
    );
    steps.push(
        json!({ "event": "alice reçoit (texte vide)", "alice_ratchet_secret_drawn": rng_a.take() }),
    );

    json!({ "name": name, "mode": format!("{:?}", a.mode()).to_lowercase(),
        "now": NOW,
        "rng": { "alice": format!("{name}/alice/cliquet"), "bob": format!("{name}/bob/cliquet") },
        "setup": setup, "steps": steps })
}

fn base64_std(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn group() -> Value {
    let gid: [u8; 16] = h32("groupe/id")[..16].try_into().unwrap();
    let ck = h32("groupe/chaine");
    let seed = h32("groupe/ed25519");
    let mut s = SenderKeyState::generate_with(gid, &ck, &seed);
    let d = s.distribution();
    let mut messages = Vec::new();
    let mut chain = ck;
    for text in ["Bonjour le groupe", "Deuxième"] {
        let (next, mk) = kdf::kdf_ck(&chain);
        let (key, nonce) = kdf::message_key(&mk);
        let t = s.encrypt_token(text).unwrap();
        let Token::Group(g) = &t else { unreachable!() };
        messages.push(json!({ "text": text, "iteration": g.iteration, "chain_key": hex(&chain),
            "mk": hex(mk.as_ref()), "key": hex(key.as_ref()), "nonce": hex(&nonce),
            "aad": hex(&g.prefix()), "ciphertext": hex(&g.ciphertext), "signature": hex(&g.signature),
            "token": t.encode() }));
        chain = *next;
    }
    // La distribution, envoyée par une session PSK fixe.
    let key = h32("groupe/session");
    let mut sess = Session::initiate_psk_with(&key, &h32("groupe/ek")).unwrap();
    let dist_token = sess.encrypt_distribution(&d).unwrap();
    json!({
        "group_id": hex(&gid), "chain_key": hex(&ck), "signing_seed": hex(&seed),
        "signing_public": hex(&d.signing_public), "sender_id": hex(&d.sender_id),
        "distribution": hex(&d.to_bytes()),
        "distribution_via_psk_session": { "key": hex(&key), "ek_secret": hex(&h32("groupe/ek")),
            "token": dist_token, "note": "type 0x03 : AAD = AD ‖ en-tête ‖ 0x03" },
        "messages": messages,
    })
}

pub fn generate() -> Value {
    json!({
        "description": "Vecteurs de référence de brocolis-proto (docs/SECURITE.md). Octets en hexadécimal. h32(x) = SHA-256(x UTF-8) ; h64(x) = h32(x + \"/0\") ‖ h32(x + \"/1\").",
        "rng": "Deterministic(graine) : bloc i = SHA-256(\"Brocolis_vecteurs\" ‖ graine UTF-8 ‖ i u64 BE), i = 0, 1, …, octets servis dans l'ordre. Les secrets tirés pendant le cliquet sont aussi écrits en clair (*_drawn).",
        "version": 1,
        "primitives": primitives(),
        "padding": padding(),
        "protected_key": protected_keys(),
        "legacy_tokens": legacy_tokens(),
        "sessions": [session_case("hybride", Some(true)), session_case("classique", Some(false)), session_case("psk", None)],
        "group": group(),
    })
}

fn main() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors.json");
    let text = serde_json::to_string_pretty(&generate()).unwrap() + "\n";
    std::fs::write(&path, text).unwrap();
    println!("{}", path.display());
}
