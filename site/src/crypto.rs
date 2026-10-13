//! La cryptographie de la discussion en ligne : EXACTEMENT celle de l'app
//! (`Shared/BrocolisKeyAgreement.swift`, `BrocolisCrypto.swift`,
//! `BrocolisMessagingCore.swift`), pour qu'un navigateur et un iPhone se
//! comprennent :
//!
//! - identité X25519 ; clé d'emballage = HKDF-SHA256(secret partagé,
//!   sel `brocolis-x25519-wrap`, info = les deux clés publiques triées) ;
//! - clé de groupe AES-256 emballée en AES-GCM « combined »
//!   (nonce 12 octets ‖ chiffré ‖ tag 16 octets), en base64 ;
//! - messages : jetons `[[BROCOLIS:v1:<base64 combined>]]` ;
//! - conversation : base64url(SHA-256("brocolis-conv-v1" ‖ clé)) ;
//! - empreinte : 8 premiers octets de SHA-256, en hexa groupé par 4.
//!
//! Rien de tout cela ne quitte le navigateur en clair.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

const WRAP_SALT: &[u8] = b"brocolis-x25519-wrap";
const CONV_PREFIX: &[u8] = b"brocolis-conv-v1";
pub const TOKEN_HEAD: &str = "[[BROCOLIS:";
pub const TOKEN_V1: &str = "[[BROCOLIS:v1:";
pub const TOKEN_END: &str = "]]";

/// Des octets aléatoires (crypto.getRandomValues dans le navigateur).
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

pub fn b64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

pub fn unb64(text: &str) -> Option<Vec<u8>> {
    STANDARD.decode(text.trim()).ok()
}

/// Une identité X25519 (clé privée brute, 32 octets).
pub struct Identity(StaticSecret);

impl Identity {
    pub fn generate() -> Self {
        Identity(StaticSecret::from(random_bytes::<32>()))
    }

    pub fn from_b64(text: &str) -> Option<Self> {
        let raw: [u8; 32] = unb64(text)?.try_into().ok()?;
        Some(Identity(StaticSecret::from(raw)))
    }

    pub fn secret_b64(&self) -> String {
        b64(&self.0.to_bytes())
    }

    pub fn public_raw(&self) -> [u8; 32] {
        PublicKey::from(&self.0).to_bytes()
    }

    pub fn public_b64(&self) -> String {
        b64(&self.public_raw())
    }

    /// La clé d'emballage partagée avec `peer` (même valeur des deux côtés).
    fn wrap_key(&self, peer_b64: &str) -> Option<[u8; 32]> {
        let peer: [u8; 32] = unb64(peer_b64)?.try_into().ok()?;
        let shared = self.0.diffie_hellman(&PublicKey::from(peer));
        let info = sorted_concat(&self.public_raw(), &peer);
        let mut out = [0u8; 32];
        Hkdf::<Sha256>::new(Some(WRAP_SALT), shared.as_bytes())
            .expand(&info, &mut out)
            .ok()?;
        Some(out)
    }

    /// Emballe la clé de groupe pour `peer` (comme `wrapGroupKey`).
    pub fn wrap_group_key(&self, group_key: &[u8; 32], peer_b64: &str) -> Option<String> {
        Some(b64(&seal(&self.wrap_key(peer_b64)?, group_key)?))
    }

    /// Déballe une clé de groupe reçue de `from` (comme `unwrapGroupKey`).
    pub fn unwrap_group_key(&self, blob_b64: &str, from_b64: &str) -> Option<[u8; 32]> {
        let plain = open(&self.wrap_key(from_b64)?, &unb64(blob_b64)?)?;
        plain.try_into().ok()
    }
}

fn sorted_concat(a: &[u8], b: &[u8]) -> Vec<u8> {
    if a <= b { [a, b].concat() } else { [b, a].concat() }
}

/// AES-256-GCM, représentation « combined » de CryptoKit.
pub fn seal(key: &[u8; 32], plain: &[u8]) -> Option<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let nonce = random_bytes::<12>();
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(Nonce::from_slice(&nonce), plain).ok()?);
    Some(out)
}

pub fn open(key: &[u8; 32], combined: &[u8]) -> Option<Vec<u8>> {
    if combined.len() < 12 + 16 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let (nonce, body) = combined.split_at(12);
    cipher.decrypt(Nonce::from_slice(nonce), body).ok()
}

/// Un jeton `[[BROCOLIS:v1:…]]` pour `text`.
pub fn seal_token(key: &[u8; 32], text: &str) -> Option<String> {
    Some(format!("{TOKEN_V1}{}{TOKEN_END}", b64(&seal(key, text.as_bytes())?)))
}

/// Déchiffre les jetons v1 de `text` ; `None` si aucun n'a pu l'être.
pub fn open_tokens(key: &[u8; 32], text: &str) -> Option<String> {
    let mut out = String::new();
    let mut rest = text;
    let mut opened = 0;
    while let Some(start) = rest.find(TOKEN_V1) {
        let after = &rest[start + TOKEN_V1.len()..];
        let Some(end) = after.find(TOKEN_END) else { break };
        out.push_str(&rest[..start]);
        match unb64(&after[..end]).and_then(|c| open(key, &c)).and_then(|p| String::from_utf8(p).ok()) {
            Some(plain) => {
                out.push_str(&plain);
                opened += 1;
            }
            None => out.push_str(&rest[start..start + TOKEN_V1.len() + end + TOKEN_END.len()]),
        }
        rest = &after[end + TOKEN_END.len()..];
    }
    out.push_str(rest);
    (opened > 0).then_some(out)
}

/// L'identifiant de conversation dérivé de la clé (comme l'app).
pub fn conversation_id(key: &[u8; 32]) -> String {
    let mut h = Sha256::new();
    h.update(CONV_PREFIX);
    h.update(key);
    URL_SAFE_NO_PAD.encode(h.finalize())
}

/// L'empreinte à comparer de vive voix (`AB12-CD34-EF56-7890`).
pub fn fingerprint(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let hex: String = digest[..8].iter().map(|b| format!("{b:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// Un code d'appairage comme ceux de l'app (6 caractères sans 0/O/1/I).
pub fn pairing_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    random_bytes::<6>()
        .iter()
        .map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char)
        .collect()
}

/// Un identifiant au format UUID v4.
pub fn uuid() -> String {
    let mut b = random_bytes::<16>();
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02X}")).collect();
    format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..])
}

/// Un QR code en SVG (pour `<img src="data:image/svg+xml,…">`).
pub fn qr_svg(text: &str) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color<'_>>()
            .min_dimensions(200, 200)
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_key_travels_wrapped_between_two_identities() {
        let (alice, bob) = (Identity::generate(), Identity::generate());
        let key = random_bytes::<32>();
        let blob = alice.wrap_group_key(&key, &bob.public_b64()).unwrap();
        assert_eq!(bob.unwrap_group_key(&blob, &alice.public_b64()), Some(key));
        // Un tiers ne peut pas déballer.
        assert_eq!(Identity::generate().unwrap_group_key(&blob, &alice.public_b64()), None);
    }

    #[test]
    fn identity_survives_a_round_trip_through_storage() {
        let id = Identity::generate();
        let back = Identity::from_b64(&id.secret_b64()).unwrap();
        assert_eq!(back.public_b64(), id.public_b64());
    }

    #[test]
    fn tokens_round_trip_and_leave_plain_text_alone() {
        let key = random_bytes::<32>();
        let token = seal_token(&key, "salut 🥦").unwrap();
        assert!(token.starts_with(TOKEN_V1) && token.ends_with(TOKEN_END));
        assert_eq!(open_tokens(&key, &token).as_deref(), Some("salut 🥦"));
        assert_eq!(open_tokens(&key, &format!("a {token} b")).as_deref(), Some("a salut 🥦 b"));
        assert_eq!(open_tokens(&random_bytes::<32>(), &token), None);
        assert_eq!(open_tokens(&key, "rien"), None);
    }

    #[test]
    fn conversation_id_and_fingerprint_have_the_app_shape() {
        let key = [7u8; 32];
        let id = conversation_id(&key);
        assert_eq!(id.len(), 43);
        assert!(!id.contains(['+', '/', '=']));
        let fp = fingerprint(&key);
        assert_eq!(fp.len(), 19);
        assert_eq!(fp.matches('-').count(), 3);
    }

    #[test]
    fn codes_and_ids_look_like_the_app_ones() {
        let code = pairing_code();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| "ABCDEFGHJKLMNPQRSTUVWXYZ23456789".contains(c)));
        let id = uuid();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(qr_svg("https://example.com/?code=K7P2QX").unwrap().contains("<svg"));
    }
}

#[cfg(test)]
mod vectors {
    use super::*;

    /// Valeurs fixes recoupées avec une implémentation indépendante (Python
    /// `cryptography`, mêmes primitives que CryptoKit) : clé publique, HKDF,
    /// identifiant de conversation et empreinte identiques à l'app.
    #[test]
    fn fixed_vectors_match_the_app() {
        let alice = Identity(StaticSecret::from([1u8; 32]));
        let bob = Identity(StaticSecret::from([2u8; 32]));
        assert_eq!(alice.public_b64(), "pOCSkrZRwni5dyxWn1+puxPZBrRqtoyd+dwrRAn4ogk=");
        let k = alice.wrap_key(&bob.public_b64()).unwrap();
        assert_eq!(k, bob.wrap_key(&alice.public_b64()).unwrap());
        assert_eq!(b64(&k), "rv+EmjbG8ZYNWUlwkDV57/YVEL9zkAScnM6iKz0T+UM=");
        assert_eq!(conversation_id(&[7u8; 32]), "0cPmmicIaMcaC1bV4yPaLjxHmek65VPazyk_X5QT9cM");
        assert_eq!(fingerprint(&[7u8; 32]), "4BB0-6F8E-4E3A-7715");
        // Une clé emballée et un jeton produits ailleurs (même algorithme).
        let blob = "81p2c6nvKV6OSrdquUov4sR9A5t47pJNiL7Jp8fiFhB7ar7PZf8em8dWQKxQqu/NP/BohUyZB0nEsJ5M";
        assert_eq!(bob.unwrap_group_key(blob, &alice.public_b64()), Some([9u8; 32]));
        let token = "[[BROCOLIS:v1:uAI9wrumtTlX/P8fBdLphS15X//kXm4SZje5yfVDld2L3Ac=]]";
        assert_eq!(open_tokens(&[9u8; 32], token).as_deref(), Some("bonjour"));
    }
}
