//! Les primitives et chaque dérivation du protocole, exposées telles quelles
//! pour que les vecteurs (et les portages Swift, Kotlin) vérifient chaque
//! étape intermédiaire.
//!
//! | Fonction | Spécification |
//! |---|---|
//! | [`sk_x3dh`] | §4.2 : `HKDF(0³², FF³² ‖ DH1 ‖ DH2 ‖ DH3 [‖ SS], info)` |
//! | [`sk_psk`] | §4.2 : clé partagée |
//! | [`kdf_rk`] | §4.3 `KDF_RK` |
//! | [`kdf_ck`] | §4.3 `KDF_CK` |
//! | [`message_key`] | §4.3 `ENCRYPT(mk)` → clé AES ‖ nonce |
//! | [`session_id`] | §4.4 `SHA-256(AD)[0..8]` |

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::{Erreur, Resultat};

/// `"Brocolis_v3_X25519_MLKEM768_SHA-256"` : l'info de SK avec ML-KEM.
pub const INFO_PQ: &[u8] = b"Brocolis_v3_X25519_MLKEM768_SHA-256";
/// `"Brocolis_v3_X25519_SHA-256"` : l'info de SK sans ML-KEM (`pq = 0`).
pub const INFO_CLASSIQUE: &[u8] = b"Brocolis_v3_X25519_SHA-256";
/// `"Brocolis_v3_PSK_SHA-256"` : l'info de SK pour une clé partagée.
pub const INFO_PSK: &[u8] = b"Brocolis_v3_PSK_SHA-256";
/// `"Brocolis_v3_PSK_Ratchet"` : la clé de cliquet initiale du répondeur
/// d'une session à clé partagée (écart documenté, voir `docs/SECURITE.md`).
pub const INFO_PSK_RATCHET: &[u8] = b"Brocolis_v3_PSK_Ratchet";
/// `"Brocolis_v3_Ratchet"` : l'info de `KDF_RK`.
pub const INFO_RATCHET: &[u8] = b"Brocolis_v3_Ratchet";
/// `"Brocolis_v3_MessageKeys"` : l'info de `ENCRYPT(mk)`.
pub const INFO_MESSAGE: &[u8] = b"Brocolis_v3_MessageKeys";

/// 32 octets nuls : le sel des HKDF « sans sel » de la spécification.
pub const SEL_NUL: [u8; 32] = [0u8; 32];

/// HKDF-SHA256 (RFC 5869) de longueur quelconque ; refuse une longueur
/// au-delà de 255 × 32 octets.
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Resultat<Vec<u8>> {
    let mut out = vec![0u8; len];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut out)
        .map_err(|_| Erreur::TropGrand)?;
    Ok(out)
}

/// HKDF-SHA256 de longueur fixe (N ≤ 64 dans tout le protocole).
pub(crate) fn hkdf_n<const N: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    const { assert!(N <= 255 * 32) };
    let mut out = Zeroizing::new([0u8; N]);
    // N ≤ 255 × 32 est vérifié à la compilation : `expand` ne peut pas échouer.
    if Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, out.as_mut())
        .is_err()
    {
        unreachable!("HKDF : longueur vérifiée à la compilation");
    }
    out
}

/// HMAC-SHA256.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // HMAC accepte une clé de toute longueur.
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| unreachable!("HMAC : toute longueur de clé"));
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// SHA-256.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// AES-256-GCM, nonce de 12 octets : chiffré ‖ tag (16). Seule une entrée
/// de plus de 2³⁶ octets échoue ([`Erreur::TropGrand`]).
pub fn aes_gcm_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], msg: &[u8]) -> Resultat<Vec<u8>> {
    Aes256Gcm::new(&(*key).into())
        .encrypt(&Nonce::from(*nonce), Payload { msg, aad })
        .map_err(|_| Erreur::TropGrand)
}

/// Ouvre un AES-256-GCM (chiffré ‖ tag) ; le tag est vérifié en temps
/// constant par `aes-gcm`.
pub fn aes_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ct: &[u8],
) -> Resultat<Zeroizing<Vec<u8>>> {
    Aes256Gcm::new(&(*key).into())
        .decrypt(&Nonce::from(*nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| Erreur::Dechiffrement)
}

/// La clé publique X25519 d'un secret de 32 octets (bruts, réduits par
/// RFC 7748 au moment du calcul : comme CryptoKit et BouncyCastle).
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    PublicKey::from(&StaticSecret::from(*secret)).to_bytes()
}

/// Vrai si une clé publique X25519 est **canonique** : bit 255 nul et
/// u < 2²⁵⁵ − 19. RFC 7748 ignore le bit 255 et réduit u modulo p : sans ce
/// contrôle, une même clé aurait plusieurs écritures, et un premier message
/// rejoué avec EK réécrite passerait la mémoire des clés éphémères.
pub fn x25519_is_canonical(public: &[u8; 32]) -> bool {
    if public[31] & 0x80 != 0 {
        return false;
    }
    // u ≥ p ⇔ u = 2²⁵⁵ − 19 + k, k < 19 : 0x7f, 30 × 0xff, puis ≥ 0xed.
    !(public[31] == 0x7f && public[1..31].iter().all(|&b| b == 0xff) && public[0] >= 0xed)
}

/// X25519(secret, public). Refuse ([`Erreur::CleInvalide`]) une clé
/// publique non canonique ([`x25519_is_canonical`]) et un résultat nul (clé
/// publique de petit ordre).
pub fn x25519(secret: &[u8; 32], public: &[u8; 32]) -> Resultat<Zeroizing<[u8; 32]>> {
    if !x25519_is_canonical(public) {
        return Err(Erreur::CleInvalide);
    }
    let shared = StaticSecret::from(*secret).diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(Erreur::CleInvalide);
    }
    Ok(Zeroizing::new(shared.to_bytes()))
}

/// Vérifie une signature Ed25519 (vérification **stricte** : R et A de
/// petit ordre et S non canonique refusés, comme RFC 8032 §5.1.7 le
/// recommande). Refuse aussi une clé publique faible.
pub fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Resultat<()> {
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public).map_err(|_| Erreur::CleInvalide)?;
    if vk.is_weak() {
        return Err(Erreur::CleInvalide);
    }
    vk.verify_strict(msg, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| Erreur::Signature)
}

/// SK de l'établissement (§4.2) : `HKDF-SHA256(sel = 32 × 0x00, ikm = 32 ×
/// 0xFF ‖ DH1 ‖ DH2 ‖ DH3 [‖ SS], info)`. Avec `ss`, l'info est
/// [`INFO_PQ`] ; sans, [`INFO_CLASSIQUE`].
pub fn sk_x3dh(
    dh1: &[u8; 32],
    dh2: &[u8; 32],
    dh3: &[u8; 32],
    ss: Option<&[u8; 32]>,
) -> Zeroizing<[u8; 32]> {
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 * 5));
    ikm.extend_from_slice(&[0xFF; 32]);
    ikm.extend_from_slice(dh1);
    ikm.extend_from_slice(dh2);
    ikm.extend_from_slice(dh3);
    let info = match ss {
        Some(ss) => {
            ikm.extend_from_slice(ss);
            INFO_PQ
        }
        None => INFO_CLASSIQUE,
    };
    hkdf_n::<32>(&SEL_NUL, &ikm, info)
}

/// SK d'une session à clé partagée (§4.2) :
/// `HKDF-SHA256(sel = 32 × 0x00, ikm = clé, "Brocolis_v3_PSK_SHA-256", 32)`.
pub fn sk_psk(key: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_n::<32>(&SEL_NUL, key, INFO_PSK)
}

/// Le secret X25519 (32 octets bruts) de la clé de cliquet initiale du
/// répondeur d'une session à clé partagée :
/// `HKDF-SHA256(sel = 32 × 0x00, ikm = SK, "Brocolis_v3_PSK_Ratchet", 32)`.
pub fn psk_ratchet_secret(sk: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf_n::<32>(&SEL_NUL, sk, INFO_PSK_RATCHET)
}

/// `KDF_RK(rk, dh) = HKDF-SHA256(sel = rk, ikm = dh, "Brocolis_v3_Ratchet",
/// 64)` → `(rk', ck)`.
pub fn kdf_rk(rk: &[u8; 32], dh: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let out = hkdf_n::<64>(rk, dh, INFO_RATCHET);
    let mut a = Zeroizing::new([0u8; 32]);
    let mut b = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(&out[..32]);
    b.copy_from_slice(&out[32..]);
    (a, b)
}

/// `KDF_CK(ck)` → `(ck', mk)` avec `mk = HMAC-SHA256(ck, 0x01)` et
/// `ck' = HMAC-SHA256(ck, 0x02)`.
pub fn kdf_ck(ck: &[u8; 32]) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>) {
    let mk = Zeroizing::new(hmac_sha256(ck, &[0x01]));
    let next = Zeroizing::new(hmac_sha256(ck, &[0x02]));
    (next, mk)
}

/// `ENCRYPT(mk)` : `HKDF-SHA256(sel = 32 × 0x00, ikm = mk,
/// "Brocolis_v3_MessageKeys", 44)` → clé AES (32) et nonce (12).
pub fn message_key(mk: &[u8; 32]) -> (Zeroizing<[u8; 32]>, [u8; 12]) {
    let out = hkdf_n::<44>(&SEL_NUL, mk, INFO_MESSAGE);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&out[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&out[32..]);
    (key, nonce)
}

/// L'identifiant de session : `SHA-256(AD)[0..8]` (§4.4).
pub fn session_id(ad: &[u8]) -> [u8; 8] {
    let h = sha256(ad);
    let mut id = [0u8; 8];
    id.copy_from_slice(&h[..8]);
    id
}

/// L'empreinte à comparer de vive voix (`AB12-CD34-EF56-7890`) : les 8
/// premiers octets du SHA-256 des données, comme les empreintes de clé de
/// l'app Brocolis.
pub fn fingerprint(data: &[u8]) -> String {
    let digest = sha256(data);
    let hex: Vec<String> = digest[..8].iter().map(|b| format!("{b:02X}")).collect();
    hex.chunks(2)
        .map(|c| c.concat())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hkdf_rfc5869_cas_1() {
        let ikm = [0x0b; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let okm = hkdf_sha256(&salt, &ikm, &info, 42).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn sel_nul_egal_sans_sel() {
        // HKDF : un sel absent vaut HashLen octets nuls (RFC 5869 §2.2).
        let a = hkdf_sha256(&SEL_NUL, b"ikm", b"info", 44).unwrap();
        let mut b = vec![0u8; 44];
        Hkdf::<Sha256>::new(None, b"ikm")
            .expand(b"info", &mut b)
            .unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn x25519_rfc7748() {
        let a = unhex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let b = unhex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        assert_eq!(
            hex(&x25519_public(&a)),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        let k = x25519(&a, &x25519_public(&b)).unwrap();
        assert_eq!(
            hex(k.as_ref()),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
        assert_eq!(x25519(&a, &[0u8; 32]), Err(Erreur::CleInvalide));
        // La même clé, bit 255 levé : refusée.
        let mut b_pub = x25519_public(&b);
        b_pub[31] |= 0x80;
        assert_eq!(x25519(&a, &b_pub), Err(Erreur::CleInvalide));
        let mut p = [0xffu8; 32];
        p[31] = 0x7f;
        p[0] = 0xed;
        assert!(!x25519_is_canonical(&p));
        p[0] = 0xec;
        assert!(x25519_is_canonical(&p));
    }

    #[test]
    fn fingerprint_format() {
        let f = fingerprint(&[7u8; 32]);
        assert_eq!(f.len(), 19);
        assert_eq!(f.matches('-').count(), 3);
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }
}
