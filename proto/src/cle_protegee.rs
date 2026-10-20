//! Une clé Brocolis (32 octets) protégée par une phrase secrète (§3.2), pour
//! la sortir de l'appareil sans la montrer.
//!
//! - `[[BROCOLIS-CLE:v1:<base64>]]` (lecture seulement) : sel (16) ‖ nonce
//!   (12) ‖ AES-256-GCM(clé) ‖ tag, sous PBKDF2-HMAC-SHA256(phrase, sel,
//!   600 000 tours), données associées `brocolis-cle-v1` ;
//! - `[[BROCOLIS-CLE:v2:<base64>]]` (par défaut) : Argon2id, format exact
//!   de §3.2 (83 octets), l'en-tête et les paramètres authentifiés.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use crate::hasard::{CryptoRng, bytes};
use crate::kdf::{aes_gcm_open, aes_gcm_seal};
use crate::{Erreur, Resultat};

/// Le début d'une clé protégée v1.
pub const HEAD_V1: &str = "[[BROCOLIS-CLE:v1:";
/// Le début d'une clé protégée v2.
pub const HEAD_V2: &str = "[[BROCOLIS-CLE:v2:";
const END: &str = "]]";
const AD_V1: &[u8] = b"brocolis-cle-v1";
/// Les tours de PBKDF2 de la v1.
pub const PBKDF2_ROUNDS: u32 = 600_000;
/// La phrase la plus courte acceptée (en caractères) pour protéger une clé ;
/// à l'import, toute phrase est essayée.
pub const PHRASE_MIN: usize = 8;
const V1_LEN: usize = 16 + 12 + 32 + 16;
const V2_LEN: usize = 83;
const V2_HEADER: usize = 35;

/// Les paramètres Argon2id d'une clé protégée v2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Argon2Params {
    /// m : mémoire, en Kio.
    pub m_kib: u32,
    /// t : nombre de passes.
    pub t: u8,
    /// p : parallélisme.
    pub p: u8,
}

impl Argon2Params {
    /// Le défaut : 64 Mio, 3 passes, 1 voie (§3.2).
    pub const DEFAULT: Argon2Params = Argon2Params {
        m_kib: 65_536,
        t: 3,
        p: 1,
    };
    /// Les plus petits paramètres acceptés à l'import (19 Mio, 2 passes,
    /// 1 voie : le minimum de l'OWASP), utilisés par les vecteurs rapides.
    pub const MINIMUM: Argon2Params = Argon2Params {
        m_kib: 19_456,
        t: 2,
        p: 1,
    };
    /// La plus grande mémoire acceptée (1 Gio).
    pub const MAX_M_KIB: u32 = 1_048_576;
    /// Le plus grand nombre de passes accepté (borne ajoutée à la
    /// spécification, voir `docs/SECURITE.md`).
    pub const MAX_T: u8 = 16;

    /// Vérifie les bornes de §3.2 (m ≥ 19 456, t ≥ 2, m ≤ 1 048 576), plus
    /// p ≥ 1, t ≤ 16 et m ≥ 8p (exigences d'Argon2 et borne de temps).
    pub fn check(&self) -> Resultat<()> {
        let ok = self.m_kib >= Self::MINIMUM.m_kib
            && self.m_kib <= Self::MAX_M_KIB
            && self.t >= 2
            && self.t <= Self::MAX_T
            && self.p >= 1
            && self.m_kib >= 8 * u32::from(self.p);
        if ok { Ok(()) } else { Err(Erreur::Parametres) }
    }
}

fn pbkdf2_key(phrase: &str, salt: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(phrase.as_bytes(), salt, PBKDF2_ROUNDS, out.as_mut());
    out
}

/// La clé de chiffrement v2 : `Argon2id(phrase UTF-8, sel, m, t, p, 32)`
/// (version 0x13, sans secret ni données associées Argon2).
pub fn argon2id_key(
    phrase: &str,
    salt: &[u8; 16],
    params: Argon2Params,
) -> Resultat<Zeroizing<[u8; 32]>> {
    params.check()?;
    let p = Params::new(params.m_kib, params.t.into(), params.p.into(), Some(32))
        .map_err(|_| Erreur::Parametres)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(phrase.as_bytes(), salt, out.as_mut())
        .map_err(|_| Erreur::Parametres)?;
    Ok(out)
}

/// Le contenu entre `head` et `]]` dans un texte collé.
fn inner<'a>(text: &'a str, head: &str) -> Option<&'a str> {
    let start = text.find(head)? + head.len();
    let end = text[start..].find(END)?;
    Some(&text[start..start + end])
}

/// Vrai si le texte contient une clé protégée (v1 ou v2).
pub fn has_protected_key(text: &str) -> bool {
    text.contains(HEAD_V1) || text.contains(HEAD_V2)
}

/// Écrit une clé protégée v1 avec un sel et un nonce donnés. **Héritage** :
/// sert aux vecteurs et à l'interopérabilité ; on n'écrit plus que la v2.
pub fn protect_key_v1_with(
    key: &[u8; 32],
    phrase: &str,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Resultat<String> {
    let ct = aes_gcm_seal(&pbkdf2_key(phrase, salt), nonce, AD_V1, key)?;
    let payload = [salt.as_slice(), nonce, &ct].concat();
    Ok(format!("{HEAD_V1}{}{END}", STANDARD.encode(payload)))
}

/// Écrit une clé protégée v2 avec des paramètres, un sel et un nonce donnés
/// (les vecteurs ; [`protect_key`] tire sel et nonce au hasard).
pub fn protect_key_v2_with(
    key: &[u8; 32],
    phrase: &str,
    params: Argon2Params,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Resultat<String> {
    if phrase.chars().count() < PHRASE_MIN {
        return Err(Erreur::PhraseTropCourte);
    }
    let mut header = Vec::with_capacity(V2_LEN);
    header.push(0x02);
    header.extend_from_slice(&params.m_kib.to_be_bytes());
    header.push(params.t);
    header.push(params.p);
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce);
    let k = argon2id_key(phrase, salt, params)?;
    let ct = aes_gcm_seal(&k, nonce, &header, key)?;
    header.extend_from_slice(&ct);
    Ok(format!("{HEAD_V2}{}{END}", STANDARD.encode(header)))
}

/// Protège une clé par une phrase secrète (v2, paramètres par défaut, sel et
/// nonce aléatoires). Refuse une phrase de moins de [`PHRASE_MIN`]
/// caractères.
pub fn protect_key(
    key: &[u8; 32],
    phrase: &str,
    rng: &mut (impl CryptoRng + ?Sized),
) -> Resultat<String> {
    protect_key_v2_with(key, phrase, Argon2Params::DEFAULT, &bytes(rng), &bytes(rng))
}

/// Retrouve la clé d'un jeton `[[BROCOLIS-CLE:v1:…]]` ou `v2` collé (seul ou
/// dans un texte ; la v2 est cherchée d'abord). Phrase fausse ou jeton
/// abîmé : [`Erreur::Dechiffrement`] ; paramètres v2 hors bornes :
/// [`Erreur::Parametres`] (avant tout calcul).
pub fn unprotect_key(text: &str, phrase: &str) -> Resultat<Zeroizing<[u8; 32]>> {
    if let Some(b) = inner(text, HEAD_V2) {
        return unprotect_v2(b, phrase);
    }
    if let Some(b) = inner(text, HEAD_V1) {
        return unprotect_v1(b, phrase);
    }
    Err(Erreur::JetonAbsent)
}

fn decode(b: &str, len: usize) -> Resultat<Zeroizing<Vec<u8>>> {
    // Une clé protégée fait moins de 120 caractères : rien à décoder au-delà.
    if b.len() > 4 * len.div_ceil(3) {
        return Err(Erreur::Format);
    }
    let data = Zeroizing::new(STANDARD.decode(b).map_err(|_| Erreur::Base64)?);
    if data.len() != len {
        return Err(Erreur::Format);
    }
    Ok(data)
}

fn to_key(plain: &[u8]) -> Resultat<Zeroizing<[u8; 32]>> {
    let mut key = Zeroizing::new([0u8; 32]);
    if plain.len() != 32 {
        return Err(Erreur::Format);
    }
    key.copy_from_slice(plain);
    Ok(key)
}

fn unprotect_v1(b: &str, phrase: &str) -> Resultat<Zeroizing<[u8; 32]>> {
    let data = decode(b, V1_LEN)?;
    let (salt, rest) = data.split_at(16);
    let (nonce, ct) = rest.split_at(12);
    let nonce: [u8; 12] = nonce.try_into().map_err(|_| Erreur::Format)?;
    let plain = aes_gcm_open(&pbkdf2_key(phrase, salt), &nonce, AD_V1, ct)?;
    to_key(&plain)
}

/// Les paramètres d'une clé protégée v2 (sans la phrase), pour prévenir
/// l'utilisateur avant un calcul long.
pub fn v2_params(text: &str) -> Resultat<Argon2Params> {
    let data = decode(inner(text, HEAD_V2).ok_or(Erreur::JetonAbsent)?, V2_LEN)?;
    parse_v2_params(&data)
}

fn parse_v2_params(data: &[u8]) -> Resultat<Argon2Params> {
    if data[0] != 0x02 {
        return Err(Erreur::Format);
    }
    let params = Argon2Params {
        m_kib: u32::from_be_bytes([data[1], data[2], data[3], data[4]]),
        t: data[5],
        p: data[6],
    };
    params.check()?;
    Ok(params)
}

fn unprotect_v2(b: &str, phrase: &str) -> Resultat<Zeroizing<[u8; 32]>> {
    let data = decode(b, V2_LEN)?;
    let params = parse_v2_params(&data)?;
    let salt: [u8; 16] = data[7..23].try_into().map_err(|_| Erreur::Format)?;
    let nonce: [u8; 12] = data[23..35].try_into().map_err(|_| Erreur::Format)?;
    let k = argon2id_key(phrase, &salt, params)?;
    let plain = aes_gcm_open(&k, &nonce, &data[..V2_HEADER], &data[V2_HEADER..])?;
    to_key(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTEUR_V1: &str = "[[BROCOLIS-CLE:v1:ERERERERERERERERERERESIiIiIiIiIiIiIiIsq57j18BXkqq/4VdIw82nQqzrax9Cfn2mfUJjWH8l327NAf2rWaSYCJh3BfGH4eWA==]]";

    fn cle() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    #[test]
    fn vecteur_commun_v1() {
        // Le vecteur commun (cle-protegee.md) : Talka, Brocolis iOS/Android.
        let token =
            protect_key_v1_with(&cle(), "brocoli vert 2026", &[0x11; 16], &[0x22; 12]).unwrap();
        assert_eq!(token, VECTEUR_V1);
        let k = unprotect_key(&format!("Voici : {VECTEUR_V1} !"), "brocoli vert 2026").unwrap();
        assert_eq!(*k, cle());
        assert_eq!(
            unprotect_key(VECTEUR_V1, "brocoli vert 2025"),
            Err(Erreur::Dechiffrement)
        );
    }

    #[test]
    fn v2_aller_retour_parametres_minimaux() {
        let p = Argon2Params::MINIMUM;
        let token =
            protect_key_v2_with(&cle(), "une phrase longue", p, &[1; 16], &[2; 12]).unwrap();
        assert!(token.starts_with(HEAD_V2) && token.ends_with("]]"));
        assert_eq!(v2_params(&token), Ok(p));
        assert_eq!(*unprotect_key(&token, "une phrase longue").unwrap(), cle());
        assert_eq!(
            unprotect_key(&token, "une phrase longuE"),
            Err(Erreur::Dechiffrement)
        );
    }

    #[test]
    fn v2_en_tete_authentifie() {
        let token = protect_key_v2_with(
            &cle(),
            "une phrase longue",
            Argon2Params::MINIMUM,
            &[1; 16],
            &[2; 12],
        )
        .unwrap();
        let b = inner(&token, HEAD_V2).unwrap();
        let data = STANDARD.decode(b).unwrap();
        // Chaque octet modifié (en-tête, sel, nonce, chiffré, tag) est refusé.
        for i in 0..data.len() {
            let mut d = data.clone();
            d[i] ^= 0x01;
            let t = format!("{HEAD_V2}{}]]", STANDARD.encode(&d));
            let r = unprotect_key(&t, "une phrase longue");
            assert!(r.is_err(), "octet {i}");
        }
    }

    #[test]
    fn v2_bornes_a_l_import() {
        let mut data = vec![0x02u8];
        for (m, t, p, ok) in [
            (19_455u32, 2u8, 1u8, false),
            (19_456, 1, 1, false),
            (1_048_577, 3, 1, false),
            (19_456, 2, 0, false),
            (19_456, 17, 1, false),
            (u32::MAX, 255, 255, false),
            (19_456, 2, 1, true),
        ] {
            data.truncate(1);
            data.extend_from_slice(&m.to_be_bytes());
            data.extend_from_slice(&[t, p]);
            data.resize(V2_LEN, 0);
            let r = parse_v2_params(&data);
            assert_eq!(r.is_ok(), ok, "{m} {t} {p}");
        }
        data[0] = 0x03;
        assert_eq!(parse_v2_params(&data), Err(Erreur::Format));
    }

    #[test]
    fn phrase_courte_et_jetons_abimes() {
        assert_eq!(
            protect_key_v2_with(&cle(), "court", Argon2Params::MINIMUM, &[1; 16], &[2; 12]),
            Err(Erreur::PhraseTropCourte)
        );
        assert_eq!(unprotect_key("rien", "x"), Err(Erreur::JetonAbsent));
        assert_eq!(
            unprotect_key("[[BROCOLIS-CLE:v1:AAAA]]", "x"),
            Err(Erreur::Format)
        );
        assert_eq!(
            unprotect_key("[[BROCOLIS-CLE:v1:pas du base64]]", "x"),
            Err(Erreur::Base64)
        );
        assert_eq!(
            unprotect_key("[[BROCOLIS-CLE:v2:AAAA", "x"),
            Err(Erreur::JetonAbsent)
        );
        let long = format!("[[BROCOLIS-CLE:v2:{}]]", "A".repeat(10_000));
        assert_eq!(unprotect_key(&long, "x"), Err(Erreur::Format));
    }

    #[test]
    fn protect_key_par_defaut() {
        let mut rng = crate::hasard::Deterministic::new(b"defaut");
        let token = protect_key(&cle(), "une phrase longue", &mut rng).unwrap();
        assert_eq!(v2_params(&token), Ok(Argon2Params::DEFAULT));
        assert_eq!(*unprotect_key(&token, "une phrase longue").unwrap(), cle());
    }
}
