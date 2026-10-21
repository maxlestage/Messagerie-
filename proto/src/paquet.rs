//! L'appareil, ses clés et son paquet de clés publiques (§4.1).
//!
//! Chaque appareil a une identité (IK : X25519 pour l'échange, Ed25519 pour
//! signer), une clé pré-signée X25519 (SPK) et, s'il sait faire ML-KEM, une
//! clé d'encapsulation ML-KEM-768 signée (PQPK), toutes deux renouvelées
//! chaque semaine (les anciennes gardées un mois pour les messages en
//! retard).
//!
//! ## Le paquet (format binaire v1)
//!
//! ```text
//! octet 0          : 0x01 (version du paquet)
//! octets 1–32      : IK X25519
//! octets 33–64     : IK Ed25519 (clé de vérification)
//! octets 65–68     : id SPK (u32 BE)
//! octets 69–100    : SPK (X25519)
//! octets 101–164   : signature Ed25519 de "Brocolis_v3_SPK" ‖ IK X25519 ‖ id SPK ‖ SPK
//! octet 165        : 0x00 sans ML-KEM, 0x01 avec
//! si 0x01 :
//!   octets 166–169   : id PQPK (u32 BE)
//!   octets 170–1353  : PQPK (clé d'encapsulation ML-KEM-768, 1 184 octets)
//!   octets 1354–1417 : signature Ed25519 de "Brocolis_v3_PQPK" ‖ IK X25519 ‖ id PQPK ‖ PQPK
//! ```
//!
//! 166 octets sans ML-KEM, 1 418 avec. Les signatures portent aussi IK
//! X25519, ce qui lie les deux moitiés de l'identité ; l'empreinte
//! ([`IdentityPublic::fingerprint`]) porte sur IK X25519 ‖ IK Ed25519.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::{Signer, SigningKey};
use ml_kem::{B32, DecapsulationKey768, EncapsulationKey768, KeyExport, Seed};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hasard::{CryptoRng, bytes};
use crate::kdf::{ed25519_verify, fingerprint, x25519_is_canonical, x25519_public};
use crate::{Erreur, JOUR, Resultat};

/// La version du format binaire du paquet.
pub const BUNDLE_VERSION: u8 = 0x01;
/// La longueur d'une clé d'encapsulation ML-KEM-768.
pub const PQPK_LEN: usize = 1_184;
/// La longueur d'un paquet sans ML-KEM.
pub const BUNDLE_LEN_CLASSIC: usize = 166;
/// La longueur d'un paquet avec ML-KEM.
pub const BUNDLE_LEN_PQ: usize = 1_418;
/// Le contexte signé avec la SPK.
pub const SIG_CONTEXT_SPK: &[u8] = b"Brocolis_v3_SPK";
/// Le contexte signé avec la PQPK.
pub const SIG_CONTEXT_PQPK: &[u8] = b"Brocolis_v3_PQPK";
/// Le renouvellement des clés pré-signées : chaque semaine.
pub const PREKEY_ROTATION: u64 = 7 * JOUR;
/// Une clé pré-signée remplacée est gardée un mois (30 jours).
pub const PREKEY_GRACE: u64 = 30 * JOUR;

/// Ce que l'appareil doit garder secret de son identité.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecret {
    /// Le secret X25519 (32 octets bruts).
    #[serde(with = "crate::serde_b64")]
    pub dh: [u8; 32],
    /// La graine Ed25519 (32 octets).
    #[serde(with = "crate::serde_b64")]
    pub sign: [u8; 32],
}

impl IdentitySecret {
    /// L'identité publique.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            dh: x25519_public(&self.dh),
            sign: SigningKey::from_bytes(&self.sign)
                .verifying_key()
                .to_bytes(),
        }
    }

    pub(crate) fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.sign)
    }
}

/// L'identité publique d'un appareil : IK X25519 et IK Ed25519.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityPublic {
    /// IK X25519.
    #[serde(with = "crate::serde_b64")]
    pub dh: [u8; 32],
    /// IK Ed25519 (clé de vérification).
    #[serde(with = "crate::serde_b64")]
    pub sign: [u8; 32],
}

impl IdentityPublic {
    /// L'empreinte de l'identité, à comparer de vive voix :
    /// `SHA-256(IK X25519 ‖ IK Ed25519)[0..8]` en `XXXX-XXXX-XXXX-XXXX`.
    pub fn fingerprint(&self) -> String {
        fingerprint(&[self.dh.as_slice(), &self.sign].concat())
    }
}

/// Une clé pré-signée X25519 (secrète).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SignedPreKey {
    /// Son identifiant.
    pub id: u32,
    /// Le secret X25519.
    #[serde(with = "crate::serde_b64")]
    pub secret: [u8; 32],
    /// Sa création (secondes Unix).
    pub created_at: u64,
    /// Son remplacement (secondes Unix), si elle n'est plus la courante.
    pub replaced_at: Option<u64>,
}

/// Une clé ML-KEM-768 (secrète : sa graine FIPS 203 `d ‖ z`, 64 octets).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PqPreKey {
    /// Son identifiant.
    pub id: u32,
    /// La graine `d ‖ z`.
    #[serde(with = "crate::serde_b64")]
    pub seed: [u8; 64],
    /// Sa création (secondes Unix).
    pub created_at: u64,
    /// Son remplacement (secondes Unix), si elle n'est plus la courante.
    pub replaced_at: Option<u64>,
}

/// La clé d'encapsulation ML-KEM-768 (1 184 octets) d'une graine.
pub fn mlkem_public(seed: &[u8; 64]) -> Vec<u8> {
    let dk = DecapsulationKey768::from_seed(Seed::from(*seed));
    dk.encapsulation_key().to_bytes().to_vec()
}

/// ML-KEM-768.Encaps avec le message `m` donné (32 octets aléatoires) :
/// `(CT, SS)`. Refuse une clé d'encapsulation invalide.
pub fn mlkem_encapsulate(pqpk: &[u8], m: &[u8; 32]) -> Resultat<(Vec<u8>, Zeroizing<[u8; 32]>)> {
    let key = ml_kem::array::Array::try_from(pqpk).map_err(|_| Erreur::CleInvalide)?;
    let ek = EncapsulationKey768::new(&key).map_err(|_| Erreur::CleInvalide)?;
    let (ct, ss) = ek.encapsulate_deterministic(&B32::from(*m));
    Ok((ct.to_vec(), Zeroizing::new(ss.into())))
}

/// ML-KEM-768.Decaps (rejet implicite : un chiffré altéré donne un secret
/// faux, sans erreur, et le message est ensuite refusé).
pub fn mlkem_decapsulate(seed: &[u8; 64], ct: &[u8]) -> Resultat<Zeroizing<[u8; 32]>> {
    use ml_kem::Decapsulate;
    let ct = ml_kem::array::Array::try_from(ct).map_err(|_| Erreur::Format)?;
    let dk = DecapsulationKey768::from_seed(Seed::from(*seed));
    Ok(Zeroizing::new(dk.decapsulate(&ct).into()))
}

fn spk_signed_message(ik: &[u8; 32], id: u32, spk: &[u8; 32]) -> Vec<u8> {
    [SIG_CONTEXT_SPK, ik, &id.to_be_bytes(), spk].concat()
}

fn pqpk_signed_message(ik: &[u8; 32], id: u32, pqpk: &[u8]) -> Vec<u8> {
    [SIG_CONTEXT_PQPK, ik, &id.to_be_bytes(), pqpk].concat()
}

/// `"Brocolis_v4_Caps"` : le contexte de la capacité v4 signée (§9.6).
pub const SIG_CONTEXT_CAPS4: &[u8] = b"Brocolis_v4_Caps";

fn caps4_message(ik: &[u8; 32]) -> Vec<u8> {
    [SIG_CONTEXT_CAPS4, ik, &[0x04]].concat()
}

/// Vérifie la capacité v4 d'un correspondant (signature stricte par son IK
/// Ed25519, sur son IK X25519).
pub fn verify_caps4(identity: &IdentityPublic, signature: &[u8; 64]) -> Resultat<()> {
    crate::kdf::ed25519_verify(&identity.sign, &caps4_message(&identity.dh), signature)
}

/// La partie ML-KEM d'un paquet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqBundle {
    /// L'identifiant de la PQPK.
    pub id: u32,
    /// La clé d'encapsulation ML-KEM-768 (1 184 octets).
    pub key: Vec<u8>,
    /// Sa signature par IK Ed25519.
    pub signature: [u8; 64],
}

/// Un paquet de clés publiques, signatures vérifiées.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyBundle {
    /// L'identité.
    pub identity: IdentityPublic,
    /// L'identifiant de la SPK.
    pub spk_id: u32,
    /// La SPK.
    pub spk: [u8; 32],
    /// Sa signature par IK Ed25519.
    pub spk_signature: [u8; 64],
    /// La PQPK, si l'appareil sait faire ML-KEM.
    pub pq: Option<PqBundle>,
}

impl KeyBundle {
    /// Les octets du paquet (format v1, voir le module).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_LEN_PQ);
        out.push(BUNDLE_VERSION);
        out.extend_from_slice(&self.identity.dh);
        out.extend_from_slice(&self.identity.sign);
        out.extend_from_slice(&self.spk_id.to_be_bytes());
        out.extend_from_slice(&self.spk);
        out.extend_from_slice(&self.spk_signature);
        match &self.pq {
            None => out.push(0x00),
            Some(pq) => {
                out.push(0x01);
                out.extend_from_slice(&pq.id.to_be_bytes());
                out.extend_from_slice(&pq.key);
                out.extend_from_slice(&pq.signature);
            }
        }
        out
    }

    /// Lit un paquet et **vérifie** tout : version, longueur exacte, clés
    /// (Ed25519 non faible, X25519 non nulle, ML-KEM bien formée) et
    /// signatures (Ed25519 stricte).
    pub fn from_bytes(data: &[u8]) -> Resultat<Self> {
        if data.len() != BUNDLE_LEN_CLASSIC && data.len() != BUNDLE_LEN_PQ {
            return Err(Erreur::Format);
        }
        if data[0] != BUNDLE_VERSION {
            return Err(Erreur::Format);
        }
        let arr32 = |r: core::ops::Range<usize>| -> Resultat<[u8; 32]> {
            data[r].try_into().map_err(|_| Erreur::Format)
        };
        let arr64 = |r: core::ops::Range<usize>| -> Resultat<[u8; 64]> {
            data[r].try_into().map_err(|_| Erreur::Format)
        };
        let u32_at =
            |i: usize| u32::from_be_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
        let identity = IdentityPublic {
            dh: arr32(1..33)?,
            sign: arr32(33..65)?,
        };
        let spk_id = u32_at(65);
        let spk = arr32(69..101)?;
        let spk_signature = arr64(101..165)?;
        let pq = match (data[165], data.len()) {
            (0x00, BUNDLE_LEN_CLASSIC) => None,
            (0x01, BUNDLE_LEN_PQ) => Some(PqBundle {
                id: u32_at(166),
                key: data[170..170 + PQPK_LEN].to_vec(),
                signature: arr64(1354..1418)?,
            }),
            _ => return Err(Erreur::Format),
        };
        let bundle = KeyBundle {
            identity,
            spk_id,
            spk,
            spk_signature,
            pq,
        };
        bundle.verify()?;
        Ok(bundle)
    }

    /// Vérifie les clés et les signatures du paquet.
    pub fn verify(&self) -> Resultat<()> {
        for key in [&self.identity.dh, &self.spk] {
            if !x25519_is_canonical(key) || bool::from(key.ct_eq(&[0u8; 32])) {
                return Err(Erreur::CleInvalide);
            }
        }
        ed25519_verify(
            &self.identity.sign,
            &spk_signed_message(&self.identity.dh, self.spk_id, &self.spk),
            &self.spk_signature,
        )?;
        if let Some(pq) = &self.pq {
            if pq.key.len() != PQPK_LEN || pq.id == 0 {
                return Err(Erreur::Format);
            }
            ed25519_verify(
                &self.identity.sign,
                &pqpk_signed_message(&self.identity.dh, pq.id, &pq.key),
                &pq.signature,
            )?;
            // La clé doit être une clé ML-KEM valide (FIPS 203, contrôle du
            // module) : on l'encapsule une fois pour rien.
            mlkem_encapsulate(&pq.key, &[0u8; 32])?;
        }
        Ok(())
    }

    /// Le paquet en base64 standard.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.to_bytes())
    }

    /// Lit (et vérifie) un paquet en base64 standard.
    pub fn from_base64(text: &str) -> Resultat<Self> {
        if text.len() > 2 * BUNDLE_LEN_PQ {
            return Err(Erreur::TropGrand);
        }
        Self::from_bytes(&STANDARD.decode(text.trim()).map_err(|_| Erreur::Base64)?)
    }
}

/// Les clés éphémères déjà vues dans un premier message (type 0x01) :
/// rejouer un premier message ne rouvre pas de session (§1 : « un rejeu est
/// ignoré »). Bornée : [`ReplayGuard::MAX`] entrées, [`ReplayGuard::MAX_AGE`].
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ReplayGuard {
    seen: Vec<SeenEphemeral>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SeenEphemeral {
    #[serde(with = "crate::serde_b64")]
    ek: [u8; 32],
    at: u64,
}

impl ReplayGuard {
    /// Le nombre maximal de clés retenues (les plus anciennes partent).
    pub const MAX: usize = 4_096;
    /// L'âge maximal d'une entrée : la vie d'une clé pré-signée (7 + 30
    /// jours).
    pub const MAX_AGE: u64 = PREKEY_ROTATION + PREKEY_GRACE;

    /// Vrai si cette clé éphémère a déjà ouvert une session.
    pub fn seen(&self, ek: &[u8; 32]) -> bool {
        self.seen.iter().any(|s| &s.ek == ek)
    }

    /// Retient une clé éphémère.
    pub fn insert(&mut self, ek: [u8; 32], now: u64) {
        self.purge(now);
        self.seen.push(SeenEphemeral { ek, at: now });
        if self.seen.len() > Self::MAX {
            let extra = self.seen.len() - Self::MAX;
            self.seen.drain(..extra);
        }
    }

    /// Oublie les entrées trop vieilles.
    pub fn purge(&mut self, now: u64) {
        self.seen
            .retain(|s| s.at.saturating_add(Self::MAX_AGE) > now);
    }

    /// Le nombre d'entrées.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Vrai si aucune entrée.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

/// Un appareil : son identité, ses clés pré-signées (la courante et celles
/// gardées pour les retardataires) et la mémoire des premiers messages.
/// Sérialisable (JSON) ; à garder chiffré par la clé matérielle (§3.1).
#[derive(Clone, Serialize, Deserialize)]
pub struct Device {
    /// La version du format de l'état.
    pub v: u8,
    identity: IdentitySecret,
    signed_prekeys: Vec<SignedPreKey>,
    pq_prekeys: Vec<PqPreKey>,
    #[serde(default)]
    replay: ReplayGuard,
}

fn next_id(rng: &mut (impl CryptoRng + ?Sized), last: Option<u32>) -> u32 {
    match last {
        Some(id) => id.wrapping_add(1).max(1),
        None => (u32::from_be_bytes(bytes(rng)) >> 1).max(1),
    }
}

impl Device {
    /// Un nouvel appareil : identité, SPK et, avec `pq`, PQPK.
    ///
    /// Ordre de tirage (vecteurs) : secret X25519 d'IK (32), graine Ed25519
    /// (32), puis comme [`Device::rotate`].
    pub fn generate(rng: &mut (impl CryptoRng + ?Sized), now: u64, pq: bool) -> Self {
        let identity = IdentitySecret {
            dh: bytes(rng),
            sign: bytes(rng),
        };
        Self::from_identity(identity, rng, now, pq)
    }

    /// Un appareil à partir d'une identité existante (nouvelles SPK et PQPK).
    pub fn from_identity(
        identity: IdentitySecret,
        rng: &mut (impl CryptoRng + ?Sized),
        now: u64,
        pq: bool,
    ) -> Self {
        let mut d = Device {
            v: 1,
            identity,
            signed_prekeys: Vec::new(),
            pq_prekeys: Vec::new(),
            replay: ReplayGuard::default(),
        };
        d.add_prekeys(rng, now, pq);
        d
    }

    /// Un appareil à partir de secrets donnés (vecteurs, import) : identité,
    /// SPK et, optionnellement, PQPK (id et graine `d ‖ z`).
    pub fn from_secrets(
        identity: IdentitySecret,
        spk: (u32, [u8; 32]),
        pq: Option<(u32, [u8; 64])>,
        now: u64,
    ) -> Self {
        Device {
            v: 1,
            identity,
            signed_prekeys: vec![SignedPreKey {
                id: spk.0,
                secret: spk.1,
                created_at: now,
                replaced_at: None,
            }],
            pq_prekeys: pq
                .map(|(id, seed)| {
                    vec![PqPreKey {
                        id,
                        seed,
                        created_at: now,
                        replaced_at: None,
                    }]
                })
                .unwrap_or_default(),
            replay: ReplayGuard::default(),
        }
    }

    fn add_prekeys(&mut self, rng: &mut (impl CryptoRng + ?Sized), now: u64, pq: bool) {
        let spk_id = next_id(rng, self.signed_prekeys.last().map(|k| k.id));
        let secret = bytes(rng);
        for k in &mut self.signed_prekeys {
            k.replaced_at.get_or_insert(now);
        }
        self.signed_prekeys.push(SignedPreKey {
            id: spk_id,
            secret,
            created_at: now,
            replaced_at: None,
        });
        if pq {
            let pq_id = next_id(rng, self.pq_prekeys.last().map(|k| k.id));
            let seed = bytes(rng);
            for k in &mut self.pq_prekeys {
                k.replaced_at.get_or_insert(now);
            }
            self.pq_prekeys.push(PqPreKey {
                id: pq_id,
                seed,
                created_at: now,
                replaced_at: None,
            });
        }
    }

    /// Renouvelle la SPK (et la PQPK si l'appareil en a une) ; les
    /// anciennes restent utilisables [`PREKEY_GRACE`], puis [`Device::purge`]
    /// les efface.
    ///
    /// Ordre de tirage : id SPK (4 octets, seulement la première fois),
    /// secret SPK (32), id PQPK (4, la première fois), graine ML-KEM (64).
    pub fn rotate(&mut self, rng: &mut (impl CryptoRng + ?Sized), now: u64) {
        let pq = !self.pq_prekeys.is_empty();
        self.add_prekeys(rng, now, pq);
        self.purge(now);
    }

    /// Ajoute ML-KEM à un appareil qui n'en avait pas (iPhone passé à
    /// iOS 26, par exemple), en renouvelant la SPK.
    pub fn enable_pq(&mut self, rng: &mut (impl CryptoRng + ?Sized), now: u64) {
        self.add_prekeys(rng, now, true);
    }

    /// Vrai si la SPK courante a une semaine ou plus.
    pub fn needs_rotation(&self, now: u64) -> bool {
        self.signed_prekeys
            .last()
            .is_none_or(|k| k.created_at.saturating_add(PREKEY_ROTATION) <= now)
    }

    /// Efface les clés remplacées depuis plus d'un mois et les vieilles
    /// entrées de la mémoire des premiers messages.
    pub fn purge(&mut self, now: u64) {
        let keep = |r: Option<u64>| r.is_none_or(|r| r.saturating_add(PREKEY_GRACE) > now);
        self.signed_prekeys.retain(|k| keep(k.replaced_at));
        self.pq_prekeys.retain(|k| keep(k.replaced_at));
        self.replay.purge(now);
    }

    /// L'identité publique.
    pub fn identity(&self) -> IdentityPublic {
        self.identity.public()
    }

    /// L'identité secrète (pour l'établissement).
    pub fn identity_secret(&self) -> &IdentitySecret {
        &self.identity
    }

    /// Vrai si l'appareil a une clé ML-KEM courante.
    pub fn supports_pq(&self) -> bool {
        self.pq_prekeys.iter().any(|k| k.replaced_at.is_none())
    }

    /// Le paquet de clés publiques courant, signé.
    pub fn bundle(&self) -> Resultat<KeyBundle> {
        let ik = self.identity.public();
        let sk = self.identity.signing_key();
        let spk_key = self
            .signed_prekeys
            .iter()
            .rev()
            .find(|k| k.replaced_at.is_none())
            .ok_or(Erreur::Etat)?;
        let spk = x25519_public(&spk_key.secret);
        let spk_signature = sk
            .sign(&spk_signed_message(&ik.dh, spk_key.id, &spk))
            .to_bytes();
        let pq = self
            .pq_prekeys
            .iter()
            .rev()
            .find(|k| k.replaced_at.is_none())
            .map(|k| {
                let key = mlkem_public(&k.seed);
                let signature = sk.sign(&pqpk_signed_message(&ik.dh, k.id, &key)).to_bytes();
                PqBundle {
                    id: k.id,
                    key,
                    signature,
                }
            });
        Ok(KeyBundle {
            identity: ik,
            spk_id: spk_key.id,
            spk,
            spk_signature,
            pq,
        })
    }

    pub(crate) fn spk_secret(&self, id: u32) -> Resultat<[u8; 32]> {
        self.signed_prekeys
            .iter()
            .find(|k| k.id == id)
            .map(|k| k.secret)
            .ok_or(Erreur::CleInconnue)
    }

    pub(crate) fn pq_seed(&self, id: u32) -> Resultat<Zeroizing<[u8; 64]>> {
        self.pq_prekeys
            .iter()
            .find(|k| k.id == id)
            .map(|k| Zeroizing::new(k.seed))
            .ok_or(Erreur::CleInconnue)
    }

    /// Les secrets X25519 de toutes les SPK gardées (la courante d'abord).
    pub(crate) fn spk_secrets(&self) -> Vec<[u8; 32]> {
        self.signed_prekeys.iter().rev().map(|k| k.secret).collect()
    }

    /// Les graines ML-KEM de toutes les PQPK gardées (la courante d'abord).
    pub(crate) fn pq_seeds(&self) -> Vec<Zeroizing<[u8; 64]>> {
        self.pq_prekeys
            .iter()
            .rev()
            .map(|k| Zeroizing::new(k.seed))
            .collect()
    }

    /// La capacité v4 signée (§9.6) : `Ed25519(IK, "Brocolis_v4_Caps" ‖ IK
    /// X25519 ‖ 0x04)`. Seul un appareil qui a ML-KEM la publie.
    pub fn caps4(&self) -> Option<[u8; 64]> {
        self.supports_pq().then(|| {
            let ik = self.identity.public();
            self.identity
                .signing_key()
                .sign(&caps4_message(&ik.dh))
                .to_bytes()
        })
    }

    pub(crate) fn replay_mut(&mut self) -> &mut ReplayGuard {
        &mut self.replay
    }

    /// L'état en JSON.
    pub fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Relit un état JSON.
    pub fn from_json(text: &str) -> Resultat<Self> {
        let d: Device = serde_json::from_str(text).map_err(|_| Erreur::Etat)?;
        if d.v != 1 {
            return Err(Erreur::Etat);
        }
        Ok(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasard::Deterministic;

    #[test]
    fn paquet_aller_retour_et_signatures() {
        for pq in [false, true] {
            let mut rng = Deterministic::new(b"paquet");
            let d = Device::generate(&mut rng, 1_000, pq);
            let b = d.bundle().unwrap();
            let bytes = b.to_bytes();
            assert_eq!(
                bytes.len(),
                if pq {
                    BUNDLE_LEN_PQ
                } else {
                    BUNDLE_LEN_CLASSIC
                }
            );
            assert_eq!(KeyBundle::from_bytes(&bytes).unwrap(), b);
            assert_eq!(KeyBundle::from_base64(&b.to_base64()).unwrap(), b);
            // Chaque bit modifié est refusé.
            for i in 0..bytes.len() {
                let mut x = bytes.clone();
                x[i] ^= 0x01;
                assert!(KeyBundle::from_bytes(&x).is_err(), "octet {i}");
            }
        }
    }

    #[test]
    fn rotation_et_purge() {
        let mut rng = Deterministic::new(b"rotation");
        let mut d = Device::generate(&mut rng, 0, true);
        let first = d.bundle().unwrap();
        assert!(!d.needs_rotation(PREKEY_ROTATION - 1));
        assert!(d.needs_rotation(PREKEY_ROTATION));
        d.rotate(&mut rng, PREKEY_ROTATION);
        let second = d.bundle().unwrap();
        assert_eq!(second.spk_id, first.spk_id.wrapping_add(1).max(1));
        assert!(d.spk_secret(first.spk_id).is_ok());
        assert!(d.pq_seed(first.pq.as_ref().unwrap().id).is_ok());
        d.purge(PREKEY_ROTATION + PREKEY_GRACE);
        assert_eq!(d.spk_secret(first.spk_id).err(), Some(Erreur::CleInconnue));
        assert!(d.spk_secret(second.spk_id).is_ok());
        let json = d.to_json();
        let back = Device::from_json(&json).unwrap();
        assert_eq!(back.bundle().unwrap(), second);
        assert_eq!(Device::from_json("{}").err(), Some(Erreur::Etat));
    }

    #[test]
    fn replay_guard_borne() {
        let mut g = ReplayGuard::default();
        for i in 0..(ReplayGuard::MAX + 10) {
            let mut ek = [0u8; 32];
            ek[..8].copy_from_slice(&(i as u64).to_be_bytes());
            g.insert(ek, 0);
        }
        assert_eq!(g.len(), ReplayGuard::MAX);
        assert!(!g.seen(&[0u8; 32]));
        g.purge(ReplayGuard::MAX_AGE);
        assert!(g.is_empty());
    }
}
