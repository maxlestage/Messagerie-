//! # brocolis-proto
//!
//! L'implémentation de référence du protocole de sécurité de Brocolis 🥦 et
//! Talka (voir `docs/SECURITE.md`). Les implémentations Swift, Kotlin et
//! WebAssembly retrouvent ses vecteurs (`proto/vectors.json`) octet pour
//! octet.
//!
//! - [`cle_protegee`] : une clé protégée par une phrase secrète, v1
//!   (PBKDF2, lecture) et v2 (Argon2id, §3.2) ;
//! - [`jetons`] : les jetons v1/v2 et les passages `((…))`, comme Talka ;
//! - [`remplissage`] : le remplissage à 160 octets (§3.3) ;
//! - [`paquet`] : l'appareil, ses clés et son paquet de clés publiques (§4.1) ;
//! - [`session`] : l'établissement (§4.2) et le Double Ratchet (§4.3) ;
//! - [`jeton_v3`] : l'encodage strict du jeton v3 (§4.4) ;
//! - [`groupe`] : les Sender Keys (§4.5) ;
//! - [`kdf`] : chaque dérivation, exposée pour les vecteurs et les portages.
//!
//! Règles suivies partout : aucune panique sur une entrée hostile (toute
//! erreur est une [`Erreur`]), secrets effacés de la mémoire (`zeroize`),
//! comparaisons de secrets en temps constant, l'heure et le hasard fournis par
//! l'appelant (l'heure système n'existe pas en `wasm32-unknown-unknown`).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cle_protegee;
mod erreur;
pub mod groupe;
pub mod hasard;
pub mod jeton_v3;
pub mod jetons;
pub mod kdf;
pub mod paquet;
pub mod remplissage;
mod serde_b64;
pub mod session;

pub use erreur::Erreur;
pub use groupe::{ReceivedSenderKey, SenderKeyDistribution, SenderKeyState};
pub use jeton_v3::{Envelope, GroupMessage, Header, Initial, Mode, Token};
pub use paquet::{Device, IdentityPublic, KeyBundle, ReplayGuard};
pub use session::{Content, Session};

/// Le résultat de toutes les opérations de la crate.
pub type Resultat<T> = core::result::Result<T, Erreur>;

/// Un jour, en secondes. L'heure est un nombre de secondes depuis
/// l'époque Unix, fourni par l'appelant.
pub const JOUR: u64 = 24 * 60 * 60;

/// Le nombre maximal de clés sautées gardées par session (ou par chaîne de
/// groupe), et le plus grand saut accepté en un message (§4.3).
pub const MAX_SKIP: u32 = 1_000;

/// L'âge maximal d'une clé sautée : 30 jours (§4.3).
pub const MAX_SKIP_AGE: u64 = 30 * JOUR;
