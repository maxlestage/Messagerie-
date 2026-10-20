//! Les groupes : Sender Keys (§4.5), le modèle de Signal.
//!
//! Chaque membre tire une **chaîne d'envoi** (clé de chaîne 32 octets + clé
//! de signature Ed25519) et la distribue à chaque membre par sa session v3 à
//! deux (jeton de type 0x03, [`crate::Session::encrypt_distribution`]).
//! Ses messages de groupe (type 0x04) :
//!
//! ```text
//! 0x04 ‖ id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)
//! ```
//!
//! - la chaîne avance par `KDF_CK` ; la clé du message d'itération `i` est
//!   `mk_i`, chiffrée comme au §4.3 (`ENCRYPT(mk)`, remplissage §3.3) ;
//! - données associées AES-GCM : les 29 premiers octets (type ‖ id groupe ‖
//!   id expéditeur ‖ itération) ;
//! - signature Ed25519 de tout ce qui précède (type compris), vérifiée
//!   **avant** toute autre chose ;
//! - id expéditeur = `SHA-256(clé publique de signature)[0..8]` : propre à
//!   la chaîne, il change quand la chaîne est renouvelée.
//!
//! Distribution (92 octets, puis remplissage §3.3) :
//!
//! ```text
//! id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ clé de chaîne (32) ‖ clé publique Ed25519 (32)
//! ```
//!
//! Un membre qui part : chacun tire une chaîne neuve ([`SenderKeyState::generate`])
//! et la distribue aux membres restants.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::hasard::{CryptoRng, bytes};
use crate::jeton_v3::{GroupMessage, Token};
use crate::kdf::{aes_gcm_open, aes_gcm_seal, ed25519_verify, kdf_ck, message_key, sha256};
use crate::remplissage::{pad, unpad};
use crate::{Erreur, MAX_SKIP, MAX_SKIP_AGE, Resultat};

/// La longueur d'une distribution (avant remplissage).
pub const DISTRIBUTION_LEN: usize = 92;

/// Un identifiant de groupe aléatoire (16 octets).
pub fn new_group_id(rng: &mut (impl CryptoRng + ?Sized)) -> [u8; 16] {
    bytes(rng)
}

/// L'identifiant d'expéditeur d'une chaîne : `SHA-256(clé publique)[0..8]`.
pub fn sender_id_of(signing_public: &[u8; 32]) -> [u8; 8] {
    let h = sha256(signing_public);
    let mut id = [0u8; 8];
    id.copy_from_slice(&h[..8]);
    id
}

/// Une chaîne de groupe telle qu'on la distribue.
#[derive(Clone, Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyDistribution {
    /// L'identifiant du groupe.
    pub group_id: [u8; 16],
    /// L'identifiant de l'expéditeur.
    pub sender_id: [u8; 8],
    /// L'itération de la clé de chaîne.
    pub iteration: u32,
    /// La clé de chaîne à cette itération.
    pub chain_key: [u8; 32],
    /// La clé publique Ed25519 de la chaîne.
    pub signing_public: [u8; 32],
}

impl SenderKeyDistribution {
    /// Les 92 octets.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(DISTRIBUTION_LEN));
        out.extend_from_slice(&self.group_id);
        out.extend_from_slice(&self.sender_id);
        out.extend_from_slice(&self.iteration.to_be_bytes());
        out.extend_from_slice(&self.chain_key);
        out.extend_from_slice(&self.signing_public);
        out
    }

    /// Lit 92 octets ; vérifie l'identifiant d'expéditeur et la clé
    /// publique.
    pub fn from_bytes(b: &[u8]) -> Resultat<Self> {
        if b.len() != DISTRIBUTION_LEN {
            return Err(Erreur::Format);
        }
        let mut d = SenderKeyDistribution {
            group_id: [0; 16],
            sender_id: [0; 8],
            iteration: u32::from_be_bytes([b[24], b[25], b[26], b[27]]),
            chain_key: [0; 32],
            signing_public: [0; 32],
        };
        d.group_id.copy_from_slice(&b[..16]);
        d.sender_id.copy_from_slice(&b[16..24]);
        d.chain_key.copy_from_slice(&b[28..60]);
        d.signing_public.copy_from_slice(&b[60..92]);
        d.check()?;
        Ok(d)
    }

    fn check(&self) -> Resultat<()> {
        if sender_id_of(&self.signing_public) != self.sender_id {
            return Err(Erreur::Format);
        }
        let vk = VerifyingKey::from_bytes(&self.signing_public).map_err(|_| Erreur::CleInvalide)?;
        if vk.is_weak() {
            return Err(Erreur::CleInvalide);
        }
        Ok(())
    }
}

/// Sa propre chaîne d'envoi dans un groupe.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SenderKeyState {
    v: u8,
    #[serde(with = "crate::serde_b64")]
    group_id: [u8; 16],
    #[serde(with = "crate::serde_b64")]
    chain_key: [u8; 32],
    iteration: u32,
    #[serde(with = "crate::serde_b64")]
    signing_seed: [u8; 32],
}

impl SenderKeyState {
    /// Une chaîne neuve. Ordre de tirage : clé de chaîne (32), graine
    /// Ed25519 (32).
    pub fn generate(group_id: [u8; 16], rng: &mut (impl CryptoRng + ?Sized)) -> Self {
        let chain_key = Zeroizing::new(bytes::<32>(rng));
        let seed = Zeroizing::new(bytes::<32>(rng));
        Self::generate_with(group_id, &chain_key, &seed)
    }

    /// Une chaîne à partir des secrets donnés (les vecteurs).
    pub fn generate_with(
        group_id: [u8; 16],
        chain_key: &[u8; 32],
        signing_seed: &[u8; 32],
    ) -> Self {
        SenderKeyState {
            v: 1,
            group_id,
            chain_key: *chain_key,
            iteration: 0,
            signing_seed: *signing_seed,
        }
    }

    fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.signing_seed)
    }

    /// La clé publique Ed25519 de la chaîne.
    pub fn signing_public(&self) -> [u8; 32] {
        self.signing_key().verifying_key().to_bytes()
    }

    /// L'identifiant d'expéditeur.
    pub fn sender_id(&self) -> [u8; 8] {
        sender_id_of(&self.signing_public())
    }

    /// L'identifiant du groupe.
    pub fn group_id(&self) -> [u8; 16] {
        self.group_id
    }

    /// L'itération courante (celle du prochain message).
    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    /// La distribution de la chaîne à son itération courante.
    pub fn distribution(&self) -> SenderKeyDistribution {
        SenderKeyDistribution {
            group_id: self.group_id,
            sender_id: self.sender_id(),
            iteration: self.iteration,
            chain_key: self.chain_key,
            signing_public: self.signing_public(),
        }
    }

    /// Chiffre et signe un message de groupe (jeton décodé).
    pub fn encrypt_token(&mut self, text: &str) -> Resultat<Token> {
        if text.len() > crate::session::MAX_PLAINTEXT {
            return Err(Erreur::TropGrand);
        }
        let next_iteration = self.iteration.checked_add(1).ok_or(Erreur::Epuise)?;
        let ck = Zeroizing::new(self.chain_key);
        let (next, mk) = kdf_ck(&ck);
        let (key, nonce) = message_key(&mk);
        let mut msg = GroupMessage {
            group_id: self.group_id,
            sender_id: self.sender_id(),
            iteration: self.iteration,
            ciphertext: Vec::new(),
            signature: [0u8; 64],
        };
        msg.ciphertext = aes_gcm_seal(&key, &nonce, &msg.prefix(), &pad(text.as_bytes()))?;
        msg.signature = self.signing_key().sign(&msg.signed_bytes()).to_bytes();
        self.chain_key = *next;
        self.iteration = next_iteration;
        Ok(Token::Group(msg))
    }

    /// Chiffre et signe un message de groupe : `[[BROCOLIS:v3:…]]`.
    pub fn encrypt(&mut self, text: &str) -> Resultat<String> {
        Ok(self.encrypt_token(text)?.encode())
    }

    /// L'état en JSON.
    pub fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Relit un état JSON.
    pub fn from_json(text: &str) -> Resultat<Self> {
        let s: Self = serde_json::from_str(text).map_err(|_| Erreur::Etat)?;
        if s.v != 1 {
            return Err(Erreur::Etat);
        }
        Ok(s)
    }
}

#[derive(Clone, Serialize, Deserialize, Zeroize)]
struct GroupSkippedKey {
    iteration: u32,
    #[serde(with = "crate::serde_b64")]
    mk: [u8; 32],
    stored_at: u64,
}

/// La chaîne d'un autre membre, reçue par une distribution.
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ReceivedSenderKey {
    v: u8,
    #[serde(with = "crate::serde_b64")]
    group_id: [u8; 16],
    #[serde(with = "crate::serde_b64")]
    sender_id: [u8; 8],
    #[serde(with = "crate::serde_b64")]
    chain_key: [u8; 32],
    iteration: u32,
    #[serde(with = "crate::serde_b64")]
    signing_public: [u8; 32],
    skipped: Vec<GroupSkippedKey>,
}

impl ReceivedSenderKey {
    /// La chaîne d'une distribution (vérifiée).
    pub fn from_distribution(d: &SenderKeyDistribution) -> Resultat<Self> {
        d.check()?;
        Ok(ReceivedSenderKey {
            v: 1,
            group_id: d.group_id,
            sender_id: d.sender_id,
            chain_key: d.chain_key,
            iteration: d.iteration,
            signing_public: d.signing_public,
            skipped: Vec::new(),
        })
    }

    /// L'identifiant du groupe.
    pub fn group_id(&self) -> [u8; 16] {
        self.group_id
    }

    /// L'identifiant d'expéditeur.
    pub fn sender_id(&self) -> [u8; 8] {
        self.sender_id
    }

    /// Vrai si ce message de groupe est de cette chaîne.
    pub fn matches(&self, msg: &GroupMessage) -> bool {
        msg.group_id == self.group_id && msg.sender_id == self.sender_id
    }

    /// Le nombre de clés sautées gardées.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// Vérifie la signature puis déchiffre. Transactionnel ; un message
    /// déjà lu donne [`Erreur::Rejoue`].
    pub fn decrypt(&mut self, msg: &GroupMessage, now: u64) -> Resultat<String> {
        if !self.matches(msg) {
            return Err(Erreur::ExpediteurInconnu);
        }
        ed25519_verify(&self.signing_public, &msg.signed_bytes(), &msg.signature)?;
        let mut next = self.clone();
        next.skipped
            .retain(|k| k.stored_at.saturating_add(MAX_SKIP_AGE) > now);
        let mk = if msg.iteration < next.iteration {
            let pos = next
                .skipped
                .iter()
                .position(|k| k.iteration == msg.iteration)
                .ok_or(Erreur::Rejoue)?;
            let mut k = next.skipped.remove(pos);
            let mk = Zeroizing::new(k.mk);
            k.zeroize();
            mk
        } else {
            if u64::from(msg.iteration) - u64::from(next.iteration) > u64::from(MAX_SKIP) {
                return Err(Erreur::TropDeClesSautees);
            }
            let mut ck = Zeroizing::new(next.chain_key);
            while next.iteration < msg.iteration {
                let (n, mk) = kdf_ck(&ck);
                next.skipped.push(GroupSkippedKey {
                    iteration: next.iteration,
                    mk: *mk,
                    stored_at: now,
                });
                *ck = *n;
                next.iteration += 1;
            }
            let (n, mk) = kdf_ck(&ck);
            next.chain_key = *n;
            next.iteration = next.iteration.checked_add(1).ok_or(Erreur::Epuise)?;
            let max = MAX_SKIP as usize;
            if next.skipped.len() > max {
                let extra = next.skipped.len() - max;
                for mut k in next.skipped.drain(..extra) {
                    k.zeroize();
                }
            }
            mk
        };
        let (key, nonce) = message_key(&mk);
        let padded = aes_gcm_open(&key, &nonce, &msg.prefix(), &msg.ciphertext)?;
        let text = String::from_utf8(unpad(&padded)?.to_vec()).map_err(|_| Erreur::Utf8)?;
        *self = next;
        Ok(text)
    }

    /// L'état en JSON.
    pub fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Relit un état JSON.
    pub fn from_json(text: &str) -> Resultat<Self> {
        let s: Self = serde_json::from_str(text).map_err(|_| Erreur::Etat)?;
        if s.v != 1
            || s.skipped.len() > MAX_SKIP as usize
            || sender_id_of(&s.signing_public) != s.sender_id
        {
            return Err(Erreur::Etat);
        }
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasard::Deterministic;

    fn group(token: &str) -> GroupMessage {
        match Token::decode(token).unwrap() {
            Token::Group(g) => g,
            _ => panic!(),
        }
    }

    #[test]
    fn aller_retour_desordre_rejeu() {
        let mut rng = Deterministic::new(b"groupe");
        let gid = new_group_id(&mut rng);
        let mut s = SenderKeyState::generate(gid, &mut rng);
        let d = SenderKeyDistribution::from_bytes(&s.distribution().to_bytes()).unwrap();
        let mut r = ReceivedSenderKey::from_distribution(&d).unwrap();
        let msgs: Vec<String> = (0..5)
            .map(|i| s.encrypt(&format!("m{i}")).unwrap())
            .collect();
        for i in [3, 0, 4, 1, 2] {
            assert_eq!(r.decrypt(&group(&msgs[i]), 0).unwrap(), format!("m{i}"));
        }
        assert_eq!(r.skipped_len(), 0);
        assert_eq!(r.decrypt(&group(&msgs[2]), 0), Err(Erreur::Rejoue));
        let mut bad = group(&msgs[1]);
        bad.ciphertext[0] ^= 1;
        assert_eq!(r.decrypt(&bad, 0), Err(Erreur::Signature));
        let back = ReceivedSenderKey::from_json(&r.to_json()).unwrap();
        assert_eq!(back.sender_id(), s.sender_id());
    }

    #[test]
    fn distribution_verifiee() {
        let mut rng = Deterministic::new(b"dist");
        let s = SenderKeyState::generate([1; 16], &mut rng);
        let mut b = s.distribution().to_bytes().to_vec();
        b[16] ^= 1;
        assert_eq!(SenderKeyDistribution::from_bytes(&b), Err(Erreur::Format));
        assert_eq!(
            SenderKeyDistribution::from_bytes(&b[..91]),
            Err(Erreur::Format)
        );
    }
}
