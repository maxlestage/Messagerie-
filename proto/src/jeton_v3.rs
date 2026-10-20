//! Le jeton v3 (§4.4) : `[[BROCOLIS:v3:<base64>]]`, encodage et décodage
//! **stricts** (toute longueur, tout octet de type ou de mode inattendu, tout
//! champ réservé non nul est refusé ; aucune panique).
//!
//! ```text
//! octet 0 : type
//!   0x01 premier message   : id session (8) ‖ IK_A (32) ‖ EK_A (32) ‖ mode (1)
//!                            ‖ [CT ML-KEM (1 088) si mode = 0x01]
//!                            ‖ id SPK (u32 BE) ‖ id PQPK (u32 BE)
//!                            ‖ en-tête (40) ‖ chiffré
//!   0x02 message           : id session (8) ‖ en-tête (40) ‖ chiffré
//!   0x03 distribution      : id session (8) ‖ en-tête (40) ‖ chiffré
//!                            (une chaîne de groupe, §4.5, par la session à deux)
//!   0x04 message de groupe : id groupe (16) ‖ id expéditeur (8)
//!                            ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)
//! en-tête = DH_pub (32) ‖ PN (u32 BE) ‖ N (u32 BE)
//! chiffré = AES-256-GCM(remplissage §3.3) ‖ tag : 160·k + 16 octets, k ≥ 1
//! ```
//!
//! `mode` (le drapeau `pq` de la spécification) : `0x00` X25519 seul, `0x01`
//! X25519 + ML-KEM-768, `0x02` clé partagée (alors IK_A, id SPK et id PQPK
//! sont nuls). En mode `0x00`, id PQPK est nul.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::remplissage::BLOC;
use crate::{Erreur, Resultat};

/// Le début d'un jeton v3.
pub const HEAD: &str = "[[BROCOLIS:v3:";
const END: &str = "]]";

/// Type 0x01 : premier message, qui établit la session.
pub const TYPE_INITIAL: u8 = 0x01;
/// Type 0x02 : message d'une session établie.
pub const TYPE_MESSAGE: u8 = 0x02;
/// Type 0x03 : distribution d'une chaîne de groupe.
pub const TYPE_DISTRIBUTION: u8 = 0x03;
/// Type 0x04 : message de groupe signé.
pub const TYPE_GROUP: u8 = 0x04;

/// La longueur d'un chiffré ML-KEM-768.
pub const KEM_CT_LEN: usize = 1_088;
/// La longueur d'un en-tête de ratchet.
pub const HEADER_LEN: usize = 40;
/// La taille maximale d'un jeton v3 décodé : 256 Kio.
pub const MAX_TOKEN_BYTES: usize = 256 * 1024;

/// Le mode d'établissement d'une session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode {
    /// X25519 seul (`pq = 0`) : « session non post-quantique ».
    Classic,
    /// X25519 + ML-KEM-768 (`pq = 1`).
    Hybrid,
    /// Clé Brocolis partagée (extension, octet `0x02`).
    Psk,
}

impl Mode {
    /// L'octet du mode.
    pub fn byte(self) -> u8 {
        match self {
            Mode::Classic => 0x00,
            Mode::Hybrid => 0x01,
            Mode::Psk => 0x02,
        }
    }

    fn from_byte(b: u8) -> Resultat<Self> {
        match b {
            0x00 => Ok(Mode::Classic),
            0x01 => Ok(Mode::Hybrid),
            0x02 => Ok(Mode::Psk),
            _ => Err(Erreur::Format),
        }
    }
}

/// L'en-tête d'un message du Double Ratchet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// La clé publique de cliquet de l'expéditeur.
    pub dh: [u8; 32],
    /// La longueur de sa chaîne d'envoi précédente.
    pub pn: u32,
    /// Le numéro du message dans sa chaîne d'envoi.
    pub n: u32,
}

impl Header {
    /// Les 40 octets de l'en-tête.
    pub fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..32].copy_from_slice(&self.dh);
        out[32..36].copy_from_slice(&self.pn.to_be_bytes());
        out[36..].copy_from_slice(&self.n.to_be_bytes());
        out
    }

    fn parse(r: &mut Reader<'_>) -> Resultat<Self> {
        Ok(Header {
            dh: r.array()?,
            pn: r.u32()?,
            n: r.u32()?,
        })
    }
}

/// Un message chiffré par le ratchet d'une session (types 0x02 et 0x03, et la
/// fin d'un 0x01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    /// L'identifiant de session : `SHA-256(AD)[0..8]`.
    pub session_id: [u8; 8],
    /// L'en-tête du ratchet.
    pub header: Header,
    /// Le chiffré AES-256-GCM ‖ tag.
    pub ciphertext: Vec<u8>,
}

/// Le premier message d'une session (type 0x01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initial {
    /// La clé d'identité X25519 de l'initiateur (nulle en mode clé partagée).
    pub identity: [u8; 32],
    /// La clé éphémère EK de l'initiateur.
    pub ephemeral: [u8; 32],
    /// Le mode d'établissement.
    pub mode: Mode,
    /// Le chiffré ML-KEM-768 (mode hybride seulement).
    pub kem_ciphertext: Option<Vec<u8>>,
    /// L'identifiant de la clé pré-signée du répondeur utilisée.
    pub spk_id: u32,
    /// L'identifiant de sa clé ML-KEM utilisée (0 sans ML-KEM).
    pub pq_id: u32,
    /// Le message lui-même.
    pub envelope: Envelope,
}

/// Un message de groupe (type 0x04).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupMessage {
    /// L'identifiant du groupe.
    pub group_id: [u8; 16],
    /// L'identifiant de l'expéditeur (de sa chaîne).
    pub sender_id: [u8; 8],
    /// L'itération de la chaîne.
    pub iteration: u32,
    /// Le chiffré AES-256-GCM ‖ tag.
    pub ciphertext: Vec<u8>,
    /// La signature Ed25519 de tout ce qui précède (type compris).
    pub signature: [u8; 64],
}

impl GroupMessage {
    /// Les 29 premiers octets : type ‖ id groupe ‖ id expéditeur ‖
    /// itération (les données associées du chiffrement).
    pub fn prefix(&self) -> [u8; 29] {
        let mut out = [0u8; 29];
        out[0] = TYPE_GROUP;
        out[1..17].copy_from_slice(&self.group_id);
        out[17..25].copy_from_slice(&self.sender_id);
        out[25..].copy_from_slice(&self.iteration.to_be_bytes());
        out
    }

    /// Ce que couvre la signature : préfixe ‖ chiffré.
    pub fn signed_bytes(&self) -> Vec<u8> {
        [self.prefix().as_slice(), &self.ciphertext].concat()
    }
}

/// Un jeton v3 décodé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    /// Type 0x01.
    Initial(Initial),
    /// Type 0x02.
    Message(Envelope),
    /// Type 0x03.
    Distribution(Envelope),
    /// Type 0x04.
    Group(GroupMessage),
}

struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Resultat<&'a [u8]> {
        if self.data.len() < n {
            return Err(Erreur::Format);
        }
        let (head, rest) = self.data.split_at(n);
        self.data = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Resultat<[u8; N]> {
        self.take(N)?.try_into().map_err(|_| Erreur::Format)
    }

    fn u8(&mut self) -> Resultat<u8> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Resultat<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}

/// Vérifie la longueur d'un chiffré : 160·k + 16 octets, k ≥ 1.
fn check_ciphertext(ct: &[u8]) -> Resultat<()> {
    if ct.len() < BLOC + 16 || !(ct.len() - 16).is_multiple_of(BLOC) {
        return Err(Erreur::Format);
    }
    Ok(())
}

impl Token {
    /// Décode les octets d'un jeton v3.
    pub fn from_bytes(data: &[u8]) -> Resultat<Self> {
        if data.len() > MAX_TOKEN_BYTES {
            return Err(Erreur::TropGrand);
        }
        let mut r = Reader { data };
        let kind = r.u8()?;
        match kind {
            TYPE_INITIAL => {
                let session_id = r.array()?;
                let identity = r.array()?;
                let ephemeral = r.array()?;
                let mode = Mode::from_byte(r.u8()?)?;
                let kem_ciphertext = match mode {
                    Mode::Hybrid => Some(r.take(KEM_CT_LEN)?.to_vec()),
                    _ => None,
                };
                let spk_id = r.u32()?;
                let pq_id = r.u32()?;
                match mode {
                    Mode::Classic if pq_id != 0 => return Err(Erreur::Format),
                    Mode::Psk if identity != [0u8; 32] || spk_id != 0 || pq_id != 0 => {
                        return Err(Erreur::Format);
                    }
                    _ => {}
                }
                let header = Header::parse(&mut r)?;
                let ciphertext = r.data.to_vec();
                check_ciphertext(&ciphertext)?;
                Ok(Token::Initial(Initial {
                    identity,
                    ephemeral,
                    mode,
                    kem_ciphertext,
                    spk_id,
                    pq_id,
                    envelope: Envelope {
                        session_id,
                        header,
                        ciphertext,
                    },
                }))
            }
            TYPE_MESSAGE | TYPE_DISTRIBUTION => {
                let session_id = r.array()?;
                let header = Header::parse(&mut r)?;
                let ciphertext = r.data.to_vec();
                check_ciphertext(&ciphertext)?;
                let env = Envelope {
                    session_id,
                    header,
                    ciphertext,
                };
                Ok(if kind == TYPE_MESSAGE {
                    Token::Message(env)
                } else {
                    Token::Distribution(env)
                })
            }
            TYPE_GROUP => {
                let group_id = r.array()?;
                let sender_id = r.array()?;
                let iteration = r.u32()?;
                let rest = r.data;
                if rest.len() < 64 {
                    return Err(Erreur::Format);
                }
                let (ct, sig) = rest.split_at(rest.len() - 64);
                check_ciphertext(ct)?;
                Ok(Token::Group(GroupMessage {
                    group_id,
                    sender_id,
                    iteration,
                    ciphertext: ct.to_vec(),
                    signature: sig.try_into().map_err(|_| Erreur::Format)?,
                }))
            }
            _ => Err(Erreur::Format),
        }
    }

    /// Les octets du jeton.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            Token::Initial(i) => {
                out.push(TYPE_INITIAL);
                out.extend_from_slice(&i.envelope.session_id);
                out.extend_from_slice(&i.identity);
                out.extend_from_slice(&i.ephemeral);
                out.push(i.mode.byte());
                if let Some(ct) = &i.kem_ciphertext {
                    out.extend_from_slice(ct);
                }
                out.extend_from_slice(&i.spk_id.to_be_bytes());
                out.extend_from_slice(&i.pq_id.to_be_bytes());
                out.extend_from_slice(&i.envelope.header.to_bytes());
                out.extend_from_slice(&i.envelope.ciphertext);
            }
            Token::Message(e) | Token::Distribution(e) => {
                out.push(if matches!(self, Token::Message(_)) {
                    TYPE_MESSAGE
                } else {
                    TYPE_DISTRIBUTION
                });
                out.extend_from_slice(&e.session_id);
                out.extend_from_slice(&e.header.to_bytes());
                out.extend_from_slice(&e.ciphertext);
            }
            Token::Group(g) => {
                out.extend_from_slice(&g.signed_bytes());
                out.extend_from_slice(&g.signature);
            }
        }
        out
    }

    /// Décode un jeton `[[BROCOLIS:v3:<base64>]]`, exactement (sans espace
    /// autour ; voir [`find_all`] pour un texte collé).
    pub fn decode(text: &str) -> Resultat<Self> {
        let b = text
            .strip_prefix(HEAD)
            .and_then(|t| t.strip_suffix(END))
            .ok_or(Erreur::JetonAbsent)?;
        if b.len() > 4 * MAX_TOKEN_BYTES.div_ceil(3) {
            return Err(Erreur::TropGrand);
        }
        let data = STANDARD.decode(b).map_err(|_| Erreur::Base64)?;
        Self::from_bytes(&data)
    }

    /// Le jeton `[[BROCOLIS:v3:<base64>]]`.
    pub fn encode(&self) -> String {
        format!("{HEAD}{}{END}", STANDARD.encode(self.to_bytes()))
    }

    /// L'identifiant de session (types 0x01 à 0x03).
    pub fn session_id(&self) -> Option<[u8; 8]> {
        match self {
            Token::Initial(i) => Some(i.envelope.session_id),
            Token::Message(e) | Token::Distribution(e) => Some(e.session_id),
            Token::Group(_) => None,
        }
    }
}

/// Les jetons v3 d'un texte collé, dans l'ordre (chaque `[[BROCOLIS:v3:…]]`
/// complet), décodés ou non.
pub fn find_all(text: &str) -> Vec<(&str, Resultat<Token>)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(HEAD) {
        let Some(end) = rest[start..].find(END) else {
            break;
        };
        let token = &rest[start..start + end + END.len()];
        out.push((token, Token::decode(token)));
        rest = &rest[start + end + END.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env() -> Envelope {
        Envelope {
            session_id: [1; 8],
            header: Header {
                dh: [2; 32],
                pn: 3,
                n: 0x01020304,
            },
            ciphertext: vec![9; 176],
        }
    }

    #[test]
    fn aller_retour_de_chaque_type() {
        let tokens = [
            Token::Message(env()),
            Token::Distribution(env()),
            Token::Initial(Initial {
                identity: [4; 32],
                ephemeral: [5; 32],
                mode: Mode::Hybrid,
                kem_ciphertext: Some(vec![6; KEM_CT_LEN]),
                spk_id: 7,
                pq_id: 8,
                envelope: env(),
            }),
            Token::Initial(Initial {
                identity: [4; 32],
                ephemeral: [5; 32],
                mode: Mode::Classic,
                kem_ciphertext: None,
                spk_id: 7,
                pq_id: 0,
                envelope: env(),
            }),
            Token::Initial(Initial {
                identity: [0; 32],
                ephemeral: [5; 32],
                mode: Mode::Psk,
                kem_ciphertext: None,
                spk_id: 0,
                pq_id: 0,
                envelope: env(),
            }),
            Token::Group(GroupMessage {
                group_id: [1; 16],
                sender_id: [2; 8],
                iteration: 3,
                ciphertext: vec![4; 176],
                signature: [5; 64],
            }),
        ];
        for t in tokens {
            let text = t.encode();
            assert_eq!(Token::decode(&text).unwrap(), t);
            // Toute troncature est refusée (un chiffré de 336 octets tronqué
            // de 160 resterait bien formé : la signature ou le tag le
            // refusent ensuite).
            let bytes = t.to_bytes();
            for n in 0..bytes.len() {
                assert!(Token::from_bytes(&bytes[..n]).is_err(), "{n}");
            }
        }
    }

    #[test]
    fn refus_stricts() {
        let mut b = Token::Message(env()).to_bytes();
        b.push(0);
        assert_eq!(Token::from_bytes(&b), Err(Erreur::Format));
        let mut b = Token::Message(env()).to_bytes();
        b[0] = 0x05;
        assert_eq!(Token::from_bytes(&b), Err(Erreur::Format));
        let classic_with_pq = Token::Initial(Initial {
            identity: [4; 32],
            ephemeral: [5; 32],
            mode: Mode::Classic,
            kem_ciphertext: None,
            spk_id: 7,
            pq_id: 1,
            envelope: env(),
        });
        assert_eq!(
            Token::from_bytes(&classic_with_pq.to_bytes()),
            Err(Erreur::Format)
        );
        assert_eq!(
            Token::decode("[[BROCOLIS:v3:AAAA]] "),
            Err(Erreur::JetonAbsent)
        );
        assert_eq!(Token::decode("[[BROCOLIS:v3:A===]]"), Err(Erreur::Base64));
        assert_eq!(Token::from_bytes(&[]), Err(Erreur::Format));
        assert_eq!(
            Token::from_bytes(&vec![2u8; MAX_TOKEN_BYTES + 1]),
            Err(Erreur::TropGrand)
        );
    }

    #[test]
    fn jetons_dans_un_texte() {
        let a = Token::Message(env()).encode();
        let text = format!("avant {a} milieu [[BROCOLIS:v3:AAAA]] fin [[BROCOLIS:v3:");
        let found = find_all(&text);
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].0, a);
        assert!(found[0].1.is_ok() && found[1].1.is_err());
    }
}
