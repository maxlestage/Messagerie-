//! Le jeton v4 (§9.4) : `[[BROCOLIS:v4:<base64>]]`, encodage et décodage
//! **stricts**, et l'en-tête de cliquet (§9.3), qui voyage chiffré.
//!
//! ```text
//! octet 0 : type
//!   0x01 premier message : EK_A (32) ‖ CT ML-KEM (1 088) ‖ préambule chiffré (48)
//!                          ‖ nonce d'en-tête (12) ‖ longueur (u16 BE) ‖ en-tête chiffré ‖ chiffré
//!   0x02 message         : nonce d'en-tête (12) ‖ longueur (u16 BE) ‖ en-tête chiffré ‖ chiffré
//! en-tête (clair) = DH (32) ‖ PN (u32 BE) ‖ N (u32 BE) ‖ drapeaux (1) ‖ ek (1 184) ‖ [ct (1 088)]
//! en-tête chiffré : 1 241 ou 2 329 octets ; chiffré : 160·k + 16 octets, k ≥ 1
//! ```
//!
//! Aucun identifiant n'est en clair : sans la clé d'en-tête, un 0x02 ne se
//! distingue pas d'octets aléatoires de même longueur.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::paquet::PQPK_LEN;
use crate::remplissage::BLOC;
use crate::{Erreur, Resultat};

/// Le début d'un jeton v4.
pub const HEAD: &str = "[[BROCOLIS:v4:";
const END: &str = "]]";

/// Type 0x01 : premier message d'une session établie par paquet.
pub const TYPE_INITIAL: u8 = 0x01;
/// Type 0x02 : tout autre message (premier message à clé partagée compris).
pub const TYPE_MESSAGE: u8 = 0x02;

/// La longueur d'un chiffré ML-KEM-768.
pub const KEM_CT_LEN: usize = 1_088;
/// La longueur du préambule chiffré : IK_A (32) ‖ tag (16).
pub const PREAMBLE_LEN: usize = 48;
/// L'en-tête en clair, sans `ct` : DH, PN, N, drapeaux, ek.
pub const HEADER_LEN: usize = 32 + 4 + 4 + 1 + PQPK_LEN;
/// L'en-tête en clair, avec `ct`.
pub const HEADER_LEN_CT: usize = HEADER_LEN + KEM_CT_LEN;
/// La taille maximale d'un jeton v4 décodé : 256 Kio.
pub const MAX_TOKEN_BYTES: usize = 256 * 1024;

/// Le genre de ce que porte un message (premier octet du clair, §9.3).
pub const GENRE_TEXTE: u8 = 0x00;
/// Une distribution de chaîne de groupe (§4.5).
pub const GENRE_DISTRIBUTION: u8 = 0x01;

/// L'en-tête du cliquet v4, en clair.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header4 {
    /// La clé publique de cliquet X25519 de l'expéditeur.
    pub dh: [u8; 32],
    /// La longueur de sa chaîne d'envoi précédente.
    pub pn: u32,
    /// Le numéro du message dans sa chaîne.
    pub n: u32,
    /// Sa clé d'encapsulation ML-KEM-768 de cliquet courante (1 184 octets).
    pub ek: Vec<u8>,
    /// L'encapsulation qui a ouvert cette chaîne (absente de la première
    /// chaîne de l'initiateur).
    pub ct: Option<Vec<u8>>,
}

impl Header4 {
    /// Les octets de l'en-tête en clair.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN_CT);
        out.extend_from_slice(&self.dh);
        out.extend_from_slice(&self.pn.to_be_bytes());
        out.extend_from_slice(&self.n.to_be_bytes());
        out.push(u8::from(self.ct.is_some()));
        out.extend_from_slice(&self.ek);
        if let Some(ct) = &self.ct {
            out.extend_from_slice(ct);
        }
        out
    }

    /// Relit un en-tête en clair (strict : longueur, drapeaux).
    pub fn from_bytes(b: &[u8]) -> Resultat<Self> {
        let mut r = Reader { data: b };
        let dh = r.array()?;
        let pn = r.u32()?;
        let n = r.u32()?;
        let flags = r.u8()?;
        let ek = r.take(PQPK_LEN)?.to_vec();
        let ct = match flags {
            0x00 => None,
            0x01 => Some(r.take(KEM_CT_LEN)?.to_vec()),
            _ => return Err(Erreur::Format),
        };
        if !r.data.is_empty() {
            return Err(Erreur::Format);
        }
        Ok(Header4 { dh, pn, n, ek, ct })
    }
}

/// La partie chiffrée commune à tous les messages v4.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body4 {
    /// Le nonce de l'en-tête (dérivé de la clé de message, §9.1).
    pub header_nonce: [u8; 12],
    /// L'en-tête chiffré (AES-256-GCM ‖ tag).
    pub header: Vec<u8>,
    /// Le chiffré du message (AES-256-GCM ‖ tag).
    pub ciphertext: Vec<u8>,
}

/// Le préambule d'un premier message v4 (type 0x01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Preamble4 {
    /// La clé éphémère EK_A.
    pub ephemeral: [u8; 32],
    /// L'encapsulation ML-KEM-768 vers la PQPK du répondeur.
    pub kem_ciphertext: Vec<u8>,
    /// IK_A chiffrée (§9.4).
    pub sealed_identity: [u8; PREAMBLE_LEN],
}

impl Preamble4 {
    /// Les données associées du préambule chiffré : `0x01 ‖ EK_A ‖ CT`.
    pub fn aad(&self) -> Vec<u8> {
        [&[TYPE_INITIAL][..], &self.ephemeral, &self.kem_ciphertext].concat()
    }
}

/// Un jeton v4 décodé.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token4 {
    /// Type 0x01.
    Initial(Preamble4, Body4),
    /// Type 0x02.
    Message(Body4),
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

    fn u16(&mut self) -> Resultat<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Resultat<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}

fn parse_body(r: &mut Reader<'_>) -> Resultat<Body4> {
    let header_nonce = r.array()?;
    let len = usize::from(r.u16()?);
    if len != HEADER_LEN + 16 && len != HEADER_LEN_CT + 16 {
        return Err(Erreur::Format);
    }
    let header = r.take(len)?.to_vec();
    let ciphertext = r.data.to_vec();
    if ciphertext.len() < BLOC + 16 || !(ciphertext.len() - 16).is_multiple_of(BLOC) {
        return Err(Erreur::Format);
    }
    Ok(Body4 {
        header_nonce,
        header,
        ciphertext,
    })
}

impl Body4 {
    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.header_nonce);
        // La longueur est l'une des deux valeurs permises (< 65 536).
        out.extend_from_slice(&(self.header.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.header);
        out.extend_from_slice(&self.ciphertext);
    }
}

impl Token4 {
    /// L'octet de type.
    pub fn kind(&self) -> u8 {
        match self {
            Token4::Initial(..) => TYPE_INITIAL,
            Token4::Message(_) => TYPE_MESSAGE,
        }
    }

    /// La partie chiffrée.
    pub fn body(&self) -> &Body4 {
        match self {
            Token4::Initial(_, b) | Token4::Message(b) => b,
        }
    }

    /// Décode les octets d'un jeton v4.
    pub fn from_bytes(data: &[u8]) -> Resultat<Self> {
        if data.len() > MAX_TOKEN_BYTES {
            return Err(Erreur::TropGrand);
        }
        let mut r = Reader { data };
        match r.u8()? {
            TYPE_INITIAL => {
                let ephemeral = r.array()?;
                let kem_ciphertext = r.take(KEM_CT_LEN)?.to_vec();
                let sealed_identity = r.array()?;
                let body = parse_body(&mut r)?;
                Ok(Token4::Initial(
                    Preamble4 {
                        ephemeral,
                        kem_ciphertext,
                        sealed_identity,
                    },
                    body,
                ))
            }
            TYPE_MESSAGE => Ok(Token4::Message(parse_body(&mut r)?)),
            _ => Err(Erreur::Format),
        }
    }

    /// Les octets du jeton.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![self.kind()];
        if let Token4::Initial(p, _) = self {
            out.extend_from_slice(&p.ephemeral);
            out.extend_from_slice(&p.kem_ciphertext);
            out.extend_from_slice(&p.sealed_identity);
        }
        self.body().write(&mut out);
        out
    }

    /// Décode un jeton `[[BROCOLIS:v4:<base64>]]`, exactement.
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

    /// Le jeton `[[BROCOLIS:v4:<base64>]]`.
    pub fn encode(&self) -> String {
        format!("{HEAD}{}{END}", STANDARD.encode(self.to_bytes()))
    }
}

/// Les jetons v4 d'un texte collé, dans l'ordre, décodés ou non.
pub fn find_all(text: &str) -> Vec<(&str, Resultat<Token4>)> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find(HEAD) {
        let Some(end) = rest[start..].find(END) else {
            break;
        };
        let token = &rest[start..start + end + END.len()];
        out.push((token, Token4::decode(token)));
        rest = &rest[start + end + END.len()..];
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(ct: bool) -> Body4 {
        Body4 {
            header_nonce: [3; 12],
            header: vec![4; if ct { HEADER_LEN_CT } else { HEADER_LEN } + 16],
            ciphertext: vec![5; 176],
        }
    }

    #[test]
    fn aller_retour() {
        for t in [
            Token4::Message(body(false)),
            Token4::Message(body(true)),
            Token4::Initial(
                Preamble4 {
                    ephemeral: [1; 32],
                    kem_ciphertext: vec![2; KEM_CT_LEN],
                    sealed_identity: [6; PREAMBLE_LEN],
                },
                body(false),
            ),
        ] {
            assert_eq!(Token4::decode(&t.encode()).unwrap(), t);
        }
    }

    #[test]
    fn refus_stricts() {
        let ok = Token4::Message(body(false)).to_bytes();
        // Type inconnu.
        let mut b = ok.clone();
        b[0] = 0x03;
        assert_eq!(Token4::from_bytes(&b), Err(Erreur::Format));
        // Longueur d'en-tête non permise.
        let mut b = ok.clone();
        b[13] = 0x00;
        b[14] = 0x10;
        assert_eq!(Token4::from_bytes(&b), Err(Erreur::Format));
        // Chiffré tronqué.
        assert_eq!(Token4::from_bytes(&ok[..ok.len() - 1]), Err(Erreur::Format));
        assert_eq!(Token4::from_bytes(&[]), Err(Erreur::Format));
        assert_eq!(
            Token4::decode("[[BROCOLIS:v3:AA==]]"),
            Err(Erreur::JetonAbsent)
        );
    }

    #[test]
    fn en_tete_strict() {
        let h = Header4 {
            dh: [7; 32],
            pn: 1,
            n: 2,
            ek: vec![8; PQPK_LEN],
            ct: Some(vec![9; KEM_CT_LEN]),
        };
        let b = h.to_bytes();
        assert_eq!(b.len(), HEADER_LEN_CT);
        assert_eq!(Header4::from_bytes(&b).unwrap(), h);
        let mut bad = b.clone();
        bad[40] = 2;
        assert_eq!(Header4::from_bytes(&bad), Err(Erreur::Format));
        assert_eq!(Header4::from_bytes(&b[..HEADER_LEN]), Err(Erreur::Format));
    }
}
