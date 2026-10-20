//! Le remplissage (§3.3) : la longueur d'un message ne se lit pas sur le
//! jeton. Avant chiffrement : texte ‖ `0x80` ‖ des `0x00` jusqu'au multiple
//! de 160 octets suivant (comme Signal). Au déchiffrement : retirer les
//! `0x00` de fin puis le `0x80` ; absent → refusé.

use zeroize::Zeroizing;

use crate::{Erreur, Resultat};

/// La taille des blocs de remplissage.
pub const BLOC: usize = 160;

/// `données ‖ 0x80 ‖ 0x00…` jusqu'au multiple de 160 suivant (au moins un
/// octet de remplissage : 159 octets donnent 160, 160 en donnent 320).
pub fn pad(data: &[u8]) -> Zeroizing<Vec<u8>> {
    let len = (data.len() / BLOC + 1) * BLOC;
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    out.extend_from_slice(data);
    out.push(0x80);
    out.resize(len, 0x00);
    out
}

/// Retire le remplissage. Refuse ([`Erreur::Remplissage`]) une longueur
/// qui n'est pas un multiple non nul de 160 (plus strict que la
/// spécification, voir `docs/SECURITE.md`) ou l'absence du `0x80`.
pub fn unpad(padded: &[u8]) -> Resultat<&[u8]> {
    if padded.is_empty() || !padded.len().is_multiple_of(BLOC) {
        return Err(Erreur::Remplissage);
    }
    let end = padded
        .iter()
        .rposition(|&b| b != 0x00)
        .ok_or(Erreur::Remplissage)?;
    if padded[end] != 0x80 {
        return Err(Erreur::Remplissage);
    }
    Ok(&padded[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longueurs() {
        for (n, attendu) in [
            (0, 160),
            (1, 160),
            (158, 160),
            (159, 160),
            (160, 320),
            (319, 320),
            (320, 480),
        ] {
            let data = vec![0x41u8; n];
            let p = pad(&data);
            assert_eq!(p.len(), attendu, "{n}");
            assert_eq!(p[n], 0x80);
            assert!(p[n + 1..].iter().all(|&b| b == 0));
            assert_eq!(unpad(&p).unwrap(), &data[..]);
        }
    }

    #[test]
    fn zeros_et_0x80_dans_le_texte() {
        let data = [0x80, 0x00, 0x00, 0x80, 0x00];
        assert_eq!(unpad(&pad(&data)).unwrap(), &data);
    }

    #[test]
    fn refus() {
        assert_eq!(unpad(&[]), Err(Erreur::Remplissage));
        assert_eq!(unpad(&[0u8; 160]), Err(Erreur::Remplissage));
        let mut p = pad(b"abc").to_vec();
        p[3] = 0x81;
        assert_eq!(unpad(&p), Err(Erreur::Remplissage));
        let p = pad(b"abc");
        assert_eq!(unpad(&p[..159]), Err(Erreur::Remplissage));
    }
}
