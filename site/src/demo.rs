//! La démonstration « Ce que tu écris, ce que voit l'app » : découpe un message
//! en texte clair et en secrets `((…))`, et fabrique des jetons
//! `[[BROCOLIS:v1:…]]` **factices**, de la bonne longueur (nonce 12 octets +
//! chiffré + tag 16 octets, en base64). Rien n'est chiffré ici : c'est une
//! illustration, la vraie cryptographie vit dans l'app.

/// Un morceau du message.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Segment {
    Plain(String),
    Secret(String),
}

/// Découpe `text` : les passages `((entre doubles parenthèses))` sont des
/// secrets ; avec `all`, tout le message en est un. Un `((` jamais fermé reste
/// du texte, comme dans l'app.
pub fn segments(text: &str, all: bool) -> Vec<Segment> {
    if all {
        let whole = text.replace("((", "").replace("))", "");
        return if whole.trim().is_empty() {
            Vec::new()
        } else {
            vec![Segment::Secret(whole)]
        };
    }
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("((") {
        let after = &rest[start + 2..];
        let Some(len) = after.find("))") else { break };
        if start > 0 {
            out.push(Segment::Plain(rest[..start].to_owned()));
        }
        let secret = &after[..len];
        if secret.is_empty() {
            out.push(Segment::Plain("(())".to_owned()));
        } else {
            out.push(Segment::Secret(secret.to_owned()));
        }
        rest = &after[len + 2..];
    }
    if !rest.is_empty() {
        out.push(Segment::Plain(rest.to_owned()));
    }
    out
}

/// Le nombre de secrets d'un découpage.
pub fn secret_count(segments: &[Segment]) -> usize {
    segments
        .iter()
        .filter(|s| matches!(s, Segment::Secret(_)))
        .count()
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// FNV-1a : le même secret donne le même jeton, à `salt` près.
fn hash(text: &str, salt: u64) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325 ^ salt, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Un jeton factice pour `secret` : `[[BROCOLIS:v1:<base64>]]`, avec autant de
/// caractères qu'un vrai (12 + n + 16 octets).
pub fn fake_token(secret: &str, salt: u64) -> String {
    let bytes = 12 + secret.len() + 16;
    let len = bytes.div_ceil(3) * 4;
    let pad = (3 - bytes % 3) % 3;
    let mut state = hash(secret, salt) | 1;
    let mut body = String::with_capacity(len);
    for _ in 0..len - pad {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        body.push(ALPHABET[(state % 64) as usize] as char);
    }
    body.extend(std::iter::repeat_n('=', pad));
    format!("[[BROCOLIS:v1:{body}]]")
}

/// Des caractères au hasard (pour l'effet de brouillage), à partir de `seed`.
pub fn noise(len: usize, seed: u64) -> String {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            ALPHABET[(state % 64) as usize] as char
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plain(s: &str) -> Segment {
        Segment::Plain(s.into())
    }
    fn secret(s: &str) -> Segment {
        Segment::Secret(s.into())
    }

    #[test]
    fn only_marked_passages_are_secrets() {
        assert_eq!(
            segments("Rendez-vous ((20h)) au ((ciné)).", false),
            vec![
                plain("Rendez-vous "),
                secret("20h"),
                plain(" au "),
                secret("ciné"),
                plain(".")
            ]
        );
        assert_eq!(
            segments("rien à cacher", false),
            vec![plain("rien à cacher")]
        );
        assert_eq!(segments("", false), vec![]);
    }

    #[test]
    fn unclosed_and_empty_markers_stay_text() {
        assert_eq!(segments("a ((b", false), vec![plain("a ((b")]);
        assert_eq!(
            segments("a (()) b", false),
            vec![plain("a "), plain("(())"), plain(" b")]
        );
    }

    #[test]
    fn everything_becomes_one_secret() {
        assert_eq!(segments("a ((b)) c", true), vec![secret("a b c")]);
        assert_eq!(segments("   ", true), vec![]);
        assert_eq!(secret_count(&segments("((x)) ((y))", false)), 2);
    }

    #[test]
    fn tokens_look_like_real_ones() {
        let t = fake_token("20h", 7);
        assert!(t.starts_with("[[BROCOLIS:v1:") && t.ends_with("]]"));
        // 12 + 3 + 16 = 31 octets → 44 caractères base64, dont « == ».
        let body = &t["[[BROCOLIS:v1:".len()..t.len() - 2];
        assert_eq!(body.len(), 44);
        assert!(body.ends_with("=="));
        // 32 octets → un seul « = ».
        assert!(fake_token("20h!", 7).ends_with("=]]") && !fake_token("20h!", 7).ends_with("==]]"));
        assert_eq!(fake_token("20h", 7), t, "stable");
        assert_ne!(fake_token("21h", 7), t);
        assert_eq!(noise(10, 3).len(), 10);
    }
}
