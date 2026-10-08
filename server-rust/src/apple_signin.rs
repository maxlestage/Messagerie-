//! « Se connecter avec Apple » : vérifie le jeton d'identité (JWT RS256) que
//! l'app reçoit d'Apple, pour savoir à coup sûr quel e-mail appartient à
//! l'appelant. Sert uniquement aux accès offerts (`BROCOLIS_PRO_EMAILS`).
//!
//! Vérifications : signature par une clé publique d'Apple (récupérée sur
//! https://appleid.apple.com/auth/keys et mise en cache), émetteur Apple,
//! audience = bundle ID de l'app, expiration, et e-mail marqué vérifié.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;

pub const APPLE_ISSUER: &str = "https://appleid.apple.com";
const APPLE_KEYS_URL: &str = "https://appleid.apple.com/auth/keys";
const KEYS_TTL: Duration = Duration::from_secs(60 * 60);

/// Bundle ID attendu dans `aud` : `APPLE_BUNDLE_ID`, sinon `APNS_BUNDLE_ID`,
/// sinon celui de l'app.
pub fn expected_audience() -> String {
    ["APPLE_BUNDLE_ID", "APNS_BUNDLE_ID"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.trim().is_empty()))
        .map(|v| v.trim().to_string())
        .unwrap_or_else(|| "rs.brocolis.messagerie".to_string())
}

/// Une clé publique d'Apple (JWK RSA).
#[derive(Clone, Debug, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub n: String,
    pub e: String,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Claims {
    email: Option<String>,
    /// Apple envoie tantôt `true`, tantôt `"true"`.
    email_verified: Option<serde_json::Value>,
}

#[derive(Debug, PartialEq)]
pub enum VerifyError {
    /// Jeton illisible, mal signé, expiré, ou pas destiné à cette app.
    Invalid(String),
    /// Jeton valide mais sans e-mail vérifié.
    NoVerifiedEmail,
    /// Clé de signature inconnue (Apple a peut-être tourné ses clés).
    UnknownKey,
}

/// Vérifie le jeton avec les clés fournies et renvoie l'e-mail (en minuscules).
/// Pure (pas de réseau) : c'est elle que les tests exercent.
pub fn verify_with_keys(token: &str, keys: &[Jwk], audience: &str) -> Result<String, VerifyError> {
    let header =
        jsonwebtoken::decode_header(token).map_err(|e| VerifyError::Invalid(e.to_string()))?;
    if header.alg != Algorithm::RS256 {
        return Err(VerifyError::Invalid(format!("algorithme {:?} refusé", header.alg)));
    }
    let kid = header.kid.ok_or_else(|| VerifyError::Invalid("kid absent".into()))?;
    let jwk = keys.iter().find(|k| k.kid == kid).ok_or(VerifyError::UnknownKey)?;
    let key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
        .map_err(|e| VerifyError::Invalid(e.to_string()))?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[APPLE_ISSUER]);
    validation.set_required_spec_claims(&["exp", "iss", "aud"]);

    let claims = jsonwebtoken::decode::<Claims>(token, &key, &validation)
        .map_err(|e| VerifyError::Invalid(e.to_string()))?
        .claims;

    let verified = match claims.email_verified {
        Some(serde_json::Value::Bool(b)) => b,
        Some(serde_json::Value::String(s)) => s == "true",
        _ => false,
    };
    match claims.email {
        Some(email) if verified && !email.trim().is_empty() => Ok(email.trim().to_lowercase()),
        _ => Err(VerifyError::NoVerifiedEmail),
    }
}

/// `true` si `email` figure dans la liste (séparée par des virgules), sans
/// tenir compte de la casse ni des espaces. Une entrée vide n'ouvre rien.
pub fn email_in_list(raw: &str, email: &str) -> bool {
    let email = email.trim();
    if email.is_empty() {
        return false;
    }
    raw.split(',')
        .map(str::trim)
        .any(|entry| !entry.is_empty() && entry.eq_ignore_ascii_case(email))
}

/// Clés publiques d'Apple, mises en cache une heure (et rechargées si un jeton
/// arrive signé par une clé encore inconnue).
pub struct AppleKeys {
    client: reqwest::Client,
    cache: Mutex<Option<(Vec<Jwk>, Instant)>>,
}

impl Default for AppleKeys {
    fn default() -> Self {
        Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(8))
                .build()
                .unwrap_or_default(),
            cache: Mutex::new(None),
        }
    }
}

impl AppleKeys {
    async fn fetch(&self) -> Result<Vec<Jwk>, String> {
        let set: JwkSet = self
            .client
            .get(APPLE_KEYS_URL)
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        *self.cache.lock().unwrap() = Some((set.keys.clone(), Instant::now()));
        Ok(set.keys)
    }

    async fn keys(&self, force: bool) -> Result<Vec<Jwk>, String> {
        if !force {
            if let Some((keys, at)) = self.cache.lock().unwrap().as_ref() {
                if at.elapsed() < KEYS_TTL {
                    return Ok(keys.clone());
                }
            }
        }
        self.fetch().await
    }

    /// Vérifie un jeton d'identité. `Err(None)` : Apple injoignable.
    pub async fn verify(&self, token: &str, audience: &str) -> Result<String, Option<VerifyError>> {
        // Un jeton illisible est refusé sans même interroger Apple.
        jsonwebtoken::decode_header(token).map_err(|e| Some(VerifyError::Invalid(e.to_string())))?;
        let keys = self.keys(false).await.map_err(|_| None)?;
        match verify_with_keys(token, &keys, audience) {
            Err(VerifyError::UnknownKey) => {
                let keys = self.keys(true).await.map_err(|_| None)?;
                verify_with_keys(token, &keys, audience).map_err(Some)
            }
            other => other.map_err(Some),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::traits::PublicKeyParts;
    use serde_json::json;
    use std::sync::OnceLock;

    const AUD: &str = "rs.brocolis.messagerie";

    fn b64url(bytes: &[u8]) -> String {
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
            let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
            for i in 0..=chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            }
        }
        out
    }

    /// Paire de clés générée à la volée (aucune clé privée dans le dépôt).
    fn test_key() -> &'static (EncodingKey, Jwk) {
        static KEY: OnceLock<(EncodingKey, Jwk)> = OnceLock::new();
        KEY.get_or_init(|| {
            let private = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
            let pem = private.to_pkcs8_pem(Default::default()).unwrap();
            let jwk = Jwk {
                kid: "test-kid".into(),
                n: b64url(&private.n().to_bytes_be()),
                e: b64url(&private.e().to_bytes_be()),
            };
            (EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(), jwk)
        })
    }

    fn sign(claims: serde_json::Value) -> String {
        let (key, jwk) = test_key();
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(jwk.kid.clone());
        jsonwebtoken::encode(&header, &claims, key).unwrap()
    }

    fn claims(email: &str, verified: serde_json::Value) -> serde_json::Value {
        let exp = chrono::Utc::now().timestamp() + 600;
        json!({ "iss": APPLE_ISSUER, "aud": AUD, "exp": exp, "sub": "001.abc",
                "email": email, "email_verified": verified })
    }

    fn keys() -> Vec<Jwk> {
        vec![test_key().1.clone()]
    }

    #[test]
    fn accepts_a_valid_token_and_lowercases_the_email() {
        let token = sign(claims("Max@iCloud.com", json!("true")));
        assert_eq!(verify_with_keys(&token, &keys(), AUD), Ok("max@icloud.com".into()));
        let token = sign(claims("max@icloud.com", json!(true)));
        assert_eq!(verify_with_keys(&token, &keys(), AUD), Ok("max@icloud.com".into()));
    }

    #[test]
    fn rejects_a_token_for_another_app() {
        let mut c = claims("max@icloud.com", json!(true));
        c["aud"] = json!("com.someone.else");
        assert!(matches!(verify_with_keys(&sign(c), &keys(), AUD), Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn rejects_a_token_not_issued_by_apple() {
        let mut c = claims("max@icloud.com", json!(true));
        c["iss"] = json!("https://evil.example");
        assert!(matches!(verify_with_keys(&sign(c), &keys(), AUD), Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn rejects_an_expired_token() {
        let mut c = claims("max@icloud.com", json!(true));
        c["exp"] = json!(chrono::Utc::now().timestamp() - 3600);
        assert!(matches!(verify_with_keys(&sign(c), &keys(), AUD), Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn rejects_a_tampered_token() {
        let token = sign(claims("someone@else.com", json!(true)));
        let mut parts: Vec<String> = token.split('.').map(String::from).collect();
        // Charge utile remplacée, signature d'origine conservée.
        parts[1] = b64url(claims("max@icloud.com", json!(true)).to_string().as_bytes());
        let forged = parts.join(".");
        assert!(matches!(verify_with_keys(&forged, &keys(), AUD), Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn rejects_an_unverified_email() {
        let token = sign(claims("max@icloud.com", json!("false")));
        assert_eq!(verify_with_keys(&token, &keys(), AUD), Err(VerifyError::NoVerifiedEmail));
    }

    #[test]
    fn reports_an_unknown_signing_key() {
        let token = sign(claims("max@icloud.com", json!(true)));
        let other = vec![Jwk { kid: "autre".into(), ..test_key().1.clone() }];
        assert_eq!(verify_with_keys(&token, &other, AUD), Err(VerifyError::UnknownKey));
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(verify_with_keys("pas.un.jeton", &keys(), AUD), Err(VerifyError::Invalid(_))));
    }

    #[test]
    fn email_list_ignores_case_spaces_and_empty_entries() {
        assert!(email_in_list("a@x.fr, Max@iCloud.com", "max@icloud.com"));
        assert!(!email_in_list("a@x.fr,,", ""));
        assert!(!email_in_list("", "max@icloud.com"));
        assert!(!email_in_list("max@icloud.com.evil", "max@icloud.com"));
    }
}
