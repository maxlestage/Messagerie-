//! Client APNs (mises à jour de Live Activity) : JWT ES256 + HTTP/2 vers Apple.
//!
//! Équivalent Rust de `server/apns.js`. Authentification par jeton (clé .p8,
//! JWT ES256), transport HTTP/2 (reqwest + rustls). Le token de la Live Activity
//! est fourni par l'app. `None` si la configuration APNs est incomplète : la
//! route d'envoi répond alors 503, comme côté Node.

use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn unix_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub struct Apns {
    key: jsonwebtoken::EncodingKey,
    key_id: String,
    team_id: String,
    host: String,
    topic: String,
    client: reqwest::Client,
    cached_jwt: Mutex<Option<(String, Instant)>>,
}

impl Apns {
    /// Construit l'expéditeur depuis l'environnement, ou `None` si incomplet.
    /// Variables : APNS_KEY_P8, APNS_KEY_ID, APNS_TEAM_ID, APNS_BUNDLE_ID,
    /// APNS_ENV ("sandbox" par défaut, ou "production").
    pub fn from_env() -> Option<Self> {
        let key_p8 = std::env::var("APNS_KEY_P8").ok().filter(|s| !s.is_empty())?;
        let key_id = std::env::var("APNS_KEY_ID").ok().filter(|s| !s.is_empty())?;
        let team_id = std::env::var("APNS_TEAM_ID").ok().filter(|s| !s.is_empty())?;
        let bundle_id = std::env::var("APNS_BUNDLE_ID").ok().filter(|s| !s.is_empty())?;

        let key = match jsonwebtoken::EncodingKey::from_ec_pem(key_p8.as_bytes()) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("APNS_KEY_P8 illisible: {e}");
                return None;
            }
        };
        let env = std::env::var("APNS_ENV").unwrap_or_else(|_| "sandbox".to_string());
        let host = if env == "production" {
            "https://api.push.apple.com"
        } else {
            "https://api.sandbox.push.apple.com"
        };
        let client = reqwest::Client::builder().build().ok()?;

        Some(Apns {
            key,
            key_id,
            team_id,
            host: host.to_string(),
            topic: format!("{bundle_id}.push-type.liveactivity"),
            client,
            cached_jwt: Mutex::new(None),
        })
    }

    /// JWT APNs (valable ≤ 60 min) — renouvelé toutes les ~50 min.
    fn jwt(&self) -> Result<String, String> {
        {
            let cache = self.cached_jwt.lock().unwrap();
            if let Some((tok, exp)) = cache.as_ref() {
                if Instant::now() < *exp {
                    return Ok(tok.clone());
                }
            }
        }
        #[derive(serde::Serialize)]
        struct Claims {
            iss: String,
            iat: u64,
        }
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
        header.kid = Some(self.key_id.clone());
        let claims = Claims { iss: self.team_id.clone(), iat: unix_secs() };
        let tok = jsonwebtoken::encode(&header, &claims, &self.key).map_err(|e| e.to_string())?;
        *self.cached_jwt.lock().unwrap() =
            Some((tok.clone(), Instant::now() + Duration::from_secs(50 * 60)));
        Ok(tok)
    }

    /// Envoie une mise à jour ("update") ou fin ("end") de Live Activity.
    /// Renvoie le statut HTTP renvoyé par APNs.
    pub async fn send_live_activity(
        &self,
        device_token: &str,
        event: &str,
        content_state: &serde_json::Value,
        dismissal_date: Option<i64>,
    ) -> Result<u16, String> {
        let jwt = self.jwt()?;
        let mut aps = serde_json::json!({
            "timestamp": unix_secs(),
            "event": event,
            "content-state": content_state,
        });
        if event == "end" {
            if let Some(d) = dismissal_date {
                aps["dismissal-date"] = serde_json::json!(d);
            }
        }
        let payload = serde_json::json!({ "aps": aps });
        let url = format!("{}/3/device/{}", self.host, device_token);

        let resp = self
            .client
            .post(&url)
            .header("authorization", format!("bearer {jwt}"))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "liveactivity")
            .header("apns-priority", "10")
            .json(&payload)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        Ok(resp.status().as_u16())
    }
}
