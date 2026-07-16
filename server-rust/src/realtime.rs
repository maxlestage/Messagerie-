//! Temps réel inter-dynos via Redis (Heroku Key-Value), équivalent de
//! `server/realtime.js`.
//!
//! Chaque message est publié sur un canal Redis ; chaque dyno rediffuse à SES
//! abonnés SSE locaux (via le callback fourni). No-op sans `REDIS_URL` : on
//! retombe sur le temps réel intra-dyno, suffisant à un seul dyno. Les clients
//! dédoublonnent par id : une double livraison est inoffensive.
//!
//! Le serveur ne diffuse que du chiffré.

use futures_util::StreamExt;
use redis::AsyncCommands;
use std::time::Duration;
use tokio::sync::mpsc;

const CHANNEL: &str = "brocolis:messages";

pub struct Realtime {
    tx: Option<mpsc::UnboundedSender<String>>,
    origin: String,
}

impl Realtime {
    /// Désactivé : temps réel intra-dyno uniquement.
    pub fn disabled() -> Self {
        Realtime { tx: None, origin: String::new() }
    }

    /// Se connecte à Redis. `on_remote(convId, ligne_sse)` est appelé pour chaque
    /// message publié par un AUTRE dyno (à rediffuser aux abonnés locaux).
    pub async fn connect<F>(redis_url: Option<String>, on_remote: F) -> Self
    where
        F: Fn(String, String) + Send + Sync + 'static,
    {
        let Some(url) = redis_url.filter(|s| !s.is_empty()) else {
            return Self::disabled();
        };
        let origin = uuid::Uuid::new_v4().to_string();

        // Certificat Heroku Key-Value auto-signé → TLS « insecure » (comme le
        // rejectUnauthorized:false du Node).
        let info = match redis::IntoConnectionInfo::into_connection_info(url.as_str()) {
            Ok(mut info) => {
                if let redis::ConnectionAddr::TcpTls { ref mut insecure, .. } = info.addr {
                    *insecure = true;
                }
                info
            }
            Err(e) => {
                eprintln!("REDIS_URL invalide ({e}), temps réel intra-dyno.");
                return Self::disabled();
            }
        };
        let client = match redis::Client::open(info) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Redis indisponible ({e}), temps réel intra-dyno.");
                return Self::disabled();
            }
        };

        // Tâche de PUBLICATION : lit une file interne et publie sur Redis.
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        {
            let client = client.clone();
            tokio::spawn(async move {
                let mut conn = match client.get_multiplexed_async_connection().await {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Redis (publication) indisponible ({e}).");
                        return;
                    }
                };
                while let Some(payload) = rx.recv().await {
                    let _: Result<(), _> = conn.publish(CHANNEL, payload).await;
                }
            });
        }

        // Tâche d'ABONNEMENT : reçoit les messages des autres dynos et rediffuse.
        {
            let origin = origin.clone();
            tokio::spawn(async move {
                loop {
                    match subscribe_loop(&client, &origin, &on_remote).await {
                        Ok(()) => {}
                        Err(e) => eprintln!("Redis (abonnement) : {e}"),
                    }
                    tokio::time::sleep(Duration::from_secs(3)).await; // reconnexion
                }
            });
            println!("Redis branché : temps réel inter-dynos actif.");
        }

        Realtime { tx: Some(tx), origin }
    }

    /// Publie une ligne SSE prête (`data: …\n\n`) pour une conversation.
    pub fn publish(&self, conv: &str, sse_line: &str) {
        if let Some(tx) = &self.tx {
            let payload = serde_json::json!({
                "origin": self.origin, "convId": conv, "line": sse_line
            })
            .to_string();
            let _ = tx.send(payload);
        }
    }
}

/// Boucle d'abonnement : délivre les messages distants via `on_remote`.
async fn subscribe_loop<F>(
    client: &redis::Client,
    origin: &str,
    on_remote: &F,
) -> Result<(), String>
where
    F: Fn(String, String) + Send + Sync + 'static,
{
    let mut pubsub = client.get_async_pubsub().await.map_err(|e| e.to_string())?;
    pubsub.subscribe(CHANNEL).await.map_err(|e| e.to_string())?;
    let mut stream = pubsub.on_message();
    while let Some(msg) = stream.next().await {
        let payload: String = match msg.get_payload() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&payload) else { continue };
        // Ignore ce que CE dyno a publié (déjà diffusé en local).
        if v.get("origin").and_then(|o| o.as_str()) == Some(origin) {
            continue;
        }
        let conv = v.get("convId").and_then(|c| c.as_str()).unwrap_or("");
        let line = v.get("line").and_then(|l| l.as_str()).unwrap_or("");
        if !conv.is_empty() && !line.is_empty() {
            on_remote(conv.to_string(), line.to_string());
        }
    }
    Ok(())
}
