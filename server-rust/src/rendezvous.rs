//! Rendez-vous X25519 + relais éphémères (mêmes routes que le serveur Node).
//!
//! Le serveur ne relaie que des CLÉS PUBLIQUES et des blobs déjà chiffrés — il
//! ne détient aucune clé secrète. Tout est en mémoire avec expiration (TTL),
//! comme côté Node : `/pair` (échange de clés publiques par code), `/wrap`
//! (clés de groupe emballées) et les push tokens de Live Activity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const TTL: Duration = Duration::from_secs(10 * 60);

struct Peer {
    pub_key: String,
    ts: Instant,
}
struct Wrap {
    from: String,
    from_pub: String,
    blob: String,
    ts: Instant,
}
struct LiveToken {
    token: String,
    ts: Instant,
}

pub struct Rendezvous {
    codes: Mutex<HashMap<String, HashMap<String, Peer>>>,
    wraps: Mutex<HashMap<String, HashMap<String, Wrap>>>,
    live: Mutex<HashMap<String, HashMap<String, LiveToken>>>,
    max_peers: usize,
}

impl Rendezvous {
    pub fn new(max_peers: usize) -> Self {
        Rendezvous {
            codes: Mutex::new(HashMap::new()),
            wraps: Mutex::new(HashMap::new()),
            live: Mutex::new(HashMap::new()),
            max_peers,
        }
    }

    /// Pairs d'un code, en excluant `peer_id`. → [{ peerId, pub }]
    pub fn peers_excluding(&self, code: &str, peer_id: &str) -> serde_json::Value {
        let map = self.codes.lock().unwrap();
        let list: Vec<serde_json::Value> = map
            .get(code)
            .map(|peers| {
                peers
                    .iter()
                    .filter(|(id, _)| id.as_str() != peer_id)
                    .map(|(id, p)| serde_json::json!({ "peerId": id, "pub": p.pub_key }))
                    .collect()
            })
            .unwrap_or_default();
        serde_json::json!({ "peers": list })
    }

    /// POST /pair : enregistre (code, peerId, pub). Renvoie Ok(peers) ou
    /// Err(()) si le plafond de participants est atteint.
    pub fn add_peer(
        &self,
        code: &str,
        peer_id: &str,
        pub_key: &str,
    ) -> Result<serde_json::Value, ()> {
        {
            let mut map = self.codes.lock().unwrap();
            let peers = map.entry(code.to_string()).or_default();
            if !peers.contains_key(peer_id) && peers.len() >= self.max_peers {
                return Err(());
            }
            peers.insert(
                peer_id.to_string(),
                Peer { pub_key: pub_key.to_string(), ts: Instant::now() },
            );
        }
        Ok(self.peers_excluding(code, peer_id))
    }

    /// GET /wrap : la clé de groupe emballée destinée à `peer_id`, ou null.
    pub fn get_wrap(&self, code: &str, peer_id: &str) -> serde_json::Value {
        let map = self.wraps.lock().unwrap();
        match map.get(code).and_then(|r| r.get(peer_id)) {
            Some(w) => serde_json::json!({ "wrap": {
                "from": w.from, "fromPub": w.from_pub, "blob": w.blob
            }}),
            None => serde_json::json!({ "wrap": serde_json::Value::Null }),
        }
    }

    /// POST /wrap : stocke une clé emballée par destinataire. Renvoie le nombre
    /// d'items acceptés.
    pub fn put_wraps(
        &self,
        code: &str,
        from: &str,
        from_pub: &str,
        items: &[(String, String)], // (toPeerId, blob)
    ) -> usize {
        let mut map = self.wraps.lock().unwrap();
        let recips = map.entry(code.to_string()).or_default();
        let now = Instant::now();
        let mut count = 0;
        for (to_id, blob) in items {
            if !to_id.is_empty() && !blob.is_empty() {
                recips.insert(
                    to_id.clone(),
                    Wrap {
                        from: from.to_string(),
                        from_pub: from_pub.to_string(),
                        blob: blob.clone(),
                        ts: now,
                    },
                );
                count += 1;
            }
        }
        count
    }

    /// POST /push/live-activity/token : enregistre le push token d'un peer.
    pub fn put_live_token(&self, code: &str, peer_id: &str, token: &str) {
        let mut map = self.live.lock().unwrap();
        map.entry(code.to_string()).or_default().insert(
            peer_id.to_string(),
            LiveToken { token: token.to_string(), ts: Instant::now() },
        );
    }

    /// Récupère le push token de Live Activity d'un peer (pour l'envoi APNs).
    pub fn live_token(&self, code: &str, peer_id: &str) -> Option<String> {
        let map = self.live.lock().unwrap();
        map.get(code).and_then(|t| t.get(peer_id)).map(|e| e.token.clone())
    }

    /// Purge des entrées expirées (> TTL). À appeler périodiquement.
    pub fn prune(&self) {
        fn sweep<T>(map: &Mutex<HashMap<String, HashMap<String, T>>>, ts: impl Fn(&T) -> Instant) {
            let mut m = map.lock().unwrap();
            let now = Instant::now();
            m.retain(|_, inner| {
                inner.retain(|_, v| now.duration_since(ts(v)) <= TTL);
                !inner.is_empty()
            });
        }
        sweep(&self.codes, |p| p.ts);
        sweep(&self.wraps, |w| w.ts);
        sweep(&self.live, |l| l.ts);
    }
}
