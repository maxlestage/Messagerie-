//! Rendez-vous X25519 + relais éphémères.
//!
//! Le serveur ne relaie que des CLÉS PUBLIQUES et des blobs déjà chiffrés — il
//! ne détient aucune clé secrète. Tout est en mémoire avec expiration (TTL) :
//! `/pair` (échange de clés publiques par code), `/wrap`
//! (clés de groupe emballées) et les push tokens de Live Activity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Une invitation vit 7 jours : deux personnes loin l'une de l'autre n'ont
/// pas à être en ligne en même temps (chacune agit quand elle ouvre l'app).
const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

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

    /// Le nombre de codes où quelqu'un attend (page Serveur du site).
    pub fn room_count(&self) -> usize {
        self.codes.lock().unwrap().len()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn peer_ids(v: &serde_json::Value) -> Vec<String> {
        v["peers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["peerId"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn pair_exchanges_public_keys_and_excludes_self() {
        let rdv = Rendezvous::new(16);
        // Alice arrive : personne d'autre encore.
        let a = rdv.add_peer("4813", "alice", "PUB_A").unwrap();
        assert!(peer_ids(&a).is_empty());
        // Bob arrive : il voit Alice, mais pas lui-même.
        let b = rdv.add_peer("4813", "bob", "PUB_B").unwrap();
        assert_eq!(peer_ids(&b), vec!["alice"]);
        assert_eq!(b["peers"][0]["pub"], "PUB_A");
        // Alice re-sonde : elle voit maintenant Bob.
        let a2 = rdv.peers_excluding("4813", "alice");
        assert_eq!(peer_ids(&a2), vec!["bob"]);
        assert_eq!(a2["peers"][0]["pub"], "PUB_B");
    }

    #[test]
    fn pair_codes_are_isolated() {
        let rdv = Rendezvous::new(16);
        rdv.add_peer("1111", "alice", "A").unwrap();
        let other = rdv.add_peer("2222", "bob", "B").unwrap();
        // Codes différents : Bob ne voit pas Alice.
        assert!(peer_ids(&other).is_empty());
    }

    #[test]
    fn pair_reconnect_updates_key_without_growing() {
        let rdv = Rendezvous::new(2);
        rdv.add_peer("c", "alice", "A1").unwrap();
        rdv.add_peer("c", "bob", "B").unwrap();
        // Alice se reconnecte avec une nouvelle clé : pas un nouveau participant.
        rdv.add_peer("c", "alice", "A2").unwrap();
        let seen = rdv.peers_excluding("c", "bob");
        let alice = seen["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["peerId"] == "alice")
            .unwrap();
        assert_eq!(alice["pub"], "A2");
    }

    #[test]
    fn pair_enforces_max_peers() {
        let rdv = Rendezvous::new(2);
        rdv.add_peer("full", "a", "A").unwrap();
        rdv.add_peer("full", "b", "B").unwrap();
        // Le 3e participant est refusé…
        assert!(rdv.add_peer("full", "c", "C").is_err());
        // …mais un participant déjà présent peut toujours se ré-annoncer.
        assert!(rdv.add_peer("full", "a", "A2").is_ok());
    }

    #[test]
    fn wrap_is_delivered_per_recipient() {
        let rdv = Rendezvous::new(16);
        let n = rdv.put_wraps(
            "g",
            "alice",
            "PUB_A",
            &[
                ("bob".into(), "BLOB_BOB".into()),
                ("carol".into(), "BLOB_CAROL".into()),
            ],
        );
        assert_eq!(n, 2);
        let bob = rdv.get_wrap("g", "bob");
        assert_eq!(bob["wrap"]["from"], "alice");
        assert_eq!(bob["wrap"]["fromPub"], "PUB_A");
        assert_eq!(bob["wrap"]["blob"], "BLOB_BOB");
        // Un destinataire inconnu obtient null.
        assert!(rdv.get_wrap("g", "dan")["wrap"].is_null());
    }

    #[test]
    fn wrap_skips_empty_items() {
        let rdv = Rendezvous::new(16);
        let n = rdv.put_wraps(
            "g",
            "a",
            "P",
            &[("".into(), "x".into()), ("bob".into(), "".into()), ("carol".into(), "ok".into())],
        );
        assert_eq!(n, 1);
        assert_eq!(rdv.get_wrap("g", "carol")["wrap"]["blob"], "ok");
    }

    #[test]
    fn live_token_round_trips() {
        let rdv = Rendezvous::new(16);
        assert!(rdv.live_token("code", "bob").is_none());
        rdv.put_live_token("code", "bob", "TOKEN_XYZ");
        assert_eq!(rdv.live_token("code", "bob").as_deref(), Some("TOKEN_XYZ"));
    }

    #[test]
    fn prune_keeps_fresh_entries() {
        let rdv = Rendezvous::new(16);
        rdv.add_peer("c", "alice", "A").unwrap();
        rdv.put_wraps("c", "alice", "A", &[("bob".into(), "B".into())]);
        rdv.put_live_token("c", "alice", "T");
        // Rien n'a expiré (TTL = 7 jours) : tout survit.
        rdv.prune();
        assert_eq!(peer_ids(&rdv.peers_excluding("c", "bob")), vec!["alice"]);
        assert_eq!(rdv.get_wrap("c", "bob")["wrap"]["blob"], "B");
        assert!(rdv.live_token("c", "alice").is_some());
    }
}
