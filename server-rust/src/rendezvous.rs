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

/// Pourquoi une inscription au salon est refusée.
#[derive(Debug, PartialEq, Eq)]
pub enum PairError {
    /// Le plafond de participants du code est atteint.
    Full,
    /// Ce peerId est déjà inscrit avec une AUTRE clé publique : on ne laisse
    /// personne remplacer la clé d'un participant (sinon l'invitant
    /// remettrait la clé de groupe à l'usurpateur).
    KeyMismatch,
}

pub struct Rendezvous {
    codes: Mutex<HashMap<String, HashMap<String, Peer>>>,
    /// L'hôte de chaque code (celui qui invite) : lui seul peut remettre la
    /// clé de groupe (`/wrap`). `bool` = revendiqué explicitement (`host`).
    hosts: Mutex<HashMap<String, (String, bool)>>,
    wraps: Mutex<HashMap<String, HashMap<String, Wrap>>>,
    live: Mutex<HashMap<String, HashMap<String, LiveToken>>>,
    max_peers: usize,
}

impl Rendezvous {
    pub fn new(max_peers: usize) -> Self {
        Rendezvous {
            codes: Mutex::new(HashMap::new()),
            hosts: Mutex::new(HashMap::new()),
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

    /// POST /pair (participant) : voir [`add_peer_as`](Self::add_peer_as).
    pub fn add_peer(&self, code: &str, peer_id: &str, pub_key: &str) -> Result<serde_json::Value, PairError> {
        self.add_peer_as(code, peer_id, pub_key, false)
    }

    /// POST /pair : enregistre (code, peerId, pub). `host` : c'est l'invitant
    /// (le premier à le revendiquer le reste ; sans revendication, le premier
    /// inscrit fait office d'hôte, pour les anciennes versions).
    pub fn add_peer_as(
        &self,
        code: &str,
        peer_id: &str,
        pub_key: &str,
        host: bool,
    ) -> Result<serde_json::Value, PairError> {
        {
            let mut map = self.codes.lock().unwrap();
            let peers = map.entry(code.to_string()).or_default();
            match peers.get(peer_id) {
                Some(p) if p.pub_key != pub_key => return Err(PairError::KeyMismatch),
                None if peers.len() >= self.max_peers => return Err(PairError::Full),
                _ => {}
            }
            let mut hosts = self.hosts.lock().unwrap();
            match hosts.get(code) {
                None => {
                    hosts.insert(code.to_string(), (peer_id.to_string(), host));
                }
                Some((_, false)) if host => {
                    hosts.insert(code.to_string(), (peer_id.to_string(), true));
                }
                _ => {}
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
    /// d'items acceptés, ou `None` si l'expéditeur n'est pas l'hôte du code
    /// (inscrit avec cette clé publique) : personne d'autre ne peut glisser sa
    /// propre clé à celui qui rejoint.
    pub fn put_wraps(
        &self,
        code: &str,
        from: &str,
        from_pub: &str,
        items: &[(String, String)], // (toPeerId, blob)
    ) -> Option<usize> {
        let is_host = self.hosts.lock().unwrap().get(code).is_some_and(|(h, _)| h == from);
        let registered = self
            .codes
            .lock()
            .unwrap()
            .get(code)
            .and_then(|peers| peers.get(from))
            .is_some_and(|p| p.pub_key == from_pub);
        if !is_host || !registered {
            return None;
        }
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
        Some(count)
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
        // Un code sans plus aucun participant perd son hôte.
        let codes = self.codes.lock().unwrap();
        self.hosts.lock().unwrap().retain(|code, _| codes.contains_key(code));
        drop(codes);
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
    fn nobody_can_replace_a_registered_public_key() {
        let rdv = Rendezvous::new(2);
        rdv.add_peer("c", "alice", "A1").unwrap();
        rdv.add_peer("c", "bob", "B").unwrap();
        // Se ré-annoncer avec la même clé : permis (l'app republie).
        assert!(rdv.add_peer("c", "alice", "A1").is_ok());
        // Usurper le peerId d'Alice avec une autre clé : refusé.
        assert_eq!(rdv.add_peer("c", "alice", "EVIL"), Err(PairError::KeyMismatch));
        assert_eq!(rdv.peers_excluding("c", "bob")["peers"][0]["pub"], "A1");
    }

    #[test]
    fn only_the_host_hands_out_the_group_key() {
        let rdv = Rendezvous::new(16);
        // Bob rejoint AVANT que l'hôte ne se montre (ordre libre)…
        rdv.add_peer("g", "bob", "PUB_B").unwrap();
        rdv.add_peer_as("g", "alice", "PUB_A", true).unwrap();
        rdv.add_peer("g", "mallory", "PUB_M").unwrap();
        // …Mallory, simple participant, ne peut pas glisser SA clé à Bob.
        assert_eq!(rdv.put_wraps("g", "mallory", "PUB_M", &[("bob".into(), "EVIL".into())]), None);
        // Ni en se faisant passer pour Alice avec une autre clé publique.
        assert_eq!(rdv.put_wraps("g", "alice", "PUB_M", &[("bob".into(), "EVIL".into())]), None);
        assert!(rdv.get_wrap("g", "bob")["wrap"].is_null());
        // L'hôte, lui, remet la clé.
        assert_eq!(rdv.put_wraps("g", "alice", "PUB_A", &[("bob".into(), "OK".into())]), Some(1));
        assert_eq!(rdv.get_wrap("g", "bob")["wrap"]["blob"], "OK");
        // Une seconde revendication d'hôte ne change rien.
        rdv.add_peer_as("g", "mallory2", "PUB_M2", true).unwrap();
        assert_eq!(rdv.put_wraps("g", "mallory2", "PUB_M2", &[("bob".into(), "EVIL".into())]), None);
    }

    #[test]
    fn pair_enforces_max_peers() {
        let rdv = Rendezvous::new(2);
        rdv.add_peer("full", "a", "A").unwrap();
        rdv.add_peer("full", "b", "B").unwrap();
        // Le 3e participant est refusé…
        assert!(rdv.add_peer("full", "c", "C").is_err());
        // …mais un participant déjà présent peut toujours se ré-annoncer.
        assert!(rdv.add_peer("full", "a", "A").is_ok());
    }

    #[test]
    fn wrap_is_delivered_per_recipient() {
        let rdv = Rendezvous::new(16);
        rdv.add_peer_as("g", "alice", "PUB_A", true).unwrap();
        let n = rdv.put_wraps(
            "g",
            "alice",
            "PUB_A",
            &[
                ("bob".into(), "BLOB_BOB".into()),
                ("carol".into(), "BLOB_CAROL".into()),
            ],
        );
        assert_eq!(n, Some(2));
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
        rdv.add_peer("g", "a", "P").unwrap();
        let n = rdv.put_wraps(
            "g",
            "a",
            "P",
            &[("".into(), "x".into()), ("bob".into(), "".into()), ("carol".into(), "ok".into())],
        );
        assert_eq!(n, Some(1));
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
