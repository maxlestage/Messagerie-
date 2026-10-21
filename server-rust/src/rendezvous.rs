//! Rendez-vous X25519 + relais éphémères.
//!
//! Le serveur ne relaie que des CLÉS PUBLIQUES et des blobs déjà chiffrés — il
//! ne détient aucune clé secrète. Tout est en mémoire avec expiration (TTL) :
//! `/pair` (échange de clés publiques par code, et des paquets de clés v3
//! quand le client en publie un : `docs/SECURITE.md` §8.4), `/wrap`
//! (clés de groupe emballées) et les push tokens de Live Activity.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Une invitation vit 7 jours : deux personnes loin l'une de l'autre n'ont
/// pas à être en ligne en même temps (chacune agit quand elle ouvre l'app).
const TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

struct Peer {
    pub_key: String,
    /// Le paquet de clés v3 (base64), s'il en a publié un, et son identité
    /// (IK X25519 ‖ IK Ed25519) : une rotation garde la même.
    bundle: Option<(String, [u8; 64])>,
    /// Sa capacité v4 signée (base64, §9.6), vérifiée contre l'identité du
    /// paquet.
    caps: Option<String>,
    ts: Instant,
}

/// Un paquet de clés v3 déjà vérifié (`brocolis_proto::KeyBundle`), tel que
/// le salon le garde : son base64 et son identité.
pub struct PublishedBundle {
    pub base64: String,
    pub identity: [u8; 64],
    /// La capacité v4 signée (base64), déjà vérifiée, si le client en publie
    /// une (`docs/SECURITE.md` §9.6).
    pub caps: Option<String>,
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
    /// Ce participant a déjà publié un paquet v3 d'une AUTRE identité : on
    /// ne laisse personne glisser ses clés à la place des siennes (une
    /// rotation, elle, garde l'identité).
    BundleMismatch,
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

    /// Pairs d'un code, en excluant `peer_id`. → [{ peerId, pub, bundle?,
    /// caps? }] (`bundle` et `caps` seulement pour qui en a publié : un
    /// ancien client ne les voit pas et n'en a pas besoin).
    pub fn peers_excluding(&self, code: &str, peer_id: &str) -> serde_json::Value {
        let map = self.codes.lock().unwrap();
        let list: Vec<serde_json::Value> = map
            .get(code)
            .map(|peers| {
                peers
                    .iter()
                    .filter(|(id, _)| id.as_str() != peer_id)
                    .map(|(id, p)| {
                        let mut v = serde_json::json!({ "peerId": id, "pub": p.pub_key });
                        if let Some((b, _)) = &p.bundle {
                            v["bundle"] = serde_json::Value::from(b.as_str());
                        }
                        if let Some(c) = &p.caps {
                            v["caps"] = serde_json::Value::from(c.as_str());
                        }
                        v
                    })
                    .collect()
            })
            .unwrap_or_default();
        serde_json::json!({ "peers": list })
    }

    /// POST /pair (participant) : voir [`add_peer_as`](Self::add_peer_as).
    pub fn add_peer(&self, code: &str, peer_id: &str, pub_key: &str) -> Result<serde_json::Value, PairError> {
        self.add_peer_as(code, peer_id, pub_key, false)
    }

    /// POST /pair, sans paquet v3 : voir [`add_peer_with`](Self::add_peer_with).
    pub fn add_peer_as(
        &self,
        code: &str,
        peer_id: &str,
        pub_key: &str,
        host: bool,
    ) -> Result<serde_json::Value, PairError> {
        self.add_peer_with(code, peer_id, pub_key, host, None)
    }

    /// POST /pair : enregistre (code, peerId, pub) et, s'il y en a un, le
    /// paquet de clés v3 (déjà vérifié). `host` : c'est l'invitant (le
    /// premier à le revendiquer le reste ; sans revendication, le premier
    /// inscrit fait office d'hôte, pour les anciennes versions). Republier
    /// sans paquet garde celui qui est connu ; un paquet d'une autre
    /// identité est refusé.
    pub fn add_peer_with(
        &self,
        code: &str,
        peer_id: &str,
        pub_key: &str,
        host: bool,
        bundle: Option<PublishedBundle>,
    ) -> Result<serde_json::Value, PairError> {
        {
            let mut map = self.codes.lock().unwrap();
            let peers = map.entry(code.to_string()).or_default();
            let mut kept = None;
            let mut kept_caps = None;
            match peers.get(peer_id) {
                Some(p) if p.pub_key != pub_key => return Err(PairError::KeyMismatch),
                Some(p) => {
                    if let (Some((_, known)), Some(new)) = (&p.bundle, &bundle) {
                        if *known != new.identity {
                            return Err(PairError::BundleMismatch);
                        }
                    }
                    kept = p.bundle.clone();
                    kept_caps = p.caps.clone();
                }
                None if peers.len() >= self.max_peers => return Err(PairError::Full),
                None => {}
            }
            // Une capacité accompagne toujours un paquet (même identité) ;
            // republier sans elle garde celle qui est connue.
            let (bundle, caps) = match bundle {
                Some(b) => {
                    let caps = b.caps.or(kept_caps);
                    (Some((b.base64, b.identity)), caps)
                }
                None => (kept, kept_caps),
            };
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
                Peer { pub_key: pub_key.to_string(), bundle, caps, ts: Instant::now() },
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

    fn bundle(b: &str, id: u8) -> Option<PublishedBundle> {
        Some(PublishedBundle { base64: b.into(), identity: [id; 64], caps: None })
    }

    #[test]
    fn v4_caps_travel_with_the_bundle_and_survive_republish() {
        let rdv = Rendezvous::new(16);
        let with_caps = Some(PublishedBundle { base64: "B".into(), identity: [1; 64], caps: Some("CAPS".into()) });
        rdv.add_peer_with("c", "alice", "A", true, with_caps).unwrap();
        let v = rdv.add_peer("c", "bob", "B").unwrap();
        assert_eq!(v["peers"][0]["caps"], "CAPS");
        // Rotation du paquet sans capacité, puis republication nue : gardée.
        rdv.add_peer_with("c", "alice", "A", true, bundle("B2", 1)).unwrap();
        rdv.add_peer_as("c", "alice", "A", true).unwrap();
        let v = rdv.peers_excluding("c", "bob");
        assert_eq!(v["peers"][0]["caps"], "CAPS");
        assert_eq!(v["peers"][0]["bundle"], "B2");
        // Qui n'en publie pas n'a pas de champ.
        assert!(rdv.peers_excluding("c", "alice")["peers"][0].get("caps").is_none());
    }

    #[test]
    fn v3_bundles_travel_with_the_public_keys() {
        let rdv = Rendezvous::new(16);
        rdv.add_peer_with("c", "alice", "A", true, bundle("BUNDLE_A", 1)).unwrap();
        // Un ancien client : pas de paquet, et il ne voit qu'un champ de plus.
        let old = rdv.add_peer("c", "carol", "C").unwrap();
        assert_eq!(old["peers"][0]["bundle"], "BUNDLE_A");
        let b = rdv.add_peer_with("c", "bob", "B", false, bundle("BUNDLE_B", 2)).unwrap();
        let peers = b["peers"].as_array().unwrap();
        let alice = peers.iter().find(|p| p["peerId"] == "alice").unwrap();
        let carol = peers.iter().find(|p| p["peerId"] == "carol").unwrap();
        assert_eq!(alice["bundle"], "BUNDLE_A");
        assert!(carol.get("bundle").is_none(), "pas de champ pour qui n'a rien publié");
        // Rotation (même identité) : le paquet est remplacé.
        rdv.add_peer_with("c", "alice", "A", true, bundle("BUNDLE_A2", 1)).unwrap();
        // Republier sans paquet le garde.
        rdv.add_peer_as("c", "alice", "A", true).unwrap();
        let v = rdv.peers_excluding("c", "bob");
        let alice = v["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "alice").unwrap().clone();
        assert_eq!(alice["bundle"], "BUNDLE_A2");
        // Glisser le paquet d'une autre identité sous le peerId d'Alice : refusé.
        assert_eq!(
            rdv.add_peer_with("c", "alice", "A", true, bundle("EVIL", 9)),
            Err(PairError::BundleMismatch)
        );
        let v = rdv.peers_excluding("c", "bob");
        let alice = v["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "alice").unwrap().clone();
        assert_eq!(alice["bundle"], "BUNDLE_A2");
        // Un premier paquet pour un participant qui n'en avait pas : accepté.
        rdv.add_peer_with("c", "carol", "C", false, bundle("BUNDLE_C", 3)).unwrap();
        assert!(rdv.peers_excluding("c", "bob")["peers"].as_array().unwrap().iter().any(|p| p["bundle"] == "BUNDLE_C"));
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
