//! Live Activity mise à jour par le serveur : chaque appareil abonne sa Live
//! Activity (push token APNs) aux conversations de ses clés ; à chaque message
//! reçu ou lu, le serveur lui pousse le nombre de messages non lus et l'heure
//! du dernier — jamais le contenu, qu'il ne sait pas lire. L'app peut donc
//! être fermée : le compteur de la Dynamic Island suit quand même.
//!
//! Tout est en mémoire ; l'app se réabonne au lancement, au retour au premier
//! plan et quand iOS change le token.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// La Live Activity d'un appareil.
#[derive(Clone, Debug, PartialEq)]
pub struct LiveReg {
    /// Push token APNs de la Live Activity (hex).
    pub token: String,
    /// Depuis quand elle tourne (secondes Unix), renvoyé tel quel dans
    /// `contentState.since`.
    pub since: i64,
    /// Les conversations suivies.
    pub conversations: HashSet<String>,
}

#[derive(Default)]
pub struct LiveSubscriptions {
    /// Par appareil (`X-User-Id`).
    devices: Mutex<HashMap<String, LiveReg>>,
}

impl LiveSubscriptions {
    /// Enregistre (ou remplace) la Live Activity d'un appareil et la liste des
    /// conversations qu'il suit.
    pub fn subscribe(&self, user: &str, token: &str, since: i64, conversations: Vec<String>) {
        let reg = LiveReg {
            token: token.to_owned(),
            since,
            conversations: conversations.into_iter().filter(|c| !c.is_empty()).collect(),
        };
        self.devices.lock().unwrap().insert(user.to_owned(), reg);
    }

    /// Les appareils (autres que `except`) qui suivent `conv`.
    pub fn followers(&self, conv: &str, except: &str) -> Vec<(String, LiveReg)> {
        self.devices
            .lock()
            .unwrap()
            .iter()
            .filter(|(user, reg)| user.as_str() != except && reg.conversations.contains(conv))
            .map(|(user, reg)| (user.clone(), reg.clone()))
            .collect()
    }

    /// La Live Activity d'un appareil, s'il en a abonné une.
    pub fn of(&self, user: &str) -> Option<LiveReg> {
        self.devices.lock().unwrap().get(user).cloned()
    }

    /// Oublie un appareil (token refusé par APNs : la Live Activity est finie).
    pub fn forget(&self, user: &str, token: &str) {
        let mut map = self.devices.lock().unwrap();
        if map.get(user).is_some_and(|r| r.token == token) {
            map.remove(user);
        }
    }

    pub fn len(&self) -> usize {
        self.devices.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Le `contentState` poussé : même forme que `BrocolisActivityAttributes`
/// côté app (`since`, `unread`, `lastAt`), sans nom ni contenu.
pub fn content_state(since: i64, unread: u64, last_at: Option<i64>) -> serde_json::Value {
    let mut state = serde_json::json!({ "since": since, "unread": unread });
    if let Some(at) = last_at.filter(|_| unread > 0) {
        state["lastAt"] = serde_json::json!(at);
    }
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn followers_are_the_other_devices_of_the_conversation() {
        let live = LiveSubscriptions::default();
        live.subscribe("alice", "TA", 1, vec!["c1".into(), "c2".into()]);
        live.subscribe("bob", "TB", 2, vec!["c1".into()]);
        live.subscribe("carol", "TC", 3, vec!["c9".into()]);
        let mut f: Vec<String> = live.followers("c1", "alice").into_iter().map(|(u, _)| u).collect();
        f.sort();
        assert_eq!(f, vec!["bob"]);
        assert_eq!(live.followers("c2", "bob")[0].0, "alice");
        // Se réabonner remplace : nouveau token, nouvelles conversations.
        live.subscribe("bob", "TB2", 2, vec!["c3".into()]);
        assert!(live.followers("c1", "alice").is_empty());
        assert_eq!(live.of("bob").unwrap().token, "TB2");
        // Un vieux token refusé n'efface pas le nouveau.
        live.forget("bob", "TB");
        assert!(live.of("bob").is_some());
        live.forget("bob", "TB2");
        assert!(live.of("bob").is_none());
    }

    #[test]
    fn the_state_never_carries_content() {
        assert_eq!(content_state(10, 2, Some(20)), serde_json::json!({ "since": 10, "unread": 2, "lastAt": 20 }));
        // Tout lu : le compteur retombe, plus d'heure de dernier message.
        assert_eq!(content_state(10, 0, Some(20)), serde_json::json!({ "since": 10, "unread": 0 }));
    }
}
