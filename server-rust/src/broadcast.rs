//! Diffusion temps réel dans le processus : un canal `broadcast` par
//! conversation. Chaque flux SSE s'abonne ; `POST /v1/messages` et `/v1/read`
//! publient. Un seul processus sert tout le monde : plus besoin de Redis pour
//! relayer entre plusieurs dynos.

use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::broadcast;

#[derive(Default)]
pub struct Broadcaster {
    channels: Mutex<HashMap<String, broadcast::Sender<String>>>,
}

impl Broadcaster {
    /// S'abonne aux événements (JSON) d'une conversation.
    pub fn subscribe(&self, conv: &str) -> broadcast::Receiver<String> {
        let mut map = self.channels.lock().unwrap();
        map.entry(conv.to_string())
            .or_insert_with(|| broadcast::channel(64).0)
            .subscribe()
    }

    /// Publie un événement JSON ; sans abonné, il est simplement perdu.
    pub fn publish(&self, conv: &str, json: String) {
        let map = self.channels.lock().unwrap();
        if let Some(tx) = map.get(conv) {
            let _ = tx.send(json);
        }
    }

    /// Retire les canaux sans plus aucun abonné.
    pub fn prune(&self) {
        self.channels
            .lock()
            .unwrap()
            .retain(|_, tx| tx.receiver_count() > 0);
    }

    /// Le nombre de flux ouverts, toutes conversations confondues.
    pub fn listeners(&self) -> usize {
        self.channels
            .lock()
            .unwrap()
            .values()
            .map(broadcast::Sender::receiver_count)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn events_reach_only_their_conversation() {
        let bc = Broadcaster::default();
        let mut a = bc.subscribe("a");
        let mut b = bc.subscribe("b");
        bc.publish("a", "hello".into());
        assert_eq!(a.recv().await.unwrap(), "hello");
        assert!(b.try_recv().is_err());
        assert_eq!(bc.listeners(), 2);
        drop(a);
        drop(b);
        bc.prune();
        assert_eq!(bc.listeners(), 0);
        assert!(bc.channels.lock().unwrap().is_empty());
    }
}
