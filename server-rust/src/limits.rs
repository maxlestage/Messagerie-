//! Garde-fous contre les abus : un nombre de requêtes par minute et par
//! adresse (et par appareil), pour chaque usage sensible. Au-delà : `429`.
//!
//! Les plafonds sont larges pour un usage normal (une app qui sonde le salon
//! toutes les 1,5 s reste dessous) mais rendent impossible de deviner des codes
//! d'invitation (8 caractères, 32⁸ ≈ 10¹² possibilités) ou d'inonder la
//! messagerie.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const WINDOW: Duration = Duration::from_secs(60);

/// Les usages limités, avec leur plafond par minute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    /// Inscription dans un salon (`POST /pair`).
    PairPublish,
    /// Lecture d'un salon ou d'une clé remise (`GET /pair`, `GET /wrap`).
    PairRead,
    /// Remise de clés (`POST /wrap`).
    Wrap,
    /// Envoi d'un message (`POST /v1/messages`).
    Send,
    /// Liaison d'un e-mail Apple (`POST /v1/plan/apple`).
    AppleLink,
    /// Push de Live Activity (`/push/…`, `/v1/live`).
    Push,
}

impl Kind {
    /// Par appareil ; par adresse IP, dix fois plus (une box, un bureau…).
    pub fn per_minute(self) -> u32 {
        match self {
            Kind::PairPublish => 30,
            Kind::PairRead => 240,
            Kind::Wrap => 60,
            Kind::Send => 120,
            Kind::AppleLink => 10,
            Kind::Push => 60,
        }
    }
}

#[derive(Default)]
pub struct Limits {
    buckets: Mutex<HashMap<(Kind, String), (Instant, u32)>>,
}

impl Limits {
    /// Compte une requête de `who` ; `false` si le plafond est dépassé.
    pub fn allow(&self, kind: Kind, who: &str) -> bool {
        self.allow_at(kind, who, Instant::now())
    }

    fn allow_at(&self, kind: Kind, who: &str, now: Instant) -> bool {
        let cap = if who.starts_with("ip:") { kind.per_minute() * 10 } else { kind.per_minute() };
        let mut map = self.buckets.lock().unwrap();
        let entry = map.entry((kind, who.to_owned())).or_insert((now, 0));
        if now.duration_since(entry.0) >= WINDOW {
            *entry = (now, 0);
        }
        entry.1 += 1;
        entry.1 <= cap
    }

    /// Oublie les fenêtres terminées (appelé avec la maintenance).
    pub fn prune(&self) {
        let now = Instant::now();
        self.buckets
            .lock()
            .unwrap()
            .retain(|_, (start, _)| now.duration_since(*start) < WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_window_caps_requests_then_reopens() {
        let limits = Limits::default();
        let t0 = Instant::now();
        for _ in 0..Kind::AppleLink.per_minute() {
            assert!(limits.allow_at(Kind::AppleLink, "1.2.3.4", t0));
        }
        assert!(!limits.allow_at(Kind::AppleLink, "1.2.3.4", t0));
        // Un autre appelant, ou un autre usage, a son propre compteur.
        assert!(limits.allow_at(Kind::AppleLink, "5.6.7.8", t0));
        assert!(limits.allow_at(Kind::Send, "1.2.3.4", t0));
        // Une minute plus tard, ça repart.
        assert!(limits.allow_at(Kind::AppleLink, "1.2.3.4", t0 + WINDOW));
    }

    #[test]
    fn guessing_invitation_codes_is_hopeless() {
        // Au plus 2 400 lectures par minute et par adresse, contre 32⁸ codes :
        // il faudrait des siècles pour en trouver un au hasard.
        let codes = 32f64.powi(8);
        let years = codes / (f64::from(Kind::PairRead.per_minute() * 10) * 60.0 * 24.0 * 365.0);
        assert!(years > 500.0);
    }
}
