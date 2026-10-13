//! Serveur Brocolis 🥦, tout en Rust :
//!
//! - [Vitesse](https://maxlestage.github.io/Vitesse/) pour le web : l'API de
//!   messagerie chiffrée, le rendez-vous X25519, le flux temps réel (SSE) ;
//! - [Memoire](https://maxlestage.github.io/Memoire/) pour les données, en
//!   mémoire : ni Postgres ni Redis ;
//! - [Active](https://maxlestage.github.io/Active/) pour le site, rendu ici
//!   même (crate `brocolis-site`).
//!
//! Le serveur ne voit et ne garde que du chiffré.

pub mod api;
pub mod apns;
pub mod apple_signin;
pub mod broadcast;
pub mod limits;
pub mod live;
pub mod rendezvous;
pub mod store;

use std::sync::Arc;
use std::time::{Duration, Instant};

use brocolis_site::server::Site;
use vitesse::prelude::*;

use crate::api::{Push, Started};
use crate::apns::Apns;
use crate::apple_signin::AppleKeys;
use crate::broadcast::Broadcaster;
use crate::live::LiveSubscriptions;
use crate::rendezvous::Rendezvous;
use crate::store::Store;

/// Ce que partagent les requêtes et les tâches de fond.
#[derive(Clone)]
pub struct Services {
    pub store: Arc<Store>,
    pub broadcaster: Arc<Broadcaster>,
    pub rendezvous: Arc<Rendezvous>,
    pub live: Arc<LiveSubscriptions>,
    /// Plafonds de requêtes par minute (anti-abus).
    pub limits: Arc<limits::Limits>,
}

impl Services {
    pub fn new(store: Store, max_peers: usize) -> Services {
        Services {
            store: Arc::new(store),
            broadcaster: Arc::new(Broadcaster::default()),
            rendezvous: Arc::new(Rendezvous::new(max_peers)),
            live: Arc::new(LiveSubscriptions::default()),
            limits: Arc::new(limits::Limits::default()),
        }
    }
}

/// Corps de requête maximal : les médias chiffrés (photos, notes vocales).
pub const BODY_LIMIT: usize = 8 * 1024 * 1024;

/// L'application complète : l'API, puis le site. Les tests construisent
/// exactement la même (avec `vitesse::test::TestClient`).
pub fn app(services: &Services, push: Option<Apns>, site: Arc<Site>) -> App {
    let mut app = App::new();
    // CORS ouvert : le serveur ne relaie que du public ou du chiffré (clés
    // publiques, jetons). Le site peut aussi être servi d'ailleurs.
    app.middleware(middleware::cors());
    app.body_limit(BODY_LIMIT);
    app.state(services.store.clone());
    app.state(services.broadcaster.clone());
    app.state(services.rendezvous.clone());
    app.state(services.live.clone());
    app.state(services.limits.clone());
    // Heroku place un routeur devant le dyno : l'adresse du client est la
    // dernière de `X-Forwarded-For` (sert aux plafonds par adresse).
    app.trust_proxy(1usize);
    app.state(Push(push));
    app.state(AppleKeys::default());
    app.state(Started(Instant::now()));

    api::routes(&mut app);
    brocolis_site::server::configure(&mut app, site.clone());

    // Adresse inconnue : JSON pour l'API, la page 404 du site sinon.
    app.fallback(move |req: Request| {
        let site = site.clone();
        async move {
            if api::is_api_path(req.path()) {
                api::unknown(req).await
            } else {
                brocolis_site::server::not_found(&site, &req)
            }
        }
    });
    app
}

/// Les tâches de fond : rétention des messages (toutes les heures), purge des
/// relais éphémères et des canaux temps réel abandonnés (toutes les minutes).
pub fn spawn_maintenance(services: &Services) {
    let store = services.store.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            tick.tick().await;
            let cutoff = chrono::Utc::now() - chrono::Duration::days(api::retention_days());
            let cutoff = cutoff.to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            match store.purge_before(&cutoff).await {
                Ok(0) => {}
                Ok(n) => println!(
                    "[rétention] {n} message(s) de plus de {} jours supprimés",
                    api::retention_days()
                ),
                Err(e) => eprintln!("[rétention] {e}"),
            }
        }
    });
    let rendezvous = services.rendezvous.clone();
    let broadcaster = services.broadcaster.clone();
    let limits = services.limits.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            rendezvous.prune();
            broadcaster.prune();
            limits.prune();
        }
    });
}
