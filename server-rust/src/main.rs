//! Démarre le serveur Brocolis 🥦 sur `PORT` (fourni par Heroku), 8788 sinon.
//!
//! Variables facultatives :
//! - `MEMOIRE_PATH` : garde aussi les données dans ce fichier (relu au
//!   démarrage) ; sans elle, tout vit en mémoire ;
//! - `MEMORY_BUDGET_MB` (200) : taille maximale du chiffré gardé en mémoire ;
//! - `MESSAGE_RETENTION_DAYS` (7), `MAX_PEERS` (16) ;
//! - `APNS_*`, `BROCOLIS_PRO_IDS`, `BROCOLIS_PRO_EMAILS` (voir app.json) ;
//! - `SITE_DIR` : le dossier du site (`assets/` et `pkg/`).

use std::sync::Arc;

use brocolis_messagerie::apns::Apns;
use brocolis_messagerie::store::Store;
use brocolis_messagerie::{app, spawn_maintenance, Services};

fn env_number<T: std::str::FromStr>(name: &str, default: T) -> T {
    std::env::var(name)
        .ok()
        .and_then(|v| v.trim().parse().ok())
        .unwrap_or(default)
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let port: u16 = env_number("PORT", 8788);
    let budget_mb: i64 = env_number("MEMORY_BUDGET_MB", 200);
    let budget = budget_mb.max(1) * 1024 * 1024;

    let store = match std::env::var("MEMOIRE_PATH")
        .ok()
        .filter(|p| !p.trim().is_empty())
    {
        Some(path) => {
            println!("Données en mémoire, gardées dans {path} (Memoire).");
            Store::open(path.trim(), budget).await
        }
        None => {
            println!("Données en mémoire seulement (Memoire) : rien n'est écrit sur disque.");
            Store::in_memory(budget).await
        }
    }
    .map_err(|e| std::io::Error::other(format!("stockage Memoire : {e}")))?;

    let services = Services::new(store, env_number("MAX_PEERS", 16));
    spawn_maintenance(&services);

    // Push APNs (Live Activity) : None si config incomplète → route 503.
    let push = Apns::from_env();
    if push.is_some() {
        println!("APNs configuré : mises à jour de Live Activity actives.");
    }

    let site = Arc::new(brocolis_site::server::Site::load());
    if !site.has_bundle() {
        eprintln!("attention : site/pkg manque, les pages ne seront pas animées (voir le README).");
    }

    println!("Brocolis 🥦 (Vitesse + Memoire + Active) à l'écoute sur le port {port}");
    app(&services, push, site).listen(port).await
}
