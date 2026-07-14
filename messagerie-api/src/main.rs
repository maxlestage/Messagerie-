//! API de messagerie chiffrée de bout en bout — Actix-web.
//!
//! Le serveur route et stocke des messages **déjà chiffrés** (AES-256-GCM côté
//! client). Il ne détient aucune clé et ne peut rien lire : « en clair dans
//! l'app, illisible partout ailleurs ».
//!
//! Lancer :  `cargo run`  (écoute sur 0.0.0.0:$PORT, défaut 8080)
//!
//! Routes :
//!   GET  /health
//!   POST /v1/conversations          { participants:[{id,displayName}] }
//!   GET  /v1/conversations
//!   POST /v1/messages               { conversationId, senderId, ciphertext }
//!   GET  /v1/messages?conversationId=..&after=<seq>
//!   GET  /v1/stream?conversationId=..   (Server-Sent Events)
//!
//! Toutes les routes /v1 exigent l'en-tête `X-User-Id`.

mod handlers;
mod models;
mod store;

use actix_web::{web, App, HttpServer};
use store::Store;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    // Store partagé entre tous les workers (Arc via web::Data).
    let store = web::Data::new(Store::new());

    log::info!("Messagerie chiffrée à l'écoute sur 0.0.0.0:{port}");

    HttpServer::new(move || {
        App::new()
            .app_data(store.clone())
            // Limite la taille des corps JSON (les messages sont petits, même
            // chiffrés) — garde-fou anti-abus.
            .app_data(web::JsonConfig::default().limit(256 * 1024))
            .wrap(actix_web::middleware::Logger::default())
            .route("/health", web::get().to(handlers::health))
            .service(
                web::scope("/v1")
                    .route("/conversations", web::post().to(handlers::create_conversation))
                    .route("/conversations", web::get().to(handlers::list_conversations))
                    .route("/messages", web::post().to(handlers::send_message))
                    .route("/messages", web::get().to(handlers::list_messages))
                    .route("/stream", web::get().to(handlers::stream_messages)),
            )
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{http::StatusCode, test};

    fn app_store() -> web::Data<Store> {
        web::Data::new(Store::new())
    }

    #[actix_web::test]
    async fn health_ok() {
        let app = test::init_service(App::new().route("/health", web::get().to(handlers::health)))
            .await;
        let req = test::TestRequest::get().uri("/health").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    fn service_app(
        store: web::Data<Store>,
    ) -> App<
        impl actix_web::dev::ServiceFactory<
            actix_web::dev::ServiceRequest,
            Config = (),
            Response = actix_web::dev::ServiceResponse,
            Error = actix_web::Error,
            InitError = (),
        >,
    > {
        App::new().app_data(store).service(
            web::scope("/v1")
                .route("/conversations", web::post().to(handlers::create_conversation))
                .route("/conversations", web::get().to(handlers::list_conversations))
                .route("/messages", web::post().to(handlers::send_message))
                .route("/messages", web::get().to(handlers::list_messages)),
        )
    }

    #[actix_web::test]
    async fn requires_auth() {
        let app = test::init_service(service_app(app_store())).await;
        let req = test::TestRequest::get().uri("/v1/conversations").to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[actix_web::test]
    async fn full_flow_create_send_fetch() {
        let store = app_store();
        let app = test::init_service(service_app(store)).await;

        // Création d'une conversation entre "alice" et "bob".
        let create = test::TestRequest::post()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "alice"))
            .set_json(serde_json::json!({
                "participants": [
                    {"id": "alice", "displayName": "Alice"},
                    {"id": "bob", "displayName": "Bob"}
                ]
            }))
            .to_request();
        let convo: serde_json::Value = test::call_and_read_body_json(&app, create).await;
        let cid = convo["id"].as_str().unwrap().to_string();

        // Alice envoie un message chiffré.
        let send = test::TestRequest::post()
            .uri("/v1/messages")
            .insert_header(("X-User-Id", "alice"))
            .set_json(serde_json::json!({
                "conversationId": cid,
                "senderId": "alice",
                "ciphertext": "QUJD"  // base64 factice, le serveur ne le lit pas
            }))
            .to_request();
        let resp = test::call_service(&app, send).await;
        assert_eq!(resp.status(), StatusCode::CREATED);

        // Bob récupère l'historique.
        let list = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={cid}"))
            .insert_header(("X-User-Id", "bob"))
            .to_request();
        let page: serde_json::Value = test::call_and_read_body_json(&app, list).await;
        assert_eq!(page["messages"].as_array().unwrap().len(), 1);
        assert_eq!(page["messages"][0]["ciphertext"], "QUJD");
        assert_eq!(page["cursor"].as_u64().unwrap(), 1);
    }

    #[actix_web::test]
    async fn outsider_cannot_read() {
        let store = app_store();
        let app = test::init_service(service_app(store)).await;

        let create = test::TestRequest::post()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "alice"))
            .set_json(serde_json::json!({
                "participants": [
                    {"id": "alice", "displayName": "Alice"},
                    {"id": "bob", "displayName": "Bob"}
                ]
            }))
            .to_request();
        let convo: serde_json::Value = test::call_and_read_body_json(&app, create).await;
        let cid = convo["id"].as_str().unwrap().to_string();

        let list = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={cid}"))
            .insert_header(("X-User-Id", "eve"))
            .to_request();
        let resp = test::call_service(&app, list).await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[actix_web::test]
    async fn send_is_idempotent_on_id() {
        let store = app_store();
        let app = test::init_service(service_app(store)).await;

        let create = test::TestRequest::post()
            .uri("/v1/conversations")
            .insert_header(("X-User-Id", "alice"))
            .set_json(serde_json::json!({
                "participants": [
                    {"id": "alice", "displayName": "Alice"},
                    {"id": "bob", "displayName": "Bob"}
                ]
            }))
            .to_request();
        let convo: serde_json::Value = test::call_and_read_body_json(&app, create).await;
        let cid = convo["id"].as_str().unwrap().to_string();

        let payload = serde_json::json!({
            "id": "fixed-id-1",
            "conversationId": cid,
            "senderId": "alice",
            "ciphertext": "QUJD"
        });
        for _ in 0..2 {
            let send = test::TestRequest::post()
                .uri("/v1/messages")
                .insert_header(("X-User-Id", "alice"))
                .set_json(&payload)
                .to_request();
            let resp = test::call_service(&app, send).await;
            assert_eq!(resp.status(), StatusCode::CREATED);
        }

        let list = test::TestRequest::get()
            .uri(&format!("/v1/messages?conversationId={cid}"))
            .insert_header(("X-User-Id", "alice"))
            .to_request();
        let page: serde_json::Value = test::call_and_read_body_json(&app, list).await;
        assert_eq!(page["messages"].as_array().unwrap().len(), 1);
    }
}
