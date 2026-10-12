//! Tests bout-en-bout de l'API, sur la vraie application (mêmes routes, même
//! stockage Memoire) : plus besoin de Postgres, ils tournent partout.

use std::sync::Arc;
use std::time::Duration;

use brocolis_messagerie::store::Store;
use brocolis_messagerie::{app, Services};
use brocolis_site::server::Site;
use serde_json::{json, Value};
use vitesse::test::TestClient;

async fn services() -> Services {
    Services::new(Store::in_memory(64 * 1024 * 1024).await.unwrap(), 16)
}

async fn client() -> TestClient {
    TestClient::new(app(&services().await, None, Arc::new(Site::load())))
}

async fn create_conv(client: &TestClient, owner: &str, participants: Value) -> String {
    let res = client
        .post("/v1/conversations")
        .header("x-user-id", owner)
        .json(&json!({ "participants": participants }))
        .await;
    assert_eq!(res.status(), 201, "création conversation : {}", res.text());
    res.json::<Value>()["id"].as_str().unwrap().to_string()
}

async fn post_msg(client: &TestClient, sender: &str, conv: &str, id: &str, ct: &str) -> i64 {
    let res = client
        .post("/v1/messages")
        .header("x-user-id", sender)
        .json(&json!({ "conversationId": conv, "id": id, "ciphertext": ct }))
        .await;
    assert_eq!(res.status(), 201, "envoi message : {}", res.text());
    res.json::<Value>()["seq"].as_i64().unwrap()
}

#[tokio::test]
async fn health_and_stats() {
    let client = client().await;
    let res = client
        .get("/health")
        .header("origin", "https://ailleurs.example")
        .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.text(), "ok");
    // CORS ouvert, comme avant.
    assert_eq!(res.header("access-control-allow-origin"), Some("*"));

    post_msg(&client, "a", "conv", "m1", "XYZ").await;
    let stats: Value = client.get("/stats").await.json();
    assert_eq!(stats["messages"], 1);
    assert_eq!(stats["conversations"], 1);
    assert_eq!(stats["bytes"], 3);
    assert_eq!(stats["storage"], "memoire");
}

#[tokio::test]
async fn message_lifecycle_end_to_end() {
    let client = client().await;
    let conv = create_conv(
        &client,
        "alice",
        json!([{ "id": "alice", "displayName": "Alice" }, { "id": "bob", "displayName": "Bob" }]),
    )
    .await;

    // Bob envoie un message.
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "bob")
        .json(&json!({ "conversationId": conv, "id": "mid", "ciphertext": "SECRET" }))
        .await;
    assert_eq!(res.status(), 201);
    let posted: Value = res.json();
    let seq = posted["seq"].as_i64().unwrap();
    assert_eq!(posted["senderId"], "bob");
    assert_eq!(posted["ciphertext"], "SECRET");
    assert_eq!(posted["conversationId"], conv);
    assert!(posted["sentAt"].as_str().unwrap().ends_with('Z'));

    // Ré-envoi du MÊME id : idempotent (200, même seq, pas de doublon).
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "bob")
        .json(&json!({ "conversationId": conv, "id": "mid", "ciphertext": "SECRET" }))
        .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>()["seq"].as_i64().unwrap(), seq);

    // Alice lit l'historique : un seul message, curseur = seq, aucun lecteur.
    let got: Value = client
        .get(&format!("/v1/messages?conversationId={conv}"))
        .header("x-user-id", "alice")
        .await
        .json();
    assert_eq!(got["messages"].as_array().unwrap().len(), 1);
    assert_eq!(got["cursor"].as_i64().unwrap(), seq);
    assert!(got["readers"].as_object().unwrap().is_empty());
    assert_eq!(got["hasMore"], false);

    // Alice pose un accusé de lecture jusqu'à seq.
    let res = client
        .post("/v1/read")
        .header("x-user-id", "alice")
        .json(&json!({ "conversationId": conv, "upTo": seq }))
        .await;
    assert_eq!(res.status(), 200);
    assert_eq!(res.json::<Value>()["ok"], true);

    // Bob voit maintenant qu'Alice a lu jusqu'à seq.
    let got: Value = client
        .get(&format!("/v1/messages?conversationId={conv}"))
        .header("x-user-id", "bob")
        .await
        .json();
    assert_eq!(got["readers"]["alice"].as_i64().unwrap(), seq);

    // Rattrapage `after=seq` : plus rien de neuf, le curseur ne bouge pas.
    let got: Value = client
        .get(&format!("/v1/messages?conversationId={conv}&after={seq}"))
        .header("x-user-id", "alice")
        .await
        .json();
    assert!(got["messages"].as_array().unwrap().is_empty());
    assert_eq!(got["cursor"].as_i64().unwrap(), seq);
}

#[tokio::test]
async fn messages_are_paginated() {
    let client = client().await;
    let conv = create_conv(
        &client,
        "alice",
        json!([{ "id": "alice" }, { "id": "bob" }]),
    )
    .await;
    let mut ids = Vec::new();
    for i in 0..5 {
        let id = format!("m{i}");
        post_msg(&client, "bob", &conv, &id, &format!("c{i}")).await;
        ids.push(id);
    }
    let page = |after: i64, limit: i64| {
        let client = &client;
        let conv = conv.clone();
        async move {
            client
                .get(&format!(
                    "/v1/messages?conversationId={conv}&after={after}&limit={limit}"
                ))
                .header("x-user-id", "alice")
                .await
                .json::<Value>()
        }
    };
    let p1 = page(0, 2).await;
    assert_eq!(p1["messages"].as_array().unwrap().len(), 2);
    assert_eq!(p1["hasMore"], true);
    assert_eq!(p1["limit"], 2);
    assert_eq!(p1["messages"][0]["id"], ids[0]);
    assert_eq!(p1["messages"][1]["id"], ids[1]);
    let p2 = page(p1["cursor"].as_i64().unwrap(), 2).await;
    assert_eq!(p2["messages"][0]["id"], ids[2]);
    assert_eq!(p2["messages"][1]["id"], ids[3]);
    assert_eq!(p2["hasMore"], true);
    let p3 = page(p2["cursor"].as_i64().unwrap(), 2).await;
    assert_eq!(p3["messages"].as_array().unwrap().len(), 1);
    assert_eq!(p3["messages"][0]["id"], ids[4]);
    assert_eq!(p3["hasMore"], false);
    // `limit` hors bornes est ramené au plafond (jamais illimité).
    assert_eq!(page(0, 100_000).await["limit"], 500);
}

#[tokio::test]
async fn access_control_end_to_end() {
    let client = client().await;
    let conv = create_conv(
        &client,
        "alice",
        json!([{ "id": "alice" }, { "id": "bob" }]),
    )
    .await;

    // Sans X-User-Id → 401.
    let res = client
        .get(&format!("/v1/messages?conversationId={conv}"))
        .await;
    assert_eq!(res.status(), 401);
    assert_eq!(res.text(), "x-user-id requis");

    // Non-participant (carol) → 403 partout.
    let res = client
        .get(&format!("/v1/messages?conversationId={conv}"))
        .header("x-user-id", "carol")
        .await;
    assert_eq!(res.status(), 403);
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "carol")
        .json(&json!({ "conversationId": conv, "id": "x", "ciphertext": "y" }))
        .await;
    assert_eq!(res.status(), 403);
    let res = client
        .post("/v1/read")
        .header("x-user-id", "carol")
        .json(&json!({ "conversationId": conv, "upTo": 1 }))
        .await;
    assert_eq!(res.status(), 403);
    let res = client
        .get(&format!("/v1/stream?conversationId={conv}"))
        .header("x-user-id", "carol")
        .await;
    assert_eq!(res.status(), 403);

    // Conversation INCONNUE (scellée) → autorisée, rien de lisible sans la clé.
    let res = client
        .get("/v1/messages?conversationId=inconnue")
        .header("x-user-id", "zoe")
        .await;
    assert_eq!(res.status(), 200);

    // Corps invalide → 400 ; champs vides → 400.
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "zoe")
        .header("content-type", "application/json")
        .body("pas du json")
        .await;
    assert_eq!(res.status(), 400);
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "zoe")
        .json(&json!({ "conversationId": " ", "id": "x", "ciphertext": "y" }))
        .await;
    assert_eq!(res.status(), 400);
}

#[tokio::test]
async fn conversation_membership_rules() {
    let client = client().await;
    // Moins de 2 participants → 400.
    let res = client
        .post("/v1/conversations")
        .header("x-user-id", "alice")
        .json(&json!({ "participants": [{ "id": "alice" }] }))
        .await;
    assert_eq!(res.status(), 400);
    // Créateur absent de la liste → 403.
    let res = client
        .post("/v1/conversations")
        .header("x-user-id", "alice")
        .json(&json!({ "participants": [{ "id": "bob" }, { "id": "carol" }] }))
        .await;
    assert_eq!(res.status(), 403);
    // Conversation valide : elle apparaît chez Alice, pas chez Carol.
    let conv = create_conv(
        &client,
        "alice",
        json!([{ "id": "alice" }, { "id": "bob", "displayName": "Bob" }]),
    )
    .await;
    let list: Value = client
        .get("/v1/conversations")
        .header("x-user-id", "alice")
        .await
        .json();
    let mine = list
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == conv)
        .unwrap();
    assert_eq!(mine["participants"][1]["displayName"], "Bob");
    let list: Value = client
        .get("/v1/conversations")
        .header("x-user-id", "carol")
        .await
        .json();
    assert!(list.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn pairing_and_group_key_relay() {
    let client = client().await;
    // Alice publie sa clé : personne d'autre encore.
    let res = client
        .post("/pair")
        .json(&json!({ "code": "4813", "peerId": "alice", "pub": "PUB_A" }))
        .await;
    assert_eq!(res.status(), 200);
    assert!(res.json::<Value>()["peers"].as_array().unwrap().is_empty());
    // Bob arrive : il voit Alice.
    let res: Value = client
        .post("/pair")
        .json(&json!({ "code": "4813", "peerId": "bob", "pub": "PUB_B" }))
        .await
        .json();
    assert_eq!(res["peers"][0]["peerId"], "alice");
    assert_eq!(res["peers"][0]["pub"], "PUB_A");
    // Lecture publique du salon (page Salon du site).
    let res: Value = client.get("/pair?code=4813").await.json();
    assert_eq!(res["peers"].as_array().unwrap().len(), 2);
    let res = client.get("/pair").await;
    assert_eq!(res.status(), 400, "code requis");

    // Clé de groupe emballée pour Bob.
    let res: Value = client
        .post("/wrap")
        .json(
            &json!({ "code": "4813", "fromPeerId": "alice", "fromPub": "PUB_A",
                        "items": [{ "toPeerId": "bob", "blob": "BLOB" }] }),
        )
        .await
        .json();
    assert_eq!(res["count"], 1);
    let res: Value = client.get("/wrap?code=4813&peerId=bob").await.json();
    assert_eq!(res["wrap"]["blob"], "BLOB");
    assert_eq!(res["wrap"]["fromPub"], "PUB_A");
    let res: Value = client.get("/wrap?code=4813&peerId=dan").await.json();
    assert!(res["wrap"].is_null());

    // Push : token enregistré, mais APNs non configuré → 503.
    let res = client
        .post("/push/live-activity/token")
        .json(&json!({ "code": "4813", "peerId": "bob", "token": "T" }))
        .await;
    assert_eq!(res.status(), 200);
    let res = client
        .post("/push/live-activity/update")
        .json(&json!({ "code": "4813", "peerId": "bob", "contentState": { "unread": 1 } }))
        .await;
    assert_eq!(res.status(), 503);
    let res = client
        .post("/push/live-activity/update")
        .json(&json!({ "code": "4813", "peerId": "nobody", "contentState": {} }))
        .await;
    assert_eq!(res.status(), 404);
}

/// Accès offert par e-mail : un appareil rattaché à un e-mail Apple listé dans
/// `BROCOLIS_PRO_EMAILS` obtient Pro ; retirer l'e-mail de la liste ou
/// détacher l'appareil le retire. Seul ce test touche à ces variables.
#[tokio::test]
async fn plan_follows_the_linked_apple_email() {
    let services = services().await;
    let client = TestClient::new(app(&services, None, Arc::new(Site::load())));
    services
        .store
        .link_email("device-1", "max@icloud.com")
        .await
        .unwrap();

    std::env::set_var("BROCOLIS_PRO_EMAILS", "ami@exemple.fr, Max@iCloud.com");
    let v: Value = client
        .get("/v1/plan")
        .header("x-user-id", "device-1")
        .await
        .json();
    assert_eq!(v["tier"], "pro");
    assert_eq!(v["email"], "max@icloud.com");

    std::env::set_var("BROCOLIS_PRO_EMAILS", "ami@exemple.fr");
    let v: Value = client
        .get("/v1/plan")
        .header("x-user-id", "device-1")
        .await
        .json();
    assert_eq!(v["tier"], "free", "retiré de la liste = plus de Pro");

    std::env::set_var("BROCOLIS_PRO_EMAILS", "max@icloud.com");
    let v: Value = client
        .delete("/v1/plan/apple")
        .header("x-user-id", "device-1")
        .await
        .json();
    assert_eq!(v["tier"], "free", "appareil détaché");
    let v: Value = client
        .get("/v1/plan")
        .header("x-user-id", "device-1")
        .await
        .json();
    assert_eq!(v["email"], Value::Null);
    std::env::remove_var("BROCOLIS_PRO_EMAILS");

    // Un jeton Apple illisible est refusé (401) sans rien enregistrer.
    let res = client
        .post("/v1/plan/apple")
        .header("x-user-id", "device-2")
        .json(&json!({ "identityToken": "pas-un-jeton" }))
        .await;
    assert_eq!(res.status(), 401);
    let res = client.get("/v1/plan").await;
    assert_eq!(res.status(), 401);
}

#[tokio::test]
async fn the_site_is_served_next_to_the_api() {
    let client = client().await;
    // `/` mène à l'accueil dans la langue du navigateur.
    let res = client
        .get("/")
        .header("accept-language", "es-ES,es;q=0.9")
        .await;
    assert!(res.status().is_redirection());
    assert_eq!(res.header("location"), Some("/es/"));
    // L'ancienne adresse de la vitrine.
    let res = client.get("/site/").await;
    assert!(res.status().is_redirection());
    assert_eq!(res.header("location"), Some("/"));

    let res = client.get("/fr/").await;
    assert_eq!(res.status(), 200);
    let html = res.text();
    assert!(html.contains(r#"data-island="demo""#));
    assert!(html.contains("Brocolis"));
    // Premier accueil : le rideau joue, et un cookie s'en souvient.
    assert!(html.contains(r#"id="splash""#));
    assert!(res
        .header("set-cookie")
        .unwrap()
        .starts_with("brocolis-intro=1"));
    // Le thème vient du cookie.
    let html = client
        .get("/en/salon/")
        .header("cookie", "brocolis-theme=dark")
        .await
        .text();
    assert!(html.contains(r#"data-theme="dark""#));
    assert!(html.contains(r#"data-island="salon""#));
    assert_eq!(client.get("/es/serveur/").await.status(), 200);
    assert_eq!(client.get("/fr/licence/").await.status(), 200);
    assert!(client.get("/fr/salon").await.status().is_redirection());

    // Inconnu : la page 404 du site… ou du JSON pour l'API.
    let res = client.get("/fr/nulle-part/").await;
    assert_eq!(res.status(), 404);
    assert!(res.text().contains("404"));
    for path in ["/v1/nope", "/v1/a/b", "/push/nope"] {
        let res = client.get(path).await;
        assert_eq!(res.status(), 404, "{path}");
        assert!(res.json::<Value>()["error"].is_string(), "{path}");
    }
    // Une route d'API connue, mauvaise méthode : pas la page du site.
    assert_ne!(client.get("/v1/read").await.status(), 200);

    // Fichiers statiques.
    assert_eq!(client.get("/assets/style.css").await.status(), 200);
    assert_eq!(client.get("/photo.png").await.status(), 200);
    assert!(client
        .get("/sitemap.xml")
        .await
        .text()
        .contains("/es/serveur/"));
    assert!(client
        .get("/fr/manifest.webmanifest")
        .await
        .text()
        .contains("Brocolis"));
}

/// Le flux temps réel, sur un vrai port : un message posté arrive aussitôt
/// aux abonnés, puis l'accusé de lecture.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stream_delivers_messages_and_read_receipts() {
    let services = services().await;
    let server = app(&services, None, Arc::new(Site::load()))
        .bind(([127, 0, 0, 1], 0))
        .await
        .unwrap();
    let base = format!("http://{}", server.local_addr());
    tokio::spawn(server.run());

    let http = reqwest::Client::new();
    let mut stream = http
        .get(format!("{base}/v1/stream?conversationId=live"))
        .header("x-user-id", "alice")
        .send()
        .await
        .unwrap();
    assert_eq!(stream.status(), 200);
    assert_eq!(stream.headers()["content-type"], "text/event-stream");

    let mut received = String::new();
    // L'amorce (un commentaire `: ok`) arrive tout de suite.
    let chunk = tokio::time::timeout(Duration::from_secs(5), stream.chunk())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    received.push_str(&String::from_utf8_lossy(&chunk));
    assert!(received.starts_with(": ok"), "{received:?}");

    let posted: Value = http
        .post(format!("{base}/v1/messages"))
        .header("x-user-id", "bob")
        .json(&json!({ "conversationId": "live", "id": "m1", "ciphertext": "TOKEN" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    http.post(format!("{base}/v1/read"))
        .header("x-user-id", "alice")
        .json(&json!({ "conversationId": "live", "upTo": posted["seq"] }))
        .send()
        .await
        .unwrap();

    while !received.contains(r#""type":"read""#) {
        let chunk = tokio::time::timeout(Duration::from_secs(5), stream.chunk())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        received.push_str(&String::from_utf8_lossy(&chunk));
    }
    let events: Vec<Value> = received
        .lines()
        .filter_map(|l| l.strip_prefix("data: "))
        .map(|d| serde_json::from_str(d).unwrap())
        .collect();
    assert_eq!(events[0]["id"], "m1");
    assert_eq!(events[0]["ciphertext"], "TOKEN");
    assert_eq!(events[0]["seq"], posted["seq"]);
    assert_eq!(events[1]["type"], "read");
    assert_eq!(events[1]["reader"], "alice");
    assert_eq!(events[1]["upTo"], posted["seq"]);
}
