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
    app(&services().await, None, Arc::new(Site::load()))
        .test()
        .await
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

    // Le navigateur (EventSource) passe l'identifiant en paramètre : mêmes
    // règles d'accès que l'en-tête.
    let res = client.get(&format!("/v1/stream?conversationId={conv}&userId=carol")).await;
    assert_eq!(res.status(), 403);
    let res = client.get("/v1/messages?conversationId=inconnue&userId=zoe").await;
    assert_eq!(res.status(), 200);
    let res = client.get("/v1/messages?conversationId=inconnue").await;
    assert_eq!(res.status(), 401);

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
    const PUB_A: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const PUB_B: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const PUB_M: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const BLOB: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";
    // Alice invite : elle publie sa clé en revendiquant l'hôte.
    let res = client
        .post("/pair")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "alice", "pub": PUB_A, "host": true }))
        .await;
    assert_eq!(res.status(), 200);
    assert!(res.json::<Value>()["peers"].as_array().unwrap().is_empty());
    // Bob arrive : il voit Alice.
    let res: Value = client
        .post("/pair")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "bob", "pub": PUB_B }))
        .await
        .json();
    assert_eq!(res["peers"][0]["peerId"], "alice");
    assert_eq!(res["peers"][0]["pub"], PUB_A);
    // Lecture publique du salon (page Salon du site).
    let res: Value = client.get("/pair?code=K7P2QXAB").await.json();
    assert_eq!(res["peers"].as_array().unwrap().len(), 2);
    let res = client.get("/pair").await;
    assert_eq!(res.status(), 400, "code requis");

    // ── Tricheurs ──
    // Code mal formé, clé publique qui n'en est pas une : refusés.
    let res = client.get("/pair?code=abc").await;
    assert_eq!(res.status(), 400);
    let res = client
        .post("/pair")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "eve", "pub": "PAS_UNE_CLE" }))
        .await;
    assert_eq!(res.status(), 400);
    // Remplacer la clé publique de Bob pour intercepter sa clé : refusé.
    let res = client
        .post("/pair")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "bob", "pub": PUB_M }))
        .await;
    assert_eq!(res.status(), 409);
    // Mallory rejoint, puis tente de glisser SA clé à Bob : refusé (pas l'hôte).
    client
        .post("/pair")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "mallory", "pub": PUB_M }))
        .await;
    let res = client
        .post("/wrap")
        .json(&json!({ "code": "K7P2QXAB", "fromPeerId": "mallory", "fromPub": PUB_M,
                        "items": [{ "toPeerId": "bob", "blob": "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG" }] }))
        .await;
    assert_eq!(res.status(), 403);
    // Ni en se faisant passer pour Alice avec sa propre clé.
    let res = client
        .post("/wrap")
        .json(&json!({ "code": "K7P2QXAB", "fromPeerId": "alice", "fromPub": PUB_M,
                        "items": [{ "toPeerId": "bob", "blob": "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYG" }] }))
        .await;
    assert_eq!(res.status(), 403);
    let res: Value = client.get("/wrap?code=K7P2QXAB&peerId=bob").await.json();
    assert!(res["wrap"].is_null());

    // L'hôte remet la clé de groupe emballée pour Bob.
    let res: Value = client
        .post("/wrap")
        .json(
            &json!({ "code": "K7P2QXAB", "fromPeerId": "alice", "fromPub": PUB_A,
                        "items": [{ "toPeerId": "bob", "blob": BLOB }, { "toPeerId": "carol", "blob": "trop court" }] }),
        )
        .await
        .json();
    assert_eq!(res["count"], 1, "un blob mal formé est ignoré");
    let res: Value = client.get("/wrap?code=K7P2QXAB&peerId=bob").await.json();
    assert_eq!(res["wrap"]["blob"], BLOB);
    assert_eq!(res["wrap"]["fromPub"], PUB_A);
    let res: Value = client.get("/wrap?code=K7P2QXAB&peerId=dan").await.json();
    assert!(res["wrap"].is_null());

    // Push : token enregistré, mais APNs non configuré → 503.
    let res = client
        .post("/push/live-activity/token")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "bob", "token": "T" }))
        .await;
    assert_eq!(res.status(), 200);
    let res = client
        .post("/push/live-activity/update")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "bob", "contentState": { "unread": 1 } }))
        .await;
    assert_eq!(res.status(), 503);
    let res = client
        .post("/push/live-activity/update")
        .json(&json!({ "code": "K7P2QXAB", "peerId": "nobody", "contentState": {} }))
        .await;
    assert_eq!(res.status(), 404);
}

/// L'appairage v3 (`docs/SECURITE.md` §8.4) : chacun publie son paquet de
/// clés avec sa clé publique ; le salon le vérifie, le rend aux autres, et
/// un ancien client continue de s'appairer sans rien voir changer. Puis les
/// deux ouvrent une session à double cliquet avec ce que le salon leur a
/// donné et se parlent par la messagerie : le serveur ne voit que des
/// paquets publics et des jetons v3.
#[tokio::test]
async fn pairing_exchanges_v3_bundles_then_a_ratchet_session_talks() {
    use brocolis_proto::{hasard, Content, Device, KeyBundle, Token};
    let client = client().await;
    let rng = &mut hasard::system();
    let now = 1_800_000_000;
    let alice = Device::generate(rng, now, true);
    let mut bob = Device::generate(rng, now, false);
    let bundle_a = alice.bundle().unwrap().to_base64();
    let bundle_b = bob.bundle().unwrap().to_base64();
    const PUB_A: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const PUB_B: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const PUB_C: &str = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=";
    const CODE: &str = "V3PAIRAB";

    let res = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "alice", "pub": PUB_A, "host": true, "bundle": bundle_a }))
        .await;
    assert_eq!(res.status(), 200, "{}", res.text());
    // Un ancien client (sans paquet) s'inscrit comme avant.
    let res = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "carol", "pub": PUB_C }))
        .await;
    assert_eq!(res.status(), 200);
    let res: Value = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "bob", "pub": PUB_B, "bundle": bundle_b }))
        .await
        .json();
    let peers = res["peers"].as_array().unwrap();
    let seen_a = peers.iter().find(|p| p["peerId"] == "alice").unwrap();
    assert_eq!(seen_a["pub"], PUB_A);
    let carol = peers.iter().find(|p| p["peerId"] == "carol").unwrap();
    assert!(carol.get("bundle").is_none());
    let seen_a = KeyBundle::from_base64(seen_a["bundle"].as_str().unwrap()).unwrap();
    assert_eq!(seen_a.identity, alice.identity());
    assert!(seen_a.pq.is_some(), "le paquet garde sa clé ML-KEM");
    let res: Value = client.get(&format!("/pair?code={CODE}&peerId=alice")).await.json();
    let seen_b = res["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "bob").unwrap();
    let seen_b = KeyBundle::from_base64(seen_b["bundle"].as_str().unwrap()).unwrap();
    assert_eq!(seen_b.identity, bob.identity());

    // ── Tricheurs ──
    // Un paquet abîmé (une signature fausse) : refusé, le salon ne change pas.
    let mut bytes = alice.bundle().unwrap().to_bytes();
    bytes[120] ^= 1;
    assert!(KeyBundle::from_bytes(&bytes).is_err());
    let forged = brocolis_site::crypto::b64(&bytes);
    let res = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "dave", "pub": PUB_C, "bundle": forged }))
        .await;
    assert_eq!(res.status(), 400);
    let res = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "dave", "pub": PUB_C, "bundle": "pas un paquet" }))
        .await;
    assert_eq!(res.status(), 400);
    // Le paquet d'une autre identité sous le peerId de Bob : refusé.
    let mallory = Device::generate(rng, now, false).bundle().unwrap().to_base64();
    let res = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "bob", "pub": PUB_B, "bundle": mallory }))
        .await;
    assert_eq!(res.status(), 409);
    // Republier sans paquet (ancienne version de la même app) : il reste.
    let res: Value = client
        .post("/pair")
        .json(&json!({ "code": CODE, "peerId": "bob", "pub": PUB_B }))
        .await
        .json();
    let again = res["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "alice").unwrap();
    assert!(again["bundle"].is_string());
    let res: Value = client.get(&format!("/pair?code={CODE}&peerId=alice")).await.json();
    let still_b = res["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "bob").unwrap();
    assert_eq!(KeyBundle::from_base64(still_b["bundle"].as_str().unwrap()).unwrap().identity, bob.identity());

    // ── La session, par la messagerie ──
    let mut a = alice.initiate(&seen_b, seen_b.pq.is_some(), rng).unwrap();
    assert!(!a.is_post_quantum(), "Bob n'a pas ML-KEM : X25519 seul");
    let first = a.encrypt("Salut Bob 🥦").unwrap();
    post_msg(&client, "alice-device", "conv-v3", "m1", &first).await;
    let page: Value = client
        .get("/v1/messages?conversationId=conv-v3&after=0")
        .header("x-user-id", "bob-device")
        .await
        .json();
    let ct = page["messages"][0]["ciphertext"].as_str().unwrap();
    assert!(ct.starts_with("[[BROCOLIS:v3:"));
    let Token::Initial(initial) = Token::decode(ct).unwrap() else { panic!("premier message attendu") };
    assert_eq!(initial.identity, seen_a.identity.dh, "IK_A est celle du paquet vu au salon");
    let (mut b, content) = bob.accept(&initial, now, rng).unwrap();
    assert_eq!(content, Content::Text("Salut Bob 🥦".into()));
    let reply = b.encrypt("Bien reçu").unwrap();
    post_msg(&client, "bob-device", "conv-v3", "m2", &reply).await;
    assert_eq!(a.decrypt_text(&reply, now, rng).unwrap(), Content::Text("Bien reçu".into()));
    assert!(a.is_confirmed());
    // Le serveur renvoie le premier message : rejeu ignoré.
    assert!(b.decrypt_text(&first, now, rng).is_err());
}

/// La capacité v4 (`docs/SECURITE.md` §9.6) : signée par l'identité du
/// paquet publié, vérifiée par le salon et rendue aux autres. Puis une
/// session à triple cliquet passe par la messagerie sans rien laisser en
/// clair qu'un jeton v4.
#[tokio::test]
async fn pairing_relays_signed_v4_caps_then_a_triple_ratchet_talks() {
    use brocolis_proto::{hasard, Content, Device, KeyBundle, Token4};
    let client = client().await;
    let rng = &mut hasard::system();
    let now = 1_800_000_000;
    let alice = Device::generate(rng, now, true);
    let mut bob = Device::generate(rng, now, true);
    let b64 = brocolis_site::crypto::b64;
    const PUB_A: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const PUB_B: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const CODE: &str = "V4PAIRAB";
    let pair = |peer: &'static str, pubk: &'static str, body: Value| {
        let mut body = body;
        body["code"] = CODE.into();
        body["peerId"] = peer.into();
        body["pub"] = pubk.into();
        body
    };

    // ── Tricheurs ──
    // Une capacité sans paquet, abîmée, ou signée par une autre identité.
    let caps_a = b64(&alice.caps4().unwrap());
    let res = client.post("/pair").json(&pair("alice", PUB_A, json!({ "caps": caps_a }))).await;
    assert_eq!(res.status(), 400);
    let mut bad = alice.caps4().unwrap();
    bad[3] ^= 1;
    let bundle_a = alice.bundle().unwrap().to_base64();
    let res = client.post("/pair").json(&pair("alice", PUB_A, json!({ "bundle": bundle_a, "caps": b64(&bad) }))).await;
    assert_eq!(res.status(), 400);
    let other = b64(&Device::generate(rng, now, true).caps4().unwrap());
    let res = client.post("/pair").json(&pair("alice", PUB_A, json!({ "bundle": bundle_a, "caps": other }))).await;
    assert_eq!(res.status(), 400);
    // Une capacité sur un paquet sans ML-KEM : refusée aussi.
    let classic = Device::generate(rng, now, false);
    let res = client
        .post("/pair")
        .json(&pair("alice", PUB_A, json!({ "bundle": classic.bundle().unwrap().to_base64(), "caps": caps_a })))
        .await;
    assert_eq!(res.status(), 400);

    // ── Les honnêtes ──
    let res = client.post("/pair").json(&pair("alice", PUB_A, json!({ "host": true, "bundle": bundle_a, "caps": caps_a }))).await;
    assert_eq!(res.status(), 200, "{}", res.text());
    let bundle_b = bob.bundle().unwrap().to_base64();
    let caps_b = b64(&bob.caps4().unwrap());
    let res: Value = client.post("/pair").json(&pair("bob", PUB_B, json!({ "bundle": bundle_b, "caps": caps_b }))).await.json();
    let seen_a = res["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "alice").unwrap().clone();
    assert_eq!(seen_a["caps"], caps_a.as_str());
    // Republier sans capacité la garde.
    client.post("/pair").json(&pair("bob", PUB_B, json!({}))).await;
    let res: Value = client.get(&format!("/pair?code={CODE}&peerId=alice")).await.json();
    let seen_b = res["peers"].as_array().unwrap().iter().find(|p| p["peerId"] == "bob").unwrap().clone();
    assert_eq!(seen_b["caps"], caps_b.as_str());
    let bundle_seen_b = KeyBundle::from_base64(seen_b["bundle"].as_str().unwrap()).unwrap();
    let raw: [u8; 64] = brocolis_site::crypto::unb64(seen_b["caps"].as_str().unwrap()).unwrap().try_into().unwrap();
    brocolis_proto::paquet::verify_caps4(&bundle_seen_b.identity, &raw).unwrap();

    // ── La session v4, par la messagerie ──
    let mut a = alice.initiate4(&bundle_seen_b, rng).unwrap();
    let first = a.encrypt("Salut Bob 🥦").unwrap();
    post_msg(&client, "alice-device", "conv-v4", "m1", &first).await;
    let page: Value = client
        .get("/v1/messages?conversationId=conv-v4&after=0")
        .header("x-user-id", "bob-device")
        .await
        .json();
    let ct = page["messages"][0]["ciphertext"].as_str().unwrap();
    assert!(ct.starts_with("[[BROCOLIS:v4:"));
    assert!(!ct.contains("alice"));
    let token = Token4::decode(ct).unwrap();
    let (mut b, content) = bob.accept4(&token, now, rng).unwrap();
    assert_eq!(content, Content::Text("Salut Bob 🥦".into()));
    let reply = b.encrypt("Bien reçu").unwrap();
    post_msg(&client, "bob-device", "conv-v4", "m2", &reply).await;
    assert_eq!(a.decrypt_text(&reply, now, rng).unwrap(), Content::Text("Bien reçu".into()));
    assert!(b.decrypt_text(&first, now, rng).is_err(), "rejeu ignoré");
}

/// Accès offert par e-mail : un appareil rattaché à un e-mail Apple listé dans
/// `BROCOLIS_PRO_EMAILS` obtient Pro ; retirer l'e-mail de la liste ou
/// détacher l'appareil le retire. Seul ce test touche à ces variables.
#[tokio::test]
async fn plan_follows_the_linked_apple_email() {
    let svc = services().await;
    let client = app(&svc, None, Arc::new(Site::load()))
        .test()
        .await;
    svc.store
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

    // Redémarrage du serveur : mémoire vide, mais l'app renvoie son ticket.
    std::env::set_var("BROCOLIS_GRANT_SECRET", "secret-de-test");
    std::env::set_var(
        "BROCOLIS_PRO_EMAILS",
        "maxlestage@icloud.com,\nclement67114@gmail.com",
    );
    let ticket =
        brocolis_messagerie::apple_signin::issue_ticket("device-3", "clement67114@gmail.com")
            .unwrap();
    let restarted = app(&services().await, None, Arc::new(Site::load()))
        .test()
        .await;
    let v: Value = restarted
        .get("/v1/plan")
        .header("x-user-id", "device-3")
        .await
        .json();
    assert_eq!(v["tier"], "free", "sans ticket, rien ne survit");
    let v: Value = restarted
        .get("/v1/plan")
        .header("x-user-id", "device-3")
        .header("x-brocolis-grant", ticket.as_str())
        .await
        .json();
    assert_eq!(v["tier"], "pro", "le ticket rétablit l'accès");
    assert_eq!(v["email"], "clement67114@gmail.com");
    // Le lien est de nouveau en mémoire : plus besoin du ticket.
    let v: Value = restarted
        .get("/v1/plan")
        .header("x-user-id", "device-3")
        .await
        .json();
    assert_eq!(v["tier"], "pro");
    // Un ticket volé ne sert pas sur un autre appareil.
    let v: Value = restarted
        .get("/v1/plan")
        .header("x-user-id", "device-4")
        .header("x-brocolis-grant", ticket.as_str())
        .await
        .json();
    assert_eq!(v["tier"], "free");
    // Retiré de la liste : le ticket n'ouvre plus rien.
    std::env::set_var("BROCOLIS_PRO_EMAILS", "maxlestage@icloud.com");
    let v: Value = restarted
        .get("/v1/plan")
        .header("x-user-id", "device-3")
        .await
        .json();
    assert_eq!(v["tier"], "free");
    std::env::remove_var("BROCOLIS_GRANT_SECRET");
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
    // Un port libre, puis l'app Paquets complète (bouclier compris) dessus.
    let port = std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut server = app(&services, None, Arc::new(Site::load()));
    server.port(port).quiet();
    tokio::spawn(server.serve());
    let base = format!("http://127.0.0.1:{port}");
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

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

/// L'app abonne sa Live Activity à ses conversations : seulement celles
/// auxquelles elle a droit, avec un token hexadécimal.
#[tokio::test]
async fn live_activity_subscription() {
    let svc = services().await;
    let client = app(&svc, None, Arc::new(Site::load()))
        .test()
        .await;
    let private = create_conv(&client, "alice", json!([{ "id": "alice" }, { "id": "bob" }])).await;

    let res = client
        .post("/v1/live")
        .header("x-user-id", "carol")
        .json(&json!({ "token": "a1b2c3", "conversationIds": ["scellee", private], "since": 1000 }))
        .await;
    assert_eq!(res.status(), 200);
    let body: Value = res.json();
    assert_eq!(body["conversations"], 1, "pas la conversation privée d'Alice et Bob");
    assert_eq!(body["push"], false, "APNs non configuré dans les tests");
    let reg = svc.live.of("carol").unwrap();
    assert_eq!(reg.since, 1000);
    assert!(reg.conversations.contains("scellee"));

    // Bob poste dans la conversation scellée : Carol en est abonnée.
    assert_eq!(svc.live.followers("scellee", "bob").len(), 1);
    post_msg(&client, "bob", "scellee", "m1", "X").await;
    assert_eq!(svc.store.unread("scellee", "carol").await.unwrap().0, 1);

    let res = client
        .post("/v1/live")
        .header("x-user-id", "carol")
        .json(&json!({ "token": "pas-hexa!", "conversationIds": ["x"] }))
        .await;
    assert_eq!(res.status(), 400);
    let res = client.post("/v1/live").json(&json!({ "token": "ab", "conversationIds": [] })).await;
    assert_eq!(res.status(), 401);
}

// ── Le bouclier 🔒 (Securite, branché par Paquets) ───────────────────────────

#[tokio::test]
async fn pages_ship_hardened_headers_and_a_tight_csp() {
    let client = client().await;
    let res = client.get("/fr/").await;
    assert_eq!(res.status(), 200);
    let csp = res.header("content-security-policy").unwrap().to_owned();
    assert!(csp.contains("default-src 'self'"), "{csp}");
    assert!(csp.contains("'wasm-unsafe-eval'"), "{csp}");
    assert!(csp.contains("object-src 'none'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert!(!csp.contains("script-src 'self' 'unsafe-inline'"), "{csp}");
    assert!(res.header("strict-transport-security").is_some());
    assert_eq!(res.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(res.header("x-frame-options"), Some("DENY"));
    assert!(res.header("x-request-id").is_some());
    // Le micro reste permis pour les notes vocales, pas la caméra.
    let permissions = res.header("permissions-policy").unwrap();
    assert!(permissions.contains("microphone=(self)"), "{permissions}");
    assert!(permissions.contains("camera=()"), "{permissions}");
    // Le pied de page le dit.
    let html = res.text();
    assert!(html.contains("made-with"), "badge « Écrit avec Paquets »");
    assert!(html.contains("Securite"));
}

#[tokio::test]
async fn the_csp_allows_exactly_the_inline_code_of_the_pages() {
    let site = Site::load();
    let csp = brocolis_messagerie::bouclier::content_security_policy(&site).to_string();
    let html = brocolis_site::server::pages::inline_code(&site);
    for hash in paquets::securite::prelude::ContentSecurityPolicy::hashes_for_inline_styles(&html) {
        assert!(csp.contains(&hash), "{hash} manque dans {csp}");
    }
    for hash in paquets::securite::prelude::ContentSecurityPolicy::hashes_for_inline_scripts(&html)
    {
        assert!(csp.contains(&hash), "{hash} manque dans {csp}");
    }
}

#[tokio::test]
async fn the_waf_and_the_bot_blocker_turn_attacks_away() {
    let client = client().await;
    let sqli = client
        .get("/v1/messages?conversationId=x%27%20UNION%20SELECT%20password%20FROM%20users--")
        .header("x-user-id", "alice")
        .await;
    assert_eq!(sqli.status(), 403, "{}", sqli.text());

    let xss = client
        .get("/fr/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
        .await;
    assert_eq!(xss.status(), 403);

    let scanner = client
        .get("/health")
        .header("user-agent", "sqlmap/1.7")
        .await;
    assert_eq!(scanner.status(), 403);

    let traversal = client.get("/assets/..%2f..%2fetc%2fpasswd").await;
    assert!(traversal.status() == 400 || traversal.status() == 403);

    // Les vraies requêtes passent toujours.
    assert_eq!(client.get("/health").await.status(), 200);
}

#[tokio::test]
async fn api_bodies_are_json_and_bounded() {
    let client = client().await;
    let form = client
        .post("/v1/messages")
        .header("x-user-id", "alice")
        .header("content-type", "application/x-www-form-urlencoded")
        .header("content-length", "34")
        .body("conversationId=c&id=m&ciphertext=x")
        .await;
    assert_eq!(form.status(), 415);

    // 256 Ko au plus hors messages…
    let big = json!({ "code": "123456", "peerId": "p", "pub": "A".repeat(300 * 1024) }).to_string();
    let res = client
        .post("/pair")
        .header("content-type", "application/json")
        .header("content-length", &big.len().to_string())
        .body(big)
        .await;
    assert_eq!(res.status(), 413);

    // … mais une photo chiffrée de 1 Mo passe dans un message.
    let photo =
        json!({ "conversationId": "c", "id": "photo", "ciphertext": "B".repeat(1024 * 1024) })
            .to_string();
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "alice")
        .header("content-type", "application/json")
        .header("content-length", &photo.len().to_string())
        .body(photo)
        .await;
    assert_eq!(res.status(), 201, "{}", res.text());
}

#[tokio::test]
async fn the_api_stays_open_to_other_origins() {
    let client = client().await;
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "alice")
        .header("origin", "https://ailleurs.example")
        .header("sec-fetch-site", "cross-site")
        .json(&json!({ "conversationId": "c", "id": "m", "ciphertext": "X" }))
        .await;
    assert_eq!(res.status(), 201, "{}", res.text());
    assert_eq!(res.header("access-control-allow-origin"), Some("*"));
}

#[tokio::test]
async fn attackers_get_banned_but_chatty_devices_do_not() {
    // Un scanner : 20 attaques refusées par le pare-feu, puis banni.
    let scanner = client().await;
    for _ in 0..20 {
        let res = scanner.get("/fr/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E").await;
        assert_eq!(res.status(), 403);
    }
    let res = scanner.get("/health").await;
    assert_eq!(res.status(), 403, "l'adresse est bannie");
    assert!(res.text().contains("ban"), "{}", res.text());

    // Un appareil trop bavard prend des 429, mais son adresse n'est pas
    // bannie : ses voisins de box continuent.
    let client = client().await;
    for i in 0..130 {
        client
            .post("/v1/messages")
            .header("x-user-id", "bavard")
            .json(&json!({ "conversationId": "c", "id": format!("m{i}"), "ciphertext": "X" }))
            .await;
    }
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "voisin")
        .json(&json!({ "conversationId": "c2", "id": "1", "ciphertext": "X" }))
        .await;
    assert_eq!(res.status(), 201, "{}", res.text());
}

#[tokio::test]
async fn plain_http_behind_heroku_goes_to_https() {
    let client = client().await;
    let res = client
        .get("/fr/")
        .header("host", "brocolis.example")
        .header("x-forwarded-proto", "http")
        .await;
    assert!(
        res.status() == 301 || res.status() == 308,
        "{}",
        res.status()
    );
    assert_eq!(res.header("location"), Some("https://brocolis.example/fr/"));
}

#[tokio::test]
async fn stats_show_the_shield() {
    let client = client().await;
    client.get("/health").header("user-agent", "nikto").await;
    let stats: Value = client.get("/stats").await.json();
    let guards: Vec<&str> = stats["shield"]["guards"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g.as_str().unwrap())
        .collect();
    for guard in ["waf", "rate_limit", "ban", "csrf", "security_headers"] {
        assert!(guards.contains(&guard), "{guard} : {guards:?}");
    }
    assert!(stats["shield"]["blocked"].as_u64().unwrap() >= 1);
}

/// Tricheurs et robots : les plafonds par minute et la taille des messages.
#[tokio::test]
async fn abuse_is_capped() {
    let client = client().await;
    // Inonder la messagerie depuis un même appareil : 429 au-delà du plafond.
    let mut last = 0;
    for i in 0..130 {
        let res = client
            .post("/v1/messages")
            .header("x-user-id", "spammeur")
            .json(&json!({ "conversationId": "flood", "id": format!("m{i}"), "ciphertext": "[[BROCOLIS:v1:AAAA]]" }))
            .await;
        last = res.status().as_u16();
    }
    assert_eq!(last, 429);
    // Un autre appareil n'est pas puni pour lui.
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "voisin")
        .json(&json!({ "conversationId": "calme", "id": "1", "ciphertext": "[[BROCOLIS:v1:AAAA]]" }))
        .await;
    assert_eq!(res.status(), 201);
    // Un message plus lourd que 4 Mo : 413.
    let huge = "A".repeat(4 * 1024 * 1024 + 1);
    let res = client
        .post("/v1/messages")
        .header("x-user-id", "voisin")
        .json(&json!({ "conversationId": "calme", "id": "2", "ciphertext": huge }))
        .await;
    assert_eq!(res.status(), 413);
    // Essayer en boucle des codes de salon : bloqué aussi.
    let mut blocked = false;
    for i in 0..2500 {
        let res = client.get(&format!("/pair?code=AAAA{:04}", i % 10000)).await;
        if res.status() == 429 {
            blocked = true;
            break;
        }
    }
    assert!(blocked, "deviner des codes doit être plafonné");
}
