//! Le coffre du navigateur : les secrets de la discussion (identité X25519,
//! clé de la discussion) sont chiffrés AVANT d'aller dans `localStorage`.
//!
//! - La clé maîtresse est une clé AES-256-GCM WebCrypto **non exportable**
//!   (`extractable: false`) : ni la page, ni une extension, ni un script injecté
//!   ne peuvent en lire les octets — seulement demander au navigateur de
//!   chiffrer / déchiffrer tant que la page est ouverte.
//! - Elle est gardée dans IndexedDB (base `brocolis.web`, magasin `coffre`) :
//!   un `CryptoKey` s'y stocke tel quel, sans jamais être sérialisé en clair.
//! - Valeur stockée : `coffre1:` + base64(nonce (12) ‖ chiffré ‖ tag (16)), avec
//!   le NOM de l'entrée en données associées (deux entrées ne s'échangent pas).
//! - Migration : une ancienne valeur en clair est relue, rechiffrée, et
//!   remplacée seulement si l'écriture chiffrée a réussi.
//!
//! Repli : sans WebCrypto (page hors HTTPS) ni IndexedDB (certains modes
//! privés), on garde l'ancien comportement — en clair dans `localStorage` —
//! plutôt que de casser la discussion. Ce repli est volontaire et limité à ces
//! navigateurs-là.

use std::cell::RefCell;

use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

use super::{storage, window};
use crate::crypto;

const DB: &str = "brocolis.web";
const STORE: &str = "coffre";
const MASTER: &str = "maitresse";
const PREFIX: &str = "coffre1:";
const NONCE_LEN: usize = 12;

thread_local! {
    /// La clé maîtresse, une fois chargée (ou créée) pour cette page.
    static MASTER_KEY: RefCell<Option<web_sys::CryptoKey>> = const { RefCell::new(None) };
}

/// Lit le secret `name` : déchiffré s'il est au coffre ; une ancienne valeur
/// en clair est rechiffrée au passage (puis renvoyée).
pub async fn load(name: &str) -> Option<String> {
    let raw = storage()?.get_item(name).ok().flatten().filter(|s| !s.is_empty())?;
    if let Some(sealed) = raw.strip_prefix(PREFIX) {
        // Clé maîtresse perdue (données du site effacées en partie) : illisible.
        return open(name, sealed).await;
    }
    // Migration : l'ancienne valeur en clair n'est remplacée que si le
    // chiffrement ET l'écriture ont réussi (sinon `set_item` n'a rien changé).
    if let Some(sealed) = seal(name, &raw).await
        && let Some(s) = storage()
    {
        let _ = s.set_item(name, &sealed);
    }
    Some(raw)
}

/// Écrit le secret `name`, chiffré. `keep` est vérifié juste avant l'écriture
/// (le chiffrement est asynchrone : l'utilisateur a pu « Quitter » entre-temps).
pub async fn save(name: &str, value: &str, keep: impl Fn() -> bool) {
    let sealed = seal(name, value).await;
    if !keep() {
        return;
    }
    let Some(s) = storage() else { return };
    // Repli sans WebCrypto / IndexedDB : en clair, comme avant (voir l'en-tête).
    let _ = s.set_item(name, sealed.as_deref().unwrap_or(value));
}

// ── Chiffrement ──────────────────────────────────────────────────────────────

fn subtle() -> Option<web_sys::SubtleCrypto> {
    // `crypto.subtle` n'existe que dans un contexte sécurisé (HTTPS, localhost).
    let crypto = window().crypto().ok()?;
    let subtle = js_sys::Reflect::get(&crypto, &"subtle".into()).ok()?;
    if subtle.is_undefined() || subtle.is_null() {
        return None;
    }
    Some(crypto.subtle())
}

fn aes_gcm(nonce: &[u8], name: &str) -> js_sys::Object {
    let algo = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&algo, &"name".into(), &"AES-GCM".into());
    let _ = js_sys::Reflect::set(&algo, &"iv".into(), &js_sys::Uint8Array::from(nonce));
    let _ = js_sys::Reflect::set(&algo, &"additionalData".into(), &js_sys::Uint8Array::from(name.as_bytes()));
    let _ = js_sys::Reflect::set(&algo, &"tagLength".into(), &JsValue::from_f64(128.0));
    algo
}

async fn seal(name: &str, plain: &str) -> Option<String> {
    let subtle = subtle()?;
    let key = master_key().await?;
    let nonce = crypto::random_bytes::<NONCE_LEN>();
    let promise = subtle
        .encrypt_with_object_and_u8_array(&aes_gcm(&nonce, name), &key, plain.as_bytes())
        .ok()?;
    let out = js_sys::Uint8Array::new(&JsFuture::from(promise).await.ok()?).to_vec();
    let mut packed = nonce.to_vec();
    packed.extend_from_slice(&out);
    Some(format!("{PREFIX}{}", crypto::b64(&packed)))
}

async fn open(name: &str, sealed: &str) -> Option<String> {
    let packed = crypto::unb64(sealed)?;
    if packed.len() < NONCE_LEN + 16 {
        return None;
    }
    let subtle = subtle()?;
    let key = master_key().await?;
    let (nonce, body) = packed.split_at(NONCE_LEN);
    let promise = subtle.decrypt_with_object_and_u8_array(&aes_gcm(nonce, name), &key, body).ok()?;
    let plain = js_sys::Uint8Array::new(&JsFuture::from(promise).await.ok()?).to_vec();
    String::from_utf8(plain).ok()
}

// ── La clé maîtresse (IndexedDB) ─────────────────────────────────────────────

/// La clé maîtresse : relue dans IndexedDB, ou créée (non exportable) au
/// premier usage.
async fn master_key() -> Option<web_sys::CryptoKey> {
    if let Some(key) = MASTER_KEY.with(|k| k.borrow().clone()) {
        return Some(key);
    }
    let db = open_db().await?;
    let key = match stored_key(&db).await {
        Some(key) => key,
        None => {
            let fresh = generate_key().await?;
            // `add` (et non `put`) : si un autre onglet l'a créée entre-temps,
            // l'ajout échoue et on relit la sienne — jamais deux clés.
            if request(store(&db, "readwrite")?.add_with_key(&fresh, &MASTER.into()).ok()?)
                .await
                .is_some()
            {
                fresh
            } else {
                stored_key(&db).await?
            }
        }
    };
    MASTER_KEY.with(|k| *k.borrow_mut() = Some(key.clone()));
    Some(key)
}

async fn generate_key() -> Option<web_sys::CryptoKey> {
    let subtle = subtle()?;
    let algo = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&algo, &"name".into(), &"AES-GCM".into());
    let _ = js_sys::Reflect::set(&algo, &"length".into(), &JsValue::from_f64(256.0));
    let usages = js_sys::Array::of2(&"encrypt".into(), &"decrypt".into());
    // extractable = false : les octets de la clé ne sortent jamais du navigateur.
    let promise = subtle.generate_key_with_object(&algo, false, &usages).ok()?;
    JsFuture::from(promise).await.ok()?.dyn_into().ok()
}

async fn stored_key(db: &web_sys::IdbDatabase) -> Option<web_sys::CryptoKey> {
    let value = request(store(db, "readonly")?.get(&MASTER.into()).ok()?).await?;
    value.dyn_into().ok()
}

fn store(db: &web_sys::IdbDatabase, mode: &str) -> Option<web_sys::IdbObjectStore> {
    let mode = if mode == "readwrite" {
        web_sys::IdbTransactionMode::Readwrite
    } else {
        web_sys::IdbTransactionMode::Readonly
    };
    db.transaction_with_str_and_mode(STORE, mode).ok()?.object_store(STORE).ok()
}

async fn open_db() -> Option<web_sys::IdbDatabase> {
    let factory = window().indexed_db().ok().flatten()?;
    let req = factory.open_with_u32(DB, 1).ok()?;
    let upgrade_req = req.clone();
    let on_upgrade = Closure::once(move |_: web_sys::Event| {
        if let Ok(db) = upgrade_req.result().and_then(|r| r.dyn_into::<web_sys::IdbDatabase>()) {
            let _ = db.create_object_store(STORE);
        }
    });
    req.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));
    let db = request(req.clone().unchecked_into()).await;
    req.set_onupgradeneeded(None);
    drop(on_upgrade);
    db?.dyn_into().ok()
}

/// Attend une requête IndexedDB : son résultat, ou None en cas d'erreur.
async fn request(req: web_sys::IdbRequest) -> Option<JsValue> {
    let pending = req.clone();
    let promise = js_sys::Promise::new(&mut |resolve, reject| {
        pending.set_onsuccess(Some(&resolve));
        pending.set_onerror(Some(&reject));
    });
    let outcome = JsFuture::from(promise).await;
    req.set_onsuccess(None);
    req.set_onerror(None);
    outcome.ok()?;
    let value = req.result().ok()?;
    (!value.is_undefined()).then_some(value)
}
