//! Le protocole v3 dans Brocolis (`docs/SECURITE.md` §8) : sessions à double
//! cliquet, établies en hybride X25519 + ML-KEM-768, avec
//! [`brocolis_proto`], la référence du dépôt.
//!
//! Ce module est **pur** (ni réseau, ni stockage, ni navigateur) : la
//! discussion du site (`client/chat.rs`) le fait tourner dans la page, les
//! tests le font tourner ici, et c'est la même logique que l'iPhone
//! (`Shared/BrocolisV3.swift`) et qu'Android :
//!
//! - **un appareil** ([`Device`]) par installation, entretenu à chaque
//!   chargement (§8.1) ;
//! - **des sessions par contact** (deux au plus, la dernière qui a servi
//!   envoie), et par clé partagée en PSK (§8.2) ;
//! - **les messages ouverts** : un message v3 ne se déchiffre qu'une fois,
//!   son clair est gardé sous l'empreinte du jeton (§8.2) ;
//! - **le choix du format** d'un envoi (§8.5) et **la réception** (§8.6),
//!   réparation comprise (seulement une session perdue) ;
//! - **l'empreinte d'appairage** qui couvre les identités v3 (§8.4) et
//!   **l'enveloppe des médias** de la messagerie (§8.7).
//!
//! Ce qui a changé se lit avec [`Engine::take_dirty`] : l'appelant l'écrit
//! (appareil d'abord) avant de rendre le jeton (§8.3).

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use brocolis_proto::session::MAX_PLAINTEXT;
use brocolis_proto::{
    Content, Device, Erreur, JOUR, KeyBundle, Mode, ReplayGuard, Session, Token, hasard, jeton_v3,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::crypto;

/// Le début du clair v3 qui porte une clé de média (§8.7).
pub const MEDIA_PREFIX: &str = "BRCM3:";
/// Au-delà de cette taille (ou pour un média `BRCM1:`), le clair part dans
/// l'enveloppe des médias (§8.7).
pub const MEDIA_THRESHOLD: usize = 16 * 1024;
/// Un paquet reçu à l'appairage sert à ouvrir une session pendant 30 jours :
/// au-delà, sa SPK a pu être effacée (§8.5).
pub const BUNDLE_MAX_AGE: u64 = 30 * JOUR;
/// Ce qui précède les deux identités dans l'empreinte d'appairage (§8.4).
pub const FINGERPRINT_CONTEXT: &[u8] = b"Brocolis_v3_Appairage";
/// Les messages ouverts gardés : 2 000 au plus…
pub const OPENED_MAX: usize = 2_000;
/// …et 1 Mio de clair (§8.2).
pub const OPENED_MAX_BYTES: usize = 1 << 20;
/// Deux sessions au plus par contact (§8.2).
const SESSIONS_PER_PEER: usize = 2;

/// La protection d'une clé, affichée partout (§8.8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    /// 🔐 double cliquet, établi en hybride X25519 + ML-KEM-768.
    PostQuantum,
    /// 🔐 double cliquet, X25519 seul.
    Classic,
    /// 🔐 double cliquet, à partir de la clé partagée.
    Psk,
    /// L'ancien format (v1/v2).
    Legacy,
}

impl Protection {
    /// La clé du texte affiché (`i18n`).
    pub fn i18n_key(self) -> &'static str {
        match self {
            Protection::PostQuantum => "chat.v3pq",
            Protection::Classic => "chat.v3classic",
            Protection::Psk => "chat.v3psk",
            Protection::Legacy => "chat.v3legacy",
        }
    }
}

/// Une clé nommée, telle que le moteur la voit (§8.5).
#[derive(Clone, Copy)]
pub struct KeyInfo<'a> {
    /// L'identifiant de la clé (où ranger ses sessions PSK).
    pub id: &'a str,
    /// La clé partagée elle-même.
    pub key: [u8; 32],
    /// Le paquet du correspondant reçu à l'appairage, s'il y en a un.
    pub bundle: Option<&'a KeyBundle>,
    /// Quand ce paquet est arrivé (secondes Unix).
    pub bundle_at: u64,
    /// Une clé de groupe (3 personnes ou plus) : jamais de v3.
    pub group: bool,
    /// L'utilisateur l'a marquée « à deux, double cliquet » (PSK).
    pub psk: bool,
}

/// Le résultat d'une réception.
#[derive(Debug, PartialEq, Eq)]
pub enum Opened {
    /// Le clair (déchiffré à l'instant, ou gardé).
    Text(String),
    /// Déjà lu, et le clair n'est plus gardé.
    Replay,
    /// Illisible (pas pour nous, session perdue, altéré…).
    Failed(Erreur),
}

/// Faut-il réparer ? Seulement une session **perdue** (§8.6) : un
/// déchiffrement raté sur une session connue est un rejeu ou une
/// falsification, et ne doit rien remettre à zéro.
pub fn needs_repair(e: &Erreur) -> bool {
    matches!(e, Erreur::SessionInconnue | Erreur::CleInconnue)
}

/// L'empreinte d'appairage à deux (§8.4) :
/// `SHA-256("Brocolis_v3_Appairage" ‖ K ‖ min(P_A, P_B) ‖ max(P_A, P_B))[0..8]`,
/// P = IK X25519 ‖ IK Ed25519.
pub fn pairing_fingerprint(key: &[u8; 32], a: &[u8; 64], b: &[u8; 64]) -> String {
    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
    let mut h = Sha256::new();
    h.update(FINGERPRINT_CONTEXT);
    h.update(key);
    h.update(lo);
    h.update(hi);
    let digest = h.finalize();
    let hex: String = digest[..8].iter().map(|b| format!("{b:02X}")).collect();
    hex.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect::<Vec<_>>()
        .join("-")
}

/// L'identité d'un paquet : IK X25519 ‖ IK Ed25519.
pub fn identity_of(bundle: &KeyBundle) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&bundle.identity.dh);
    out[32..].copy_from_slice(&bundle.identity.sign);
    out
}

/// Le jeton sans aucun blanc (une messagerie peut couper une longue ligne).
pub fn normalize(token: &str) -> String {
    token.chars().filter(|c| !c.is_whitespace()).collect()
}

/// L'empreinte d'un jeton, sous laquelle son clair est gardé (§8.2).
pub fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(normalize(token).as_bytes()))
}

/// Les jetons v3 d'un texte (début, fin), dans l'ordre.
pub fn find_tokens(text: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(start) = text[from..].find(jeton_v3::HEAD) {
        let start = from + start;
        let Some(end) = text[start..].find("]]") else {
            break;
        };
        let end = start + end + 2;
        out.push((start, end));
        from = end;
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Les sessions d'un contact (ou d'une clé PSK).
#[derive(Default)]
struct Peer {
    sessions: Vec<Session>,
    current: Option<[u8; 8]>,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct StoredPeer {
    current: String,
    sessions: Vec<Value>,
}

impl Peer {
    fn from_stored(stored: &StoredPeer) -> Peer {
        let sessions: Vec<Session> = stored
            .sessions
            .iter()
            .filter_map(|v| Session::from_json(&v.to_string()).ok())
            .take(SESSIONS_PER_PEER)
            .collect();
        let current = sessions
            .iter()
            .map(Session::session_id)
            .find(|id| hex(id) == stored.current);
        Peer { sessions, current }
    }

    fn to_stored(&self) -> StoredPeer {
        StoredPeer {
            current: self.current.as_ref().map(|id| hex(id)).unwrap_or_default(),
            sessions: self
                .sessions
                .iter()
                .filter_map(|s| serde_json::from_str(&s.to_json()).ok())
                .collect(),
        }
    }

    fn get(&mut self, id: &[u8; 8]) -> Option<&mut Session> {
        self.sessions.iter_mut().find(|s| s.session_id() == *id)
    }

    fn sending_id(&self) -> Option<[u8; 8]> {
        self.current
            .filter(|id| self.sessions.iter().any(|s| s.session_id() == *id))
            .or_else(|| self.sessions.last().map(Session::session_id))
    }

    fn sending(&mut self) -> Option<&mut Session> {
        let id = self.sending_id()?;
        self.get(&id)
    }

    /// Range une session (elle remplace celle de même identifiant, la plus
    /// ancienne part au-delà de deux) et en fait la session d'envoi.
    fn put(&mut self, s: Session) {
        let id = s.session_id();
        self.sessions.retain(|x| x.session_id() != id);
        self.sessions.push(s);
        while self.sessions.len() > SESSIONS_PER_PEER {
            self.sessions.remove(0);
        }
        self.current = Some(id);
    }
}

/// Un message ouvert, gardé (§8.2).
#[derive(Clone, Serialize, Deserialize)]
struct OpenedEntry {
    h: String,
    text: String,
    at: u64,
    mine: bool,
}

/// L'état gardé (chiffré par l'appelant) : sessions et messages ouverts.
#[derive(Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Stored {
    v: u8,
    peers: BTreeMap<String, StoredPeer>,
    psk: BTreeMap<String, StoredPeer>,
    psk_seen: Vec<String>,
    psk_replay: ReplayGuard,
    opened: Vec<OpenedEntry>,
}

/// Ce qu'il faut écrire après une opération, dans cet ordre (§8.3).
#[derive(Debug, Default)]
pub struct Dirty {
    /// L'appareil (JSON de la référence), s'il a changé.
    pub device: Option<String>,
    /// L'état (sessions, messages ouverts), s'il a changé.
    pub state: Option<String>,
}

/// L'appareil v3 et ses sessions, le temps d'une transaction (§8.3).
pub struct Engine {
    device: Device,
    peers: BTreeMap<String, Peer>,
    psk: BTreeMap<String, Peer>,
    psk_seen: Vec<String>,
    psk_replay: ReplayGuard,
    opened: Vec<OpenedEntry>,
    device_dirty: bool,
    state_dirty: bool,
}

impl Engine {
    /// Charge l'appareil et l'état gardés (ou les crée), puis entretient
    /// l'appareil (§8.1). Un état illisible repart de zéro.
    pub fn load(device_json: Option<&str>, state_json: Option<&str>, now: u64) -> Engine {
        let rng = &mut hasard::system();
        let device = device_json.and_then(|j| Device::from_json(j).ok());
        let created = device.is_none();
        let device = device.unwrap_or_else(|| Device::generate(rng, now, true));
        let stored: Stored = state_json
            .and_then(|j| serde_json::from_str(j).ok())
            .unwrap_or_default();
        let mut engine = Engine {
            device,
            peers: stored
                .peers
                .iter()
                .map(|(k, v)| (k.clone(), Peer::from_stored(v)))
                .collect(),
            psk: stored
                .psk
                .iter()
                .map(|(k, v)| (k.clone(), Peer::from_stored(v)))
                .collect(),
            psk_seen: stored.psk_seen,
            psk_replay: stored.psk_replay,
            opened: stored.opened,
            device_dirty: created,
            state_dirty: false,
        };
        engine.maintain(now);
        engine
    }

    /// SPK et PQPK neuves chaque semaine, ML-KEM dès qu'il est là, purge.
    fn maintain(&mut self, now: u64) {
        let rng = &mut hasard::system();
        if self.device.needs_rotation(now) {
            self.device.rotate(rng, now);
            self.device_dirty = true;
        }
        if !self.device.supports_pq() {
            self.device.enable_pq(rng, now);
            self.device_dirty = true;
        }
        self.device.purge(now);
        for peer in self.peers.values_mut().chain(self.psk.values_mut()) {
            for s in &mut peer.sessions {
                s.purge(now);
            }
        }
    }

    /// Ce qui a changé depuis le dernier appel (l'appareil d'abord).
    pub fn take_dirty(&mut self) -> Dirty {
        let device =
            std::mem::take(&mut self.device_dirty).then(|| self.device.to_json().to_string());
        let state = std::mem::take(&mut self.state_dirty).then(|| self.state_json());
        Dirty { device, state }
    }

    /// L'état complet, en JSON.
    pub fn state_json(&self) -> String {
        let stored = Stored {
            v: 1,
            peers: self
                .peers
                .iter()
                .map(|(k, p)| (k.clone(), p.to_stored()))
                .collect(),
            psk: self
                .psk
                .iter()
                .map(|(k, p)| (k.clone(), p.to_stored()))
                .collect(),
            psk_seen: self.psk_seen.clone(),
            psk_replay: self.psk_replay.clone(),
            opened: self.opened.clone(),
        };
        serde_json::to_string(&stored).unwrap_or_default()
    }

    /// Le paquet de clés à publier dans le salon (base64).
    pub fn bundle_b64(&self) -> Option<String> {
        self.device.bundle().ok().map(|b| b.to_base64())
    }

    /// Mon identité : IK X25519 ‖ IK Ed25519.
    pub fn identity(&self) -> [u8; 64] {
        let id = self.device.identity();
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&id.dh);
        out[32..].copy_from_slice(&id.sign);
        out
    }

    fn contact<'a>(k: &KeyInfo<'a>) -> Option<&'a KeyBundle> {
        k.bundle.filter(|_| !k.group)
    }

    fn fresh(k: &KeyInfo<'_>, now: u64) -> bool {
        k.bundle_at.saturating_add(BUNDLE_MAX_AGE) > now
    }

    fn psk_allowed(&self, k: &KeyInfo<'_>, now: u64) -> bool {
        !k.group
            && (k.psk
                || self.psk_seen.iter().any(|id| id == k.id)
                // Un contact v3 dont le paquet est trop vieux : il est à
                // jour (il a publié un paquet), la PSK est sûre.
                || (k.bundle.is_some() && !Self::fresh(k, now)))
    }

    /// La protection de la clé, telle que le prochain envoi la donnera (§8.8).
    pub fn protection(&self, k: &KeyInfo<'_>, now: u64) -> Protection {
        if let Some(b) = Self::contact(k) {
            let owner = hex(&b.identity.dh);
            if let Some(peer) = self.peers.get(&owner)
                && let Some(id) = peer.sending_id()
                && let Some(s) = peer.sessions.iter().find(|s| s.session_id() == id)
            {
                return if s.is_post_quantum() {
                    Protection::PostQuantum
                } else {
                    Protection::Classic
                };
            }
            if Self::fresh(k, now) {
                return if b.pq.is_some() {
                    Protection::PostQuantum
                } else {
                    Protection::Classic
                };
            }
        }
        if self.psk_allowed(k, now) {
            Protection::Psk
        } else {
            Protection::Legacy
        }
    }

    /// Ouvre la session vers le contact s'il n'y en a pas encore (l'invitant,
    /// à la fin de l'appairage : §8.4). Rien ne part : le premier message
    /// (0x01) la portera.
    pub fn open_session(&mut self, k: &KeyInfo<'_>, now: u64) -> bool {
        let Some(b) = Self::contact(k).filter(|_| Self::fresh(k, now)) else {
            return false;
        };
        let peer = self.peers.entry(hex(&b.identity.dh)).or_default();
        if peer.sending_id().is_some() {
            return true;
        }
        match self
            .device
            .initiate(b, b.pq.is_some(), &mut hasard::system())
        {
            Ok(s) => {
                peer.put(s);
                self.state_dirty = true;
                true
            }
            Err(_) => false,
        }
    }

    /// Chiffre `text` pour la clé `k` en v3 (§8.5) : sa session de contact,
    /// une session neuve vers son paquet, ou la PSK. `None` : l'appelant
    /// chiffre en v1/v2.
    pub fn seal(&mut self, k: &KeyInfo<'_>, text: &str, now: u64) -> Option<String> {
        if text.len() > MAX_PLAINTEXT {
            return None;
        }
        let token = self
            .seal_contact(k, text, now)
            .or_else(|| self.seal_psk(k, text, now))?;
        self.remember(&token, text, true, now);
        Some(token)
    }

    fn seal_contact(&mut self, k: &KeyInfo<'_>, text: &str, now: u64) -> Option<String> {
        let b = Self::contact(k)?;
        let fresh = Self::fresh(k, now);
        let peer = self.peers.entry(hex(&b.identity.dh)).or_default();
        if let Some(s) = peer.sending() {
            match s.encrypt(text) {
                Ok(token) => {
                    self.state_dirty = true;
                    return Some(token);
                }
                // Chaîne épuisée ou état abîmé : une session neuve.
                Err(_) => peer.sessions.clear(),
            }
        }
        if !fresh {
            return None;
        }
        let mut s = self
            .device
            .initiate(b, b.pq.is_some(), &mut hasard::system())
            .ok()?;
        let token = s.encrypt(text).ok()?;
        peer.put(s);
        self.state_dirty = true;
        Some(token)
    }

    fn seal_psk(&mut self, k: &KeyInfo<'_>, text: &str, now: u64) -> Option<String> {
        if !self.psk_allowed(k, now) {
            return None;
        }
        let peer = self.psk.entry(k.id.to_owned()).or_default();
        if let Some(s) = peer.sending() {
            match s.encrypt(text) {
                Ok(token) => {
                    self.state_dirty = true;
                    return Some(token);
                }
                Err(_) => peer.sessions.clear(),
            }
        }
        let mut s = Session::initiate_psk(&k.key, &mut hasard::system()).ok()?;
        let token = s.encrypt(text).ok()?;
        peer.put(s);
        self.state_dirty = true;
        Some(token)
    }

    /// Le clair gardé d'un jeton, s'il l'est.
    pub fn recall(&self, token: &str) -> Option<&str> {
        let h = token_hash(token);
        self.opened
            .iter()
            .find(|e| e.h == h)
            .map(|e| e.text.as_str())
    }

    /// Garde le clair d'un jeton (§8.2).
    pub fn remember(&mut self, token: &str, text: &str, mine: bool, now: u64) {
        let h = token_hash(token);
        if self.opened.iter().any(|e| e.h == h) {
            return;
        }
        self.opened.push(OpenedEntry {
            h,
            text: text.to_owned(),
            at: now,
            mine,
        });
        let mut total: usize = self.opened.iter().map(|e| e.text.len()).sum();
        while self.opened.len() > OPENED_MAX || (total > OPENED_MAX_BYTES && self.opened.len() > 1)
        {
            total -= self.opened.remove(0).text.len();
        }
        self.state_dirty = true;
    }

    /// Ouvre un jeton v3 reçu (§8.6) : le clair gardé, sinon la session, un
    /// premier message d'un contact (ou en PSK d'une de `keys`).
    pub fn open(&mut self, token: &str, keys: &[KeyInfo<'_>], now: u64) -> Opened {
        if let Some(text) = self.recall(token) {
            return Opened::Text(text.to_owned());
        }
        let decoded = match Token::decode(&normalize(token)) {
            Ok(t) => t,
            Err(e) => return Opened::Failed(e),
        };
        match self.decrypt(&decoded, keys, now) {
            Ok(text) => {
                self.remember(token, &text, false, now);
                Opened::Text(text)
            }
            Err(Erreur::Rejoue) => Opened::Replay,
            Err(e) => Opened::Failed(e),
        }
    }

    fn decrypt(&mut self, token: &Token, keys: &[KeyInfo<'_>], now: u64) -> Result<String, Erreur> {
        let id = token.session_id().ok_or(Erreur::SessionInconnue)?;
        let rng = &mut hasard::system();
        for table in [&mut self.peers, &mut self.psk] {
            for peer in table.values_mut() {
                let Some(s) = peer.get(&id) else { continue };
                match s.decrypt(token, now, rng) {
                    Ok(content) => {
                        peer.current = Some(id);
                        self.state_dirty = true;
                        return text_of(content);
                    }
                    // L'autre a ouvert une session neuve (il avait perdu la
                    // sienne) : elle remplacera celle-ci.
                    Err(Erreur::NouvelleSession) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let Token::Initial(first) = token else {
            return Err(Erreur::SessionInconnue);
        };
        if first.mode == Mode::Psk {
            for k in keys.iter().filter(|k| !k.group) {
                match Session::accept_psk(&[k.key], first, &mut self.psk_replay, now, rng) {
                    Ok((s, content)) => {
                        self.psk.entry(k.id.to_owned()).or_default().put(s);
                        if !self.psk_seen.iter().any(|x| x == k.id) {
                            self.psk_seen.push(k.id.to_owned());
                        }
                        self.state_dirty = true;
                        return text_of(content);
                    }
                    Err(Erreur::SessionInconnue) => continue,
                    Err(e) => return Err(e),
                }
            }
            return Err(Erreur::SessionInconnue);
        }
        // Un premier message X25519 ou hybride : seulement d'un contact
        // (paquet reçu à l'appairage), sinon l'expéditeur est inconnu.
        let known = keys
            .iter()
            .any(|k| Self::contact(k).is_some_and(|b| b.identity.dh == first.identity));
        if !known {
            return Err(Erreur::SessionInconnue);
        }
        let (s, content) = self.device.accept(first, now, rng)?;
        self.device_dirty = true;
        self.peers.entry(hex(&first.identity)).or_default().put(s);
        self.state_dirty = true;
        text_of(content)
    }

    /// Oublie les sessions du contact de `k` : le prochain envoi en ouvre une
    /// neuve (§8.6, réparation).
    pub fn repair(&mut self, k: &KeyInfo<'_>) {
        if let Some(b) = k.bundle
            && self.peers.remove(&hex(&b.identity.dh)).is_some()
        {
            self.state_dirty = true;
        }
    }

    /// Oublie tout ce qui touche à une clé (« Quitter » sur le site) : ses
    /// sessions de contact et PSK. Les messages ouverts aussi.
    pub fn forget(&mut self, k: &KeyInfo<'_>) {
        if let Some(b) = k.bundle {
            self.peers.remove(&hex(&b.identity.dh));
        }
        self.psk.remove(k.id);
        self.psk_seen.retain(|x| x != k.id);
        self.opened.clear();
        self.state_dirty = true;
    }

    /// Le nombre de sessions avec le contact de `k` (tests, affichage).
    pub fn session_count(&self, k: &KeyInfo<'_>) -> usize {
        k.bundle
            .and_then(|b| self.peers.get(&hex(&b.identity.dh)))
            .map_or(0, |p| p.sessions.len())
            + self.psk.get(k.id).map_or(0, |p| p.sessions.len())
    }
}

fn text_of(content: Content) -> Result<String, Erreur> {
    match content {
        Content::Text(t) => Ok(t),
        // Brocolis ne se sert pas (encore) des chaînes de groupe.
        Content::Distribution(_) => Err(Erreur::Format),
    }
}

// ── La messagerie (§8.7) ─────────────────────────────────────────────────────

/// Le champ `ciphertext` d'un message de la messagerie, en v3 si la clé le
/// permet : un média (ou un long texte) part dans l'enveloppe des médias.
/// `None` : l'appelant envoie en v1.
pub fn seal_message(engine: &mut Engine, k: &KeyInfo<'_>, clear: &str, now: u64) -> Option<String> {
    if clear.starts_with("BRCM1:") || clear.len() > MEDIA_THRESHOLD {
        let media_key = crypto::random_bytes::<32>();
        let media = crypto::seal_token(&media_key, clear)?;
        let head = engine.seal(
            k,
            &format!("{MEDIA_PREFIX}{}", STANDARD.encode(media_key)),
            now,
        )?;
        return Some(format!("{head}{media}"));
    }
    engine.seal(k, clear, now)
}

/// Le clair d'un message de la messagerie qui porte un jeton v3 (`None` s'il
/// n'en porte pas : l'appelant essaie v1). `mine` : un de mes envois, relu
/// seulement dans les messages ouverts, jamais déchiffré ni réparé. `k` : la
/// clé de la conversation (pour la réparation).
pub fn open_message(
    engine: &mut Engine,
    ciphertext: &str,
    keys: &[KeyInfo<'_>],
    k: &KeyInfo<'_>,
    mine: bool,
    now: u64,
) -> Option<Opened> {
    let (start, end) = *find_tokens(ciphertext).first()?;
    let token = &ciphertext[start..end];
    let opened = if mine {
        engine
            .recall(token)
            .map_or(Opened::Replay, |t| Opened::Text(t.to_owned()))
    } else {
        let opened = engine.open(token, keys, now);
        if let Opened::Failed(e) = &opened
            && needs_repair(e)
        {
            engine.repair(k);
        }
        opened
    };
    Some(match opened {
        Opened::Text(t) => match t.strip_prefix(MEDIA_PREFIX) {
            Some(b64) => {
                let media_key: Option<[u8; 32]> =
                    STANDARD.decode(b64).ok().and_then(|v| v.try_into().ok());
                match media_key.and_then(|mk| crypto::open_tokens(&mk, &ciphertext[end..])) {
                    Some(media) => Opened::Text(media),
                    None => Opened::Failed(Erreur::Dechiffrement),
                }
            }
            None => Opened::Text(t),
        },
        other => other,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_800_000_000;

    struct Side {
        engine: Engine,
        id: &'static str,
    }

    impl Side {
        fn new(id: &'static str) -> Side {
            Side {
                engine: Engine::load(None, None, NOW),
                id,
            }
        }
        fn bundle(&self) -> KeyBundle {
            KeyBundle::from_base64(&self.engine.bundle_b64().unwrap()).unwrap()
        }
    }

    fn info<'a>(id: &'a str, key: [u8; 32], bundle: Option<&'a KeyBundle>) -> KeyInfo<'a> {
        KeyInfo {
            id,
            key,
            bundle,
            bundle_at: NOW,
            group: false,
            psk: false,
        }
    }

    #[test]
    fn the_pairing_fingerprint_matches_the_spec_vector() {
        assert_eq!(
            pairing_fingerprint(&[7; 32], &[1; 64], &[2; 64]),
            "1D47-6221-06A0-8AC5"
        );
        // Le même des deux côtés.
        assert_eq!(
            pairing_fingerprint(&[7; 32], &[2; 64], &[1; 64]),
            "1D47-6221-06A0-8AC5"
        );
        assert_ne!(
            pairing_fingerprint(&[8; 32], &[1; 64], &[2; 64]),
            "1D47-6221-06A0-8AC5"
        );
    }

    #[test]
    fn paired_contacts_talk_in_v3_with_disorder_and_duplicates() {
        let (mut a, mut b) = (Side::new("a"), Side::new("b"));
        let (ba, bb) = (a.bundle(), b.bundle());
        let key = [9u8; 32];
        let ka = info("k", key, Some(&bb));
        let kb = info("k", key, Some(&ba));
        assert_eq!(a.engine.protection(&ka, NOW), Protection::PostQuantum);
        assert!(a.engine.open_session(&ka, NOW));
        let m1 = a.engine.seal(&ka, "un", NOW).unwrap();
        let m2 = a.engine.seal(&ka, "deux", NOW).unwrap();
        assert!(m1.starts_with(jeton_v3::HEAD));
        // Désordre, puis doublon (gardé : rendu sans déchiffrer).
        assert_eq!(b.engine.open(&m2, &[kb], NOW), Opened::Text("deux".into()));
        assert_eq!(b.engine.open(&m1, &[kb], NOW), Opened::Text("un".into()));
        assert_eq!(b.engine.open(&m1, &[kb], NOW), Opened::Text("un".into()));
        // Coupé par une messagerie : le même message.
        let cut = format!("{}\n{}", &m1[..40], &m1[40..]);
        assert_eq!(b.engine.open(&cut, &[kb], NOW), Opened::Text("un".into()));
        assert_eq!(b.engine.protection(&kb, NOW), Protection::PostQuantum);
        let r = b.engine.seal(&kb, "réponse", NOW).unwrap();
        assert_eq!(
            a.engine.open(&r, &[ka], NOW),
            Opened::Text("réponse".into())
        );
        // Mes propres envois se relisent.
        assert_eq!(a.engine.recall(&m1), Some("un"));
        // Sans le clair gardé : déjà lu.
        b.engine.opened.clear();
        assert_eq!(b.engine.open(&m1, &[kb], NOW), Opened::Replay);
        // Un tiers qui n'est pas un contact : refusé.
        let mut c = Side::new("c");
        let kc = info("k", key, None);
        assert_eq!(
            c.engine.open(&m1, &[kc], NOW),
            Opened::Failed(Erreur::SessionInconnue)
        );
        let _ = c.id;
    }

    #[test]
    fn states_survive_a_reload_and_never_reuse_a_message_key() {
        let (mut a, mut b) = (Side::new("a"), Side::new("b"));
        let (ba, bb) = (a.bundle(), b.bundle());
        let key = [3u8; 32];
        let ka = info("k", key, Some(&bb));
        let kb = info("k", key, Some(&ba));
        let m1 = a.engine.seal(&ka, "avant", NOW).unwrap();
        let dirty = a.engine.take_dirty();
        let (dev, state) = (dirty.device.unwrap(), dirty.state.unwrap());
        // Relu : le message suivant ne réutilise pas la clé du premier.
        let mut a2 = Engine::load(Some(&dev), Some(&state), NOW);
        assert!(
            a2.take_dirty().device.is_none(),
            "rien à réécrire après un simple chargement"
        );
        let m2 = a2.seal(&ka, "après", NOW).unwrap();
        let header = |t: &str| match Token::decode(t).unwrap() {
            Token::Initial(i) => (i.envelope.header.dh, i.envelope.header.n),
            _ => panic!("premier message attendu"),
        };
        assert_eq!(header(&m1).1, 0);
        assert_eq!(header(&m2), (header(&m1).0, 1), "même chaîne, clé suivante");
        assert_eq!(b.engine.open(&m1, &[kb], NOW), Opened::Text("avant".into()));
        assert_eq!(b.engine.open(&m2, &[kb], NOW), Opened::Text("après".into()));
        let _ = (a.id, b.id);
    }

    #[test]
    fn both_start_at_once_and_a_lost_session_heals() {
        let (mut a, mut b) = (Side::new("a"), Side::new("b"));
        let (ba, bb) = (a.bundle(), b.bundle());
        let key = [4u8; 32];
        let ka = info("k", key, Some(&bb));
        let kb = info("k", key, Some(&ba));
        let x = a.engine.seal(&ka, "a", NOW).unwrap();
        let y = b.engine.seal(&kb, "b", NOW).unwrap();
        assert_eq!(b.engine.open(&x, &[kb], NOW), Opened::Text("a".into()));
        assert_eq!(a.engine.open(&y, &[ka], NOW), Opened::Text("b".into()));
        for i in 0..3 {
            let p = a.engine.seal(&ka, &format!("a{i}"), NOW).unwrap();
            let q = b.engine.seal(&kb, &format!("b{i}"), NOW).unwrap();
            assert_eq!(b.engine.open(&p, &[kb], NOW), Opened::Text(format!("a{i}")));
            assert_eq!(a.engine.open(&q, &[ka], NOW), Opened::Text(format!("b{i}")));
        }
        // B perd son état (réinstallation) : l'appareil reste.
        let dev_b = b.engine.device.to_json().to_string();
        let mut b2 = Engine::load(Some(&dev_b), None, NOW);
        let lost = a.engine.seal(&ka, "perdu ?", NOW).unwrap();
        let Opened::Failed(e) = b2.open(&lost, &[kb], NOW) else {
            panic!()
        };
        assert!(needs_repair(&e));
        b2.repair(&kb);
        let heal = b2.seal(&kb, "je reviens", NOW).unwrap();
        assert_eq!(
            a.engine.open(&heal, &[ka], NOW),
            Opened::Text("je reviens".into())
        );
        let after = a.engine.seal(&ka, "bienvenue", NOW).unwrap();
        assert_eq!(
            b2.open(&after, &[kb], NOW),
            Opened::Text("bienvenue".into())
        );
    }

    #[test]
    fn psk_is_opt_in_and_the_other_side_follows() {
        let (mut a, mut b) = (Side::new("a"), Side::new("b"));
        let key = [5u8; 32];
        let mut ka = info("ka", key, None);
        let kb = info("kb", key, None);
        // Rien ne dit que l'autre est à jour : v1.
        assert_eq!(a.engine.protection(&ka, NOW), Protection::Legacy);
        assert!(a.engine.seal(&ka, "x", NOW).is_none());
        ka.psk = true;
        let m = a.engine.seal(&ka, "en PSK", NOW).unwrap();
        assert!(matches!(Token::decode(&m).unwrap(), Token::Initial(_)));
        assert_eq!(b.engine.open(&m, &[kb], NOW), Opened::Text("en PSK".into()));
        // B suit, sans rien régler.
        assert_eq!(b.engine.protection(&kb, NOW), Protection::Psk);
        let r = b.engine.seal(&kb, "reçu", NOW).unwrap();
        assert_eq!(a.engine.open(&r, &[ka], NOW), Opened::Text("reçu".into()));
        // Une clé de groupe : jamais.
        let group = KeyInfo { group: true, ..ka };
        assert_eq!(a.engine.protection(&group, NOW), Protection::Legacy);
        assert!(a.engine.seal(&group, "x", NOW).is_none());
    }

    #[test]
    fn a_stale_bundle_falls_back_to_psk_then_legacy_for_groups() {
        let (mut a, mut b) = (Side::new("a"), Side::new("b"));
        let (ba, bb) = (a.bundle(), b.bundle());
        let later = NOW + BUNDLE_MAX_AGE + 1;
        let key = [6u8; 32];
        let ka = KeyInfo {
            bundle_at: NOW,
            ..info("k", key, Some(&bb))
        };
        let kb = info("k", key, Some(&ba));
        assert_eq!(a.engine.protection(&ka, later), Protection::Psk);
        let m = a.engine.seal(&ka, "vieux paquet", later).unwrap();
        assert_eq!(
            b.engine.open(&m, &[kb], later),
            Opened::Text("vieux paquet".into())
        );
    }

    #[test]
    fn media_travel_in_the_envelope() {
        let (mut a, mut b) = (Side::new("a"), Side::new("b"));
        let (ba, bb) = (a.bundle(), b.bundle());
        let key = [8u8; 32];
        let ka = info("k", key, Some(&bb));
        let kb = info("k", key, Some(&ba));
        let photo = format!("BRCM1:img:{}", "A".repeat(300 * 1024));
        let ct = seal_message(&mut a.engine, &ka, &photo, NOW).unwrap();
        assert_eq!(find_tokens(&ct).len(), 1);
        assert!(ct.contains("[[BROCOLIS:v1:"));
        assert_eq!(
            open_message(&mut b.engine, &ct, &[kb], &kb, false, NOW),
            Some(Opened::Text(photo.clone()))
        );
        // Relu plus tard (le clair v3 gardé) ; et mon propre envoi aussi.
        assert_eq!(
            open_message(&mut b.engine, &ct, &[kb], &kb, false, NOW),
            Some(Opened::Text(photo.clone()))
        );
        assert_eq!(
            open_message(&mut a.engine, &ct, &[ka], &ka, true, NOW),
            Some(Opened::Text(photo))
        );
        // Un ancien jeton v1 : pas pour ce module.
        let v1 = crypto::seal_token(&key, "ancien").unwrap();
        assert_eq!(
            open_message(&mut b.engine, &v1, &[kb], &kb, false, NOW),
            None
        );
    }

    #[test]
    fn opened_messages_are_bounded() {
        let mut a = Side::new("a");
        for i in 0..(OPENED_MAX + 10) {
            a.engine.remember(&format!("t{i}"), "x", false, NOW);
        }
        assert_eq!(a.engine.opened.len(), OPENED_MAX);
        a.engine
            .remember("gros", &"y".repeat(OPENED_MAX_BYTES), false, NOW);
        assert!(a.engine.opened.iter().map(|e| e.text.len()).sum::<usize>() <= OPENED_MAX_BYTES);
        assert_eq!(
            a.engine.recall("gros").map(str::len),
            Some(OPENED_MAX_BYTES)
        );
    }
}
