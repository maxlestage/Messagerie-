//! L'établissement (§4.2) et le Double Ratchet (§4.3) : une clé neuve par
//! message, effacée aussitôt utilisée.
//!
//! Comme la [spécification de Signal](https://signal.org/docs/specifications/doubleratchet/) :
//! l'initiateur A part de SK et de la SPK de B (sa clé de cliquet initiale) ;
//! B part de SK et de sa SPK. Chaque déchiffrement est **transactionnel** :
//! s'il échoue (message altéré, rejeu, trop de sauts), l'état de la session
//! est exactement celui d'avant.
//!
//! Pour recevoir un jeton v3 de type 0x01 à 0x03 :
//!
//! 1. décoder ([`Token::decode`]) et chercher la session par
//!    [`Token::session_id`] ;
//! 2. si elle existe : [`Session::decrypt`]. Une erreur
//!    [`Erreur::NouvelleSession`] sur un 0x01 veut dire « nouvelle session » :
//!    passer à l'étape 3 ;
//! 3. sinon, pour un 0x01 : [`crate::Device::accept`] (mode X25519 ou
//!    hybride) ou [`Session::accept_psk`] (clé partagée).
//!
//! [`Erreur::Rejoue`] : message déjà lu, à ignorer sans bruit.

use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::groupe::SenderKeyDistribution;
use crate::hasard::{CryptoRng, bytes};
use crate::jeton_v3::{Envelope, Header, Initial, Mode, TYPE_DISTRIBUTION, TYPE_MESSAGE, Token};
use crate::kdf::{
    aes_gcm_open, aes_gcm_seal, kdf_ck, kdf_rk, message_key, psk_ratchet_secret, session_id,
    sk_psk, sk_x3dh, x25519, x25519_public,
};
use crate::paquet::{
    Device, IdentitySecret, KeyBundle, ReplayGuard, mlkem_decapsulate, mlkem_encapsulate,
};
use crate::remplissage::{pad, unpad};
use crate::{Erreur, MAX_SKIP, MAX_SKIP_AGE, Resultat};

/// Le plus long texte (en octets UTF-8) qu'un message v3 peut porter : le
/// jeton reste sous [`crate::jeton_v3::MAX_TOKEN_BYTES`].
pub const MAX_PLAINTEXT: usize = 200 * 1024;
/// Le nombre de clés de cliquet distantes passées dont on se souvient pour
/// reconnaître un rejeu.
const PREVIOUS_DHR: usize = 16;

/// Ce que porte un message déchiffré.
#[derive(Debug, PartialEq, Eq)]
pub enum Content {
    /// Un texte (types 0x01 et 0x02).
    Text(String),
    /// Une chaîne de groupe (type 0x03).
    Distribution(SenderKeyDistribution),
}

/// Ce que l'initiateur répète dans chaque message de type 0x01 tant qu'il
/// n'a pas reçu de réponse.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Preamble {
    #[serde(with = "crate::serde_b64")]
    identity: [u8; 32],
    #[serde(with = "crate::serde_b64")]
    ephemeral: [u8; 32],
    mode: Mode,
    #[serde(with = "crate::serde_b64::opt", default)]
    kem_ciphertext: Option<Vec<u8>>,
    spk_id: u32,
    pq_id: u32,
}

/// Une clé de message sautée (message pas encore arrivé).
#[derive(Clone, Serialize, Deserialize, Zeroize)]
struct SkippedKey {
    #[serde(with = "crate::serde_b64")]
    dh: [u8; 32],
    n: u32,
    #[serde(with = "crate::serde_b64")]
    mk: [u8; 32],
    stored_at: u64,
}

/// Une clé publique (pour le JSON).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
struct PublicKey(#[serde(with = "crate::serde_b64")] [u8; 32]);

/// Une session à cliquet entre deux appareils. Sérialisable (JSON, octets
/// en base64) ; à garder chiffrée par la clé matérielle (§3.1).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Session {
    v: u8,
    #[zeroize(skip)]
    mode: Mode,
    #[serde(with = "crate::serde_b64")]
    ad: Vec<u8>,
    #[serde(with = "crate::serde_b64")]
    session_id: [u8; 8],
    #[serde(with = "crate::serde_b64")]
    rk: [u8; 32],
    #[serde(with = "crate::serde_b64")]
    dhs_secret: [u8; 32],
    #[serde(with = "crate::serde_b64")]
    dhs_public: [u8; 32],
    #[serde(with = "crate::serde_b64::opt")]
    dhr: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64::opt")]
    cks: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64::opt")]
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    skipped: Vec<SkippedKey>,
    previous_dhr: Vec<PublicKey>,
    #[zeroize(skip)]
    preamble: Option<Preamble>,
    #[serde(with = "crate::serde_b64::opt")]
    initial_ephemeral: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64::opt")]
    peer_identity: Option<[u8; 32]>,
}

impl Session {
    // ----- Création --------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn new_initiator(
        mode: Mode,
        sk: &[u8; 32],
        ad: Vec<u8>,
        ratchet_secret: &[u8; 32],
        remote_ratchet: &[u8; 32],
        preamble: Preamble,
        peer_identity: Option<[u8; 32]>,
    ) -> Resultat<Session> {
        let dh = x25519(ratchet_secret, remote_ratchet)?;
        let (rk, cks) = kdf_rk(sk, &dh);
        Ok(Session {
            v: 1,
            mode,
            session_id: session_id(&ad),
            ad,
            rk: *rk,
            dhs_secret: *ratchet_secret,
            dhs_public: x25519_public(ratchet_secret),
            dhr: Some(*remote_ratchet),
            cks: Some(*cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
            previous_dhr: Vec::new(),
            preamble: Some(preamble),
            initial_ephemeral: None,
            peer_identity,
        })
    }

    fn new_responder(
        mode: Mode,
        sk: &[u8; 32],
        ad: Vec<u8>,
        ratchet_secret: &[u8; 32],
        initial_ephemeral: [u8; 32],
        peer_identity: Option<[u8; 32]>,
    ) -> Session {
        Session {
            v: 1,
            mode,
            session_id: session_id(&ad),
            ad,
            rk: *sk,
            dhs_secret: *ratchet_secret,
            dhs_public: x25519_public(ratchet_secret),
            dhr: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped: Vec::new(),
            previous_dhr: Vec::new(),
            preamble: None,
            initial_ephemeral: Some(initial_ephemeral),
            peer_identity,
        }
    }

    /// Ouvre une session vers l'appareil du paquet (§4.2), avec ML-KEM si
    /// `pq` (le paquet doit alors en proposer : sinon
    /// [`Erreur::PqIndisponible`]).
    ///
    /// Ordre de tirage : secret EK (32), secret de cliquet (32), puis, avec
    /// `pq`, le message ML-KEM `m` (32).
    pub fn initiate(
        identity: &IdentitySecret,
        bundle: &KeyBundle,
        pq: bool,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Session> {
        bundle.verify()?;
        let ek = Zeroizing::new(bytes::<32>(rng));
        let ratchet = Zeroizing::new(bytes::<32>(rng));
        let m = if pq { Some(bytes::<32>(rng)) } else { None };
        Self::initiate_with(identity, bundle, &ek, &ratchet, m.as_ref())
    }

    /// [`Session::initiate`] avec le hasard donné (les vecteurs). Le paquet
    /// doit avoir été vérifié ([`KeyBundle::from_bytes`] le fait).
    pub fn initiate_with(
        identity: &IdentitySecret,
        bundle: &KeyBundle,
        ek_secret: &[u8; 32],
        ratchet_secret: &[u8; 32],
        kem_m: Option<&[u8; 32]>,
    ) -> Resultat<Session> {
        let ik_a = identity.public().dh;
        let ik_b = bundle.identity.dh;
        let dh1 = x25519(&identity.dh, &bundle.spk)?;
        let dh2 = x25519(ek_secret, &ik_b)?;
        let dh3 = x25519(ek_secret, &bundle.spk)?;
        let (mode, kem_ciphertext, ss, pq_id) = match kem_m {
            Some(m) => {
                let pq = bundle.pq.as_ref().ok_or(Erreur::PqIndisponible)?;
                let (ct, ss) = mlkem_encapsulate(&pq.key, m)?;
                (Mode::Hybrid, Some(ct), Some(ss), pq.id)
            }
            None => (Mode::Classic, None, None, 0),
        };
        let sk = sk_x3dh(&dh1, &dh2, &dh3, ss.as_deref());
        let ad = [ik_a, ik_b].concat();
        let preamble = Preamble {
            identity: ik_a,
            ephemeral: x25519_public(ek_secret),
            mode,
            kem_ciphertext,
            spk_id: bundle.spk_id,
            pq_id,
        };
        Self::new_initiator(
            mode,
            &sk,
            ad,
            ratchet_secret,
            &bundle.spk,
            preamble,
            Some(ik_b),
        )
    }

    /// Ouvre une session à partir d'une clé Brocolis partagée (§4.2, sans
    /// appairage). Tire le secret EK (32), qui sert aussi de première clé de
    /// cliquet.
    pub fn initiate_psk(key: &[u8; 32], rng: &mut (impl CryptoRng + ?Sized)) -> Resultat<Session> {
        let ek = Zeroizing::new(bytes::<32>(rng));
        Self::initiate_psk_with(key, &ek)
    }

    /// [`Session::initiate_psk`] avec le hasard donné.
    ///
    /// SK = `HKDF(0³², clé, "Brocolis_v3_PSK_SHA-256")` ; la clé de cliquet
    /// initiale du répondeur R est le secret X25519
    /// `HKDF(0³², SK, "Brocolis_v3_PSK_Ratchet")` (connu des deux) ;
    /// AD = EK_A ‖ R ; la première clé de cliquet de A est EK_A.
    pub fn initiate_psk_with(key: &[u8; 32], ek_secret: &[u8; 32]) -> Resultat<Session> {
        let sk = sk_psk(key);
        let r = x25519_public(&psk_ratchet_secret(&sk));
        let ek = x25519_public(ek_secret);
        let ad = [ek, r].concat();
        let preamble = Preamble {
            identity: [0u8; 32],
            ephemeral: ek,
            mode: Mode::Psk,
            kem_ciphertext: None,
            spk_id: 0,
            pq_id: 0,
        };
        Self::new_initiator(Mode::Psk, &sk, ad, ek_secret, &r, preamble, None)
    }

    /// Accepte le premier message d'une session à clé partagée : essaie
    /// chaque clé (l'identifiant de session dit laquelle). `guard` retient
    /// les clés éphémères déjà vues (un premier message rejoué est refusé :
    /// [`Erreur::Rejoue`]).
    pub fn accept_psk(
        keys: &[[u8; 32]],
        msg: &Initial,
        guard: &mut ReplayGuard,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<(Session, Content)> {
        if msg.mode != Mode::Psk || msg.envelope.header.dh != msg.ephemeral {
            return Err(Erreur::Format);
        }
        if guard.seen(&msg.ephemeral) {
            return Err(Erreur::Rejoue);
        }
        for key in keys {
            let sk = sk_psk(key);
            let r_secret = psk_ratchet_secret(&sk);
            let ad = [msg.ephemeral, x25519_public(&r_secret)].concat();
            if bool::from(session_id(&ad).ct_eq(&msg.envelope.session_id)) {
                let mut s = Self::new_responder(Mode::Psk, &sk, ad, &r_secret, msg.ephemeral, None);
                let content = s.decrypt(&Token::Initial(msg.clone()), now, rng)?;
                guard.insert(msg.ephemeral, now);
                return Ok((s, content));
            }
        }
        Err(Erreur::SessionInconnue)
    }

    // ----- Envoi -----------------------------------------------------------

    fn seal(&mut self, plain: &[u8], kind: u8) -> Resultat<Token> {
        if plain.len() > MAX_PLAINTEXT {
            return Err(Erreur::TropGrand);
        }
        let ck = Zeroizing::new(self.cks.ok_or(Erreur::Etat)?);
        let next_ns = self.ns.checked_add(1).ok_or(Erreur::Epuise)?;
        let (next, mk) = kdf_ck(&ck);
        let header = Header {
            dh: self.dhs_public,
            pn: self.pn,
            n: self.ns,
        };
        let (key, nonce) = message_key(&mk);
        let ciphertext = aes_gcm_seal(&key, &nonce, &self.aad(&header, kind), &pad(plain))?;
        self.cks = Some(*next);
        self.ns = next_ns;
        let envelope = Envelope {
            session_id: self.session_id,
            header,
            ciphertext,
        };
        Ok(match (kind, &self.preamble) {
            (TYPE_DISTRIBUTION, _) => Token::Distribution(envelope),
            (_, Some(p)) => Token::Initial(Initial {
                identity: p.identity,
                ephemeral: p.ephemeral,
                mode: p.mode,
                kem_ciphertext: p.kem_ciphertext.clone(),
                spk_id: p.spk_id,
                pq_id: p.pq_id,
                envelope,
            }),
            (_, None) => Token::Message(envelope),
        })
    }

    /// Les données associées : `AD ‖ en-tête`, et `‖ 0x03` pour une
    /// distribution (écart documenté : le type est ainsi authentifié).
    fn aad(&self, header: &Header, kind: u8) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.ad.len() + 41);
        aad.extend_from_slice(&self.ad);
        aad.extend_from_slice(&header.to_bytes());
        if kind == TYPE_DISTRIBUTION {
            aad.push(TYPE_DISTRIBUTION);
        }
        aad
    }

    /// Chiffre un texte : le jeton décodé (type 0x01 tant que l'initiateur
    /// n'a pas reçu de réponse, 0x02 ensuite).
    pub fn encrypt_token(&mut self, text: &str) -> Resultat<Token> {
        self.seal(text.as_bytes(), TYPE_MESSAGE)
    }

    /// Chiffre un texte : `[[BROCOLIS:v3:…]]`.
    pub fn encrypt(&mut self, text: &str) -> Resultat<String> {
        Ok(self.encrypt_token(text)?.encode())
    }

    /// Envoie une chaîne de groupe (type 0x03) par cette session.
    pub fn encrypt_distribution(&mut self, d: &SenderKeyDistribution) -> Resultat<String> {
        Ok(self.seal(&d.to_bytes(), TYPE_DISTRIBUTION)?.encode())
    }

    // ----- Réception -------------------------------------------------------

    /// Déchiffre un jeton décodé de cette session. Transactionnel : en cas
    /// d'erreur, la session n'a pas changé. Peut tirer une nouvelle clé de
    /// cliquet (32 octets) si le message fait tourner le cliquet.
    pub fn decrypt(
        &mut self,
        token: &Token,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Content> {
        let (env, kind) = match token {
            Token::Initial(i) => {
                if i.envelope.session_id != self.session_id {
                    return Err(Erreur::SessionInconnue);
                }
                match (&self.initial_ephemeral, &self.preamble) {
                    (Some(ek), _) if *ek == i.ephemeral => (&i.envelope, TYPE_MESSAGE),
                    // Notre propre premier message, renvoyé : ignoré.
                    (_, Some(p)) if p.ephemeral == i.ephemeral => return Err(Erreur::Rejoue),
                    _ => return Err(Erreur::NouvelleSession),
                }
            }
            Token::Message(e) => (e, TYPE_MESSAGE),
            Token::Distribution(e) => (e, TYPE_DISTRIBUTION),
            Token::Group(_) => return Err(Erreur::SessionInconnue),
        };
        if env.session_id != self.session_id {
            return Err(Erreur::SessionInconnue);
        }
        let mut next = self.clone();
        let plain = next.ratchet_decrypt(&env.header, &env.ciphertext, kind, now, rng)?;
        let content = if kind == TYPE_DISTRIBUTION {
            Content::Distribution(SenderKeyDistribution::from_bytes(&plain)?)
        } else {
            Content::Text(String::from_utf8(plain.to_vec()).map_err(|_| Erreur::Utf8)?)
        };
        // Une réponse est arrivée : l'initiateur passe aux messages 0x02.
        next.preamble = None;
        *self = next;
        Ok(content)
    }

    /// [`Session::decrypt`] d'un jeton texte `[[BROCOLIS:v3:…]]`.
    pub fn decrypt_text(
        &mut self,
        token: &str,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Content> {
        self.decrypt(&Token::decode(token)?, now, rng)
    }

    fn open(
        &self,
        mk: &[u8; 32],
        header: &Header,
        ct: &[u8],
        kind: u8,
    ) -> Resultat<Zeroizing<Vec<u8>>> {
        let (key, nonce) = message_key(mk);
        let padded = aes_gcm_open(&key, &nonce, &self.aad(header, kind), ct)?;
        Ok(Zeroizing::new(unpad(&padded)?.to_vec()))
    }

    fn ratchet_decrypt(
        &mut self,
        header: &Header,
        ct: &[u8],
        kind: u8,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Zeroizing<Vec<u8>>> {
        self.purge(now);
        if header.dh == self.dhs_public {
            // Un de nos messages, renvoyé.
            return Err(Erreur::Rejoue);
        }
        if let Some(pos) = self
            .skipped
            .iter()
            .position(|s| s.dh == header.dh && s.n == header.n)
        {
            let mk = Zeroizing::new(self.skipped[pos].mk);
            let plain = self.open(&mk, header, ct, kind)?;
            self.skipped.remove(pos).zeroize();
            return Ok(plain);
        }
        let current = self.dhr == Some(header.dh);
        if current && header.n < self.nr {
            return Err(Erreur::Rejoue);
        }
        if !current && self.previous_dhr.contains(&PublicKey(header.dh)) {
            return Err(Erreur::Rejoue);
        }
        if !current {
            self.skip(header.pn, now)?;
            self.dh_ratchet(header, rng)?;
        }
        self.skip(header.n, now)?;
        let ck = Zeroizing::new(self.ckr.ok_or(Erreur::Etat)?);
        let (next, mk) = kdf_ck(&ck);
        self.ckr = Some(*next);
        self.nr = self.nr.checked_add(1).ok_or(Erreur::Epuise)?;
        self.open(&mk, header, ct, kind)
    }

    fn skip(&mut self, until: u32, now: u64) -> Resultat<()> {
        if u64::from(self.nr) + u64::from(MAX_SKIP) < u64::from(until) {
            return Err(Erreur::TropDeClesSautees);
        }
        if let (Some(ckr), Some(dhr)) = (self.ckr, self.dhr) {
            let mut ck = Zeroizing::new(ckr);
            while self.nr < until {
                let (next, mk) = kdf_ck(&ck);
                self.skipped.push(SkippedKey {
                    dh: dhr,
                    n: self.nr,
                    mk: *mk,
                    stored_at: now,
                });
                *ck = *next;
                self.nr += 1;
            }
            self.ckr = Some(*ck);
            let max = MAX_SKIP as usize;
            if self.skipped.len() > max {
                let extra = self.skipped.len() - max;
                for mut k in self.skipped.drain(..extra) {
                    k.zeroize();
                }
            }
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &Header, rng: &mut (impl CryptoRng + ?Sized)) -> Resultat<()> {
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        if let Some(old) = self.dhr {
            self.previous_dhr.push(PublicKey(old));
            if self.previous_dhr.len() > PREVIOUS_DHR {
                self.previous_dhr.remove(0);
            }
        }
        self.dhr = Some(header.dh);
        let dh = x25519(&self.dhs_secret, &header.dh)?;
        let (rk, ckr) = kdf_rk(&self.rk, &dh);
        self.rk = *rk;
        self.ckr = Some(*ckr);
        let secret = Zeroizing::new(bytes::<32>(rng));
        self.dhs_secret = *secret;
        self.dhs_public = x25519_public(&secret);
        let dh = x25519(&self.dhs_secret, &header.dh)?;
        let (rk, cks) = kdf_rk(&self.rk, &dh);
        self.rk = *rk;
        self.cks = Some(*cks);
        Ok(())
    }

    // ----- État ------------------------------------------------------------

    /// Efface les clés sautées de plus de 30 jours.
    pub fn purge(&mut self, now: u64) {
        let mut kept = Vec::with_capacity(self.skipped.len());
        for k in self.skipped.drain(..) {
            if k.stored_at.saturating_add(MAX_SKIP_AGE) > now {
                kept.push(k);
            } else {
                let mut k = k;
                k.zeroize();
            }
        }
        self.skipped = kept;
    }

    /// L'identifiant de session (8 octets).
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    /// AD = IK_A ‖ IK_B (ou EK_A ‖ R en clé partagée).
    pub fn associated_data(&self) -> &[u8] {
        &self.ad
    }

    /// Le mode d'établissement.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Vrai si la session est post-quantique (hybride X25519 + ML-KEM).
    /// Sinon, l'appli l'affiche (« session non post-quantique »).
    pub fn is_post_quantum(&self) -> bool {
        self.mode == Mode::Hybrid
    }

    /// Vrai si l'autre côté a répondu (l'initiateur envoie des messages 0x01
    /// jusque-là).
    pub fn is_confirmed(&self) -> bool {
        self.preamble.is_none()
    }

    /// IK X25519 du correspondant (absent en clé partagée) : l'appli le
    /// compare à celui du contact (alerte si une clé d'identité change).
    pub fn peer_identity(&self) -> Option<[u8; 32]> {
        self.peer_identity
    }

    /// Le nombre de clés sautées gardées.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// La clé publique de cliquet courante (pour les vecteurs).
    pub fn ratchet_public(&self) -> [u8; 32] {
        self.dhs_public
    }

    /// La clé racine courante (pour les vecteurs : un secret !).
    #[doc(hidden)]
    pub fn debug_root_key(&self) -> [u8; 32] {
        self.rk
    }

    /// Les clés de chaîne courantes (envoi, réception) — vecteurs seulement.
    #[doc(hidden)]
    pub fn debug_chain_keys(&self) -> (Option<[u8; 32]>, Option<[u8; 32]>) {
        (self.cks, self.ckr)
    }

    /// L'état en JSON.
    pub fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Relit un état JSON (vérifie sa cohérence).
    pub fn from_json(text: &str) -> Resultat<Self> {
        let s: Session = serde_json::from_str(text).map_err(|_| Erreur::Etat)?;
        let ad_ok = s.ad.len() == 64 && session_id(&s.ad) == s.session_id;
        if s.v != 1
            || !ad_ok
            || s.skipped.len() > MAX_SKIP as usize
            || x25519_public(&s.dhs_secret) != s.dhs_public
        {
            return Err(Erreur::Etat);
        }
        Ok(s)
    }
}

impl Device {
    /// Ouvre une session vers un paquet ([`Session::initiate`]).
    pub fn initiate(
        &self,
        bundle: &KeyBundle,
        pq: bool,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Session> {
        Session::initiate(self.identity_secret(), bundle, pq, rng)
    }

    /// Accepte le premier message (type 0x01) d'une nouvelle session, en
    /// mode X25519 ou hybride : retrouve la SPK (et la PQPK) désignées,
    /// calcule SK, déchiffre. Un premier message dont la clé éphémère a
    /// déjà servi est refusé ([`Erreur::Rejoue`]).
    pub fn accept(
        &mut self,
        msg: &Initial,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<(Session, Content)> {
        if msg.mode == Mode::Psk {
            return Err(Erreur::Format);
        }
        if self.replay_mut().seen(&msg.ephemeral) {
            return Err(Erreur::Rejoue);
        }
        let spk = Zeroizing::new(self.spk_secret(msg.spk_id)?);
        let own = self.identity_secret();
        let dh1 = x25519(&spk, &msg.identity)?;
        let dh2 = x25519(&own.dh, &msg.ephemeral)?;
        let dh3 = x25519(&spk, &msg.ephemeral)?;
        let ss = match (&msg.mode, &msg.kem_ciphertext) {
            (Mode::Hybrid, Some(ct)) => Some(mlkem_decapsulate(&*self.pq_seed(msg.pq_id)?, ct)?),
            (Mode::Classic, None) => None,
            _ => return Err(Erreur::Format),
        };
        let sk = sk_x3dh(&dh1, &dh2, &dh3, ss.as_deref());
        let ad = [msg.identity, x25519_public(&own.dh)].concat();
        if session_id(&ad) != msg.envelope.session_id {
            return Err(Erreur::SessionInconnue);
        }
        let mut s =
            Session::new_responder(msg.mode, &sk, ad, &spk, msg.ephemeral, Some(msg.identity));
        let content = s.decrypt(&Token::Initial(msg.clone()), now, rng)?;
        self.replay_mut().insert(msg.ephemeral, now);
        Ok((s, content))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hasard::Deterministic;

    fn text(c: Content) -> String {
        match c {
            Content::Text(t) => t,
            Content::Distribution(_) => panic!("distribution"),
        }
    }

    fn pair(pq: bool) -> (Device, Session, Device, Deterministic) {
        let mut rng = Deterministic::new(b"session");
        let alice = Device::generate(&mut rng, 0, pq);
        let bob = Device::generate(&mut rng, 0, pq);
        let a = alice
            .initiate(&bob.bundle().unwrap(), pq, &mut rng)
            .unwrap();
        (alice, a, bob, rng)
    }

    #[test]
    fn premier_echange() {
        for pq in [false, true] {
            let (_alice, mut a, mut bob, mut rng) = pair(pq);
            let t = a.encrypt_token("Salut 🥦").unwrap();
            let Token::Initial(i) = &t else { panic!() };
            assert_eq!(i.mode, if pq { Mode::Hybrid } else { Mode::Classic });
            let (mut b, c) = bob.accept(i, 10, &mut rng).unwrap();
            assert_eq!(text(c), "Salut 🥦");
            assert_eq!(b.session_id(), a.session_id());
            assert_eq!(b.is_post_quantum(), pq);
            // Le même premier message une seconde fois : rejeu.
            assert_eq!(bob.accept(i, 11, &mut rng).err(), Some(Erreur::Rejoue));
            assert_eq!(b.decrypt(&t, 11, &mut rng), Err(Erreur::Rejoue));
            let r = b.encrypt("Bien reçu").unwrap();
            assert!(!a.is_confirmed());
            assert_eq!(text(a.decrypt_text(&r, 12, &mut rng).unwrap()), "Bien reçu");
            assert!(a.is_confirmed());
            assert!(matches!(a.encrypt_token("ok").unwrap(), Token::Message(_)));
        }
    }

    #[test]
    fn json_aller_retour() {
        let (_alice, mut a, mut bob, mut rng) = pair(true);
        let Token::Initial(i) = a.encrypt_token("x").unwrap() else {
            panic!()
        };
        let (b, _) = bob.accept(&i, 0, &mut rng).unwrap();
        let mut b2 = Session::from_json(&b.to_json()).unwrap();
        let mut a2 = Session::from_json(&a.to_json()).unwrap();
        let t = b2.encrypt("y").unwrap();
        assert_eq!(text(a2.decrypt_text(&t, 0, &mut rng).unwrap()), "y");
        assert_eq!(Session::from_json("{}").err(), Some(Erreur::Etat));
    }

    #[test]
    fn psk() {
        let mut rng = Deterministic::new(b"psk");
        let key = [7u8; 32];
        let mut a = Session::initiate_psk(&key, &mut rng).unwrap();
        let Token::Initial(i) = a.encrypt_token("par la clé").unwrap() else {
            panic!()
        };
        let mut guard = ReplayGuard::default();
        assert_eq!(
            Session::accept_psk(&[[1u8; 32]], &i, &mut guard, 0, &mut rng).err(),
            Some(Erreur::SessionInconnue)
        );
        let (mut b, c) =
            Session::accept_psk(&[[1u8; 32], key], &i, &mut guard, 0, &mut rng).unwrap();
        assert_eq!(text(c), "par la clé");
        assert_eq!(b.mode(), Mode::Psk);
        assert_eq!(
            Session::accept_psk(&[key], &i, &mut guard, 0, &mut rng).err(),
            Some(Erreur::Rejoue)
        );
        let r = b.encrypt("réponse").unwrap();
        assert_eq!(text(a.decrypt_text(&r, 0, &mut rng).unwrap()), "réponse");
    }
}
