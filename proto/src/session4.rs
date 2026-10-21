//! Le protocole v4 (§9) : établissement hybride à identité cachée, triple
//! cliquet (X25519 + ML-KEM-768 à chaque tour) et en-têtes chiffrés.
//!
//! Recevoir un jeton v4 ([`Token4`]) :
//!
//! 1. essayer chaque session connue : [`Session4::decrypt`] ; une
//!    [`Erreur::SessionInconnue`] veut dire « pas cette session » (aucune
//!    clé d'en-tête ne l'ouvre) — passer à la suivante ; toute autre erreur
//!    est définitive (rejeu, altération…) ;
//! 2. aucune session : un 0x01 va à [`crate::Device::accept4`], un 0x02 à
//!    [`Session4::accept_psk`] (clé partagée).
//!
//! Comme en v3, chaque déchiffrement est **transactionnel** : un échec
//! laisse la session exactement telle qu'elle était.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::groupe::SenderKeyDistribution;
use crate::hasard::{CryptoRng, bytes};
use crate::jeton_v4::{
    Body4, GENRE_DISTRIBUTION, GENRE_TEXTE, Header4, KEM_CT_LEN, Preamble4, TYPE_INITIAL,
    TYPE_MESSAGE, Token4,
};
use crate::kdf::{
    aes_gcm_open, aes_gcm_seal, header_keys4, kdf_ck, kdf_rk4, message_keys4, preamble_key4,
    psk4_ratchet_secret, session_id, sk4, sk4_psk, x25519, x25519_is_canonical, x25519_public,
};
use crate::paquet::{
    Device, IdentitySecret, KeyBundle, PQPK_LEN, ReplayGuard, mlkem_decapsulate, mlkem_encapsulate,
    mlkem_public,
};
use crate::remplissage::{pad, unpad};
use crate::session::{Content, MAX_PLAINTEXT};
use crate::{Erreur, MAX_SKIP, MAX_SKIP_AGE, Resultat};

/// Le nombre de clés d'en-tête de réception passées dont on se souvient
/// pour reconnaître un rejeu.
const PREVIOUS_HKR: usize = 16;

/// Comment la session v4 a été établie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Mode4 {
    /// Par paquet de clés : X25519 + ML-KEM-768, identité de l'initiateur
    /// cachée.
    Bundle,
    /// Par une clé Brocolis partagée.
    Psk,
}

/// Une clé de message sautée : `(clé d'en-tête, N) → mk`.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
struct Skipped4 {
    #[serde(with = "crate::serde_b64")]
    hk: [u8; 32],
    n: u32,
    #[serde(with = "crate::serde_b64")]
    mk: [u8; 32],
    stored_at: u64,
}

/// Une paire ML-KEM-768 de cliquet : la graine `d ‖ z` et sa clé
/// d'encapsulation (gardée pour ne pas la recalculer à chaque message).
#[derive(Clone, Serialize, Deserialize, Zeroize)]
struct KemPair {
    #[serde(with = "crate::serde_b64")]
    seed: [u8; 64],
    #[serde(with = "crate::serde_b64")]
    ek: Vec<u8>,
}

impl KemPair {
    fn from_seed(seed: [u8; 64]) -> Self {
        KemPair {
            ek: mlkem_public(&seed),
            seed,
        }
    }
}

/// Le préambule que l'initiateur répète dans ses messages 0x01.
#[derive(Clone, Serialize, Deserialize, Zeroize)]
struct StoredPreamble {
    #[serde(with = "crate::serde_b64")]
    ephemeral: [u8; 32],
    #[serde(with = "crate::serde_b64")]
    kem_ciphertext: Vec<u8>,
    #[serde(with = "crate::serde_b64")]
    sealed_identity: Vec<u8>,
}

impl StoredPreamble {
    fn to_preamble(&self) -> Resultat<Preamble4> {
        Ok(Preamble4 {
            ephemeral: self.ephemeral,
            kem_ciphertext: self.kem_ciphertext.clone(),
            sealed_identity: self
                .sealed_identity
                .as_slice()
                .try_into()
                .map_err(|_| Erreur::Etat)?,
        })
    }
}

/// Une session v4 entre deux appareils. Sérialisable (JSON) ; à garder
/// chiffrée par la clé matérielle (§3.1).
#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Session4 {
    v: u8,
    #[zeroize(skip)]
    mode: Mode4,
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
    kem: Option<KemPair>,
    #[serde(with = "crate::serde_b64::opt")]
    peer_ek: Option<Vec<u8>>,
    #[serde(with = "crate::serde_b64::opt")]
    send_ct: Option<Vec<u8>>,
    #[serde(with = "crate::serde_b64::opt")]
    cks: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64::opt")]
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    #[serde(with = "crate::serde_b64::opt")]
    hks: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64::opt")]
    hkr: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64")]
    nhks: [u8; 32],
    #[serde(with = "crate::serde_b64")]
    nhkr: [u8; 32],
    skipped: Vec<Skipped4>,
    #[serde(default)]
    previous_hkr: Vec<HeaderKey>,
    preamble: Option<StoredPreamble>,
    #[serde(with = "crate::serde_b64::opt")]
    initial_ephemeral: Option<[u8; 32]>,
    #[serde(with = "crate::serde_b64::opt")]
    peer_identity: Option<[u8; 32]>,
    confirmed: bool,
    /// Le répondeur n'a encore reçu aucune chaîne : la première peut être
    /// sans `ct` (la toute première chaîne de l'initiateur).
    responder_fresh: bool,
}

/// Une clé d'en-tête (pour le JSON).
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Zeroize)]
struct HeaderKey(#[serde(with = "crate::serde_b64")] [u8; 32]);

/// Ouvre un en-tête chiffré avec `hk` : `None` si ce n'est pas la bonne clé.
fn open_header(hk: &[u8; 32], kind: u8, body: &Body4) -> Option<Resultat<Header4>> {
    let plain = aes_gcm_open(hk, &body.header_nonce, &[kind], &body.header).ok()?;
    Some(Header4::from_bytes(&plain))
}

impl Session4 {
    // ----- Création --------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn new_initiator(
        mode: Mode4,
        sk: &[u8; 32],
        ad: Vec<u8>,
        ratchet_secret: &[u8; 32],
        remote_ratchet: &[u8; 32],
        kem: KemPair,
        preamble: Option<StoredPreamble>,
        peer_identity: Option<[u8; 32]>,
    ) -> Resultat<Session4> {
        let (hk_ab, nhk_ba) = header_keys4(sk);
        let dh = x25519(ratchet_secret, remote_ratchet)?;
        let (rk, cks, nhks) = kdf_rk4(sk, &dh, None);
        Ok(Session4 {
            v: 4,
            mode,
            session_id: session_id(&ad),
            ad,
            rk: *rk,
            dhs_secret: *ratchet_secret,
            dhs_public: x25519_public(ratchet_secret),
            dhr: Some(*remote_ratchet),
            kem: Some(kem),
            peer_ek: None,
            send_ct: None,
            cks: Some(*cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            hks: Some(*hk_ab),
            hkr: None,
            nhks: *nhks,
            nhkr: *nhk_ba,
            skipped: Vec::new(),
            previous_hkr: Vec::new(),
            preamble,
            initial_ephemeral: None,
            peer_identity,
            confirmed: false,
            responder_fresh: false,
        })
    }

    fn new_responder(
        mode: Mode4,
        sk: &[u8; 32],
        ad: Vec<u8>,
        ratchet_secret: &[u8; 32],
        initial_ephemeral: [u8; 32],
        peer_identity: Option<[u8; 32]>,
    ) -> Session4 {
        let (hk_ab, nhk_ba) = header_keys4(sk);
        Session4 {
            v: 4,
            mode,
            session_id: session_id(&ad),
            ad,
            rk: *sk,
            dhs_secret: *ratchet_secret,
            dhs_public: x25519_public(ratchet_secret),
            dhr: None,
            kem: None,
            peer_ek: None,
            send_ct: None,
            cks: None,
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            hks: None,
            hkr: None,
            nhks: *nhk_ba,
            nhkr: *hk_ab,
            skipped: Vec::new(),
            previous_hkr: Vec::new(),
            preamble: None,
            initial_ephemeral: Some(initial_ephemeral),
            peer_identity,
            confirmed: true,
            responder_fresh: true,
        }
    }

    /// Ouvre une session v4 vers l'appareil du paquet (§9.1, §9.4). Le
    /// paquet doit proposer ML-KEM ([`Erreur::PqIndisponible`] sinon).
    ///
    /// Ordre de tirage : secret EK (32), secret de cliquet (32), message
    /// ML-KEM `m` vers la PQPK (32), graine ML-KEM de cliquet (64).
    pub fn initiate(
        identity: &IdentitySecret,
        bundle: &KeyBundle,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Session4> {
        bundle.verify()?;
        let ek = Zeroizing::new(bytes::<32>(rng));
        let ratchet = Zeroizing::new(bytes::<32>(rng));
        let m = Zeroizing::new(bytes::<32>(rng));
        let seed = Zeroizing::new(bytes::<64>(rng));
        Self::initiate_with(identity, bundle, &ek, &ratchet, &m, &seed)
    }

    /// [`Session4::initiate`] avec le hasard donné (les vecteurs).
    pub fn initiate_with(
        identity: &IdentitySecret,
        bundle: &KeyBundle,
        ek_secret: &[u8; 32],
        ratchet_secret: &[u8; 32],
        kem_m: &[u8; 32],
        kem_seed: &[u8; 64],
    ) -> Resultat<Session4> {
        let pq = bundle.pq.as_ref().ok_or(Erreur::PqIndisponible)?;
        let ik_a = identity.public().dh;
        let ik_b = bundle.identity.dh;
        let dh1 = x25519(&identity.dh, &bundle.spk)?;
        let dh2 = x25519(ek_secret, &ik_b)?;
        let dh3 = x25519(ek_secret, &bundle.spk)?;
        let (ct, ss) = mlkem_encapsulate(&pq.key, kem_m)?;
        let sk = sk4(&dh1, &dh2, &dh3, &ss);
        let ephemeral = x25519_public(ek_secret);
        let (k_pre, n_pre) = preamble_key4(&dh3, &ss);
        let aad = [&[TYPE_INITIAL][..], &ephemeral, &ct].concat();
        let sealed_identity = aes_gcm_seal(&k_pre, &n_pre, &aad, &ik_a)?;
        let preamble = StoredPreamble {
            ephemeral,
            kem_ciphertext: ct,
            sealed_identity,
        };
        Self::new_initiator(
            Mode4::Bundle,
            &sk,
            [ik_a, ik_b].concat(),
            ratchet_secret,
            &bundle.spk,
            KemPair::from_seed(*kem_seed),
            Some(preamble),
            Some(ik_b),
        )
    }

    /// Ouvre une session v4 à partir d'une clé partagée. Tire le secret EK
    /// (32, aussi première clé de cliquet), puis la graine ML-KEM (64).
    pub fn initiate_psk(key: &[u8; 32], rng: &mut (impl CryptoRng + ?Sized)) -> Resultat<Session4> {
        let ek = Zeroizing::new(bytes::<32>(rng));
        let seed = Zeroizing::new(bytes::<64>(rng));
        Self::initiate_psk_with(key, &ek, &seed)
    }

    /// [`Session4::initiate_psk`] avec le hasard donné.
    pub fn initiate_psk_with(
        key: &[u8; 32],
        ek_secret: &[u8; 32],
        kem_seed: &[u8; 64],
    ) -> Resultat<Session4> {
        let sk = sk4_psk(key);
        let r = x25519_public(&psk4_ratchet_secret(&sk));
        let ad = [x25519_public(ek_secret), r].concat();
        Self::new_initiator(
            Mode4::Psk,
            &sk,
            ad,
            ek_secret,
            &r,
            KemPair::from_seed(*kem_seed),
            None,
            None,
        )
    }

    /// Accepte le premier message d'une session v4 à clé partagée : un 0x02
    /// qu'aucune session n'ouvre. Essaie la clé d'en-tête initiale de chaque
    /// clé ; [`Erreur::SessionInconnue`] si aucune ne l'ouvre. Une EK déjà
    /// vue est refusée ([`Erreur::Rejoue`]).
    pub fn accept_psk(
        keys: &[[u8; 32]],
        token: &Token4,
        guard: &mut ReplayGuard,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<(Session4, Content)> {
        let Token4::Message(body) = token else {
            return Err(Erreur::SessionInconnue);
        };
        for key in keys {
            let sk = sk4_psk(key);
            let (hk_ab, _) = header_keys4(&sk);
            let Some(header) = open_header(&hk_ab, TYPE_MESSAGE, body) else {
                continue;
            };
            let header = header?;
            if !x25519_is_canonical(&header.dh) {
                return Err(Erreur::CleInvalide);
            }
            if guard.seen(&header.dh) {
                return Err(Erreur::Rejoue);
            }
            let r_secret = psk4_ratchet_secret(&sk);
            let ad = [header.dh, x25519_public(&r_secret)].concat();
            let mut s = Self::new_responder(Mode4::Psk, &sk, ad, &r_secret, header.dh, None);
            let content = s.decrypt(token, now, rng)?;
            guard.insert(header.dh, now);
            return Ok((s, content));
        }
        Err(Erreur::SessionInconnue)
    }

    // ----- Envoi -----------------------------------------------------------

    fn seal(&mut self, genre: u8, data: &[u8]) -> Resultat<Token4> {
        if data.len() > MAX_PLAINTEXT {
            return Err(Erreur::TropGrand);
        }
        let ck = Zeroizing::new(self.cks.ok_or(Erreur::Etat)?);
        let hks = Zeroizing::new(self.hks.ok_or(Erreur::Etat)?);
        let kem = self.kem.as_ref().ok_or(Erreur::Etat)?;
        let next_ns = self.ns.checked_add(1).ok_or(Erreur::Epuise)?;
        let (next, mk) = kdf_ck(&ck);
        let (key, nonce, hnonce) = message_keys4(&mk);
        let header = Header4 {
            dh: self.dhs_public,
            pn: self.pn,
            n: self.ns,
            ek: kem.ek.clone(),
            ct: self.send_ct.clone(),
        };
        let kind = if self.preamble.is_some() {
            TYPE_INITIAL
        } else {
            TYPE_MESSAGE
        };
        let enc_header = aes_gcm_seal(&hks, &hnonce, &[kind], &header.to_bytes())?;
        let mut plain = Zeroizing::new(Vec::with_capacity(data.len() + 1));
        plain.push(genre);
        plain.extend_from_slice(data);
        let aad = self.aad(kind, &hnonce, &enc_header);
        let ciphertext = aes_gcm_seal(&key, &nonce, &aad, &pad(&plain))?;
        self.cks = Some(*next);
        self.ns = next_ns;
        let body = Body4 {
            header_nonce: hnonce,
            header: enc_header,
            ciphertext,
        };
        Ok(match &self.preamble {
            Some(p) => Token4::Initial(p.to_preamble()?, body),
            None => Token4::Message(body),
        })
    }

    /// Les données associées du chiffré : `AD ‖ type ‖ nonce d'en-tête ‖
    /// en-tête chiffré`.
    fn aad(&self, kind: u8, hnonce: &[u8; 12], enc_header: &[u8]) -> Vec<u8> {
        [&self.ad[..], &[kind], hnonce, enc_header].concat()
    }

    /// Chiffre un texte (le jeton décodé).
    pub fn encrypt_token(&mut self, text: &str) -> Resultat<Token4> {
        self.seal(GENRE_TEXTE, text.as_bytes())
    }

    /// Chiffre un texte : `[[BROCOLIS:v4:…]]`.
    pub fn encrypt(&mut self, text: &str) -> Resultat<String> {
        Ok(self.encrypt_token(text)?.encode())
    }

    /// Envoie une chaîne de groupe par cette session (genre 0x01).
    pub fn encrypt_distribution(&mut self, d: &SenderKeyDistribution) -> Resultat<String> {
        Ok(self.seal(GENRE_DISTRIBUTION, &d.to_bytes())?.encode())
    }

    // ----- Réception -------------------------------------------------------

    /// Déchiffre un jeton v4. [`Erreur::SessionInconnue`] : il n'est pas de
    /// cette session. Transactionnel. Peut tirer une nouvelle chaîne d'envoi
    /// (secret X25519 32, graine ML-KEM 64, `m` 32) si le message fait
    /// tourner le cliquet.
    pub fn decrypt(
        &mut self,
        token: &Token4,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Content> {
        if let Token4::Initial(p, _) = token {
            if self
                .preamble
                .as_ref()
                .is_some_and(|own| own.ephemeral == p.ephemeral)
            {
                // Notre propre premier message, renvoyé.
                return Err(Erreur::Rejoue);
            }
            if self.initial_ephemeral != Some(p.ephemeral) {
                return Err(Erreur::SessionInconnue);
            }
        }
        let mut next = self.clone();
        let plain = next.ratchet_decrypt(token.kind(), token.body(), now, rng)?;
        let (genre, data) = plain.split_first().ok_or(Erreur::Format)?;
        let content = match *genre {
            GENRE_TEXTE => {
                Content::Text(String::from_utf8(data.to_vec()).map_err(|_| Erreur::Utf8)?)
            }
            GENRE_DISTRIBUTION => Content::Distribution(SenderKeyDistribution::from_bytes(data)?),
            _ => return Err(Erreur::Format),
        };
        // Une réponse est arrivée : l'initiateur passe aux messages 0x02.
        if next.ckr.is_some() {
            next.preamble = None;
            next.confirmed = true;
        }
        *self = next;
        Ok(content)
    }

    /// [`Session4::decrypt`] d'un jeton texte `[[BROCOLIS:v4:…]]`.
    pub fn decrypt_text(
        &mut self,
        token: &str,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Content> {
        self.decrypt(&Token4::decode(token)?, now, rng)
    }

    fn open(&self, mk: &[u8; 32], kind: u8, body: &Body4) -> Resultat<Zeroizing<Vec<u8>>> {
        let (key, nonce, hnonce) = message_keys4(mk);
        if hnonce != body.header_nonce {
            return Err(Erreur::Dechiffrement);
        }
        let aad = self.aad(kind, &body.header_nonce, &body.header);
        let padded = aes_gcm_open(&key, &nonce, &aad, &body.ciphertext)?;
        Ok(Zeroizing::new(unpad(&padded)?.to_vec()))
    }

    fn ratchet_decrypt(
        &mut self,
        kind: u8,
        body: &Body4,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Zeroizing<Vec<u8>>> {
        self.purge(now);
        // 1. Les clés sautées des chaînes passées : une fois par clé
        //    d'en-tête distincte (la chaîne courante est traitée en 2).
        let mut tried: Vec<[u8; 32]> = Vec::new();
        for i in 0..self.skipped.len() {
            let hk = self.skipped[i].hk;
            if self.hkr == Some(hk) || tried.contains(&hk) {
                continue;
            }
            tried.push(hk);
            if let Some(header) = open_header(&hk, kind, body) {
                let header = header?;
                return self.take_skipped(hk, header.n, kind, body);
            }
        }
        // 2. La chaîne de réception courante : une clé sautée, ou la suite.
        if let Some((hkr, header)) = self
            .hkr
            .and_then(|hkr| open_header(&hkr, kind, body).map(|h| (hkr, h)))
        {
            let header = header?;
            if header.n < self.nr {
                return self.take_skipped(hkr, header.n, kind, body);
            }
            self.skip(header.n, now)?;
            return self.next_message(kind, body);
        }
        // 3. La chaîne suivante : le cliquet tourne.
        if let Some(header) = open_header(&self.nhkr.clone(), kind, body) {
            let header = header?;
            self.skip(header.pn, now)?;
            self.dh_ratchet(&header, rng)?;
            self.skip(header.n, now)?;
            return self.next_message(kind, body);
        }
        // 4. Nos propres messages, ou une chaîne passée : un rejeu.
        let own = self
            .hks
            .is_some_and(|hk| open_header(&hk, kind, body).is_some());
        let old = self
            .previous_hkr
            .iter()
            .any(|hk| open_header(&hk.0, kind, body).is_some());
        if own || old {
            return Err(Erreur::Rejoue);
        }
        Err(Erreur::SessionInconnue)
    }

    /// Le message `n` d'une chaîne dont la clé a été sautée ; absente :
    /// déjà lu.
    fn take_skipped(
        &mut self,
        hk: [u8; 32],
        n: u32,
        kind: u8,
        body: &Body4,
    ) -> Resultat<Zeroizing<Vec<u8>>> {
        let pos = self
            .skipped
            .iter()
            .position(|s| s.hk == hk && s.n == n)
            .ok_or(Erreur::Rejoue)?;
        let mk = Zeroizing::new(self.skipped[pos].mk);
        let plain = self.open(&mk, kind, body)?;
        self.skipped.remove(pos).zeroize();
        Ok(plain)
    }

    fn next_message(&mut self, kind: u8, body: &Body4) -> Resultat<Zeroizing<Vec<u8>>> {
        let ck = Zeroizing::new(self.ckr.ok_or(Erreur::Etat)?);
        let (next, mk) = kdf_ck(&ck);
        self.ckr = Some(*next);
        self.nr = self.nr.checked_add(1).ok_or(Erreur::Epuise)?;
        self.open(&mk, kind, body)
    }

    fn skip(&mut self, until: u32, now: u64) -> Resultat<()> {
        if u64::from(self.nr) + u64::from(MAX_SKIP) < u64::from(until) {
            return Err(Erreur::TropDeClesSautees);
        }
        if let (Some(ckr), Some(hkr)) = (self.ckr, self.hkr) {
            let mut ck = Zeroizing::new(ckr);
            while self.nr < until {
                let (next, mk) = kdf_ck(&ck);
                self.skipped.push(Skipped4 {
                    hk: hkr,
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

    /// Le tour de cliquet (§9.2, §9.3) : la chaîne de réception mélange
    /// X25519 et la décapsulation de `ct`, puis une nouvelle chaîne d'envoi
    /// mélange un nouveau X25519 et une encapsulation vers la clé ML-KEM
    /// annoncée par l'autre.
    fn dh_ratchet(
        &mut self,
        header: &Header4,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<()> {
        if header.ek.len() != PQPK_LEN {
            return Err(Erreur::Format);
        }
        let ss_r = match &header.ct {
            Some(ct) if ct.len() == KEM_CT_LEN => {
                let kem = self.kem.as_ref().ok_or(Erreur::Format)?;
                Some(mlkem_decapsulate(&kem.seed, ct)?)
            }
            Some(_) => return Err(Erreur::Format),
            // Seule la toute première chaîne de l'initiateur est sans `ct`.
            None if self.responder_fresh => None,
            None => return Err(Erreur::Format),
        };
        self.responder_fresh = false;
        self.pn = self.ns;
        self.ns = 0;
        self.nr = 0;
        if let Some(old) = self.hkr {
            self.previous_hkr.push(HeaderKey(old));
            if self.previous_hkr.len() > PREVIOUS_HKR {
                self.previous_hkr.remove(0).zeroize();
            }
        }
        self.hks = Some(self.nhks);
        self.hkr = Some(self.nhkr);
        self.dhr = Some(header.dh);
        let dh = x25519(&self.dhs_secret, &header.dh)?;
        let (rk, ckr, nhkr) = kdf_rk4(&self.rk, &dh, ss_r.as_deref());
        self.rk = *rk;
        self.ckr = Some(*ckr);
        self.nhkr = *nhkr;
        // Nouvelle chaîne d'envoi.
        let secret = Zeroizing::new(bytes::<32>(rng));
        let seed = Zeroizing::new(bytes::<64>(rng));
        let m = Zeroizing::new(bytes::<32>(rng));
        let (ct, ss_s) = mlkem_encapsulate(&header.ek, &m)?;
        self.dhs_secret = *secret;
        self.dhs_public = x25519_public(&secret);
        if let Some(mut old) = self.kem.replace(KemPair::from_seed(*seed)) {
            old.zeroize();
        }
        self.peer_ek = Some(header.ek.clone());
        self.send_ct = Some(ct);
        let dh = x25519(&self.dhs_secret, &header.dh)?;
        let (rk, cks, nhks) = kdf_rk4(&self.rk, &dh, Some(&ss_s));
        self.rk = *rk;
        self.cks = Some(*cks);
        self.nhks = *nhks;
        Ok(())
    }

    // ----- État ------------------------------------------------------------

    /// Efface les clés sautées de plus de 30 jours.
    pub fn purge(&mut self, now: u64) {
        let mut kept = Vec::with_capacity(self.skipped.len());
        for mut k in self.skipped.drain(..) {
            if k.stored_at.saturating_add(MAX_SKIP_AGE) > now {
                kept.push(k);
            } else {
                k.zeroize();
            }
        }
        self.skipped = kept;
    }

    /// L'identifiant local de la session (`SHA-256(AD)[0..8]`) : pour la
    /// ranger, jamais transmis.
    pub fn session_id(&self) -> [u8; 8] {
        self.session_id
    }

    /// AD = IK_A ‖ IK_B (ou EK_A ‖ R en clé partagée).
    pub fn associated_data(&self) -> &[u8] {
        &self.ad
    }

    /// Le mode d'établissement.
    pub fn mode(&self) -> Mode4 {
        self.mode
    }

    /// Vrai si l'autre côté a répondu (l'initiateur envoie des 0x01
    /// jusque-là).
    pub fn is_confirmed(&self) -> bool {
        self.confirmed
    }

    /// IK X25519 du correspondant (absent en clé partagée).
    pub fn peer_identity(&self) -> Option<[u8; 32]> {
        self.peer_identity
    }

    /// Le nombre de clés sautées gardées.
    pub fn skipped_len(&self) -> usize {
        self.skipped.len()
    }

    /// La clé publique de cliquet X25519 courante (vecteurs).
    pub fn ratchet_public(&self) -> [u8; 32] {
        self.dhs_public
    }

    /// La clé racine courante (vecteurs : un secret !).
    #[doc(hidden)]
    pub fn debug_root_key(&self) -> [u8; 32] {
        self.rk
    }

    /// Les clés d'en-tête courantes `(HKs, HKr, NHKs, NHKr)` — vecteurs.
    #[doc(hidden)]
    #[allow(clippy::type_complexity)]
    pub fn debug_header_keys(&self) -> (Option<[u8; 32]>, Option<[u8; 32]>, [u8; 32], [u8; 32]) {
        (self.hks, self.hkr, self.nhks, self.nhkr)
    }

    /// L'état en JSON.
    pub fn to_json(&self) -> Zeroizing<String> {
        Zeroizing::new(serde_json::to_string(self).unwrap_or_default())
    }

    /// Relit un état JSON (vérifie sa cohérence).
    pub fn from_json(text: &str) -> Resultat<Self> {
        let s: Session4 = serde_json::from_str(text).map_err(|_| Erreur::Etat)?;
        let ad_ok = s.ad.len() == 64 && session_id(&s.ad) == s.session_id;
        let kem_ok = s.kem.as_ref().is_none_or(|k| k.ek.len() == PQPK_LEN);
        let peer_ok = s.peer_ek.as_ref().is_none_or(|k| k.len() == PQPK_LEN);
        let ct_ok = s.send_ct.as_ref().is_none_or(|c| c.len() == KEM_CT_LEN);
        if s.v != 4
            || !ad_ok
            || !kem_ok
            || !peer_ok
            || !ct_ok
            || s.skipped.len() > MAX_SKIP as usize
            || x25519_public(&s.dhs_secret) != s.dhs_public
        {
            return Err(Erreur::Etat);
        }
        Ok(s)
    }
}

impl Device {
    /// Ouvre une session v4 vers un paquet ([`Session4::initiate`]).
    pub fn initiate4(
        &self,
        bundle: &KeyBundle,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<Session4> {
        Session4::initiate(self.identity_secret(), bundle, rng)
    }

    /// Accepte le premier message (0x01) d'une session v4 : essaie chaque
    /// SPK et PQPK gardée jusqu'à ouvrir le préambule (IK_A), puis établit la
    /// session et déchiffre. Aucune ne l'ouvre : [`Erreur::CleInconnue`]. Une
    /// EK déjà vue : [`Erreur::Rejoue`]. L'appelant vérifie ensuite que
    /// [`Session4::peer_identity`] est celle d'un contact.
    pub fn accept4(
        &mut self,
        token: &Token4,
        now: u64,
        rng: &mut (impl CryptoRng + ?Sized),
    ) -> Resultat<(Session4, Content)> {
        let Token4::Initial(p, _) = token else {
            return Err(Erreur::Format);
        };
        if !x25519_is_canonical(&p.ephemeral) {
            return Err(Erreur::CleInvalide);
        }
        if self.replay_mut().seen(&p.ephemeral) {
            return Err(Erreur::Rejoue);
        }
        let aad = p.aad();
        let mut found = None;
        'keys: for spk in self.spk_secrets() {
            let dh3 = x25519(&spk, &p.ephemeral)?;
            for seed in self.pq_seeds() {
                let ss = mlkem_decapsulate(&seed, &p.kem_ciphertext)?;
                let (k, n) = preamble_key4(&dh3, &ss);
                if let Ok(ik) = aes_gcm_open(&k, &n, &aad, &p.sealed_identity) {
                    let ik: [u8; 32] = ik.as_slice().try_into().map_err(|_| Erreur::Format)?;
                    found = Some((Zeroizing::new(spk), ss, dh3, ik));
                    break 'keys;
                }
            }
        }
        let (spk, ss, dh3, ik_a) = found.ok_or(Erreur::CleInconnue)?;
        let own = self.identity_secret();
        let dh1 = x25519(&spk, &ik_a)?;
        let dh2 = x25519(&own.dh, &p.ephemeral)?;
        let sk = sk4(&dh1, &dh2, &dh3, &ss);
        let ad = [ik_a, x25519_public(&own.dh)].concat();
        let mut s = Session4::new_responder(Mode4::Bundle, &sk, ad, &spk, p.ephemeral, Some(ik_a));
        let content = s.decrypt(token, now, rng)?;
        self.replay_mut().insert(p.ephemeral, now);
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

    fn pair() -> (Device, Session4, Device, Deterministic) {
        let mut rng = Deterministic::new(b"session4");
        let alice = Device::generate(&mut rng, 0, true);
        let bob = Device::generate(&mut rng, 0, true);
        let a = alice.initiate4(&bob.bundle().unwrap(), &mut rng).unwrap();
        (alice, a, bob, rng)
    }

    #[test]
    fn premier_echange_et_triple_cliquet() {
        let (alice, mut a, mut bob, mut rng) = pair();
        let t = a.encrypt_token("Salut 🥦").unwrap();
        assert!(matches!(t, Token4::Initial(..)));
        // L'identité d'Alice n'est pas dans le jeton.
        let bytes = t.to_bytes();
        let ik_a = alice.identity().dh;
        assert!(!bytes.windows(32).any(|w| w == ik_a));
        let (mut b, c) = bob.accept4(&t, 10, &mut rng).unwrap();
        assert_eq!(text(c), "Salut 🥦");
        assert_eq!(b.peer_identity(), Some(ik_a));
        assert_eq!(b.session_id(), a.session_id());
        assert_eq!(bob.accept4(&t, 11, &mut rng).err(), Some(Erreur::Rejoue));
        assert_eq!(b.decrypt(&t, 11, &mut rng), Err(Erreur::Rejoue));
        // Plusieurs tours : chaque réponse porte une encapsulation.
        for i in 0..4 {
            let r = b.encrypt_token(&format!("b{i}")).unwrap();
            let Token4::Message(body) = &r else { panic!() };
            assert_eq!(body.header.len(), crate::jeton_v4::HEADER_LEN_CT + 16);
            assert_eq!(text(a.decrypt(&r, 12, &mut rng).unwrap()), format!("b{i}"));
            assert!(a.is_confirmed());
            let m = a.encrypt_token(&format!("a{i}")).unwrap();
            assert!(matches!(m, Token4::Message(_)));
            assert_eq!(text(b.decrypt(&m, 12, &mut rng).unwrap()), format!("a{i}"));
        }
    }

    #[test]
    fn desordre_rejeu_et_echo() {
        let (_alice, mut a, mut bob, mut rng) = pair();
        let first = a.encrypt_token("1").unwrap();
        let (mut b, _) = bob.accept4(&first, 0, &mut rng).unwrap();
        let r = b.encrypt_token("r").unwrap();
        a.decrypt(&r, 0, &mut rng).unwrap();
        let m1 = a.encrypt_token("m1").unwrap();
        let m2 = a.encrypt_token("m2").unwrap();
        let m3 = a.encrypt_token("m3").unwrap();
        assert_eq!(text(b.decrypt(&m3, 0, &mut rng).unwrap()), "m3");
        assert_eq!(b.skipped_len(), 2);
        assert_eq!(text(b.decrypt(&m1, 0, &mut rng).unwrap()), "m1");
        assert_eq!(text(b.decrypt(&m2, 0, &mut rng).unwrap()), "m2");
        assert_eq!(b.decrypt(&m2, 0, &mut rng), Err(Erreur::Rejoue));
        // Notre propre message, renvoyé : rejeu, pas « inconnu ».
        assert_eq!(a.decrypt(&m1, 0, &mut rng), Err(Erreur::Rejoue));
        // Un message d'une autre session : inconnu.
        let (_x, mut other, _y, _) = pair();
        let foreign = other.encrypt_token("x").unwrap();
        let Token4::Initial(_, body) = foreign else {
            panic!()
        };
        assert_eq!(
            b.decrypt(&Token4::Message(body), 0, &mut rng),
            Err(Erreur::SessionInconnue)
        );
    }

    #[test]
    fn alteration_refusee_et_etat_intact() {
        let (_alice, mut a, mut bob, mut rng) = pair();
        let first = a.encrypt_token("1").unwrap();
        let (mut b, _) = bob.accept4(&first, 0, &mut rng).unwrap();
        let r = b.encrypt_token("r").unwrap();
        let before = a.to_json();
        let mut bytes = r.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let bad = Token4::from_bytes(&bytes).unwrap();
        assert_eq!(a.decrypt(&bad, 0, &mut rng), Err(Erreur::Dechiffrement));
        assert_eq!(*a.to_json(), *before, "transactionnel");
        // L'en-tête altéré : aucune clé ne l'ouvre.
        let mut bytes = r.to_bytes();
        bytes[20] ^= 1;
        let bad = Token4::from_bytes(&bytes).unwrap();
        assert_eq!(a.decrypt(&bad, 0, &mut rng), Err(Erreur::SessionInconnue));
        assert_eq!(text(a.decrypt(&r, 0, &mut rng).unwrap()), "r");
    }

    #[test]
    fn psk_v4() {
        let mut rng = Deterministic::new(b"psk4");
        let key = [7u8; 32];
        let mut a = Session4::initiate_psk(&key, &mut rng).unwrap();
        let t = a.encrypt_token("par la clé").unwrap();
        assert!(matches!(t, Token4::Message(_)));
        let mut guard = ReplayGuard::default();
        assert_eq!(
            Session4::accept_psk(&[[1u8; 32]], &t, &mut guard, 0, &mut rng).err(),
            Some(Erreur::SessionInconnue)
        );
        let (mut b, c) =
            Session4::accept_psk(&[[1u8; 32], key], &t, &mut guard, 0, &mut rng).unwrap();
        assert_eq!(text(c), "par la clé");
        assert_eq!(b.mode(), Mode4::Psk);
        assert_eq!(
            Session4::accept_psk(&[key], &t, &mut guard, 0, &mut rng).err(),
            Some(Erreur::Rejoue)
        );
        let r = b.encrypt("réponse").unwrap();
        assert_eq!(text(a.decrypt_text(&r, 0, &mut rng).unwrap()), "réponse");
        let m = a.encrypt("encore").unwrap();
        assert_eq!(text(b.decrypt_text(&m, 0, &mut rng).unwrap()), "encore");
    }

    #[test]
    fn json_aller_retour() {
        let (_alice, mut a, mut bob, mut rng) = pair();
        let t = a.encrypt_token("x").unwrap();
        let (b, _) = bob.accept4(&t, 0, &mut rng).unwrap();
        let mut b2 = Session4::from_json(&b.to_json()).unwrap();
        let mut a2 = Session4::from_json(&a.to_json()).unwrap();
        let r = b2.encrypt("y").unwrap();
        assert_eq!(text(a2.decrypt_text(&r, 0, &mut rng).unwrap()), "y");
        assert_eq!(Session4::from_json("{}").err(), Some(Erreur::Etat));
    }

    #[test]
    fn capacite_v4_signee() {
        let mut rng = Deterministic::new(b"caps");
        let a = Device::generate(&mut rng, 0, true);
        let b = Device::generate(&mut rng, 0, true);
        let caps = a.caps4().unwrap();
        assert!(crate::paquet::verify_caps4(&a.identity(), &caps).is_ok());
        // Sur une autre identité, ou altérée : refusée.
        assert_eq!(
            crate::paquet::verify_caps4(&b.identity(), &caps),
            Err(Erreur::Signature)
        );
        let mut bad = caps;
        bad[0] ^= 1;
        assert!(crate::paquet::verify_caps4(&a.identity(), &bad).is_err());
        // Sans ML-KEM, pas de capacité v4.
        assert!(Device::generate(&mut rng, 0, false).caps4().is_none());
    }

    #[test]
    fn un_paquet_sans_ml_kem_est_refuse() {
        let mut rng = Deterministic::new(b"classique");
        let alice = Device::generate(&mut rng, 0, true);
        let bob = Device::generate(&mut rng, 0, false);
        assert_eq!(
            alice.initiate4(&bob.bundle().unwrap(), &mut rng).err(),
            Some(Erreur::PqIndisponible)
        );
    }
}
