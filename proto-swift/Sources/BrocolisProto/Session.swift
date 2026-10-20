// L'établissement (§4.2, §7.3, §7.4) et le Double Ratchet (§4.3, §7.5) :
// une clé neuve par message, effacée aussitôt utilisée —
// `brocolis_proto::session`.
//
// L'initiateur A part de SK et de la SPK de B (sa clé de cliquet initiale) ;
// B part de SK et de sa SPK. Chaque déchiffrement est **transactionnel** :
// s'il échoue (message altéré, rejeu, trop de sauts), l'état de la session
// est exactement celui d'avant.
//
// Pour recevoir un jeton v3 de type 0x01 à 0x03 :
//
// 1. décoder (`Token.decode`) et chercher la session par `Token.sessionId` ;
// 2. si elle existe : `Session.decrypt`. Une erreur `.nouvelleSession` sur un
//    0x01 veut dire « nouvelle session » : passer à l'étape 3 ;
// 3. sinon, pour un 0x01 : `Device.accept` (mode X25519 ou hybride) ou
//    `Session.acceptPsk` (clé partagée).
//
// `.rejoue` : message déjà lu, à ignorer sans bruit.

/// Ce que porte un message déchiffré.
public enum Content: Equatable, Sendable {
    /// Un texte (types 0x01 et 0x02).
    case text(String)
    /// Une chaîne de groupe (type 0x03).
    case distribution(SenderKeyDistribution)
}

/// Le résultat d'une encapsulation ML-KEM faite ailleurs : pour rejouer les
/// vecteurs (CryptoKit tire lui-même l'aléa `m`, voir `MlKem`).
public struct KemEncapsulation: Sendable {
    /// Le chiffré ML-KEM-768 (1 088 octets).
    public var ciphertext: [UInt8]
    /// Le secret partagé SS (32 octets).
    public var shared: [UInt8]

    public init(ciphertext: [UInt8], shared: [UInt8]) {
        self.ciphertext = ciphertext
        self.shared = shared
    }
}

/// Ce que l'initiateur répète dans chaque message de type 0x01 tant qu'il
/// n'a pas reçu de réponse.
struct Preamble: Codable, Equatable {
    var identity: [UInt8]
    var ephemeral: [UInt8]
    var mode: Mode
    var kemCiphertext: [UInt8]?
    var spkId: UInt32
    var pqId: UInt32

    enum CodingKeys: String, CodingKey {
        case identity, ephemeral, mode
        case kemCiphertext = "kem_ciphertext"
        case spkId = "spk_id"
        case pqId = "pq_id"
    }

    init(identity: [UInt8], ephemeral: [UInt8], mode: Mode, kemCiphertext: [UInt8]?, spkId: UInt32, pqId: UInt32) {
        self.identity = identity
        self.ephemeral = ephemeral
        self.mode = mode
        self.kemCiphertext = kemCiphertext
        self.spkId = spkId
        self.pqId = pqId
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        identity = try c.bytes(.identity, length: 32)
        ephemeral = try c.bytes(.ephemeral, length: 32)
        mode = try c.decode(Mode.self, forKey: .mode)
        // `#[serde(with = "serde_b64::opt", default)]` : absent = `None`.
        kemCiphertext = c.contains(.kemCiphertext) ? try c.optionalBytes(.kemCiphertext) : nil
        spkId = try c.decode(UInt32.self, forKey: .spkId)
        pqId = try c.decode(UInt32.self, forKey: .pqId)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(identity, forKey: .identity)
        try c.encodeBytes(ephemeral, forKey: .ephemeral)
        try c.encode(mode, forKey: .mode)
        try c.encodeOptionalBytes(kemCiphertext, forKey: .kemCiphertext)
        try c.encode(spkId, forKey: .spkId)
        try c.encode(pqId, forKey: .pqId)
    }
}

/// Une clé de message sautée (message pas encore arrivé).
struct SkippedKey: Codable {
    var dh: [UInt8]
    var n: UInt32
    var mk: [UInt8]
    var storedAt: UInt64

    enum CodingKeys: String, CodingKey {
        case dh, n, mk
        case storedAt = "stored_at"
    }

    init(dh: [UInt8], n: UInt32, mk: [UInt8], storedAt: UInt64) {
        self.dh = dh
        self.n = n
        self.mk = mk
        self.storedAt = storedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        dh = try c.bytes(.dh, length: 32)
        n = try c.decode(UInt32.self, forKey: .n)
        mk = try c.bytes(.mk, length: 32)
        storedAt = try c.decode(UInt64.self, forKey: .storedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(dh, forKey: .dh)
        try c.encode(n, forKey: .n)
        try c.encodeBytes(mk, forKey: .mk)
        try c.encode(storedAt, forKey: .storedAt)
    }
}

/// L'état d'une session, tel qu'il est sérialisé (les champs de serde).
struct SessionState: Codable {
    var v: UInt8
    var mode: Mode
    var ad: [UInt8]
    var sessionId: [UInt8]
    var rk: [UInt8]
    var dhsSecret: [UInt8]
    var dhsPublic: [UInt8]
    var dhr: [UInt8]?
    var cks: [UInt8]?
    var ckr: [UInt8]?
    var ns: UInt32
    var nr: UInt32
    var pn: UInt32
    var skipped: [SkippedKey]
    var previousDhr: [[UInt8]]
    var preamble: Preamble?
    var initialEphemeral: [UInt8]?
    var peerIdentity: [UInt8]?

    enum CodingKeys: String, CodingKey {
        case v, mode, ad
        case sessionId = "session_id"
        case rk
        case dhsSecret = "dhs_secret"
        case dhsPublic = "dhs_public"
        case dhr, cks, ckr, ns, nr, pn, skipped
        case previousDhr = "previous_dhr"
        case preamble
        case initialEphemeral = "initial_ephemeral"
        case peerIdentity = "peer_identity"
    }

    init(
        mode: Mode, ad: [UInt8], rk: [UInt8], dhsSecret: [UInt8], dhr: [UInt8]?, cks: [UInt8]?,
        preamble: Preamble?, initialEphemeral: [UInt8]?, peerIdentity: [UInt8]?
    ) {
        v = 1
        self.mode = mode
        self.ad = ad
        sessionId = Kdf.sessionId(ad)
        self.rk = rk
        self.dhsSecret = dhsSecret
        dhsPublic = Kdf.x25519Public(dhsSecret)
        self.dhr = dhr
        self.cks = cks
        ckr = nil
        ns = 0
        nr = 0
        pn = 0
        skipped = []
        previousDhr = []
        self.preamble = preamble
        self.initialEphemeral = initialEphemeral
        self.peerIdentity = peerIdentity
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(UInt8.self, forKey: .v)
        mode = try c.decode(Mode.self, forKey: .mode)
        ad = try c.bytes(.ad)
        sessionId = try c.bytes(.sessionId, length: 8)
        rk = try c.bytes(.rk, length: 32)
        dhsSecret = try c.bytes(.dhsSecret, length: 32)
        dhsPublic = try c.bytes(.dhsPublic, length: 32)
        dhr = try c.optionalBytes(.dhr, length: 32)
        cks = try c.optionalBytes(.cks, length: 32)
        ckr = try c.optionalBytes(.ckr, length: 32)
        ns = try c.decode(UInt32.self, forKey: .ns)
        nr = try c.decode(UInt32.self, forKey: .nr)
        pn = try c.decode(UInt32.self, forKey: .pn)
        skipped = try c.decode([SkippedKey].self, forKey: .skipped)
        let previous = try c.decode([String].self, forKey: .previousDhr)
        previousDhr = try previous.map { text in
            guard let b = Base64.decode(text), b.count == 32 else {
                throw DecodingError.dataCorruptedError(forKey: .previousDhr, in: c, debugDescription: "clé")
            }
            return b
        }
        preamble = try c.decodeIfPresent(Preamble.self, forKey: .preamble)
        initialEphemeral = try c.optionalBytes(.initialEphemeral, length: 32)
        peerIdentity = try c.optionalBytes(.peerIdentity, length: 32)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(v, forKey: .v)
        try c.encode(mode, forKey: .mode)
        try c.encodeBytes(ad, forKey: .ad)
        try c.encodeBytes(sessionId, forKey: .sessionId)
        try c.encodeBytes(rk, forKey: .rk)
        try c.encodeBytes(dhsSecret, forKey: .dhsSecret)
        try c.encodeBytes(dhsPublic, forKey: .dhsPublic)
        try c.encodeOptionalBytes(dhr, forKey: .dhr)
        try c.encodeOptionalBytes(cks, forKey: .cks)
        try c.encodeOptionalBytes(ckr, forKey: .ckr)
        try c.encode(ns, forKey: .ns)
        try c.encode(nr, forKey: .nr)
        try c.encode(pn, forKey: .pn)
        try c.encode(skipped, forKey: .skipped)
        try c.encode(previousDhr.map { Base64.encode($0) }, forKey: .previousDhr)
        try c.encodeOptional(preamble, forKey: .preamble)
        try c.encodeOptionalBytes(initialEphemeral, forKey: .initialEphemeral)
        try c.encodeOptionalBytes(peerIdentity, forKey: .peerIdentity)
    }

    mutating func wipe() {
        effacer(&rk)
        effacer(&dhsSecret)
        effacer(&cks)
        effacer(&ckr)
        for i in skipped.indices { effacer(&skipped[i].mk) }
    }

    // MARK: Envoi

    /// Les données associées : `AD ‖ en-tête`, et `‖ 0x03` pour une
    /// distribution (§7.6 : le type est ainsi authentifié).
    func aad(_ header: Header, _ kind: UInt8) -> [UInt8] {
        var aad = ad + header.toBytes()
        if kind == JetonV3.typeDistribution { aad.append(JetonV3.typeDistribution) }
        return aad
    }

    mutating func seal(_ plain: [UInt8], _ kind: UInt8) throws -> Token {
        guard plain.count <= Session.maxPlaintext else { throw Erreur.tropGrand }
        guard var ck = cks else { throw Erreur.etat }
        defer { effacer(&ck) }
        let (nextNs, overflow) = ns.addingReportingOverflow(1)
        guard !overflow else { throw Erreur.epuise }
        var (next, mk) = Kdf.kdfCk(ck)
        defer { effacer(&mk) }
        let header = Header(dh: dhsPublic, pn: pn, n: ns)
        var (key, nonce) = Kdf.messageKey(mk)
        defer { effacer(&key) }
        var padded = Remplissage.pad(plain)
        defer { effacer(&padded) }
        let ciphertext: [UInt8]
        do {
            ciphertext = try Kdf.aesGcmSeal(key: key, nonce: nonce, aad: aad(header, kind), message: padded)
        } catch {
            effacer(&next)
            throw error
        }
        // Effacer un tableau partagé en fait d'abord une copie (copie à
        // l'écriture) : l'ancienne clé de chaîne n'est effacée que si cet
        // état est le seul à la tenir.
        effacer(&cks)
        cks = next
        ns = nextNs
        let envelope = Envelope(sessionId: sessionId, header: header, ciphertext: ciphertext)
        if kind == JetonV3.typeDistribution { return .distribution(envelope) }
        if let p = preamble {
            return .initial(Initial(
                identity: p.identity, ephemeral: p.ephemeral, mode: p.mode, kemCiphertext: p.kemCiphertext,
                spkId: p.spkId, pqId: p.pqId, envelope: envelope))
        }
        return .message(envelope)
    }

    // MARK: Réception

    func open(_ mk: [UInt8], _ header: Header, _ ct: [UInt8], _ kind: UInt8) throws -> [UInt8] {
        var (key, nonce) = Kdf.messageKey(mk)
        defer { effacer(&key) }
        var padded = try Kdf.aesGcmOpen(key: key, nonce: nonce, aad: aad(header, kind), ciphertext: ct)
        defer { effacer(&padded) }
        return try Remplissage.unpad(padded)
    }

    mutating func ratchetDecrypt(
        _ header: Header, _ ct: [UInt8], _ kind: UInt8, _ now: UInt64, _ rng: some CryptoRng
    ) throws -> [UInt8] {
        purge(now)
        if header.dh == dhsPublic {
            // Un de nos messages, renvoyé.
            throw Erreur.rejoue
        }
        if let pos = skipped.firstIndex(where: { $0.dh == header.dh && $0.n == header.n }) {
            let plain = try open(skipped[pos].mk, header, ct, kind)
            effacer(&skipped[pos].mk)
            skipped.remove(at: pos)
            return plain
        }
        let current = dhr == header.dh
        if current && header.n < nr { throw Erreur.rejoue }
        if !current && previousDhr.contains(header.dh) { throw Erreur.rejoue }
        if !current {
            try skip(header.pn, now)
            try dhRatchet(header, rng)
        }
        try skip(header.n, now)
        guard var ck = ckr else { throw Erreur.etat }
        defer { effacer(&ck) }
        let (next, mk0) = Kdf.kdfCk(ck)
        var mk = mk0
        defer { effacer(&mk) }
        ckr = next
        let (nextNr, overflow) = nr.addingReportingOverflow(1)
        guard !overflow else { throw Erreur.epuise }
        nr = nextNr
        return try open(mk, header, ct, kind)
    }

    mutating func skip(_ until: UInt32, _ now: UInt64) throws {
        if UInt64(nr) + UInt64(Protocole.maxSkip) < UInt64(until) { throw Erreur.tropDeClesSautees }
        if var ck = ckr, let dh = dhr {
            while nr < until {
                let (next, mk) = Kdf.kdfCk(ck)
                skipped.append(SkippedKey(dh: dh, n: nr, mk: mk, storedAt: now))
                effacer(&ck)
                ck = next
                nr += 1
            }
            ckr = ck
            let max = Int(Protocole.maxSkip)
            if skipped.count > max {
                let extra = skipped.count - max
                for i in 0..<extra { effacer(&skipped[i].mk) }
                skipped.removeFirst(extra)
            }
        }
    }

    mutating func dhRatchet(_ header: Header, _ rng: some CryptoRng) throws {
        pn = ns
        ns = 0
        nr = 0
        if let old = dhr {
            previousDhr.append(old)
            if previousDhr.count > Session.previousDhrCount { previousDhr.removeFirst() }
        }
        dhr = header.dh
        var dh = try Kdf.x25519(dhsSecret, header.dh)
        let (rk1, ckr1) = Kdf.kdfRk(rk, dh)
        effacer(&dh)
        effacer(&rk)
        rk = rk1
        effacer(&ckr)
        ckr = ckr1
        let secret = rng.bytes(32)
        effacer(&dhsSecret)
        dhsSecret = secret
        dhsPublic = Kdf.x25519Public(secret)
        var dh2 = try Kdf.x25519(dhsSecret, header.dh)
        let (rk2, cks2) = Kdf.kdfRk(rk, dh2)
        effacer(&dh2)
        effacer(&rk)
        rk = rk2
        effacer(&cks)
        cks = cks2
    }

    /// Efface les clés sautées de plus de 30 jours.
    mutating func purge(_ now: UInt64) {
        for i in skipped.indices where satAdd(skipped[i].storedAt, Protocole.maxSkipAge) <= now {
            effacer(&skipped[i].mk)
        }
        skipped.removeAll { satAdd($0.storedAt, Protocole.maxSkipAge) <= now }
    }
}

/// Une session à cliquet entre deux appareils. Sérialisable (JSON, de la
/// même forme que la référence) ; à garder chiffrée par la clé matérielle
/// (§3.1). Les secrets sont effacés quand la session disparaît (au mieux).
public final class Session {
    /// Le plus long texte (en octets UTF-8) qu'un message v3 peut porter :
    /// le jeton reste sous `JetonV3.maxTokenBytes`.
    public static let maxPlaintext = 200 * 1024
    /// Le nombre de clés de cliquet distantes passées dont on se souvient
    /// pour reconnaître un rejeu.
    static let previousDhrCount = 16

    var state: SessionState

    init(state: SessionState) {
        self.state = state
    }

    deinit {
        state.wipe()
    }

    // MARK: Création

    static func newInitiator(
        mode: Mode, sk: [UInt8], ad: [UInt8], ratchetSecret: [UInt8], remoteRatchet: [UInt8],
        preamble: Preamble, peerIdentity: [UInt8]?
    ) throws -> Session {
        var dh = try Kdf.x25519(ratchetSecret, remoteRatchet)
        defer { effacer(&dh) }
        let (rk, cks) = Kdf.kdfRk(sk, dh)
        return Session(state: SessionState(
            mode: mode, ad: ad, rk: rk, dhsSecret: ratchetSecret, dhr: remoteRatchet, cks: cks,
            preamble: preamble, initialEphemeral: nil, peerIdentity: peerIdentity))
    }

    static func newResponder(
        mode: Mode, sk: [UInt8], ad: [UInt8], ratchetSecret: [UInt8], initialEphemeral: [UInt8],
        peerIdentity: [UInt8]?
    ) -> Session {
        Session(state: SessionState(
            mode: mode, ad: ad, rk: sk, dhsSecret: ratchetSecret, dhr: nil, cks: nil,
            preamble: nil, initialEphemeral: initialEphemeral, peerIdentity: peerIdentity))
    }

    /// Ouvre une session vers l'appareil du paquet (§4.2), avec ML-KEM si
    /// `pq` (le paquet doit alors en proposer, et ML-KEM être disponible
    /// ici : sinon `.pqIndisponible`).
    ///
    /// Ordre de tirage : secret EK (32), secret de cliquet (32), puis, avec
    /// `pq`, 32 octets pour le message ML-KEM `m` de la référence — tirés
    /// mais inutilisés ici (CryptoKit tire son propre aléa) : les tirages
    /// suivants restent alignés sur la référence.
    public static func initiate(
        identity: IdentitySecret, bundle: KeyBundle, pq: Bool, rng: some CryptoRng
    ) throws -> Session {
        try bundle.verify()
        var ek = rng.bytes(32)
        defer { effacer(&ek) }
        var ratchet = rng.bytes(32)
        defer { effacer(&ratchet) }
        if pq { _ = rng.bytes(32) }
        return try establish(identity: identity, bundle: bundle, ekSecret: ek, ratchetSecret: ratchet) {
            guard pq else { return nil }
            guard let p = bundle.pq else { throw Erreur.pqIndisponible }
            let r = try MlKem.encapsulate(p.key)
            return KemEncapsulation(ciphertext: r.ciphertext, shared: r.shared)
        }
    }

    /// `initiate` en mode hybride si le paquet propose ML-KEM et que cet
    /// appareil sait le faire, en X25519 seul sinon (« session non
    /// post-quantique », §4.2).
    public static func initiateBest(identity: IdentitySecret, bundle: KeyBundle, rng: some CryptoRng) throws -> Session {
        try initiate(identity: identity, bundle: bundle, pq: bundle.pq != nil && MlKem.isAvailable, rng: rng)
    }

    /// `initiate` avec le hasard donné (les vecteurs). `kem` : le résultat
    /// d'une encapsulation ML-KEM vers la PQPK du paquet (mode hybride), ou
    /// `nil` (X25519 seul). Le paquet doit avoir été vérifié
    /// (`KeyBundle.fromBytes` le fait).
    public static func initiateWith(
        identity: IdentitySecret, bundle: KeyBundle, ekSecret: [UInt8], ratchetSecret: [UInt8],
        kem: KemEncapsulation?
    ) throws -> Session {
        try establish(identity: identity, bundle: bundle, ekSecret: ekSecret, ratchetSecret: ratchetSecret) {
            guard let kem else { return nil }
            guard bundle.pq != nil else { throw Erreur.pqIndisponible }
            guard kem.ciphertext.count == JetonV3.kemCtLength, kem.shared.count == 32 else { throw Erreur.format }
            return kem
        }
    }

    static func establish(
        identity: IdentitySecret, bundle: KeyBundle, ekSecret: [UInt8], ratchetSecret: [UInt8],
        kem: () throws -> KemEncapsulation?
    ) throws -> Session {
        guard ekSecret.count == 32, ratchetSecret.count == 32, bundle.spk.count == 32,
              bundle.identity.dh.count == 32
        else { throw Erreur.format }
        let ikA = Kdf.x25519Public(identity.dh)
        let ikB = bundle.identity.dh
        var dh1 = try Kdf.x25519(identity.dh, bundle.spk)
        defer { effacer(&dh1) }
        var dh2 = try Kdf.x25519(ekSecret, ikB)
        defer { effacer(&dh2) }
        var dh3 = try Kdf.x25519(ekSecret, bundle.spk)
        defer { effacer(&dh3) }
        let mode: Mode
        var ss: [UInt8]? = nil
        defer { effacer(&ss) }
        var kemCiphertext: [UInt8]? = nil
        var pqId: UInt32 = 0
        if let r = try kem() {
            mode = .hybrid
            ss = r.shared
            kemCiphertext = r.ciphertext
            pqId = bundle.pq?.id ?? 0
        } else {
            mode = .classic
        }
        var sk = Kdf.skX3dh(dh1: dh1, dh2: dh2, dh3: dh3, ss: ss)
        defer { effacer(&sk) }
        let preamble = Preamble(
            identity: ikA, ephemeral: Kdf.x25519Public(ekSecret), mode: mode, kemCiphertext: kemCiphertext,
            spkId: bundle.spkId, pqId: pqId)
        return try newInitiator(
            mode: mode, sk: sk, ad: ikA + ikB, ratchetSecret: ratchetSecret, remoteRatchet: bundle.spk,
            preamble: preamble, peerIdentity: ikB)
    }

    /// Ouvre une session à partir d'une clé Brocolis partagée (§4.2, §7.4,
    /// sans appairage ; **deux personnes seulement**). Tire le secret EK
    /// (32), qui sert aussi de première clé de cliquet.
    public static func initiatePsk(key: [UInt8], rng: some CryptoRng) throws -> Session {
        var ek = rng.bytes(32)
        defer { effacer(&ek) }
        return try initiatePskWith(key: key, ekSecret: ek)
    }

    /// `initiatePsk` avec le hasard donné.
    ///
    /// SK = `HKDF(0³², clé, "Brocolis_v3_PSK_SHA-256")` ; la clé de cliquet
    /// initiale du répondeur R est le secret X25519
    /// `HKDF(0³², SK, "Brocolis_v3_PSK_Ratchet")` (connu des deux) ;
    /// AD = EK_A ‖ R ; la première clé de cliquet de A est EK_A.
    public static func initiatePskWith(key: [UInt8], ekSecret: [UInt8]) throws -> Session {
        guard key.count == 32, ekSecret.count == 32 else { throw Erreur.format }
        var sk = Kdf.skPsk(key)
        defer { effacer(&sk) }
        var rSecret = Kdf.pskRatchetSecret(sk)
        defer { effacer(&rSecret) }
        let r = Kdf.x25519Public(rSecret)
        let ek = Kdf.x25519Public(ekSecret)
        let preamble = Preamble(
            identity: [UInt8](repeating: 0, count: 32), ephemeral: ek, mode: .psk, kemCiphertext: nil, spkId: 0, pqId: 0)
        return try newInitiator(
            mode: .psk, sk: sk, ad: ek + r, ratchetSecret: ekSecret, remoteRatchet: r, preamble: preamble,
            peerIdentity: nil)
    }

    /// Accepte le premier message d'une session à clé partagée : essaie
    /// chaque clé (l'identifiant de session dit laquelle). `guard` retient
    /// les clés éphémères déjà vues (un premier message rejoué est refusé :
    /// `.rejoue`).
    public static func acceptPsk(
        keys: [[UInt8]], message msg: Initial, guard replay: inout ReplayGuard, now: UInt64, rng: some CryptoRng
    ) throws -> (Session, Content) {
        guard msg.mode == .psk, msg.envelope.header.dh == msg.ephemeral else { throw Erreur.format }
        if replay.seen(msg.ephemeral) { throw Erreur.rejoue }
        for key in keys where key.count == 32 {
            var sk = Kdf.skPsk(key)
            defer { effacer(&sk) }
            var rSecret = Kdf.pskRatchetSecret(sk)
            defer { effacer(&rSecret) }
            let ad = msg.ephemeral + Kdf.x25519Public(rSecret)
            if Octets.ctEq(Kdf.sessionId(ad), msg.envelope.sessionId) {
                let s = newResponder(
                    mode: .psk, sk: sk, ad: ad, ratchetSecret: rSecret, initialEphemeral: msg.ephemeral,
                    peerIdentity: nil)
                let content = try s.decrypt(.initial(msg), now: now, rng: rng)
                replay.insert(msg.ephemeral, now: now)
                return (s, content)
            }
        }
        throw Erreur.sessionInconnue
    }

    // MARK: Envoi

    /// Chiffre un texte : le jeton décodé (type 0x01 tant que l'initiateur
    /// n'a pas reçu de réponse, 0x02 ensuite).
    public func encryptToken(_ text: String) throws -> Token {
        try state.seal(Array(text.utf8), JetonV3.typeMessage)
    }

    /// Chiffre un texte : `[[BROCOLIS:v3:…]]`.
    public func encrypt(_ text: String) throws -> String {
        try encryptToken(text).encode()
    }

    /// Envoie une chaîne de groupe (type 0x03) par cette session.
    public func encryptDistribution(_ d: SenderKeyDistribution) throws -> String {
        var bytes = d.toBytes()
        defer { effacer(&bytes) }
        return try state.seal(bytes, JetonV3.typeDistribution).encode()
    }

    // MARK: Réception

    /// Déchiffre un jeton décodé de cette session. Transactionnel : en cas
    /// d'erreur, la session n'a pas changé. Peut tirer une nouvelle clé de
    /// cliquet (32 octets) si le message fait tourner le cliquet.
    public func decrypt(_ token: Token, now: UInt64, rng: some CryptoRng) throws -> Content {
        let env: Envelope
        let kind: UInt8
        switch token {
        case .initial(let i):
            guard i.envelope.sessionId == state.sessionId else { throw Erreur.sessionInconnue }
            if let ek = state.initialEphemeral, ek == i.ephemeral {
                env = i.envelope
                kind = JetonV3.typeMessage
            } else if let p = state.preamble, p.ephemeral == i.ephemeral {
                // Notre propre premier message, renvoyé : ignoré.
                throw Erreur.rejoue
            } else {
                throw Erreur.nouvelleSession
            }
        case .message(let e):
            env = e
            kind = JetonV3.typeMessage
        case .distribution(let e):
            env = e
            kind = JetonV3.typeDistribution
        case .group:
            throw Erreur.sessionInconnue
        }
        guard env.sessionId == state.sessionId else { throw Erreur.sessionInconnue }
        guard env.header.dh.count == 32 else { throw Erreur.format }
        var next = state
        var plain = try next.ratchetDecrypt(env.header, env.ciphertext, kind, now, rng)
        defer { effacer(&plain) }
        let content: Content
        if kind == JetonV3.typeDistribution {
            content = .distribution(try SenderKeyDistribution.fromBytes(plain))
        } else {
            guard let text = Octets.utf8(plain) else { throw Erreur.utf8 }
            content = .text(text)
        }
        // Une réponse est arrivée : l'initiateur passe aux messages 0x02.
        next.preamble = nil
        state = next
        return content
    }

    /// `decrypt` d'un jeton texte `[[BROCOLIS:v3:…]]`.
    public func decryptText(_ token: String, now: UInt64, rng: some CryptoRng) throws -> Content {
        try decrypt(Token.decode(token), now: now, rng: rng)
    }

    // MARK: État

    /// Efface les clés sautées de plus de 30 jours.
    public func purge(now: UInt64) {
        state.purge(now)
    }

    /// L'identifiant de session (8 octets).
    public var sessionId: [UInt8] { state.sessionId }

    /// AD = IK_A ‖ IK_B (ou EK_A ‖ R en clé partagée).
    public var associatedData: [UInt8] { state.ad }

    /// Le mode d'établissement.
    public var mode: Mode { state.mode }

    /// Vrai si la session est post-quantique (hybride X25519 + ML-KEM).
    /// Sinon, l'appli l'affiche (« session non post-quantique »).
    public var isPostQuantum: Bool { state.mode == .hybrid }

    /// Vrai si l'autre côté a répondu (l'initiateur envoie des messages
    /// 0x01 jusque-là).
    public var isConfirmed: Bool { state.preamble == nil }

    /// IK X25519 du correspondant (absent en clé partagée) : l'appli le
    /// compare à celui du contact (alerte si une clé d'identité change).
    public var peerIdentity: [UInt8]? { state.peerIdentity }

    /// Le nombre de clés sautées gardées.
    public var skippedCount: Int { state.skipped.count }

    /// La clé publique de cliquet courante (pour les vecteurs).
    public var ratchetPublic: [UInt8] { state.dhsPublic }

    /// La clé racine courante (pour les vecteurs : un secret !).
    public var debugRootKey: [UInt8] { state.rk }

    /// Les clés de chaîne courantes (envoi, réception) — vecteurs seulement.
    public var debugChainKeys: (sending: [UInt8]?, receiving: [UInt8]?) { (state.cks, state.ckr) }

    /// L'état en JSON (même forme que `Session::to_json`).
    public func toJson() -> String {
        Json.encode(state)
    }

    /// Relit un état JSON (celui de `toJson` ou de la référence) et vérifie
    /// sa cohérence.
    public static func fromJson(_ text: String) throws -> Session {
        let s = try Json.decode(SessionState.self, text)
        let adOk = s.ad.count == 64 && Kdf.sessionId(s.ad) == s.sessionId
        guard s.v == 1, adOk, s.skipped.count <= Int(Protocole.maxSkip),
              Kdf.x25519Public(s.dhsSecret) == s.dhsPublic
        else { throw Erreur.etat }
        return Session(state: s)
    }
}

extension Device {
    /// Ouvre une session vers un paquet (`Session.initiate`).
    public func initiate(bundle: KeyBundle, pq: Bool, rng: some CryptoRng) throws -> Session {
        try Session.initiate(identity: identitySecret, bundle: bundle, pq: pq, rng: rng)
    }

    /// Ouvre une session vers un paquet, hybride si possible
    /// (`Session.initiateBest`).
    public func initiateBest(bundle: KeyBundle, rng: some CryptoRng) throws -> Session {
        try Session.initiateBest(identity: identitySecret, bundle: bundle, rng: rng)
    }

    /// Accepte le premier message (type 0x01) d'une nouvelle session, en
    /// mode X25519 ou hybride : retrouve la SPK (et la PQPK) désignées,
    /// calcule SK, déchiffre. Un premier message dont la clé éphémère a
    /// déjà servi est refusé (`.rejoue`).
    public func accept(_ msg: Initial, now: UInt64, rng: some CryptoRng) throws -> (Session, Content) {
        if msg.mode == .psk { throw Erreur.format }
        if state.replay.seen(msg.ephemeral) { throw Erreur.rejoue }
        var spk = try spkSecret(msg.spkId)
        defer { effacer(&spk) }
        let own = state.identity
        var dh1 = try Kdf.x25519(spk, msg.identity)
        defer { effacer(&dh1) }
        var dh2 = try Kdf.x25519(own.dh, msg.ephemeral)
        defer { effacer(&dh2) }
        var dh3 = try Kdf.x25519(spk, msg.ephemeral)
        defer { effacer(&dh3) }
        var ss: [UInt8]? = nil
        defer { effacer(&ss) }
        switch (msg.mode, msg.kemCiphertext) {
        case (.hybrid, .some(let ct)):
            var seed = try pqSeed(msg.pqId)
            defer { effacer(&seed) }
            ss = try MlKem.decapsulate(seed: seed, ciphertext: ct)
        case (.classic, .none):
            break
        default:
            throw Erreur.format
        }
        var sk = Kdf.skX3dh(dh1: dh1, dh2: dh2, dh3: dh3, ss: ss)
        defer { effacer(&sk) }
        let ad = msg.identity + Kdf.x25519Public(own.dh)
        guard Kdf.sessionId(ad) == msg.envelope.sessionId else { throw Erreur.sessionInconnue }
        let s = Session.newResponder(
            mode: msg.mode, sk: sk, ad: ad, ratchetSecret: spk, initialEphemeral: msg.ephemeral,
            peerIdentity: msg.identity)
        let content = try s.decrypt(.initial(msg), now: now, rng: rng)
        state.replay.insert(msg.ephemeral, now: now)
        return (s, content)
    }
}
