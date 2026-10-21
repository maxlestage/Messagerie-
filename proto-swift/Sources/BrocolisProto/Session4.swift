// Le protocole v4 (§9) : établissement hybride à identité cachée, triple
// cliquet (X25519 + ML-KEM-768 à chaque tour) et en-têtes chiffrés —
// `brocolis_proto::session4`.
//
// Recevoir un jeton v4 (`Token4`) :
//
// 1. essayer chaque session connue : `Session4.decrypt` ; une erreur
//    `.sessionInconnue` veut dire « pas cette session » (aucune clé
//    d'en-tête ne l'ouvre) — passer à la suivante ; toute autre erreur est
//    définitive (rejeu, altération…) ;
// 2. aucune session : un 0x01 va à `Device.accept4`, un 0x02 à
//    `Session4.acceptPsk` (clé partagée).
//
// Comme en v3, chaque déchiffrement est **transactionnel** : un échec laisse
// la session exactement telle qu'elle était.
//
// CryptoKit tire lui-même l'aléa `m` de l'encapsulation ML-KEM (voir
// `MlKem`) : les 32 octets que la référence tire pour `m` sont tirés quand
// même (les tirages suivants restent alignés sur les vecteurs), mais
// inutilisés ; `initiateWith` prend le résultat d'une encapsulation
// (`KemEncapsulation`) au lieu de `m`.

/// Une encapsulation ML-KEM-768 vers `ek`, avec l'aléa `m` tiré par la
/// session (ignoré par la bibliothèque du système). Les tests en injectent
/// une autre pour rejouer les vecteurs.
typealias Encapsulateur4 = (_ ek: [UInt8], _ m: [UInt8]) throws -> KemEncapsulation

/// Comment la session v4 a été établie (`"Bundle"`, `"Psk"` dans le JSON,
/// comme serde).
public enum Mode4: String, Codable, Sendable {
    /// Par paquet de clés : X25519 + ML-KEM-768, identité de l'initiateur
    /// cachée.
    case bundle = "Bundle"
    /// Par une clé Brocolis partagée.
    case psk = "Psk"
}

/// Une clé de message sautée : `(clé d'en-tête, N) → mk`.
struct Skipped4: Codable {
    var hk: [UInt8]
    var n: UInt32
    var mk: [UInt8]
    var storedAt: UInt64

    enum CodingKeys: String, CodingKey {
        case hk, n, mk
        case storedAt = "stored_at"
    }

    init(hk: [UInt8], n: UInt32, mk: [UInt8], storedAt: UInt64) {
        self.hk = hk
        self.n = n
        self.mk = mk
        self.storedAt = storedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        hk = try c.bytes(.hk, length: 32)
        n = try c.decode(UInt32.self, forKey: .n)
        mk = try c.bytes(.mk, length: 32)
        storedAt = try c.decode(UInt64.self, forKey: .storedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(hk, forKey: .hk)
        try c.encode(n, forKey: .n)
        try c.encodeBytes(mk, forKey: .mk)
        try c.encode(storedAt, forKey: .storedAt)
    }
}

/// Une paire ML-KEM-768 de cliquet : la graine `d ‖ z` et sa clé
/// d'encapsulation (gardée pour ne pas la recalculer à chaque message).
struct KemPair: Codable {
    var seed: [UInt8]
    var ek: [UInt8]

    enum CodingKeys: String, CodingKey { case seed, ek }

    init(seed: [UInt8], ek: [UInt8]) {
        self.seed = seed
        self.ek = ek
    }

    /// La paire d'une graine (`.pqIndisponible` sans ML-KEM ici).
    static func fromSeed(_ seed: [UInt8]) throws -> KemPair {
        KemPair(seed: seed, ek: try MlKem.publicKey(seed: seed))
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        seed = try c.bytes(.seed, length: MlKem.seedLength)
        ek = try c.bytes(.ek)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(seed, forKey: .seed)
        try c.encodeBytes(ek, forKey: .ek)
    }

    mutating func wipe() {
        effacer(&seed)
    }
}

/// Le préambule que l'initiateur répète dans ses messages 0x01.
struct StoredPreamble: Codable {
    var ephemeral: [UInt8]
    var kemCiphertext: [UInt8]
    var sealedIdentity: [UInt8]

    enum CodingKeys: String, CodingKey {
        case ephemeral
        case kemCiphertext = "kem_ciphertext"
        case sealedIdentity = "sealed_identity"
    }

    init(ephemeral: [UInt8], kemCiphertext: [UInt8], sealedIdentity: [UInt8]) {
        self.ephemeral = ephemeral
        self.kemCiphertext = kemCiphertext
        self.sealedIdentity = sealedIdentity
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ephemeral = try c.bytes(.ephemeral, length: 32)
        kemCiphertext = try c.bytes(.kemCiphertext)
        sealedIdentity = try c.bytes(.sealedIdentity)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(ephemeral, forKey: .ephemeral)
        try c.encodeBytes(kemCiphertext, forKey: .kemCiphertext)
        try c.encodeBytes(sealedIdentity, forKey: .sealedIdentity)
    }

    func toPreamble() throws -> Preamble4 {
        guard sealedIdentity.count == JetonV4.preambleLength else { throw Erreur.etat }
        return Preamble4(ephemeral: ephemeral, kemCiphertext: kemCiphertext, sealedIdentity: sealedIdentity)
    }
}

/// L'état d'une session v4, tel qu'il est sérialisé (les champs de serde).
struct Session4State: Codable {
    var v: UInt8
    var mode: Mode4
    var ad: [UInt8]
    var sessionId: [UInt8]
    var rk: [UInt8]
    var dhsSecret: [UInt8]
    var dhsPublic: [UInt8]
    var dhr: [UInt8]?
    var kem: KemPair?
    var peerEk: [UInt8]?
    var sendCt: [UInt8]?
    var cks: [UInt8]?
    var ckr: [UInt8]?
    var ns: UInt32
    var nr: UInt32
    var pn: UInt32
    var hks: [UInt8]?
    var hkr: [UInt8]?
    var nhks: [UInt8]
    var nhkr: [UInt8]
    var skipped: [Skipped4]
    var previousHkr: [[UInt8]]
    var preamble: StoredPreamble?
    var initialEphemeral: [UInt8]?
    var peerIdentity: [UInt8]?
    var confirmed: Bool
    /// Le répondeur n'a encore reçu aucune chaîne : la première peut être
    /// sans `ct` (la toute première chaîne de l'initiateur).
    var responderFresh: Bool

    enum CodingKeys: String, CodingKey {
        case v, mode, ad
        case sessionId = "session_id"
        case rk
        case dhsSecret = "dhs_secret"
        case dhsPublic = "dhs_public"
        case dhr, kem
        case peerEk = "peer_ek"
        case sendCt = "send_ct"
        case cks, ckr, ns, nr, pn, hks, hkr, nhks, nhkr, skipped
        case previousHkr = "previous_hkr"
        case preamble
        case initialEphemeral = "initial_ephemeral"
        case peerIdentity = "peer_identity"
        case confirmed
        case responderFresh = "responder_fresh"
    }

    init(
        mode: Mode4, ad: [UInt8], rk: [UInt8], dhsSecret: [UInt8], dhr: [UInt8]?, kem: KemPair?, cks: [UInt8]?,
        hks: [UInt8]?, nhks: [UInt8], nhkr: [UInt8], preamble: StoredPreamble?, initialEphemeral: [UInt8]?,
        peerIdentity: [UInt8]?, confirmed: Bool, responderFresh: Bool
    ) {
        v = 4
        self.mode = mode
        self.ad = ad
        sessionId = Kdf.sessionId(ad)
        self.rk = rk
        self.dhsSecret = dhsSecret
        dhsPublic = Kdf.x25519Public(dhsSecret)
        self.dhr = dhr
        self.kem = kem
        peerEk = nil
        sendCt = nil
        self.cks = cks
        ckr = nil
        ns = 0
        nr = 0
        pn = 0
        self.hks = hks
        hkr = nil
        self.nhks = nhks
        self.nhkr = nhkr
        skipped = []
        previousHkr = []
        self.preamble = preamble
        self.initialEphemeral = initialEphemeral
        self.peerIdentity = peerIdentity
        self.confirmed = confirmed
        self.responderFresh = responderFresh
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(UInt8.self, forKey: .v)
        mode = try c.decode(Mode4.self, forKey: .mode)
        ad = try c.bytes(.ad)
        sessionId = try c.bytes(.sessionId, length: 8)
        rk = try c.bytes(.rk, length: 32)
        dhsSecret = try c.bytes(.dhsSecret, length: 32)
        dhsPublic = try c.bytes(.dhsPublic, length: 32)
        dhr = try c.optionalBytes(.dhr, length: 32)
        // `Option<KemPair>` sans `with` : absent ou `null` = `None`.
        kem = try c.decodeIfPresent(KemPair.self, forKey: .kem)
        peerEk = try c.optionalBytes(.peerEk)
        sendCt = try c.optionalBytes(.sendCt)
        cks = try c.optionalBytes(.cks, length: 32)
        ckr = try c.optionalBytes(.ckr, length: 32)
        ns = try c.decode(UInt32.self, forKey: .ns)
        nr = try c.decode(UInt32.self, forKey: .nr)
        pn = try c.decode(UInt32.self, forKey: .pn)
        hks = try c.optionalBytes(.hks, length: 32)
        hkr = try c.optionalBytes(.hkr, length: 32)
        nhks = try c.bytes(.nhks, length: 32)
        nhkr = try c.bytes(.nhkr, length: 32)
        skipped = try c.decode([Skipped4].self, forKey: .skipped)
        // `#[serde(default)]`.
        let previous = try c.decodeIfPresent([String].self, forKey: .previousHkr) ?? []
        previousHkr = try previous.map { text in
            guard let b = Base64.decode(text), b.count == 32 else {
                throw DecodingError.dataCorruptedError(forKey: .previousHkr, in: c, debugDescription: "clé")
            }
            return b
        }
        preamble = try c.decodeIfPresent(StoredPreamble.self, forKey: .preamble)
        initialEphemeral = try c.optionalBytes(.initialEphemeral, length: 32)
        peerIdentity = try c.optionalBytes(.peerIdentity, length: 32)
        confirmed = try c.decode(Bool.self, forKey: .confirmed)
        responderFresh = try c.decode(Bool.self, forKey: .responderFresh)
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
        try c.encodeOptional(kem, forKey: .kem)
        try c.encodeOptionalBytes(peerEk, forKey: .peerEk)
        try c.encodeOptionalBytes(sendCt, forKey: .sendCt)
        try c.encodeOptionalBytes(cks, forKey: .cks)
        try c.encodeOptionalBytes(ckr, forKey: .ckr)
        try c.encode(ns, forKey: .ns)
        try c.encode(nr, forKey: .nr)
        try c.encode(pn, forKey: .pn)
        try c.encodeOptionalBytes(hks, forKey: .hks)
        try c.encodeOptionalBytes(hkr, forKey: .hkr)
        try c.encodeBytes(nhks, forKey: .nhks)
        try c.encodeBytes(nhkr, forKey: .nhkr)
        try c.encode(skipped, forKey: .skipped)
        try c.encode(previousHkr.map { Base64.encode($0) }, forKey: .previousHkr)
        try c.encodeOptional(preamble, forKey: .preamble)
        try c.encodeOptionalBytes(initialEphemeral, forKey: .initialEphemeral)
        try c.encodeOptionalBytes(peerIdentity, forKey: .peerIdentity)
        try c.encode(confirmed, forKey: .confirmed)
        try c.encode(responderFresh, forKey: .responderFresh)
    }

    mutating func wipe() {
        effacer(&rk)
        effacer(&dhsSecret)
        effacer(&cks)
        effacer(&ckr)
        effacer(&hks)
        effacer(&hkr)
        effacer(&nhks)
        effacer(&nhkr)
        kem?.wipe()
        for i in skipped.indices { effacer(&skipped[i].mk) }
    }

    // MARK: En-têtes

    /// Ouvre un en-tête chiffré avec `hk` : `nil` si ce n'est pas la bonne
    /// clé ; ouvert mais malformé : `.format`.
    static func openHeader(_ hk: [UInt8], _ kind: UInt8, _ body: Body4) throws -> Header4? {
        guard let plain = try? Kdf.aesGcmOpen(key: hk, nonce: body.headerNonce, aad: [kind], ciphertext: body.header)
        else { return nil }
        return try Header4.fromBytes(plain)
    }

    /// Vrai si `hk` ouvre l'en-tête (bien formé ou non).
    static func opens(_ hk: [UInt8], _ kind: UInt8, _ body: Body4) -> Bool {
        (try? Kdf.aesGcmOpen(key: hk, nonce: body.headerNonce, aad: [kind], ciphertext: body.header)) != nil
    }

    // MARK: Envoi

    /// Les données associées du chiffré : `AD ‖ type ‖ nonce d'en-tête ‖
    /// en-tête chiffré`.
    func aad(_ kind: UInt8, _ headerNonce: [UInt8], _ encHeader: [UInt8]) -> [UInt8] {
        ad + [kind] + headerNonce + encHeader
    }

    mutating func seal(_ genre: UInt8, _ data: [UInt8]) throws -> Token4 {
        guard data.count <= Session.maxPlaintext else { throw Erreur.tropGrand }
        guard var ck = cks, let hk = hks, let pair = kem else { throw Erreur.etat }
        defer { effacer(&ck) }
        let (nextNs, overflow) = ns.addingReportingOverflow(1)
        guard !overflow else { throw Erreur.epuise }
        let (next0, mk0) = Kdf.kdfCk(ck)
        var next = next0
        var mk = mk0
        defer { effacer(&mk) }
        let keys = Kdf.messageKeys4(mk)
        var key = keys.key
        defer { effacer(&key) }
        let header = Header4(dh: dhsPublic, pn: pn, n: ns, ek: pair.ek, ct: sendCt)
        let kind = preamble == nil ? JetonV4.typeMessage : JetonV4.typeInitial
        var plain = [genre] + data
        defer { effacer(&plain) }
        var padded = Remplissage.pad(plain)
        defer { effacer(&padded) }
        let encHeader: [UInt8]
        let ciphertext: [UInt8]
        let tokenPreamble: Preamble4?
        do {
            encHeader = try Kdf.aesGcmSeal(key: hk, nonce: keys.headerNonce, aad: [kind], message: header.toBytes())
            ciphertext = try Kdf.aesGcmSeal(
                key: key, nonce: keys.nonce, aad: aad(kind, keys.headerNonce, encHeader), message: padded)
            tokenPreamble = try preamble?.toPreamble()
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
        let body = Body4(headerNonce: keys.headerNonce, header: encHeader, ciphertext: ciphertext)
        if let p = tokenPreamble { return .initial(p, body) }
        return .message(body)
    }

    // MARK: Réception

    func open(_ mk: [UInt8], _ kind: UInt8, _ body: Body4) throws -> [UInt8] {
        let keys = Kdf.messageKeys4(mk)
        var key = keys.key
        defer { effacer(&key) }
        guard keys.headerNonce == body.headerNonce else { throw Erreur.dechiffrement }
        var padded = try Kdf.aesGcmOpen(
            key: key, nonce: keys.nonce, aad: aad(kind, body.headerNonce, body.header), ciphertext: body.ciphertext)
        defer { effacer(&padded) }
        return try Remplissage.unpad(padded)
    }

    mutating func ratchetDecrypt(
        _ kind: UInt8, _ body: Body4, _ now: UInt64, _ rng: some CryptoRng, _ encapsuler: Encapsulateur4
    ) throws -> [UInt8] {
        purge(now)
        // 1. Les clés sautées des chaînes passées : une fois par clé
        //    d'en-tête distincte (la chaîne courante est traitée en 2).
        var tried: [[UInt8]] = []
        for s in skipped {
            let hk = s.hk
            if hkr == hk || tried.contains(hk) { continue }
            tried.append(hk)
            if let header = try Session4State.openHeader(hk, kind, body) {
                return try takeSkipped(hk, header.n, kind, body)
            }
        }
        // 2. La chaîne de réception courante : une clé sautée, ou la suite.
        if let hk = hkr, let header = try Session4State.openHeader(hk, kind, body) {
            if header.n < nr {
                return try takeSkipped(hk, header.n, kind, body)
            }
            try skip(header.n, now)
            return try nextMessage(kind, body)
        }
        // 3. La chaîne suivante : le cliquet tourne.
        if let header = try Session4State.openHeader(nhkr, kind, body) {
            try skip(header.pn, now)
            try dhRatchet(header, rng, encapsuler)
            try skip(header.n, now)
            return try nextMessage(kind, body)
        }
        // 4. Nos propres messages, ou une chaîne passée : un rejeu.
        let own = hks.map { Session4State.opens($0, kind, body) } ?? false
        let old = previousHkr.contains { Session4State.opens($0, kind, body) }
        if own || old { throw Erreur.rejoue }
        throw Erreur.sessionInconnue
    }

    /// Le message `n` d'une chaîne dont la clé a été sautée ; absente : déjà
    /// lu.
    mutating func takeSkipped(_ hk: [UInt8], _ n: UInt32, _ kind: UInt8, _ body: Body4) throws -> [UInt8] {
        guard let pos = skipped.firstIndex(where: { $0.hk == hk && $0.n == n }) else { throw Erreur.rejoue }
        let plain = try open(skipped[pos].mk, kind, body)
        effacer(&skipped[pos].mk)
        skipped.remove(at: pos)
        return plain
    }

    mutating func nextMessage(_ kind: UInt8, _ body: Body4) throws -> [UInt8] {
        guard var ck = ckr else { throw Erreur.etat }
        defer { effacer(&ck) }
        let (next, mk0) = Kdf.kdfCk(ck)
        var mk = mk0
        defer { effacer(&mk) }
        ckr = next
        let (nextNr, overflow) = nr.addingReportingOverflow(1)
        guard !overflow else { throw Erreur.epuise }
        nr = nextNr
        return try open(mk, kind, body)
    }

    mutating func skip(_ until: UInt32, _ now: UInt64) throws {
        if UInt64(nr) + UInt64(Protocole.maxSkip) < UInt64(until) { throw Erreur.tropDeClesSautees }
        if var ck = ckr, let hk = hkr {
            while nr < until {
                let (next, mk) = Kdf.kdfCk(ck)
                skipped.append(Skipped4(hk: hk, n: nr, mk: mk, storedAt: now))
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

    /// Le tour de cliquet (§9.2, §9.3) : la chaîne de réception mélange
    /// X25519 et la décapsulation de `ct`, puis une nouvelle chaîne d'envoi
    /// mélange un nouveau X25519 et une encapsulation vers la clé ML-KEM
    /// annoncée par l'autre.
    ///
    /// Ordre de tirage : secret X25519 (32), graine ML-KEM (64), `m` (32).
    mutating func dhRatchet(_ header: Header4, _ rng: some CryptoRng, _ encapsuler: Encapsulateur4) throws {
        guard header.ek.count == Paquet.pqpkLength, header.dh.count == 32 else { throw Erreur.format }
        var ssR: [UInt8]? = nil
        defer { effacer(&ssR) }
        if let ct = header.ct {
            guard ct.count == JetonV4.kemCtLength, let pair = kem else { throw Erreur.format }
            ssR = try MlKem.decapsulate(seed: pair.seed, ciphertext: ct)
        } else if !responderFresh {
            // Seule la toute première chaîne de l'initiateur est sans `ct`.
            throw Erreur.format
        }
        responderFresh = false
        pn = ns
        ns = 0
        nr = 0
        if let old = hkr {
            previousHkr.append(old)
            if previousHkr.count > Session4.previousHkrCount { previousHkr.removeFirst() }
        }
        hks = nhks
        hkr = nhkr
        dhr = header.dh
        var dh = try Kdf.x25519(dhsSecret, header.dh)
        let (rk1, ckr1, nhkr1) = Kdf.kdfRk4(rk, dh, ssR)
        effacer(&dh)
        effacer(&rk)
        rk = rk1
        effacer(&ckr)
        ckr = ckr1
        nhkr = nhkr1
        // Nouvelle chaîne d'envoi.
        let secret = rng.bytes(32)
        var seed = rng.bytes(64)
        defer { effacer(&seed) }
        var m = rng.bytes(32)
        defer { effacer(&m) }
        var enc = try encapsuler(header.ek, m)
        defer { effacer(&enc.shared) }
        guard enc.ciphertext.count == JetonV4.kemCtLength, enc.shared.count == 32 else { throw Erreur.format }
        effacer(&dhsSecret)
        dhsSecret = secret
        dhsPublic = Kdf.x25519Public(secret)
        let newPair = try KemPair.fromSeed(seed)
        kem?.wipe()
        kem = newPair
        peerEk = header.ek
        sendCt = enc.ciphertext
        var dh2 = try Kdf.x25519(dhsSecret, header.dh)
        let (rk2, cks2, nhks2) = Kdf.kdfRk4(rk, dh2, enc.shared)
        effacer(&dh2)
        effacer(&rk)
        rk = rk2
        effacer(&cks)
        cks = cks2
        nhks = nhks2
    }

    /// Efface les clés sautées de plus de 30 jours.
    mutating func purge(_ now: UInt64) {
        for i in skipped.indices where satAdd(skipped[i].storedAt, Protocole.maxSkipAge) <= now {
            effacer(&skipped[i].mk)
        }
        skipped.removeAll { satAdd($0.storedAt, Protocole.maxSkipAge) <= now }
    }
}

/// Une session v4 entre deux appareils. Sérialisable (JSON, de la même forme
/// que la référence) ; à garder chiffrée par la clé matérielle (§3.1). Les
/// secrets sont effacés quand la session disparaît (au mieux).
public final class Session4 {
    /// Le nombre de clés d'en-tête de réception passées dont on se souvient
    /// pour reconnaître un rejeu.
    static let previousHkrCount = 16

    var state: Session4State
    /// L'encapsulation ML-KEM des nouvelles chaînes d'envoi (celle du
    /// système ; les tests des vecteurs en injectent une autre).
    var encapsuler: Encapsulateur4 = Session4.encapsulerSysteme

    init(state: Session4State) {
        self.state = state
    }

    deinit {
        state.wipe()
    }

    /// ML-KEM-768.Encaps par la bibliothèque du système (`m` ignoré).
    static func encapsulerSysteme(_ ek: [UInt8], _ m: [UInt8]) throws -> KemEncapsulation {
        let r = try MlKem.encapsulate(ek)
        return KemEncapsulation(ciphertext: r.ciphertext, shared: r.shared)
    }

    /// Une copie indépendante (les tests : le `clone` de la référence).
    func copie() -> Session4 {
        let s = Session4(state: state)
        s.encapsuler = encapsuler
        return s
    }

    // MARK: Création

    static func newInitiator(
        mode: Mode4, sk: [UInt8], ad: [UInt8], ratchetSecret: [UInt8], remoteRatchet: [UInt8], kem: KemPair,
        preamble: StoredPreamble?, peerIdentity: [UInt8]?
    ) throws -> Session4 {
        let (hkAb, nhkBa) = Kdf.headerKeys4(sk)
        var dh = try Kdf.x25519(ratchetSecret, remoteRatchet)
        defer { effacer(&dh) }
        let (rk, cks, nhks) = Kdf.kdfRk4(sk, dh, nil)
        return Session4(state: Session4State(
            mode: mode, ad: ad, rk: rk, dhsSecret: ratchetSecret, dhr: remoteRatchet, kem: kem, cks: cks, hks: hkAb,
            nhks: nhks, nhkr: nhkBa, preamble: preamble, initialEphemeral: nil, peerIdentity: peerIdentity,
            confirmed: false, responderFresh: false))
    }

    static func newResponder(
        mode: Mode4, sk: [UInt8], ad: [UInt8], ratchetSecret: [UInt8], initialEphemeral: [UInt8],
        peerIdentity: [UInt8]?
    ) -> Session4 {
        let (hkAb, nhkBa) = Kdf.headerKeys4(sk)
        return Session4(state: Session4State(
            mode: mode, ad: ad, rk: sk, dhsSecret: ratchetSecret, dhr: nil, kem: nil, cks: nil, hks: nil,
            nhks: nhkBa, nhkr: hkAb, preamble: nil, initialEphemeral: initialEphemeral, peerIdentity: peerIdentity,
            confirmed: true, responderFresh: true))
    }

    /// Ouvre une session v4 vers l'appareil du paquet (§9.1, §9.4). Le paquet
    /// doit proposer ML-KEM, et ML-KEM être disponible ici
    /// (`.pqIndisponible` sinon).
    ///
    /// Ordre de tirage : secret EK (32), secret de cliquet (32), 32 octets
    /// pour le message ML-KEM `m` de la référence (tirés mais inutilisés
    /// ici), graine ML-KEM de cliquet (64).
    public static func initiate(identity: IdentitySecret, bundle: KeyBundle, rng: some CryptoRng) throws -> Session4 {
        try bundle.verify()
        var ek = rng.bytes(32)
        defer { effacer(&ek) }
        var ratchet = rng.bytes(32)
        defer { effacer(&ratchet) }
        _ = rng.bytes(32)
        var seed = rng.bytes(64)
        defer { effacer(&seed) }
        guard let pq = bundle.pq else { throw Erreur.pqIndisponible }
        let r = try MlKem.encapsulate(pq.key)
        var kem = KemEncapsulation(ciphertext: r.ciphertext, shared: r.shared)
        defer { effacer(&kem.shared) }
        return try initiateWith(
            identity: identity, bundle: bundle, ekSecret: ek, ratchetSecret: ratchet, kem: kem, kemSeed: seed)
    }

    /// `initiate` avec le hasard donné (les vecteurs). `kem` : le résultat
    /// d'une encapsulation ML-KEM vers la PQPK du paquet ; `kemSeed` : la
    /// graine (64 octets) de la première paire ML-KEM de cliquet. Le paquet
    /// doit avoir été vérifié (`KeyBundle.fromBytes` le fait).
    public static func initiateWith(
        identity: IdentitySecret, bundle: KeyBundle, ekSecret: [UInt8], ratchetSecret: [UInt8],
        kem: KemEncapsulation, kemSeed: [UInt8]
    ) throws -> Session4 {
        guard bundle.pq != nil else { throw Erreur.pqIndisponible }
        guard ekSecret.count == 32, ratchetSecret.count == 32, kemSeed.count == MlKem.seedLength,
              bundle.spk.count == 32, bundle.identity.dh.count == 32,
              kem.ciphertext.count == JetonV4.kemCtLength, kem.shared.count == 32
        else { throw Erreur.format }
        let ikA = Kdf.x25519Public(identity.dh)
        let ikB = bundle.identity.dh
        var dh1 = try Kdf.x25519(identity.dh, bundle.spk)
        defer { effacer(&dh1) }
        var dh2 = try Kdf.x25519(ekSecret, ikB)
        defer { effacer(&dh2) }
        var dh3 = try Kdf.x25519(ekSecret, bundle.spk)
        defer { effacer(&dh3) }
        var sk = Kdf.sk4(dh1: dh1, dh2: dh2, dh3: dh3, ss: kem.shared)
        defer { effacer(&sk) }
        let ephemeral = Kdf.x25519Public(ekSecret)
        let pre = Kdf.preambleKey4(dh3, kem.shared)
        var kPre = pre.key
        defer { effacer(&kPre) }
        let aad = [JetonV4.typeInitial] + ephemeral + kem.ciphertext
        let sealedIdentity = try Kdf.aesGcmSeal(key: kPre, nonce: pre.nonce, aad: aad, message: ikA)
        let preamble = StoredPreamble(ephemeral: ephemeral, kemCiphertext: kem.ciphertext, sealedIdentity: sealedIdentity)
        return try newInitiator(
            mode: .bundle, sk: sk, ad: ikA + ikB, ratchetSecret: ratchetSecret, remoteRatchet: bundle.spk,
            kem: try KemPair.fromSeed(kemSeed), preamble: preamble, peerIdentity: ikB)
    }

    /// Ouvre une session v4 à partir d'une clé partagée (deux personnes
    /// seulement). Tire le secret EK (32, aussi première clé de cliquet),
    /// puis la graine ML-KEM (64).
    public static func initiatePsk(key: [UInt8], rng: some CryptoRng) throws -> Session4 {
        var ek = rng.bytes(32)
        defer { effacer(&ek) }
        var seed = rng.bytes(64)
        defer { effacer(&seed) }
        return try initiatePskWith(key: key, ekSecret: ek, kemSeed: seed)
    }

    /// `initiatePsk` avec le hasard donné.
    ///
    /// SK = `HKDF(0³², clé, "Brocolis_v4_PSK_SHA-256")` ; la clé de cliquet
    /// initiale du répondeur R est le secret X25519
    /// `HKDF(0³², SK, "Brocolis_v4_PSK_Ratchet")` ; AD = EK_A ‖ R ; la
    /// première clé de cliquet de A est EK_A.
    public static func initiatePskWith(key: [UInt8], ekSecret: [UInt8], kemSeed: [UInt8]) throws -> Session4 {
        guard key.count == 32, ekSecret.count == 32, kemSeed.count == MlKem.seedLength else { throw Erreur.format }
        var sk = Kdf.sk4Psk(key)
        defer { effacer(&sk) }
        var rSecret = Kdf.psk4RatchetSecret(sk)
        defer { effacer(&rSecret) }
        let r = Kdf.x25519Public(rSecret)
        let ad = Kdf.x25519Public(ekSecret) + r
        return try newInitiator(
            mode: .psk, sk: sk, ad: ad, ratchetSecret: ekSecret, remoteRatchet: r, kem: try KemPair.fromSeed(kemSeed),
            preamble: nil, peerIdentity: nil)
    }

    /// Accepte le premier message d'une session v4 à clé partagée : un 0x02
    /// qu'aucune session n'ouvre. Essaie la clé d'en-tête initiale de chaque
    /// clé ; `.sessionInconnue` si aucune ne l'ouvre. Une EK déjà vue est
    /// refusée (`.rejoue`).
    public static func acceptPsk(
        keys: [[UInt8]], token: Token4, guard replay: inout ReplayGuard, now: UInt64, rng: some CryptoRng
    ) throws -> (Session4, Content) {
        try acceptPsk(keys: keys, token: token, guard: &replay, now: now, rng: rng, encapsuler: encapsulerSysteme)
    }

    static func acceptPsk(
        keys: [[UInt8]], token: Token4, guard replay: inout ReplayGuard, now: UInt64, rng: some CryptoRng,
        encapsuler: @escaping Encapsulateur4
    ) throws -> (Session4, Content) {
        guard case .message(let body) = token else { throw Erreur.sessionInconnue }
        guard body.headerNonce.count == JetonV4.headerNonceLength else { throw Erreur.format }
        for key in keys where key.count == 32 {
            var sk = Kdf.sk4Psk(key)
            defer { effacer(&sk) }
            var hk = Kdf.headerKeys4(sk)
            defer {
                effacer(&hk.hkAb)
                effacer(&hk.nhkBa)
            }
            guard let header = try Session4State.openHeader(hk.hkAb, JetonV4.typeMessage, body) else { continue }
            guard Kdf.x25519IsCanonical(header.dh) else { throw Erreur.cleInvalide }
            if replay.seen(header.dh) { throw Erreur.rejoue }
            var rSecret = Kdf.psk4RatchetSecret(sk)
            defer { effacer(&rSecret) }
            let ad = header.dh + Kdf.x25519Public(rSecret)
            let s = newResponder(
                mode: .psk, sk: sk, ad: ad, ratchetSecret: rSecret, initialEphemeral: header.dh, peerIdentity: nil)
            s.encapsuler = encapsuler
            let content = try s.decrypt(token, now: now, rng: rng)
            replay.insert(header.dh, now: now)
            return (s, content)
        }
        throw Erreur.sessionInconnue
    }

    // MARK: Envoi

    /// Chiffre un texte : le jeton décodé (0x01 tant que l'initiateur d'une
    /// session par paquet n'a pas reçu de réponse, 0x02 sinon).
    public func encryptToken(_ text: String) throws -> Token4 {
        try state.seal(JetonV4.genreTexte, Array(text.utf8))
    }

    /// Chiffre un texte : `[[BROCOLIS:v4:…]]`.
    public func encrypt(_ text: String) throws -> String {
        try encryptToken(text).encode()
    }

    /// Envoie une chaîne de groupe par cette session (genre 0x01).
    public func encryptDistribution(_ d: SenderKeyDistribution) throws -> String {
        var bytes = d.toBytes()
        defer { effacer(&bytes) }
        return try state.seal(JetonV4.genreDistribution, bytes).encode()
    }

    // MARK: Réception

    /// Déchiffre un jeton v4. `.sessionInconnue` : il n'est pas de cette
    /// session. Transactionnel : en cas d'erreur, la session n'a pas changé.
    /// Peut tirer une nouvelle chaîne d'envoi (secret X25519 32, graine
    /// ML-KEM 64, `m` 32) si le message fait tourner le cliquet.
    public func decrypt(_ token: Token4, now: UInt64, rng: some CryptoRng) throws -> Content {
        if case .initial(let p, _) = token {
            if let own = state.preamble, own.ephemeral == p.ephemeral {
                // Notre propre premier message, renvoyé.
                throw Erreur.rejoue
            }
            if state.initialEphemeral != p.ephemeral { throw Erreur.sessionInconnue }
        }
        let body = token.body
        guard body.headerNonce.count == JetonV4.headerNonceLength else { throw Erreur.format }
        var next = state
        var plain = try next.ratchetDecrypt(token.type, body, now, rng, encapsuler)
        defer { effacer(&plain) }
        guard let genre = plain.first else { throw Erreur.format }
        var data = Array(plain.dropFirst())
        defer { effacer(&data) }
        let content: Content
        switch genre {
        case JetonV4.genreTexte:
            guard let text = Octets.utf8(data) else { throw Erreur.utf8 }
            content = .text(text)
        case JetonV4.genreDistribution:
            content = .distribution(try SenderKeyDistribution.fromBytes(data))
        default:
            throw Erreur.format
        }
        // Une réponse est arrivée : l'initiateur passe aux messages 0x02.
        if next.ckr != nil {
            next.preamble = nil
            next.confirmed = true
        }
        state = next
        return content
    }

    /// `decrypt` d'un jeton texte `[[BROCOLIS:v4:…]]`.
    public func decryptText(_ token: String, now: UInt64, rng: some CryptoRng) throws -> Content {
        try decrypt(Token4.decode(token), now: now, rng: rng)
    }

    // MARK: État

    /// Efface les clés sautées de plus de 30 jours.
    public func purge(now: UInt64) {
        state.purge(now)
    }

    /// L'identifiant local de la session (`SHA-256(AD)[0..8]`) : pour la
    /// ranger, jamais transmis.
    public var sessionId: [UInt8] { state.sessionId }

    /// AD = IK_A ‖ IK_B (ou EK_A ‖ R en clé partagée).
    public var associatedData: [UInt8] { state.ad }

    /// Le mode d'établissement.
    public var mode: Mode4 { state.mode }

    /// Vrai si l'autre côté a répondu (l'initiateur envoie des 0x01
    /// jusque-là).
    public var isConfirmed: Bool { state.confirmed }

    /// IK X25519 du correspondant (absent en clé partagée) : l'appli vérifie
    /// que c'est celle d'un contact.
    public var peerIdentity: [UInt8]? { state.peerIdentity }

    /// Le nombre de clés sautées gardées.
    public var skippedCount: Int { state.skipped.count }

    /// La clé publique de cliquet X25519 courante (vecteurs).
    public var ratchetPublic: [UInt8] { state.dhsPublic }

    /// La clé racine courante (vecteurs : un secret !).
    public var debugRootKey: [UInt8] { state.rk }

    /// Les clés d'en-tête courantes `(HKs, HKr, NHKs, NHKr)` — vecteurs.
    public var debugHeaderKeys: (hks: [UInt8]?, hkr: [UInt8]?, nhks: [UInt8], nhkr: [UInt8]) {
        (state.hks, state.hkr, state.nhks, state.nhkr)
    }

    /// La clé de chaîne d'envoi courante — vecteurs.
    public var debugSendingChain: [UInt8]? { state.cks }

    /// L'état en JSON (même forme que `Session4::to_json`).
    public func toJson() -> String {
        Json.encode(state)
    }

    /// Relit un état JSON (celui de `toJson` ou de la référence) et vérifie
    /// sa cohérence.
    public static func fromJson(_ text: String) throws -> Session4 {
        let s = try Json.decode(Session4State.self, text)
        let adOk = s.ad.count == 64 && Kdf.sessionId(s.ad) == s.sessionId
        let kemOk = s.kem.map { $0.ek.count == Paquet.pqpkLength } ?? true
        let peerOk = s.peerEk.map { $0.count == Paquet.pqpkLength } ?? true
        let ctOk = s.sendCt.map { $0.count == JetonV4.kemCtLength } ?? true
        guard s.v == 4, adOk, kemOk, peerOk, ctOk, s.skipped.count <= Int(Protocole.maxSkip),
              Kdf.x25519Public(s.dhsSecret) == s.dhsPublic
        else { throw Erreur.etat }
        return Session4(state: s)
    }
}

extension Device {
    /// Ouvre une session v4 vers un paquet (`Session4.initiate`).
    public func initiate4(bundle: KeyBundle, rng: some CryptoRng) throws -> Session4 {
        try Session4.initiate(identity: identitySecret, bundle: bundle, rng: rng)
    }

    /// Accepte le premier message (0x01) d'une session v4 : essaie chaque
    /// SPK et PQPK gardée jusqu'à ouvrir le préambule (IK_A), puis établit
    /// la session et déchiffre. Aucune ne l'ouvre : `.cleInconnue`. Une EK
    /// déjà vue : `.rejoue`. L'appelant vérifie ensuite que
    /// `Session4.peerIdentity` est celle d'un contact.
    public func accept4(_ token: Token4, now: UInt64, rng: some CryptoRng) throws -> (Session4, Content) {
        try accept4(token, now: now, rng: rng, encapsuler: Session4.encapsulerSysteme)
    }

    func accept4(
        _ token: Token4, now: UInt64, rng: some CryptoRng, encapsuler: @escaping Encapsulateur4
    ) throws -> (Session4, Content) {
        guard case .initial(let p, let body) = token else { throw Erreur.format }
        guard p.ephemeral.count == 32, p.sealedIdentity.count == JetonV4.preambleLength,
              body.headerNonce.count == JetonV4.headerNonceLength
        else { throw Erreur.format }
        guard Kdf.x25519IsCanonical(p.ephemeral) else { throw Erreur.cleInvalide }
        if state.replay.seen(p.ephemeral) { throw Erreur.rejoue }
        let aad = p.aad()
        var found: (spk: [UInt8], ss: [UInt8], dh3: [UInt8], ik: [UInt8])? = nil
        search: for spk in spkSecrets() {
            var dh3 = try Kdf.x25519(spk, p.ephemeral)
            defer { effacer(&dh3) }
            for seed in pqSeeds() {
                var ss = try MlKem.decapsulate(seed: seed, ciphertext: p.kemCiphertext)
                defer { effacer(&ss) }
                let pre = Kdf.preambleKey4(dh3, ss)
                var k = pre.key
                defer { effacer(&k) }
                if let ik = try? Kdf.aesGcmOpen(key: k, nonce: pre.nonce, aad: aad, ciphertext: p.sealedIdentity) {
                    guard ik.count == 32 else { throw Erreur.format }
                    // Les `defer` de la boucle effacent une copie (copie à
                    // l'écriture) : `found` garde les valeurs.
                    found = (spk, ss, dh3, ik)
                    break search
                }
            }
        }
        guard var f = found else { throw Erreur.cleInconnue }
        defer {
            effacer(&f.spk)
            effacer(&f.ss)
            effacer(&f.dh3)
        }
        let own = state.identity
        var dh1 = try Kdf.x25519(f.spk, f.ik)
        defer { effacer(&dh1) }
        var dh2 = try Kdf.x25519(own.dh, p.ephemeral)
        defer { effacer(&dh2) }
        var sk = Kdf.sk4(dh1: dh1, dh2: dh2, dh3: f.dh3, ss: f.ss)
        defer { effacer(&sk) }
        let ad = f.ik + Kdf.x25519Public(own.dh)
        let s = Session4.newResponder(
            mode: .bundle, sk: sk, ad: ad, ratchetSecret: f.spk, initialEphemeral: p.ephemeral, peerIdentity: f.ik)
        s.encapsuler = encapsuler
        let content = try s.decrypt(token, now: now, rng: rng)
        state.replay.insert(p.ephemeral, now: now)
        return (s, content)
    }
}
