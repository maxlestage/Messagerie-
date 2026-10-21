// L'appareil, ses clés et son paquet de clés publiques (§4.1, §7.3) —
// `brocolis_proto::paquet`.
//
// Chaque appareil a une identité (IK : X25519 pour l'échange, Ed25519 pour
// signer), une clé pré-signée X25519 (SPK) et, s'il sait faire ML-KEM, une
// clé d'encapsulation ML-KEM-768 signée (PQPK), toutes deux renouvelées
// chaque semaine (les anciennes gardées un mois pour les messages en retard).
//
// Le paquet (format binaire v1) :
//
//     octet 0          : 0x01 (version du paquet)
//     octets 1–32      : IK X25519
//     octets 33–64     : IK Ed25519 (clé de vérification)
//     octets 65–68     : id SPK (u32 BE)
//     octets 69–100    : SPK (X25519)
//     octets 101–164   : signature Ed25519 de "Brocolis_v3_SPK" ‖ IK X25519 ‖ id SPK ‖ SPK
//     octet 165        : 0x00 sans ML-KEM, 0x01 avec
//     si 0x01 :
//       octets 166–169   : id PQPK (u32 BE)
//       octets 170–1353  : PQPK (clé d'encapsulation ML-KEM-768, 1 184 octets)
//       octets 1354–1417 : signature Ed25519 de "Brocolis_v3_PQPK" ‖ IK X25519 ‖ id PQPK ‖ PQPK
//
// 166 octets sans ML-KEM, 1 418 avec.

public enum Paquet {
    /// La version du format binaire du paquet.
    public static let bundleVersion: UInt8 = 0x01
    /// La longueur d'une clé d'encapsulation ML-KEM-768.
    public static let pqpkLength = 1_184
    /// La longueur d'un paquet sans ML-KEM.
    public static let bundleLengthClassic = 166
    /// La longueur d'un paquet avec ML-KEM.
    public static let bundleLengthPq = 1_418
    /// Le contexte signé avec la SPK.
    public static let sigContextSpk = Array("Brocolis_v3_SPK".utf8)
    /// Le contexte signé avec la PQPK.
    public static let sigContextPqpk = Array("Brocolis_v3_PQPK".utf8)
    /// Le renouvellement des clés pré-signées : chaque semaine.
    public static let prekeyRotation: UInt64 = 7 * Protocole.jour
    /// Une clé pré-signée remplacée est gardée un mois (30 jours).
    public static let prekeyGrace: UInt64 = 30 * Protocole.jour

    static func spkSignedMessage(_ ik: [UInt8], _ id: UInt32, _ spk: [UInt8]) -> [UInt8] {
        sigContextSpk + ik + Octets.u32be(id) + spk
    }

    static func pqpkSignedMessage(_ ik: [UInt8], _ id: UInt32, _ pqpk: [UInt8]) -> [UInt8] {
        sigContextPqpk + ik + Octets.u32be(id) + pqpk
    }

    /// Le contexte signé de la capacité v4 (§9.6).
    public static let sigContextCaps4 = Array("Brocolis_v4_Caps".utf8)

    static func caps4Message(_ ik: [UInt8]) -> [UInt8] {
        sigContextCaps4 + ik + [0x04]
    }

    /// Vérifie la capacité v4 d'un correspondant (§9.6) : signature Ed25519
    /// **stricte** par son IK Ed25519 de `"Brocolis_v4_Caps" ‖ IK X25519 ‖
    /// 0x04`. Fausse : `.signature` ; clé faible : `.cleInvalide`.
    public static func verifyCaps4(identity: IdentityPublic, signature: [UInt8]) throws {
        guard identity.dh.count == 32 else { throw Erreur.format }
        try Kdf.ed25519Verify(publicKey: identity.sign, message: caps4Message(identity.dh), signature: signature)
    }
}

/// Ce que l'appareil doit garder secret de son identité.
public struct IdentitySecret: Codable, Sendable {
    /// Le secret X25519 (32 octets bruts).
    public internal(set) var dh: [UInt8]
    /// La graine Ed25519 (32 octets).
    public internal(set) var sign: [UInt8]

    /// Une identité à partir de ses deux secrets de 32 octets.
    public init(dh: [UInt8], sign: [UInt8]) throws {
        guard dh.count == 32, sign.count == 32 else { throw Erreur.format }
        self.dh = dh
        self.sign = sign
    }

    /// L'identité publique.
    public func publicKey() -> IdentityPublic {
        IdentityPublic(dh: Kdf.x25519Public(dh), sign: Kdf.ed25519Public(seed: sign))
    }

    enum CodingKeys: String, CodingKey { case dh, sign }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        dh = try c.bytes(.dh, length: 32)
        sign = try c.bytes(.sign, length: 32)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(dh, forKey: .dh)
        try c.encodeBytes(sign, forKey: .sign)
    }

    mutating func wipe() {
        effacer(&dh)
        effacer(&sign)
    }
}

/// L'identité publique d'un appareil : IK X25519 et IK Ed25519.
public struct IdentityPublic: Equatable, Hashable, Codable, Sendable {
    /// IK X25519.
    public var dh: [UInt8]
    /// IK Ed25519 (clé de vérification).
    public var sign: [UInt8]

    public init(dh: [UInt8], sign: [UInt8]) {
        self.dh = dh
        self.sign = sign
    }

    /// L'empreinte de l'identité, à comparer de vive voix :
    /// `SHA-256(IK X25519 ‖ IK Ed25519)[0..8]` en `XXXX-XXXX-XXXX-XXXX`.
    public func fingerprint() -> String {
        Kdf.fingerprint(dh + sign)
    }

    enum CodingKeys: String, CodingKey { case dh, sign }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        dh = try c.bytes(.dh, length: 32)
        sign = try c.bytes(.sign, length: 32)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encodeBytes(dh, forKey: .dh)
        try c.encodeBytes(sign, forKey: .sign)
    }
}

/// Une clé pré-signée X25519 (secrète).
public struct SignedPreKey: Codable, Sendable {
    /// Son identifiant.
    public internal(set) var id: UInt32
    /// Le secret X25519.
    public internal(set) var secret: [UInt8]
    /// Sa création (secondes Unix).
    public internal(set) var createdAt: UInt64
    /// Son remplacement (secondes Unix), si elle n'est plus la courante.
    public internal(set) var replacedAt: UInt64?

    init(id: UInt32, secret: [UInt8], createdAt: UInt64, replacedAt: UInt64?) {
        self.id = id
        self.secret = secret
        self.createdAt = createdAt
        self.replacedAt = replacedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, secret
        case createdAt = "created_at"
        case replacedAt = "replaced_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UInt32.self, forKey: .id)
        secret = try c.bytes(.secret, length: 32)
        createdAt = try c.decode(UInt64.self, forKey: .createdAt)
        replacedAt = try c.decodeIfPresent(UInt64.self, forKey: .replacedAt)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encodeBytes(secret, forKey: .secret)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encodeOptional(replacedAt, forKey: .replacedAt)
    }
}

/// Une clé ML-KEM-768 (secrète : sa graine FIPS 203 `d ‖ z`, 64 octets).
public struct PqPreKey: Codable, Sendable {
    /// Son identifiant.
    public internal(set) var id: UInt32
    /// La graine `d ‖ z`.
    public internal(set) var seed: [UInt8]
    /// Sa création (secondes Unix).
    public internal(set) var createdAt: UInt64
    /// Son remplacement (secondes Unix), si elle n'est plus la courante.
    public internal(set) var replacedAt: UInt64?

    init(id: UInt32, seed: [UInt8], createdAt: UInt64, replacedAt: UInt64?) {
        self.id = id
        self.seed = seed
        self.createdAt = createdAt
        self.replacedAt = replacedAt
    }

    enum CodingKeys: String, CodingKey {
        case id, seed
        case createdAt = "created_at"
        case replacedAt = "replaced_at"
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(UInt32.self, forKey: .id)
        seed = try c.bytes(.seed, length: 64)
        createdAt = try c.decode(UInt64.self, forKey: .createdAt)
        replacedAt = try c.decodeIfPresent(UInt64.self, forKey: .replacedAt)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encodeBytes(seed, forKey: .seed)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encodeOptional(replacedAt, forKey: .replacedAt)
    }
}

/// La partie ML-KEM d'un paquet.
public struct PqBundle: Equatable, Sendable {
    /// L'identifiant de la PQPK.
    public var id: UInt32
    /// La clé d'encapsulation ML-KEM-768 (1 184 octets).
    public var key: [UInt8]
    /// Sa signature par IK Ed25519.
    public var signature: [UInt8]

    public init(id: UInt32, key: [UInt8], signature: [UInt8]) {
        self.id = id
        self.key = key
        self.signature = signature
    }
}

/// Un paquet de clés publiques. `fromBytes` le vérifie entièrement.
public struct KeyBundle: Equatable, Sendable {
    /// L'identité.
    public var identity: IdentityPublic
    /// L'identifiant de la SPK.
    public var spkId: UInt32
    /// La SPK.
    public var spk: [UInt8]
    /// Sa signature par IK Ed25519.
    public var spkSignature: [UInt8]
    /// La PQPK, si l'appareil sait faire ML-KEM.
    public var pq: PqBundle?

    public init(identity: IdentityPublic, spkId: UInt32, spk: [UInt8], spkSignature: [UInt8], pq: PqBundle?) {
        self.identity = identity
        self.spkId = spkId
        self.spk = spk
        self.spkSignature = spkSignature
        self.pq = pq
    }

    /// Les octets du paquet (format v1).
    public func toBytes() -> [UInt8] {
        var out = [Paquet.bundleVersion]
        out += identity.dh
        out += identity.sign
        out += Octets.u32be(spkId)
        out += spk
        out += spkSignature
        if let pq {
            out.append(0x01)
            out += Octets.u32be(pq.id)
            out += pq.key
            out += pq.signature
        } else {
            out.append(0x00)
        }
        return out
    }

    /// Lit un paquet et **vérifie** tout : version, longueur exacte, clés
    /// (Ed25519 non faible, X25519 canonique non nulle, ML-KEM bien formée)
    /// et signatures (Ed25519 stricte).
    public static func fromBytes(_ data: [UInt8]) throws -> KeyBundle {
        guard data.count == Paquet.bundleLengthClassic || data.count == Paquet.bundleLengthPq else {
            throw Erreur.format
        }
        guard data[0] == Paquet.bundleVersion else { throw Erreur.format }
        let identity = IdentityPublic(dh: Array(data[1..<33]), sign: Array(data[33..<65]))
        let spkId = Octets.readU32(data, 65)
        let spk = Array(data[69..<101])
        let spkSignature = Array(data[101..<165])
        let pq: PqBundle?
        switch (data[165], data.count) {
        case (0x00, Paquet.bundleLengthClassic):
            pq = nil
        case (0x01, Paquet.bundleLengthPq):
            pq = PqBundle(
                id: Octets.readU32(data, 166), key: Array(data[170..<(170 + Paquet.pqpkLength)]),
                signature: Array(data[1354..<1418]))
        default:
            throw Erreur.format
        }
        let bundle = KeyBundle(identity: identity, spkId: spkId, spk: spk, spkSignature: spkSignature, pq: pq)
        try bundle.verify()
        return bundle
    }

    /// Vérifie les clés et les signatures du paquet.
    public func verify() throws {
        guard identity.dh.count == 32, identity.sign.count == 32, spk.count == 32, spkSignature.count == 64 else {
            throw Erreur.format
        }
        for key in [identity.dh, spk] where !Kdf.x25519IsCanonical(key) || Octets.isZero(key) {
            throw Erreur.cleInvalide
        }
        try Kdf.ed25519Verify(
            publicKey: identity.sign, message: Paquet.spkSignedMessage(identity.dh, spkId, spk),
            signature: spkSignature)
        if let pq {
            guard pq.key.count == Paquet.pqpkLength, pq.id != 0 else { throw Erreur.format }
            try Kdf.ed25519Verify(
                publicKey: identity.sign, message: Paquet.pqpkSignedMessage(identity.dh, pq.id, pq.key),
                signature: pq.signature)
            // La clé doit être une clé ML-KEM valide (FIPS 203, contrôle du
            // module), même là où ML-KEM manque.
            guard MlKem.isValidPublicKey(pq.key) else { throw Erreur.cleInvalide }
        }
    }

    /// Le paquet en base64 standard.
    public func toBase64() -> String {
        Base64.encode(toBytes())
    }

    /// Lit (et vérifie) un paquet en base64 standard.
    public static func fromBase64(_ text: String) throws -> KeyBundle {
        guard text.utf8.count <= 2 * Paquet.bundleLengthPq else { throw Erreur.tropGrand }
        guard let data = Base64.decode(Jetons.trim(text)) else { throw Erreur.base64 }
        return try fromBytes(data)
    }
}

/// Les clés éphémères déjà vues dans un premier message (type 0x01) :
/// rejouer un premier message ne rouvre pas de session (§7.3). Bornée :
/// `ReplayGuard.max` entrées, `ReplayGuard.maxAge`.
public struct ReplayGuard: Codable, Sendable {
    struct SeenEphemeral: Codable, Sendable {
        var ek: [UInt8]
        var at: UInt64

        enum CodingKeys: String, CodingKey { case ek, at }

        init(ek: [UInt8], at: UInt64) {
            self.ek = ek
            self.at = at
        }

        init(from decoder: Decoder) throws {
            let c = try decoder.container(keyedBy: CodingKeys.self)
            ek = try c.bytes(.ek, length: 32)
            at = try c.decode(UInt64.self, forKey: .at)
        }

        func encode(to encoder: Encoder) throws {
            var c = encoder.container(keyedBy: CodingKeys.self)
            try c.encodeBytes(ek, forKey: .ek)
            try c.encode(at, forKey: .at)
        }
    }

    var seenList: [SeenEphemeral] = []

    /// Le nombre maximal de clés retenues (les plus anciennes partent).
    public static let max = 4_096
    /// L'âge maximal d'une entrée : la vie d'une clé pré-signée (7 + 30
    /// jours).
    public static let maxAge: UInt64 = Paquet.prekeyRotation + Paquet.prekeyGrace

    public init() {}

    /// Vrai si cette clé éphémère a déjà ouvert une session.
    public func seen(_ ek: [UInt8]) -> Bool {
        seenList.contains { $0.ek == ek }
    }

    /// Retient une clé éphémère.
    public mutating func insert(_ ek: [UInt8], now: UInt64) {
        purge(now: now)
        seenList.append(SeenEphemeral(ek: ek, at: now))
        if seenList.count > Self.max {
            seenList.removeFirst(seenList.count - Self.max)
        }
    }

    /// Oublie les entrées trop vieilles.
    public mutating func purge(now: UInt64) {
        seenList.removeAll { satAdd($0.at, Self.maxAge) <= now }
    }

    /// Le nombre d'entrées.
    public var count: Int { seenList.count }

    /// Vrai si aucune entrée.
    public var isEmpty: Bool { seenList.isEmpty }

    enum CodingKeys: String, CodingKey { case seen }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        seenList = try c.decode([SeenEphemeral].self, forKey: .seen)
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(seenList, forKey: .seen)
    }

    /// L'état en JSON (`{"seen":[{"ek":…,"at":…}]}`, comme serde).
    public func toJson() -> String { Json.encode(self) }

    /// Relit un état JSON.
    public static func fromJson(_ text: String) throws -> ReplayGuard { try Json.decode(ReplayGuard.self, text) }
}

/// L'état d'un appareil, tel qu'il est sérialisé (champs de serde).
struct DeviceState: Codable {
    var v: UInt8
    var identity: IdentitySecret
    var signedPrekeys: [SignedPreKey]
    var pqPrekeys: [PqPreKey]
    var replay: ReplayGuard

    enum CodingKeys: String, CodingKey {
        case v, identity
        case signedPrekeys = "signed_prekeys"
        case pqPrekeys = "pq_prekeys"
        case replay
    }

    init(v: UInt8, identity: IdentitySecret, signedPrekeys: [SignedPreKey], pqPrekeys: [PqPreKey], replay: ReplayGuard) {
        self.v = v
        self.identity = identity
        self.signedPrekeys = signedPrekeys
        self.pqPrekeys = pqPrekeys
        self.replay = replay
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(UInt8.self, forKey: .v)
        identity = try c.decode(IdentitySecret.self, forKey: .identity)
        signedPrekeys = try c.decode([SignedPreKey].self, forKey: .signedPrekeys)
        pqPrekeys = try c.decode([PqPreKey].self, forKey: .pqPrekeys)
        // `#[serde(default)]`.
        replay = try c.decodeIfPresent(ReplayGuard.self, forKey: .replay) ?? ReplayGuard()
    }

    mutating func wipe() {
        identity.wipe()
        for i in signedPrekeys.indices { effacer(&signedPrekeys[i].secret) }
        for i in pqPrekeys.indices { effacer(&pqPrekeys[i].seed) }
    }
}

/// Un appareil : son identité, ses clés pré-signées (la courante et celles
/// gardées pour les retardataires) et la mémoire des premiers messages.
/// Sérialisable (JSON) ; à garder chiffré par la clé matérielle (§3.1).
public final class Device {
    var state: DeviceState

    init(state: DeviceState) {
        self.state = state
    }

    deinit {
        state.wipe()
    }

    /// La version du format de l'état.
    public var v: UInt8 { state.v }

    static func nextId(_ rng: some CryptoRng, _ last: UInt32?) -> UInt32 {
        if let last { return Swift.max(last &+ 1, 1) }
        return Swift.max(rng.nextU32() >> 1, 1)
    }

    /// Un nouvel appareil : identité, SPK et, avec `pq` (et si ML-KEM est
    /// disponible ici : `MlKem.isAvailable`), PQPK.
    ///
    /// Ordre de tirage (vecteurs) : secret X25519 d'IK (32), graine Ed25519
    /// (32), puis comme `rotate`.
    public static func generate(rng: some CryptoRng, now: UInt64, pq: Bool) -> Device {
        let identity = try! IdentitySecret(dh: rng.bytes(32), sign: rng.bytes(32))
        return fromIdentity(identity, rng: rng, now: now, pq: pq)
    }

    /// Un appareil à partir d'une identité existante (nouvelles SPK et PQPK).
    public static func fromIdentity(_ identity: IdentitySecret, rng: some CryptoRng, now: UInt64, pq: Bool) -> Device {
        let d = Device(state: DeviceState(v: 1, identity: identity, signedPrekeys: [], pqPrekeys: [], replay: ReplayGuard()))
        d.addPrekeys(rng, now, pq && MlKem.isAvailable)
        return d
    }

    /// Un appareil à partir de secrets donnés (vecteurs, import) : identité,
    /// SPK (id, secret de 32 octets) et, optionnellement, PQPK (id, graine
    /// `d ‖ z` de 64 octets).
    public static func fromSecrets(
        identity: IdentitySecret, spk: (id: UInt32, secret: [UInt8]), pq: (id: UInt32, seed: [UInt8])?, now: UInt64
    ) throws -> Device {
        guard spk.secret.count == 32, pq.map({ $0.seed.count == 64 }) ?? true else { throw Erreur.format }
        let spks = [SignedPreKey(id: spk.id, secret: spk.secret, createdAt: now, replacedAt: nil)]
        let pqs = pq.map { [PqPreKey(id: $0.id, seed: $0.seed, createdAt: now, replacedAt: nil)] } ?? []
        return Device(state: DeviceState(v: 1, identity: identity, signedPrekeys: spks, pqPrekeys: pqs, replay: ReplayGuard()))
    }

    func addPrekeys(_ rng: some CryptoRng, _ now: UInt64, _ pq: Bool) {
        let spkId = Self.nextId(rng, state.signedPrekeys.last?.id)
        let secret = rng.bytes(32)
        for i in state.signedPrekeys.indices where state.signedPrekeys[i].replacedAt == nil {
            state.signedPrekeys[i].replacedAt = now
        }
        state.signedPrekeys.append(SignedPreKey(id: spkId, secret: secret, createdAt: now, replacedAt: nil))
        if pq {
            let pqId = Self.nextId(rng, state.pqPrekeys.last?.id)
            let seed = rng.bytes(64)
            for i in state.pqPrekeys.indices where state.pqPrekeys[i].replacedAt == nil {
                state.pqPrekeys[i].replacedAt = now
            }
            state.pqPrekeys.append(PqPreKey(id: pqId, seed: seed, createdAt: now, replacedAt: nil))
        }
    }

    /// Renouvelle la SPK (et la PQPK si l'appareil en a une) ; les
    /// anciennes restent utilisables `Paquet.prekeyGrace`, puis `purge` les
    /// efface.
    ///
    /// Ordre de tirage : id SPK (4 octets, seulement la première fois),
    /// secret SPK (32), id PQPK (4, la première fois), graine ML-KEM (64).
    public func rotate(rng: some CryptoRng, now: UInt64) {
        addPrekeys(rng, now, !state.pqPrekeys.isEmpty)
        purge(now: now)
    }

    /// Ajoute ML-KEM à un appareil qui n'en avait pas (iPhone passé à
    /// iOS 26, par exemple), en renouvelant la SPK. `.pqIndisponible` si
    /// ML-KEM manque encore ici.
    public func enablePq(rng: some CryptoRng, now: UInt64) throws {
        guard MlKem.isAvailable else { throw Erreur.pqIndisponible }
        addPrekeys(rng, now, true)
    }

    /// Vrai si la SPK courante a une semaine ou plus.
    public func needsRotation(now: UInt64) -> Bool {
        guard let k = state.signedPrekeys.last else { return true }
        return satAdd(k.createdAt, Paquet.prekeyRotation) <= now
    }

    /// Efface les clés remplacées depuis plus d'un mois et les vieilles
    /// entrées de la mémoire des premiers messages.
    public func purge(now: UInt64) {
        func keep(_ r: UInt64?) -> Bool {
            guard let r else { return true }
            return satAdd(r, Paquet.prekeyGrace) > now
        }
        for i in state.signedPrekeys.indices where !keep(state.signedPrekeys[i].replacedAt) {
            effacer(&state.signedPrekeys[i].secret)
        }
        for i in state.pqPrekeys.indices where !keep(state.pqPrekeys[i].replacedAt) {
            effacer(&state.pqPrekeys[i].seed)
        }
        state.signedPrekeys.removeAll { !keep($0.replacedAt) }
        state.pqPrekeys.removeAll { !keep($0.replacedAt) }
        state.replay.purge(now: now)
    }

    /// L'identité publique.
    public func identity() -> IdentityPublic {
        state.identity.publicKey()
    }

    /// L'identité secrète (pour l'établissement).
    public var identitySecret: IdentitySecret { state.identity }

    /// Vrai si l'appareil a une clé ML-KEM courante (et sait s'en servir
    /// ici).
    public var supportsPq: Bool {
        MlKem.isAvailable && state.pqPrekeys.contains { $0.replacedAt == nil }
    }

    /// Le paquet de clés publiques courant, signé. Sans ML-KEM disponible
    /// ici, le paquet ne propose pas de PQPK.
    public func bundle() throws -> KeyBundle {
        let ik = state.identity.publicKey()
        guard let spkKey = state.signedPrekeys.last(where: { $0.replacedAt == nil }) else { throw Erreur.etat }
        let spk = Kdf.x25519Public(spkKey.secret)
        let spkSignature = Kdf.ed25519Sign(
            seed: state.identity.sign, message: Paquet.spkSignedMessage(ik.dh, spkKey.id, spk))
        var pq: PqBundle? = nil
        if MlKem.isAvailable, let k = state.pqPrekeys.last(where: { $0.replacedAt == nil }) {
            let key = try MlKem.publicKey(seed: k.seed)
            let signature = Kdf.ed25519Sign(
                seed: state.identity.sign, message: Paquet.pqpkSignedMessage(ik.dh, k.id, key))
            pq = PqBundle(id: k.id, key: key, signature: signature)
        }
        return KeyBundle(identity: ik, spkId: spkKey.id, spk: spk, spkSignature: spkSignature, pq: pq)
    }

    func spkSecret(_ id: UInt32) throws -> [UInt8] {
        guard let k = state.signedPrekeys.first(where: { $0.id == id }) else { throw Erreur.cleInconnue }
        return k.secret
    }

    func pqSeed(_ id: UInt32) throws -> [UInt8] {
        guard let k = state.pqPrekeys.first(where: { $0.id == id }) else { throw Erreur.cleInconnue }
        return k.seed
    }

    /// Les secrets de toutes les SPK gardées (la plus récente d'abord) : un
    /// premier message v4 ne dit pas laquelle a servi (§9.4).
    func spkSecrets() -> [[UInt8]] {
        state.signedPrekeys.reversed().map { $0.secret }
    }

    /// Les graines ML-KEM de toutes les PQPK gardées (la plus récente
    /// d'abord).
    func pqSeeds() -> [[UInt8]] {
        state.pqPrekeys.reversed().map { $0.seed }
    }

    /// La capacité v4 signée (§9.6), 64 octets : `Ed25519(IK, "Brocolis_v4_Caps"
    /// ‖ IK X25519 ‖ 0x04)`, à publier avec le paquet. Seul un appareil qui a
    /// ML-KEM (ici et dans ses clés) la publie : sinon `nil`. CryptoKit peut
    /// rendre la signature aléatoire (toujours valide).
    public func caps4() -> [UInt8]? {
        guard supportsPq else { return nil }
        let ik = Kdf.x25519Public(state.identity.dh)
        return Kdf.ed25519Sign(seed: state.identity.sign, message: Paquet.caps4Message(ik))
    }

    /// La mémoire des premiers messages.
    public var replayGuard: ReplayGuard { state.replay }

    /// L'état en JSON (même forme que `Device::to_json`).
    public func toJson() -> String {
        Json.encode(state)
    }

    /// Relit un état JSON (celui de `toJson` ou de la référence Rust).
    public static func fromJson(_ text: String) throws -> Device {
        let s = try Json.decode(DeviceState.self, text)
        guard s.v == 1 else { throw Erreur.etat }
        return Device(state: s)
    }
}
