// Les groupes : Sender Keys (§4.5, §7.6, §7.7), le modèle de Signal —
// `brocolis_proto::groupe`.
//
// Chaque membre tire une **chaîne d'envoi** (clé de chaîne 32 octets + clé
// de signature Ed25519) et la distribue à chaque membre par sa session v3 à
// deux (jeton de type 0x03, `Session.encryptDistribution`). Ses messages de
// groupe (type 0x04) :
//
//     0x04 ‖ id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)
//
// - la chaîne avance par `KDF_CK` ; la clé du message d'itération `i` est
//   `mk_i`, chiffrée comme au §4.3 (`ENCRYPT(mk)`, remplissage §3.3) ;
// - données associées AES-GCM : les 29 premiers octets ;
// - signature Ed25519 (stricte) de tout ce qui précède (type compris),
//   vérifiée **avant** toute autre chose ;
// - id expéditeur = `SHA-256(clé publique de signature)[0..8]`.
//
// Distribution (92 octets, puis remplissage §3.3) :
//
//     id groupe (16) ‖ id expéditeur (8) ‖ itération (u32 BE) ‖ clé de chaîne (32) ‖ clé publique Ed25519 (32)

public enum Groupe {
    /// La longueur d'une distribution (avant remplissage).
    public static let distributionLength = 92

    /// Un identifiant de groupe aléatoire (16 octets).
    public static func newGroupId(rng: some CryptoRng) -> [UInt8] {
        rng.bytes(16)
    }

    /// L'identifiant d'expéditeur d'une chaîne : `SHA-256(clé publique)[0..8]`.
    public static func senderIdOf(_ signingPublic: [UInt8]) -> [UInt8] {
        Array(Kdf.sha256(signingPublic)[0..<8])
    }
}

/// Une chaîne de groupe telle qu'on la distribue.
public struct SenderKeyDistribution: Equatable, Sendable {
    /// L'identifiant du groupe (16 octets).
    public var groupId: [UInt8]
    /// L'identifiant de l'expéditeur (8 octets).
    public var senderId: [UInt8]
    /// L'itération de la clé de chaîne.
    public var iteration: UInt32
    /// La clé de chaîne à cette itération (secrète).
    public var chainKey: [UInt8]
    /// La clé publique Ed25519 de la chaîne.
    public var signingPublic: [UInt8]

    public init(groupId: [UInt8], senderId: [UInt8], iteration: UInt32, chainKey: [UInt8], signingPublic: [UInt8]) {
        self.groupId = groupId
        self.senderId = senderId
        self.iteration = iteration
        self.chainKey = chainKey
        self.signingPublic = signingPublic
    }

    /// Les 92 octets.
    public func toBytes() -> [UInt8] {
        groupId + senderId + Octets.u32be(iteration) + chainKey + signingPublic
    }

    /// Lit 92 octets ; vérifie l'identifiant d'expéditeur et la clé
    /// publique.
    public static func fromBytes(_ b: [UInt8]) throws -> SenderKeyDistribution {
        guard b.count == Groupe.distributionLength else { throw Erreur.format }
        let d = SenderKeyDistribution(
            groupId: Array(b[0..<16]), senderId: Array(b[16..<24]), iteration: Octets.readU32(b, 24),
            chainKey: Array(b[28..<60]), signingPublic: Array(b[60..<92]))
        try d.check()
        return d
    }

    func check() throws {
        guard groupId.count == 16, senderId.count == 8, chainKey.count == 32, signingPublic.count == 32 else {
            throw Erreur.format
        }
        guard Groupe.senderIdOf(signingPublic) == senderId else { throw Erreur.format }
        guard Kdf.ed25519IsValidPublic(signingPublic) else { throw Erreur.cleInvalide }
    }
}

struct SenderKeyStateData: Codable {
    var v: UInt8
    var groupId: [UInt8]
    var chainKey: [UInt8]
    var iteration: UInt32
    var signingSeed: [UInt8]

    enum CodingKeys: String, CodingKey {
        case v
        case groupId = "group_id"
        case chainKey = "chain_key"
        case iteration
        case signingSeed = "signing_seed"
    }

    init(v: UInt8, groupId: [UInt8], chainKey: [UInt8], iteration: UInt32, signingSeed: [UInt8]) {
        self.v = v
        self.groupId = groupId
        self.chainKey = chainKey
        self.iteration = iteration
        self.signingSeed = signingSeed
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(UInt8.self, forKey: .v)
        groupId = try c.bytes(.groupId, length: 16)
        chainKey = try c.bytes(.chainKey, length: 32)
        iteration = try c.decode(UInt32.self, forKey: .iteration)
        signingSeed = try c.bytes(.signingSeed, length: 32)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(v, forKey: .v)
        try c.encodeBytes(groupId, forKey: .groupId)
        try c.encodeBytes(chainKey, forKey: .chainKey)
        try c.encode(iteration, forKey: .iteration)
        try c.encodeBytes(signingSeed, forKey: .signingSeed)
    }
}

/// Sa propre chaîne d'envoi dans un groupe.
public final class SenderKeyState {
    var data: SenderKeyStateData

    init(data: SenderKeyStateData) {
        self.data = data
    }

    deinit {
        effacer(&data.chainKey)
        effacer(&data.signingSeed)
    }

    /// Une chaîne neuve. Ordre de tirage : clé de chaîne (32), graine
    /// Ed25519 (32).
    public static func generate(groupId: [UInt8], rng: some CryptoRng) throws -> SenderKeyState {
        var chainKey = rng.bytes(32)
        defer { effacer(&chainKey) }
        var seed = rng.bytes(32)
        defer { effacer(&seed) }
        return try generateWith(groupId: groupId, chainKey: chainKey, signingSeed: seed)
    }

    /// Une chaîne à partir des secrets donnés (les vecteurs).
    public static func generateWith(groupId: [UInt8], chainKey: [UInt8], signingSeed: [UInt8]) throws -> SenderKeyState {
        guard groupId.count == 16, chainKey.count == 32, signingSeed.count == 32 else { throw Erreur.format }
        return SenderKeyState(data: SenderKeyStateData(
            v: 1, groupId: groupId, chainKey: chainKey, iteration: 0, signingSeed: signingSeed))
    }

    /// La clé publique Ed25519 de la chaîne.
    public var signingPublic: [UInt8] { Kdf.ed25519Public(seed: data.signingSeed) }

    /// L'identifiant d'expéditeur.
    public var senderId: [UInt8] { Groupe.senderIdOf(signingPublic) }

    /// L'identifiant du groupe.
    public var groupId: [UInt8] { data.groupId }

    /// L'itération courante (celle du prochain message).
    public var iteration: UInt32 { data.iteration }

    /// La distribution de la chaîne à son itération courante.
    public func distribution() -> SenderKeyDistribution {
        let pub = signingPublic
        return SenderKeyDistribution(
            groupId: data.groupId, senderId: Groupe.senderIdOf(pub), iteration: data.iteration,
            chainKey: data.chainKey, signingPublic: pub)
    }

    /// Chiffre et signe un message de groupe (jeton décodé).
    public func encryptToken(_ text: String) throws -> Token {
        let plain = Array(text.utf8)
        guard plain.count <= Session.maxPlaintext else { throw Erreur.tropGrand }
        let (nextIteration, overflow) = data.iteration.addingReportingOverflow(1)
        guard !overflow else { throw Erreur.epuise }
        let (next, mk0) = Kdf.kdfCk(data.chainKey)
        var mk = mk0
        defer { effacer(&mk) }
        var (key, nonce) = Kdf.messageKey(mk)
        defer { effacer(&key) }
        var msg = GroupMessage(
            groupId: data.groupId, senderId: senderId, iteration: data.iteration, ciphertext: [],
            signature: [UInt8](repeating: 0, count: 64))
        var padded = Remplissage.pad(plain)
        defer { effacer(&padded) }
        msg.ciphertext = try Kdf.aesGcmSeal(key: key, nonce: nonce, aad: msg.prefix(), message: padded)
        msg.signature = Kdf.ed25519Sign(seed: data.signingSeed, message: msg.signedBytes())
        effacer(&data.chainKey)
        data.chainKey = next
        data.iteration = nextIteration
        return .group(msg)
    }

    /// Chiffre et signe un message de groupe : `[[BROCOLIS:v3:…]]`.
    public func encrypt(_ text: String) throws -> String {
        try encryptToken(text).encode()
    }

    /// L'état en JSON (même forme que `SenderKeyState::to_json`).
    public func toJson() -> String {
        Json.encode(data)
    }

    /// Relit un état JSON.
    public static func fromJson(_ text: String) throws -> SenderKeyState {
        let d = try Json.decode(SenderKeyStateData.self, text)
        guard d.v == 1 else { throw Erreur.etat }
        return SenderKeyState(data: d)
    }
}

struct GroupSkippedKey: Codable {
    var iteration: UInt32
    var mk: [UInt8]
    var storedAt: UInt64

    enum CodingKeys: String, CodingKey {
        case iteration, mk
        case storedAt = "stored_at"
    }

    init(iteration: UInt32, mk: [UInt8], storedAt: UInt64) {
        self.iteration = iteration
        self.mk = mk
        self.storedAt = storedAt
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        iteration = try c.decode(UInt32.self, forKey: .iteration)
        mk = try c.bytes(.mk, length: 32)
        storedAt = try c.decode(UInt64.self, forKey: .storedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(iteration, forKey: .iteration)
        try c.encodeBytes(mk, forKey: .mk)
        try c.encode(storedAt, forKey: .storedAt)
    }
}

struct ReceivedSenderKeyData: Codable {
    var v: UInt8
    var groupId: [UInt8]
    var senderId: [UInt8]
    var chainKey: [UInt8]
    var iteration: UInt32
    var signingPublic: [UInt8]
    var skipped: [GroupSkippedKey]

    enum CodingKeys: String, CodingKey {
        case v
        case groupId = "group_id"
        case senderId = "sender_id"
        case chainKey = "chain_key"
        case iteration
        case signingPublic = "signing_public"
        case skipped
    }

    init(
        v: UInt8, groupId: [UInt8], senderId: [UInt8], chainKey: [UInt8], iteration: UInt32,
        signingPublic: [UInt8], skipped: [GroupSkippedKey]
    ) {
        self.v = v
        self.groupId = groupId
        self.senderId = senderId
        self.chainKey = chainKey
        self.iteration = iteration
        self.signingPublic = signingPublic
        self.skipped = skipped
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decode(UInt8.self, forKey: .v)
        groupId = try c.bytes(.groupId, length: 16)
        senderId = try c.bytes(.senderId, length: 8)
        chainKey = try c.bytes(.chainKey, length: 32)
        iteration = try c.decode(UInt32.self, forKey: .iteration)
        signingPublic = try c.bytes(.signingPublic, length: 32)
        skipped = try c.decode([GroupSkippedKey].self, forKey: .skipped)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(v, forKey: .v)
        try c.encodeBytes(groupId, forKey: .groupId)
        try c.encodeBytes(senderId, forKey: .senderId)
        try c.encodeBytes(chainKey, forKey: .chainKey)
        try c.encode(iteration, forKey: .iteration)
        try c.encodeBytes(signingPublic, forKey: .signingPublic)
        try c.encode(skipped, forKey: .skipped)
    }
}

/// La chaîne d'un autre membre, reçue par une distribution.
public final class ReceivedSenderKey {
    var data: ReceivedSenderKeyData

    init(data: ReceivedSenderKeyData) {
        self.data = data
    }

    deinit {
        effacer(&data.chainKey)
        for i in data.skipped.indices { effacer(&data.skipped[i].mk) }
    }

    /// La chaîne d'une distribution (vérifiée).
    public static func fromDistribution(_ d: SenderKeyDistribution) throws -> ReceivedSenderKey {
        try d.check()
        return ReceivedSenderKey(data: ReceivedSenderKeyData(
            v: 1, groupId: d.groupId, senderId: d.senderId, chainKey: d.chainKey, iteration: d.iteration,
            signingPublic: d.signingPublic, skipped: []))
    }

    /// L'identifiant du groupe.
    public var groupId: [UInt8] { data.groupId }

    /// L'identifiant d'expéditeur.
    public var senderId: [UInt8] { data.senderId }

    /// Vrai si ce message de groupe est de cette chaîne.
    public func matches(_ msg: GroupMessage) -> Bool {
        msg.groupId == data.groupId && msg.senderId == data.senderId
    }

    /// Le nombre de clés sautées gardées.
    public var skippedCount: Int { data.skipped.count }

    /// Vérifie la signature puis déchiffre. Transactionnel ; un message
    /// déjà lu donne `.rejoue`.
    public func decrypt(_ msg: GroupMessage, now: UInt64) throws -> String {
        guard matches(msg) else { throw Erreur.expediteurInconnu }
        try Kdf.ed25519Verify(publicKey: data.signingPublic, message: msg.signedBytes(), signature: msg.signature)
        var next = data
        next.skipped.removeAll { satAdd($0.storedAt, Protocole.maxSkipAge) <= now }
        var mk = [UInt8]()
        defer { effacer(&mk) }
        if msg.iteration < next.iteration {
            guard let pos = next.skipped.firstIndex(where: { $0.iteration == msg.iteration }) else {
                throw Erreur.rejoue
            }
            mk = next.skipped[pos].mk
            next.skipped.remove(at: pos)
        } else {
            if UInt64(msg.iteration) - UInt64(next.iteration) > UInt64(Protocole.maxSkip) {
                throw Erreur.tropDeClesSautees
            }
            var ck = next.chainKey
            while next.iteration < msg.iteration {
                let (n, k) = Kdf.kdfCk(ck)
                next.skipped.append(GroupSkippedKey(iteration: next.iteration, mk: k, storedAt: now))
                effacer(&ck)
                ck = n
                next.iteration += 1
            }
            let (n, k) = Kdf.kdfCk(ck)
            effacer(&ck)
            next.chainKey = n
            let (it, overflow) = next.iteration.addingReportingOverflow(1)
            guard !overflow else { throw Erreur.epuise }
            next.iteration = it
            let max = Int(Protocole.maxSkip)
            if next.skipped.count > max {
                next.skipped.removeFirst(next.skipped.count - max)
            }
            mk = k
        }
        var (key, nonce) = Kdf.messageKey(mk)
        defer { effacer(&key) }
        var padded = try Kdf.aesGcmOpen(key: key, nonce: nonce, aad: msg.prefix(), ciphertext: msg.ciphertext)
        defer { effacer(&padded) }
        guard let text = Octets.utf8(try Remplissage.unpad(padded)) else { throw Erreur.utf8 }
        data = next
        return text
    }

    /// L'état en JSON (même forme que `ReceivedSenderKey::to_json`).
    public func toJson() -> String {
        Json.encode(data)
    }

    /// Relit un état JSON.
    public static func fromJson(_ text: String) throws -> ReceivedSenderKey {
        let d = try Json.decode(ReceivedSenderKeyData.self, text)
        guard d.v == 1, d.skipped.count <= Int(Protocole.maxSkip), Groupe.senderIdOf(d.signingPublic) == d.senderId
        else { throw Erreur.etat }
        return ReceivedSenderKey(data: d)
    }
}
