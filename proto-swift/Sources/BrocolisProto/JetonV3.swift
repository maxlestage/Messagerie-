// Le jeton v3 (§4.4) : `[[BROCOLIS:v3:<base64>]]`, encodage et décodage
// **stricts** (toute longueur, tout octet de type ou de mode inattendu, tout
// champ réservé non nul est refusé ; aucun arrêt) — `brocolis_proto::jeton_v3`.
//
//     octet 0 : type
//       0x01 premier message   : id session (8) ‖ IK_A (32) ‖ EK_A (32) ‖ mode (1)
//                                ‖ [CT ML-KEM (1 088) si mode = 0x01]
//                                ‖ id SPK (u32 BE) ‖ id PQPK (u32 BE)
//                                ‖ en-tête (40) ‖ chiffré
//       0x02 message           : id session (8) ‖ en-tête (40) ‖ chiffré
//       0x03 distribution      : id session (8) ‖ en-tête (40) ‖ chiffré
//       0x04 message de groupe : id groupe (16) ‖ id expéditeur (8)
//                                ‖ itération (u32 BE) ‖ chiffré ‖ signature (64)
//     en-tête = DH_pub (32) ‖ PN (u32 BE) ‖ N (u32 BE)
//     chiffré = AES-256-GCM(remplissage §3.3) ‖ tag : 160·k + 16 octets, k ≥ 1
//
// `mode` : `0x00` X25519 seul, `0x01` X25519 + ML-KEM-768, `0x02` clé
// partagée (alors IK_A, id SPK et id PQPK sont nuls). En mode `0x00`, id PQPK
// est nul.

public enum JetonV3 {
    /// Le début d'un jeton v3.
    public static let head = "[[BROCOLIS:v3:"
    static let headBytes = Array(head.utf8)
    static let end = Array("]]".utf8)

    /// Type 0x01 : premier message, qui établit la session.
    public static let typeInitial: UInt8 = 0x01
    /// Type 0x02 : message d'une session établie.
    public static let typeMessage: UInt8 = 0x02
    /// Type 0x03 : distribution d'une chaîne de groupe.
    public static let typeDistribution: UInt8 = 0x03
    /// Type 0x04 : message de groupe signé.
    public static let typeGroup: UInt8 = 0x04

    /// La longueur d'un chiffré ML-KEM-768.
    public static let kemCtLength = 1_088
    /// La longueur d'un en-tête de ratchet.
    public static let headerLength = 40
    /// La taille maximale d'un jeton v3 décodé : 256 Kio.
    public static let maxTokenBytes = 256 * 1024

    /// Les jetons v3 d'un texte collé, dans l'ordre (chaque
    /// `[[BROCOLIS:v3:…]]` complet), décodés ou non.
    public static func findAll(_ text: String) -> [(text: String, token: Result<Token, Erreur>)] {
        let bytes = Array(text.utf8)
        var out: [(text: String, token: Result<Token, Erreur>)] = []
        var rest = 0
        while let start = Octets.find(bytes, headBytes, from: rest) {
            guard let e = Octets.find(bytes, end, from: start) else { break }
            let token = Octets.string(bytes[start..<(e + end.count)])
            out.append((token, Result { try Token.decode(token) }.mapError { $0 as? Erreur ?? .format }))
            rest = e + end.count
        }
        return out
    }
}

/// Le mode d'établissement d'une session (`"Classic"`, `"Hybrid"`, `"Psk"`
/// dans le JSON, comme serde).
public enum Mode: String, Codable, Sendable {
    /// X25519 seul (`pq = 0`) : « session non post-quantique ».
    case classic = "Classic"
    /// X25519 + ML-KEM-768 (`pq = 1`).
    case hybrid = "Hybrid"
    /// Clé Brocolis partagée (extension, octet `0x02`).
    case psk = "Psk"

    /// L'octet du mode.
    public var byte: UInt8 {
        switch self {
        case .classic: 0x00
        case .hybrid: 0x01
        case .psk: 0x02
        }
    }

    static func from(byte b: UInt8) throws -> Mode {
        switch b {
        case 0x00: return .classic
        case 0x01: return .hybrid
        case 0x02: return .psk
        default: throw Erreur.format
        }
    }
}

/// L'en-tête d'un message du Double Ratchet.
public struct Header: Equatable, Sendable {
    /// La clé publique de cliquet de l'expéditeur (32 octets).
    public var dh: [UInt8]
    /// La longueur de sa chaîne d'envoi précédente.
    public var pn: UInt32
    /// Le numéro du message dans sa chaîne d'envoi.
    public var n: UInt32

    public init(dh: [UInt8], pn: UInt32, n: UInt32) {
        self.dh = dh
        self.pn = pn
        self.n = n
    }

    /// Les 40 octets de l'en-tête.
    public func toBytes() -> [UInt8] {
        dh + Octets.u32be(pn) + Octets.u32be(n)
    }

    static func parse(_ r: inout Reader) throws -> Header {
        Header(dh: try r.take(32), pn: try r.u32(), n: try r.u32())
    }
}

/// Un message chiffré par le ratchet d'une session (types 0x02 et 0x03, et
/// la fin d'un 0x01).
public struct Envelope: Equatable, Sendable {
    /// L'identifiant de session : `SHA-256(AD)[0..8]`.
    public var sessionId: [UInt8]
    /// L'en-tête du ratchet.
    public var header: Header
    /// Le chiffré AES-256-GCM ‖ tag.
    public var ciphertext: [UInt8]

    public init(sessionId: [UInt8], header: Header, ciphertext: [UInt8]) {
        self.sessionId = sessionId
        self.header = header
        self.ciphertext = ciphertext
    }
}

/// Le premier message d'une session (type 0x01).
public struct Initial: Equatable, Sendable {
    /// La clé d'identité X25519 de l'initiateur (nulle en mode clé partagée).
    public var identity: [UInt8]
    /// La clé éphémère EK de l'initiateur.
    public var ephemeral: [UInt8]
    /// Le mode d'établissement.
    public var mode: Mode
    /// Le chiffré ML-KEM-768 (mode hybride seulement).
    public var kemCiphertext: [UInt8]?
    /// L'identifiant de la clé pré-signée du répondeur utilisée.
    public var spkId: UInt32
    /// L'identifiant de sa clé ML-KEM utilisée (0 sans ML-KEM).
    public var pqId: UInt32
    /// Le message lui-même.
    public var envelope: Envelope

    public init(
        identity: [UInt8], ephemeral: [UInt8], mode: Mode, kemCiphertext: [UInt8]?, spkId: UInt32, pqId: UInt32,
        envelope: Envelope
    ) {
        self.identity = identity
        self.ephemeral = ephemeral
        self.mode = mode
        self.kemCiphertext = kemCiphertext
        self.spkId = spkId
        self.pqId = pqId
        self.envelope = envelope
    }
}

/// Un message de groupe (type 0x04).
public struct GroupMessage: Equatable, Sendable {
    /// L'identifiant du groupe (16 octets).
    public var groupId: [UInt8]
    /// L'identifiant de l'expéditeur, de sa chaîne (8 octets).
    public var senderId: [UInt8]
    /// L'itération de la chaîne.
    public var iteration: UInt32
    /// Le chiffré AES-256-GCM ‖ tag.
    public var ciphertext: [UInt8]
    /// La signature Ed25519 de tout ce qui précède (type compris).
    public var signature: [UInt8]

    public init(groupId: [UInt8], senderId: [UInt8], iteration: UInt32, ciphertext: [UInt8], signature: [UInt8]) {
        self.groupId = groupId
        self.senderId = senderId
        self.iteration = iteration
        self.ciphertext = ciphertext
        self.signature = signature
    }

    /// Les 29 premiers octets : type ‖ id groupe ‖ id expéditeur ‖
    /// itération (les données associées du chiffrement).
    public func prefix() -> [UInt8] {
        [JetonV3.typeGroup] + groupId + senderId + Octets.u32be(iteration)
    }

    /// Ce que couvre la signature : préfixe ‖ chiffré.
    public func signedBytes() -> [UInt8] {
        prefix() + ciphertext
    }
}

/// Un jeton v3 décodé.
public enum Token: Equatable, Sendable {
    /// Type 0x01.
    case initial(Initial)
    /// Type 0x02.
    case message(Envelope)
    /// Type 0x03.
    case distribution(Envelope)
    /// Type 0x04.
    case group(GroupMessage)

    /// Vérifie la longueur d'un chiffré : 160·k + 16 octets, k ≥ 1.
    static func checkCiphertext(_ count: Int) throws {
        guard count >= Remplissage.bloc + 16, (count - 16) % Remplissage.bloc == 0 else { throw Erreur.format }
    }

    /// Décode les octets d'un jeton v3.
    public static func fromBytes(_ data: [UInt8]) throws -> Token {
        guard data.count <= JetonV3.maxTokenBytes else { throw Erreur.tropGrand }
        var r = Reader(data: data)
        let kind = try r.u8()
        switch kind {
        case JetonV3.typeInitial:
            let sessionId = try r.take(8)
            let identity = try r.take(32)
            let ephemeral = try r.take(32)
            let mode = try Mode.from(byte: r.u8())
            var kem: [UInt8]? = nil
            if mode == .hybrid { kem = try r.take(JetonV3.kemCtLength) }
            let spkId = try r.u32()
            let pqId = try r.u32()
            switch mode {
            case .classic where pqId != 0:
                throw Erreur.format
            case .psk where !Octets.isZero(identity) || spkId != 0 || pqId != 0:
                throw Erreur.format
            default:
                break
            }
            let header = try Header.parse(&r)
            let ciphertext = r.rest()
            try checkCiphertext(ciphertext.count)
            return .initial(Initial(
                identity: identity, ephemeral: ephemeral, mode: mode, kemCiphertext: kem, spkId: spkId, pqId: pqId,
                envelope: Envelope(sessionId: sessionId, header: header, ciphertext: ciphertext)))
        case JetonV3.typeMessage, JetonV3.typeDistribution:
            let sessionId = try r.take(8)
            let header = try Header.parse(&r)
            let ciphertext = r.rest()
            try checkCiphertext(ciphertext.count)
            let env = Envelope(sessionId: sessionId, header: header, ciphertext: ciphertext)
            return kind == JetonV3.typeMessage ? .message(env) : .distribution(env)
        case JetonV3.typeGroup:
            let groupId = try r.take(16)
            let senderId = try r.take(8)
            let iteration = try r.u32()
            let rest = r.rest()
            guard rest.count >= 64 else { throw Erreur.format }
            let ct = Array(rest[0..<(rest.count - 64)])
            try checkCiphertext(ct.count)
            return .group(GroupMessage(
                groupId: groupId, senderId: senderId, iteration: iteration, ciphertext: ct,
                signature: Array(rest[(rest.count - 64)...])))
        default:
            throw Erreur.format
        }
    }

    /// Les octets du jeton.
    public func toBytes() -> [UInt8] {
        var out = [UInt8]()
        switch self {
        case .initial(let i):
            out.append(JetonV3.typeInitial)
            out += i.envelope.sessionId
            out += i.identity
            out += i.ephemeral
            out.append(i.mode.byte)
            if let ct = i.kemCiphertext { out += ct }
            out += Octets.u32be(i.spkId)
            out += Octets.u32be(i.pqId)
            out += i.envelope.header.toBytes()
            out += i.envelope.ciphertext
        case .message(let e), .distribution(let e):
            if case .message = self { out.append(JetonV3.typeMessage) } else { out.append(JetonV3.typeDistribution) }
            out += e.sessionId
            out += e.header.toBytes()
            out += e.ciphertext
        case .group(let g):
            out += g.signedBytes()
            out += g.signature
        }
        return out
    }

    /// Décode un jeton `[[BROCOLIS:v3:<base64>]]`, exactement (sans espace
    /// autour ; voir `JetonV3.findAll` pour un texte collé).
    public static func decode(_ text: String) throws -> Token {
        let t = Array(text.utf8)
        guard t.count >= JetonV3.headBytes.count + JetonV3.end.count,
              Octets.hasPrefix(t, JetonV3.headBytes), Octets.hasSuffix(t, JetonV3.end)
        else { throw Erreur.jetonAbsent }
        let b = t[JetonV3.headBytes.count..<(t.count - JetonV3.end.count)]
        guard b.count <= 4 * ((JetonV3.maxTokenBytes + 2) / 3) else { throw Erreur.tropGrand }
        guard let data = Base64.decode(bytes: b) else { throw Erreur.base64 }
        return try fromBytes(data)
    }

    /// Le jeton `[[BROCOLIS:v3:<base64>]]`.
    public func encode() -> String {
        JetonV3.head + Base64.encode(toBytes()) + "]]"
    }

    /// L'identifiant de session (types 0x01 à 0x03).
    public var sessionId: [UInt8]? {
        switch self {
        case .initial(let i): i.envelope.sessionId
        case .message(let e), .distribution(let e): e.sessionId
        case .group: nil
        }
    }

    /// L'octet de type.
    public var type: UInt8 {
        switch self {
        case .initial: JetonV3.typeInitial
        case .message: JetonV3.typeMessage
        case .distribution: JetonV3.typeDistribution
        case .group: JetonV3.typeGroup
        }
    }
}

/// Un lecteur d'octets borné : toute lecture au-delà de la fin est
/// `.format`.
struct Reader {
    let data: [UInt8]
    var position = 0

    init(data: [UInt8]) {
        self.data = data
    }

    mutating func take(_ n: Int) throws -> [UInt8] {
        guard data.count - position >= n else { throw Erreur.format }
        defer { position += n }
        return Array(data[position..<(position + n)])
    }

    mutating func u8() throws -> UInt8 {
        try take(1)[0]
    }

    mutating func u32() throws -> UInt32 {
        Octets.readU32(try take(4), 0)
    }

    mutating func rest() -> [UInt8] {
        defer { position = data.count }
        return Array(data[position...])
    }
}
