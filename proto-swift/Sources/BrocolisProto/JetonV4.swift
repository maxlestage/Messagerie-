// Le jeton v4 (§9.4) : `[[BROCOLIS:v4:<base64>]]`, encodage et décodage
// **stricts**, et l'en-tête de cliquet (§9.3), qui voyage chiffré —
// `brocolis_proto::jeton_v4`.
//
//     octet 0 : type
//       0x01 premier message : EK_A (32) ‖ CT ML-KEM (1 088) ‖ préambule chiffré (48)
//                              ‖ nonce d'en-tête (12) ‖ longueur (u16 BE) ‖ en-tête chiffré ‖ chiffré
//       0x02 message         : nonce d'en-tête (12) ‖ longueur (u16 BE) ‖ en-tête chiffré ‖ chiffré
//     en-tête (clair) = DH (32) ‖ PN (u32 BE) ‖ N (u32 BE) ‖ drapeaux (1) ‖ ek (1 184) ‖ [ct (1 088)]
//     en-tête chiffré : 1 241 ou 2 329 octets ; chiffré : 160·k + 16 octets, k ≥ 1
//
// Aucun identifiant n'est en clair : sans la clé d'en-tête, un 0x02 ne se
// distingue pas d'octets aléatoires de même longueur.

public enum JetonV4 {
    /// Le début d'un jeton v4.
    public static let head = "[[BROCOLIS:v4:"
    static let headBytes = Array(head.utf8)
    static let end = Array("]]".utf8)

    /// Type 0x01 : premier message d'une session établie par paquet.
    public static let typeInitial: UInt8 = 0x01
    /// Type 0x02 : tout autre message (premier message à clé partagée
    /// compris).
    public static let typeMessage: UInt8 = 0x02

    /// La longueur d'un chiffré ML-KEM-768.
    public static let kemCtLength = 1_088
    /// La longueur du préambule chiffré : IK_A (32) ‖ tag (16).
    public static let preambleLength = 48
    /// La longueur du nonce d'en-tête.
    public static let headerNonceLength = 12
    /// L'en-tête en clair, sans `ct` : DH, PN, N, drapeaux, ek.
    public static let headerLength = 32 + 4 + 4 + 1 + Paquet.pqpkLength
    /// L'en-tête en clair, avec `ct`.
    public static let headerLengthCt = headerLength + kemCtLength
    /// La taille maximale d'un jeton v4 décodé : 256 Kio.
    public static let maxTokenBytes = 256 * 1024

    /// Le genre de ce que porte un message (premier octet du clair, §9.3) :
    /// un texte.
    public static let genreTexte: UInt8 = 0x00
    /// Une distribution de chaîne de groupe (§4.5).
    public static let genreDistribution: UInt8 = 0x01

    /// Les jetons v4 d'un texte collé, dans l'ordre (chaque
    /// `[[BROCOLIS:v4:…]]` complet), décodés ou non.
    public static func findAll(_ text: String) -> [(text: String, token: Result<Token4, Erreur>)] {
        let bytes = Array(text.utf8)
        var out: [(text: String, token: Result<Token4, Erreur>)] = []
        var rest = 0
        while let start = Octets.find(bytes, headBytes, from: rest) {
            guard let e = Octets.find(bytes, end, from: start) else { break }
            let token = Octets.string(bytes[start..<(e + end.count)])
            out.append((token, Result { try Token4.decode(token) }.mapError { $0 as? Erreur ?? .format }))
            rest = e + end.count
        }
        return out
    }
}

/// L'en-tête du cliquet v4, en clair.
public struct Header4: Equatable, Sendable {
    /// La clé publique de cliquet X25519 de l'expéditeur (32 octets).
    public var dh: [UInt8]
    /// La longueur de sa chaîne d'envoi précédente.
    public var pn: UInt32
    /// Le numéro du message dans sa chaîne.
    public var n: UInt32
    /// Sa clé d'encapsulation ML-KEM-768 de cliquet courante (1 184 octets).
    public var ek: [UInt8]
    /// L'encapsulation qui a ouvert cette chaîne (absente de la première
    /// chaîne de l'initiateur).
    public var ct: [UInt8]?

    public init(dh: [UInt8], pn: UInt32, n: UInt32, ek: [UInt8], ct: [UInt8]?) {
        self.dh = dh
        self.pn = pn
        self.n = n
        self.ek = ek
        self.ct = ct
    }

    /// Les octets de l'en-tête en clair.
    public func toBytes() -> [UInt8] {
        var out = [UInt8]()
        out.reserveCapacity(JetonV4.headerLengthCt)
        out += dh
        out += Octets.u32be(pn)
        out += Octets.u32be(n)
        out.append(ct == nil ? 0x00 : 0x01)
        out += ek
        if let ct { out += ct }
        return out
    }

    /// Relit un en-tête en clair (strict : longueur, drapeaux).
    public static func fromBytes(_ b: [UInt8]) throws -> Header4 {
        var r = Reader(data: b)
        let dh = try r.take(32)
        let pn = try r.u32()
        let n = try r.u32()
        let flags = try r.u8()
        let ek = try r.take(Paquet.pqpkLength)
        let ct: [UInt8]?
        switch flags {
        case 0x00: ct = nil
        case 0x01: ct = try r.take(JetonV4.kemCtLength)
        default: throw Erreur.format
        }
        guard r.position == r.data.count else { throw Erreur.format }
        return Header4(dh: dh, pn: pn, n: n, ek: ek, ct: ct)
    }
}

/// La partie chiffrée commune à tous les messages v4.
public struct Body4: Equatable, Sendable {
    /// Le nonce de l'en-tête (12 octets, dérivé de la clé de message, §9.1).
    public var headerNonce: [UInt8]
    /// L'en-tête chiffré (AES-256-GCM ‖ tag).
    public var header: [UInt8]
    /// Le chiffré du message (AES-256-GCM ‖ tag).
    public var ciphertext: [UInt8]

    public init(headerNonce: [UInt8], header: [UInt8], ciphertext: [UInt8]) {
        self.headerNonce = headerNonce
        self.header = header
        self.ciphertext = ciphertext
    }

    static func parse(_ r: inout Reader) throws -> Body4 {
        let headerNonce = try r.take(JetonV4.headerNonceLength)
        let len = Int(try r.u16())
        guard len == JetonV4.headerLength + 16 || len == JetonV4.headerLengthCt + 16 else { throw Erreur.format }
        let header = try r.take(len)
        let ciphertext = r.rest()
        try Token.checkCiphertext(ciphertext.count)
        return Body4(headerNonce: headerNonce, header: header, ciphertext: ciphertext)
    }

    func write(_ out: inout [UInt8]) {
        out += headerNonce
        // La longueur est l'une des deux valeurs permises (< 65 536).
        let len = UInt16(truncatingIfNeeded: header.count)
        out.append(UInt8(len >> 8))
        out.append(UInt8(len & 0xFF))
        out += header
        out += ciphertext
    }
}

/// Le préambule d'un premier message v4 (type 0x01).
public struct Preamble4: Equatable, Sendable {
    /// La clé éphémère EK_A (32 octets).
    public var ephemeral: [UInt8]
    /// L'encapsulation ML-KEM-768 vers la PQPK du répondeur (1 088 octets).
    public var kemCiphertext: [UInt8]
    /// IK_A chiffrée (48 octets, §9.4).
    public var sealedIdentity: [UInt8]

    public init(ephemeral: [UInt8], kemCiphertext: [UInt8], sealedIdentity: [UInt8]) {
        self.ephemeral = ephemeral
        self.kemCiphertext = kemCiphertext
        self.sealedIdentity = sealedIdentity
    }

    /// Les données associées du préambule chiffré : `0x01 ‖ EK_A ‖ CT`.
    public func aad() -> [UInt8] {
        [JetonV4.typeInitial] + ephemeral + kemCiphertext
    }
}

/// Un jeton v4 décodé.
public enum Token4: Equatable, Sendable {
    /// Type 0x01.
    case initial(Preamble4, Body4)
    /// Type 0x02.
    case message(Body4)

    /// L'octet de type.
    public var type: UInt8 {
        switch self {
        case .initial: JetonV4.typeInitial
        case .message: JetonV4.typeMessage
        }
    }

    /// La partie chiffrée.
    public var body: Body4 {
        switch self {
        case .initial(_, let b), .message(let b): b
        }
    }

    /// Décode les octets d'un jeton v4.
    public static func fromBytes(_ data: [UInt8]) throws -> Token4 {
        guard data.count <= JetonV4.maxTokenBytes else { throw Erreur.tropGrand }
        var r = Reader(data: data)
        switch try r.u8() {
        case JetonV4.typeInitial:
            let ephemeral = try r.take(32)
            let kemCiphertext = try r.take(JetonV4.kemCtLength)
            let sealedIdentity = try r.take(JetonV4.preambleLength)
            let body = try Body4.parse(&r)
            return .initial(
                Preamble4(ephemeral: ephemeral, kemCiphertext: kemCiphertext, sealedIdentity: sealedIdentity), body)
        case JetonV4.typeMessage:
            return .message(try Body4.parse(&r))
        default:
            throw Erreur.format
        }
    }

    /// Les octets du jeton.
    public func toBytes() -> [UInt8] {
        var out = [type]
        if case .initial(let p, _) = self {
            out += p.ephemeral
            out += p.kemCiphertext
            out += p.sealedIdentity
        }
        body.write(&out)
        return out
    }

    /// Décode un jeton `[[BROCOLIS:v4:<base64>]]`, exactement (sans espace
    /// autour ; voir `JetonV4.findAll` pour un texte collé).
    public static func decode(_ text: String) throws -> Token4 {
        let t = Array(text.utf8)
        guard t.count >= JetonV4.headBytes.count + JetonV4.end.count,
              Octets.hasPrefix(t, JetonV4.headBytes), Octets.hasSuffix(t, JetonV4.end)
        else { throw Erreur.jetonAbsent }
        let b = t[JetonV4.headBytes.count..<(t.count - JetonV4.end.count)]
        guard b.count <= 4 * ((JetonV4.maxTokenBytes + 2) / 3) else { throw Erreur.tropGrand }
        guard let data = Base64.decode(bytes: b) else { throw Erreur.base64 }
        return try fromBytes(data)
    }

    /// Le jeton `[[BROCOLIS:v4:<base64>]]`.
    public func encode() -> String {
        JetonV4.head + Base64.encode(toBytes()) + "]]"
    }
}

extension Reader {
    /// Un `u16` gros-boutiste.
    mutating func u16() throws -> UInt16 {
        let b = try take(2)
        return UInt16(b[0]) << 8 | UInt16(b[1])
    }
}
