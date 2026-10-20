// Une clé Brocolis (32 octets) protégée par une phrase secrète (§3.2, §7.1),
// pour la sortir de l'appareil sans la montrer (`brocolis_proto::cle_protegee`).
//
// - `[[BROCOLIS-CLE:v1:<base64>]]` (lecture seulement) : sel (16) ‖ nonce
//   (12) ‖ AES-256-GCM(clé) ‖ tag, sous PBKDF2-HMAC-SHA256(phrase, sel,
//   600 000 tours), données associées `brocolis-cle-v1` ;
// - `[[BROCOLIS-CLE:v2:<base64>]]` (par défaut) : Argon2id, format exact
//   de §3.2 (83 octets), l'en-tête et les paramètres authentifiés.

/// Les paramètres Argon2id d'une clé protégée v2.
public struct Argon2Params: Equatable, Hashable, Sendable {
    /// m : mémoire, en Kio.
    public var mKib: UInt32
    /// t : nombre de passes.
    public var t: UInt8
    /// p : parallélisme.
    public var p: UInt8

    public init(mKib: UInt32, t: UInt8, p: UInt8) {
        self.mKib = mKib
        self.t = t
        self.p = p
    }

    /// Le défaut : 64 Mio, 3 passes, 1 voie (§3.2).
    public static let `default` = Argon2Params(mKib: 65_536, t: 3, p: 1)
    /// Les plus petits paramètres acceptés à l'import (19 Mio, 2 passes,
    /// 1 voie : le minimum de l'OWASP), utilisés par les vecteurs rapides.
    public static let minimum = Argon2Params(mKib: 19_456, t: 2, p: 1)
    /// La plus grande mémoire acceptée (1 Gio).
    public static let maxMKib: UInt32 = 1_048_576
    /// Le plus grand nombre de passes accepté (§7.1).
    public static let maxT: UInt8 = 16

    /// Vérifie les bornes de §3.2 et §7.1 : 19 456 ≤ m ≤ 1 048 576,
    /// 2 ≤ t ≤ 16, p ≥ 1, m ≥ 8p.
    public func check() throws {
        let ok = mKib >= Self.minimum.mKib
            && mKib <= Self.maxMKib
            && t >= 2
            && t <= Self.maxT
            && p >= 1
            && mKib >= 8 * UInt32(p)
        guard ok else { throw Erreur.parametres }
    }
}

public enum CleProtegee {
    /// Le début d'une clé protégée v1.
    public static let headV1 = "[[BROCOLIS-CLE:v1:"
    /// Le début d'une clé protégée v2.
    public static let headV2 = "[[BROCOLIS-CLE:v2:"
    static let end = Array("]]".utf8)
    static let adV1 = Array("brocolis-cle-v1".utf8)
    /// Les tours de PBKDF2 de la v1.
    public static let pbkdf2Rounds: UInt32 = 600_000
    /// La phrase la plus courte acceptée (en caractères Unicode, comme
    /// `chars().count()`) pour protéger une clé ; à l'import, toute phrase
    /// est essayée.
    public static let phraseMin = 8
    static let v1Length = 16 + 12 + 32 + 16
    static let v2Length = 83
    static let v2Header = 35

    static func pbkdf2Key(_ phrase: String, _ salt: [UInt8]) -> [UInt8] {
        Pbkdf2.sha256(password: Array(phrase.utf8), salt: salt, rounds: pbkdf2Rounds)
    }

    /// La clé de chiffrement v2 : `Argon2id(phrase UTF-8, sel, m, t, p, 32)`
    /// (version 0x13, sans secret ni données associées Argon2).
    public static func argon2idKey(phrase: String, salt: [UInt8], params: Argon2Params) throws -> [UInt8] {
        try params.check()
        guard salt.count == 16 else { throw Erreur.format }
        var password = Array(phrase.utf8)
        defer { effacer(&password) }
        return try Argon2.hash(
            variant: .id, password: password, salt: salt,
            memoryKiB: params.mKib, passes: UInt32(params.t), lanes: UInt32(params.p), length: 32)
    }

    /// Le contenu (octets) entre `head` et `]]` dans un texte collé.
    static func inner(_ text: String, _ head: String) -> [UInt8]? {
        let t = Array(text.utf8), h = Array(head.utf8)
        guard let s = Octets.find(t, h) else { return nil }
        let start = s + h.count
        guard let e = Octets.find(t, end, from: start) else { return nil }
        return Array(t[start..<e])
    }

    /// Vrai si le texte contient une clé protégée (v1 ou v2).
    public static func hasProtectedKey(_ text: String) -> Bool {
        let t = Array(text.utf8)
        return Octets.find(t, Array(headV1.utf8)) != nil || Octets.find(t, Array(headV2.utf8)) != nil
    }

    /// Écrit une clé protégée v1 avec un sel et un nonce donnés. **Héritage** :
    /// sert aux vecteurs et à l'interopérabilité ; on n'écrit plus que la v2.
    public static func protectKeyV1With(key: [UInt8], phrase: String, salt: [UInt8], nonce: [UInt8]) throws -> String {
        guard key.count == 32, salt.count == 16, nonce.count == 12 else { throw Erreur.format }
        var k = pbkdf2Key(phrase, salt)
        defer { effacer(&k) }
        let ct = try Kdf.aesGcmSeal(key: k, nonce: nonce, aad: adV1, message: key)
        return headV1 + Base64.encode(salt + nonce + ct) + "]]"
    }

    /// Écrit une clé protégée v2 avec des paramètres, un sel et un nonce
    /// donnés (les vecteurs ; `protectKey` tire sel et nonce au hasard).
    public static func protectKeyV2With(
        key: [UInt8], phrase: String, params: Argon2Params, salt: [UInt8], nonce: [UInt8]
    ) throws -> String {
        guard phrase.unicodeScalars.count >= phraseMin else { throw Erreur.phraseTropCourte }
        guard key.count == 32, salt.count == 16, nonce.count == 12 else { throw Erreur.format }
        var header: [UInt8] = [0x02]
        header += Octets.u32be(params.mKib)
        header.append(params.t)
        header.append(params.p)
        header += salt
        header += nonce
        var k = try argon2idKey(phrase: phrase, salt: salt, params: params)
        defer { effacer(&k) }
        let ct = try Kdf.aesGcmSeal(key: k, nonce: nonce, aad: header, message: key)
        return headV2 + Base64.encode(header + ct) + "]]"
    }

    /// Protège une clé par une phrase secrète (v2, paramètres par défaut, sel
    /// et nonce aléatoires). Refuse une phrase de moins de `phraseMin`
    /// caractères. Ordre de tirage : sel (16), nonce (12).
    public static func protectKey(key: [UInt8], phrase: String, rng: some CryptoRng) throws -> String {
        let salt = rng.bytes(16)
        let nonce = rng.bytes(12)
        return try protectKeyV2With(key: key, phrase: phrase, params: .default, salt: salt, nonce: nonce)
    }

    /// Retrouve la clé d'un jeton `[[BROCOLIS-CLE:v1:…]]` ou `v2` collé (seul
    /// ou dans un texte ; la v2 est cherchée d'abord). Phrase fausse ou jeton
    /// abîmé : `.dechiffrement` ; paramètres v2 hors bornes : `.parametres`
    /// (avant tout calcul).
    public static func unprotectKey(_ text: String, phrase: String) throws -> [UInt8] {
        if let b = inner(text, headV2) { return try unprotectV2(b, phrase) }
        if let b = inner(text, headV1) { return try unprotectV1(b, phrase) }
        throw Erreur.jetonAbsent
    }

    static func decode(_ b: [UInt8], _ length: Int) throws -> [UInt8] {
        // Une clé protégée fait moins de 120 caractères : rien à décoder
        // au-delà.
        guard b.count <= 4 * ((length + 2) / 3) else { throw Erreur.format }
        guard let data = Base64.decode(bytes: b) else { throw Erreur.base64 }
        guard data.count == length else { throw Erreur.format }
        return data
    }

    static func unprotectV1(_ b: [UInt8], _ phrase: String) throws -> [UInt8] {
        var data = try decode(b, v1Length)
        defer { effacer(&data) }
        var k = pbkdf2Key(phrase, Array(data[0..<16]))
        defer { effacer(&k) }
        let plain = try Kdf.aesGcmOpen(key: k, nonce: Array(data[16..<28]), aad: adV1, ciphertext: Array(data[28...]))
        guard plain.count == 32 else { throw Erreur.format }
        return plain
    }

    /// Les paramètres d'une clé protégée v2 (sans la phrase), pour prévenir
    /// l'utilisateur avant un calcul long.
    public static func v2Params(_ text: String) throws -> Argon2Params {
        guard let b = inner(text, headV2) else { throw Erreur.jetonAbsent }
        return try parseV2Params(try decode(b, v2Length))
    }

    static func parseV2Params(_ data: [UInt8]) throws -> Argon2Params {
        guard data[0] == 0x02 else { throw Erreur.format }
        let params = Argon2Params(mKib: Octets.readU32(data, 1), t: data[5], p: data[6])
        try params.check()
        return params
    }

    static func unprotectV2(_ b: [UInt8], _ phrase: String) throws -> [UInt8] {
        var data = try decode(b, v2Length)
        defer { effacer(&data) }
        let params = try parseV2Params(data)
        var k = try argon2idKey(phrase: phrase, salt: Array(data[7..<23]), params: params)
        defer { effacer(&k) }
        let plain = try Kdf.aesGcmOpen(
            key: k, nonce: Array(data[23..<35]), aad: Array(data[0..<v2Header]), ciphertext: Array(data[v2Header...]))
        guard plain.count == 32 else { throw Erreur.format }
        return plain
    }
}
