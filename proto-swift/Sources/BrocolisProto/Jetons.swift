// Les jetons de Brocolis v1 et v2, et les passages `((…))` : exactement le
// comportement de `brocolis_proto::jetons` (et de `talka-web::jetons`,
// TalkaKit `Brocolis`, `BrocolisCrypto`), lisibles pour toujours (§4.6).
//
// - une clé : 32 octets (AES-256), en base64 standard ;
// - `[[BROCOLIS:v1:<base64>]]` : AES-256-GCM « combined »
//   (nonce 12 octets ‖ chiffré ‖ tag 16 octets), pour une seule clé ;
// - `[[BROCOLIS:v2:<base64>]]` : une enveloppe pour plusieurs clés :
//   `0x01`, N, puis N clés de message emballées (60 octets chacune), puis
//   le corps chiffré sous la clé de message ;
// - `((…))` : seuls ces passages sont chiffrés, le reste part en clair.
//
// Pas de remplissage ni de données associées : ce sont les formats
// historiques, tels quels. Les jetons v3 sont ceux de `Token` ; ici, ils
// restent « verrouillés ». Tout le texte est traité en octets UTF-8.

public enum Jetons {
    /// Le début de tout jeton Brocolis.
    public static let head = "[[BROCOLIS:"
    static let headBytes = Array(head.utf8)
    static let v1 = Array("v1:".utf8)
    static let v2 = Array("v2:".utf8)
    static let end = Array("]]".utf8)
    static let markOpen = Array("((".utf8)
    static let markClose = Array("))".utf8)
    static let wrapped = 12 + 32 + 16

    /// Le texte affiché à la place d'un jeton qu'aucune clé n'ouvre.
    public static let verrou = "🔒🥦"

    /// Les espaces de Rust (`char::is_whitespace` : la propriété Unicode
    /// White_Space), pour retrouver une clé comme la référence.
    static func isWhitespace(_ c: Unicode.Scalar) -> Bool {
        switch c.value {
        case 0x09...0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
            return true
        default:
            return false
        }
    }

    static func trim(_ s: String) -> String {
        let scalars = Array(s.unicodeScalars)
        var a = 0, b = scalars.count
        while a < b && isWhitespace(scalars[a]) { a += 1 }
        while b > a && isWhitespace(scalars[b - 1]) { b -= 1 }
        var out = String.UnicodeScalarView()
        out.append(contentsOf: scalars[a..<b])
        return String(out)
    }

    /// Une clé Brocolis en base64 (32 octets), ou `nil`.
    public static func keyFromB64(_ text: String) -> [UInt8]? {
        guard let k = Base64.decode(trim(text)), k.count == 32 else { return nil }
        return k
    }

    /// Retrouve une clé dans un texte collé (l'invitation de l'app Brocolis
    /// entière, par exemple) : le premier mot qui est une clé.
    public static func findKey(_ text: String) -> String? {
        let separators = Set("«»\"'“”()[]<>".unicodeScalars)
        var word = String.UnicodeScalarView()
        func check() -> String? {
            let w = String(word)
            word = String.UnicodeScalarView()
            return keyFromB64(w) != nil ? trim(w) : nil
        }
        for c in text.unicodeScalars {
            if isWhitespace(c) || separators.contains(c) {
                if let k = check() { return k }
            } else {
                word.append(c)
            }
        }
        return check()
    }

    /// L'empreinte d'une clé, à comparer de vive voix (`AB12-CD34-EF56-7890`) :
    /// les 8 premiers octets de son SHA-256.
    public static func fingerprint(keyB64: String) -> String? {
        guard let k = keyFromB64(keyB64) else { return nil }
        return Kdf.fingerprint(k)
    }

    /// Une nouvelle clé, en base64 (32 octets tirés).
    public static func generateKey(rng: some CryptoRng) -> String {
        var k = rng.bytes(32)
        defer { effacer(&k) }
        return Base64.encode(k)
    }

    /// Vrai si le texte contient un jeton Brocolis (toute version).
    public static func hasToken(_ text: String) -> Bool {
        Octets.find(Array(text.utf8), headBytes) != nil
    }

    static func sealRaw(_ key: [UInt8], _ plain: [UInt8], _ rng: some CryptoRng) -> [UInt8]? {
        let nonce = rng.bytes(12)
        guard let ct = try? Kdf.aesGcmSeal(key: key, nonce: nonce, aad: [], message: plain) else { return nil }
        return nonce + ct
    }

    static func openRaw(_ key: [UInt8], _ combined: ArraySlice<UInt8>) -> [UInt8]? {
        guard key.count == 32, combined.count >= 12 + 16 else { return nil }
        let c = Array(combined)
        return try? Kdf.aesGcmOpen(key: key, nonce: Array(c[0..<12]), aad: [], ciphertext: Array(c[12...]))
    }

    /// Un jeton pour `text` : `v1` pour une clé (lisible par toutes les
    /// versions de Brocolis), `v2` pour plusieurs (255 au plus). Chaque clé
    /// fait 32 octets (sinon `nil`).
    ///
    /// Ordre de tirage : v1, nonce (12) ; v2, clé de message (32), puis un
    /// nonce (12) par clé, puis celui du corps (12).
    public static func sealToken(_ text: String, keys: [[UInt8]], rng: some CryptoRng) -> String? {
        guard !keys.isEmpty, keys.count <= 255, keys.allSatisfy({ $0.count == 32 }) else { return nil }
        if keys.count == 1 {
            guard let raw = sealRaw(keys[0], Array(text.utf8), rng) else { return nil }
            return head + "v1:" + Base64.encode(raw) + "]]"
        }
        var messageKey = rng.bytes(32)
        defer { effacer(&messageKey) }
        var payload: [UInt8] = [1, UInt8(keys.count)]
        for key in keys {
            guard let w = sealRaw(key, messageKey, rng) else { return nil }
            payload += w
        }
        guard let body = sealRaw(messageKey, Array(text.utf8), rng) else { return nil }
        payload += body
        return head + "v2:" + Base64.encode(payload) + "]]"
    }

    /// Chiffre un message : les passages `((…))` s'il y en a, sinon tout le
    /// texte. Un texte qui porte déjà un jeton part tel quel.
    public static func sealWith(_ text: String, keys: [[UInt8]], rng: some CryptoRng) -> String {
        if text.isEmpty || keys.isEmpty || hasToken(text) { return text }
        let bytes = Array(text.utf8)
        var out = [UInt8]()
        var rest = 0
        var marked = false
        while let start = Octets.find(bytes, markOpen, from: rest) {
            let after = start + markOpen.count
            guard let end = Octets.find(bytes, markClose, from: after) else { break }
            out += bytes[rest..<start]
            let inner = Octets.string(bytes[after..<end])
            if let token = sealToken(inner, keys: keys, rng: rng) {
                out += Array(token.utf8)
            } else {
                out += bytes[start..<(end + markClose.count)]
            }
            marked = true
            rest = end + markClose.count
        }
        if !marked {
            return sealToken(text, keys: keys, rng: rng) ?? text
        }
        out += bytes[rest...]
        return Octets.string(out)
    }

    /// `sealWith` avec le hasard du système.
    public static func seal(_ text: String, keys: [[UInt8]]) -> String {
        sealWith(text, keys: keys, rng: Hasard.system())
    }

    static func openV2(_ payload: [UInt8], _ keys: [[UInt8]]) -> [UInt8]? {
        guard payload.count >= 2 else { return nil }
        let format = payload[0], n = Int(payload[1])
        let rest = payload[2...]
        guard format == 1, rest.count >= n * wrapped + 12 + 16 else { return nil }
        let body = rest[(rest.startIndex + n * wrapped)...]
        for i in 0..<n {
            let s = rest.startIndex + i * wrapped
            let w = rest[s..<(s + wrapped)]
            for key in keys {
                if var messageKey = openRaw(key, w) {
                    defer { effacer(&messageKey) }
                    if let plain = openRaw(messageKey, body) { return plain }
                }
            }
        }
        return nil
    }

    static func openToken(_ inner: [UInt8], _ keys: [[UInt8]]) -> String? {
        var plain: [UInt8]
        if Octets.hasPrefix(inner, v1) {
            guard let combined = Base64.decode(bytes: inner[v1.count...]) else { return nil }
            guard let p = keys.lazy.compactMap({ openRaw($0, combined[...]) }).first else { return nil }
            plain = p
        } else if Octets.hasPrefix(inner, v2) {
            guard let payload = Base64.decode(bytes: inner[v2.count...]), let p = openV2(payload, keys) else {
                return nil
            }
            plain = p
        } else {
            return nil
        }
        defer { effacer(&plain) }
        return Octets.utf8(plain)
    }

    /// Ce que donne un texte une fois ses jetons ouverts.
    public struct Opened: Equatable, Sendable {
        /// Le texte, jetons ouverts remplacés par leur contenu.
        public var text: String
        /// Les jetons ouverts.
        public var opened: Int
        /// Ceux qu'aucune des clés n'ouvre (laissés tels quels).
        public var locked: Int
    }

    /// Ouvre les jetons v1/v2 de `text` avec toutes les clés.
    public static func open(_ text: String, keys: [[UInt8]]) -> Opened {
        let bytes = Array(text.utf8)
        var out = [UInt8]()
        var opened = 0, locked = 0
        var rest = 0
        while let start = Octets.find(bytes, headBytes, from: rest) {
            let after = start + headBytes.count
            guard let end = Octets.find(bytes, self.end, from: after) else { break }
            out += bytes[rest..<start]
            if let plain = openToken(Array(bytes[after..<end]), keys) {
                out += Array(plain.utf8)
                opened += 1
            } else {
                out += bytes[start..<(end + self.end.count)]
                locked += 1
            }
            rest = end + self.end.count
        }
        out += bytes[rest...]
        return Opened(text: Octets.string(out), opened: opened, locked: locked)
    }

    /// Un texte prêt à afficher : un jeton qu'aucune clé n'ouvre devient
    /// « 🔒🥦 ».
    public static func masked(_ text: String) -> String {
        let bytes = Array(text.utf8)
        guard Octets.find(bytes, headBytes) != nil else { return text }
        var out = [UInt8]()
        var rest = 0
        while let start = Octets.find(bytes, headBytes, from: rest) {
            guard let end = Octets.find(bytes, self.end, from: start) else { break }
            out += bytes[rest..<start]
            out += Array(verrou.utf8)
            rest = end + self.end.count
        }
        out += bytes[rest...]
        return Octets.string(out)
    }
}
