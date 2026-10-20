//
//  BrocolisKeyToken.swift
//  Brocolis 🥦 (partagé)
//
//  Clé Brocolis PROTÉGÉE PAR UNE PHRASE SECRÈTE, pour la sortir de l'appareil
//  (la copier, l'envoyer hors d'un canal chiffré) sans jamais l'exposer en
//  clair. Format commun avec Talka, Brocolis Android et le site :
//
//      [[BROCOLIS-CLE:v1:<base64 standard, avec =>]]
//
//  payload décodé (76 octets) = sel (16) ‖ nonce (12) ‖ AES-256-GCM(clé brute
//  32 octets) ‖ tag (16).
//
//  - clé de chiffrement = PBKDF2-HMAC-SHA256(phrase UTF-8 telle quelle, sel,
//    600 000 itérations, 32 octets) ;
//  - données associées GCM = les 15 octets ASCII `brocolis-cle-v1` ;
//  - sel et nonce aléatoires à chaque export ;
//  - phrase : 8 caractères au moins à l'export ; à l'import, toute phrase est
//    essayée.
//
//  La phrase se donne À PART (de vive voix), jamais dans le même message que
//  le jeton. PBKDF2 est écrit avec `HMAC<SHA256>` de CryptoKit (pas de
//  CommonCrypto) : le même code se compile et se teste hors iOS avec
//  swift-crypto.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

enum BrocolisKeyToken {

    static let prefix = "[[BROCOLIS-CLE:v1:"
    static let suffix = "]]"

    static let minPassphraseLength = 8
    static let iterations = 600_000

    private static let saltLength = 16
    private static let nonceLength = 12
    private static let tagLength = 16
    private static let keyLength = 32
    private static let payloadLength = 16 + 12 + 32 + 16
    private static let associatedData = Data("brocolis-cle-v1".utf8)

    enum KeyTokenError: LocalizedError, Equatable {
        case passphraseTooShort
        case passphraseMismatch
        case badKey
        case badToken
        case wrongPassphrase

        var errorDescription: String? {
            switch self {
            case .passphraseTooShort:
                return loc("La phrase secrète doit faire au moins \(BrocolisKeyToken.minPassphraseLength) caractères.",
                           "The passphrase must be at least \(BrocolisKeyToken.minPassphraseLength) characters long.",
                           "La frase secreta debe tener al menos \(BrocolisKeyToken.minPassphraseLength) caracteres.")
            case .passphraseMismatch:
                return loc("Les deux phrases secrètes ne sont pas identiques.",
                           "The two passphrases don’t match.",
                           "Las dos frases secretas no coinciden.")
            case .badKey:
                return loc("Clé invalide : elle doit faire 32 octets.",
                           "Invalid key: it must be 32 bytes.",
                           "Clave no válida: debe tener 32 bytes.")
            case .badToken:
                return loc("Clé protégée abîmée ou incomplète : recopie-la en entier, de [[ à ]].",
                           "Protected key damaged or incomplete: copy it in full, from [[ to ]].",
                           "Clave protegida dañada o incompleta: cópiala entera, de [[ a ]].")
            case .wrongPassphrase:
                return loc("Phrase secrète incorrecte (ou clé protégée abîmée). Rien n’a été importé.",
                           "Wrong passphrase (or damaged protected key). Nothing was imported.",
                           "Frase secreta incorrecta (o clave protegida dañada). No se importó nada.")
            }
        }
    }

    // MARK: Détection

    /// Le texte contient-il une clé protégée ?
    static func containsToken(_ text: String) -> Bool { text.contains(prefix) }

    // MARK: Sceller (export)

    /// Chiffre une clé Brocolis (base64, 32 octets) sous une phrase secrète.
    /// Sel et nonce aléatoires : deux exports de la même clé diffèrent.
    static func seal(keyBase64: String, passphrase: String) throws -> String {
        var salt = [UInt8](repeating: 0, count: saltLength)
        var nonce = [UInt8](repeating: 0, count: nonceLength)
        var rng = SystemRandomNumberGenerator() // CSPRNG du système
        for i in salt.indices { salt[i] = rng.next() }
        for i in nonce.indices { nonce[i] = rng.next() }
        return try seal(keyBase64: keyBase64, passphrase: passphrase,
                        salt: Data(salt), nonce: Data(nonce))
    }

    /// Variante à sel et nonce IMPOSÉS — réservée aux tests (vecteur fixe).
    static func seal(keyBase64: String, passphrase: String, salt: Data, nonce: Data) throws -> String {
        guard passphrase.count >= minPassphraseLength else { throw KeyTokenError.passphraseTooShort }
        let trimmed = keyBase64.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let raw = Data(base64Encoded: trimmed), raw.count == keyLength else {
            throw KeyTokenError.badKey
        }
        guard salt.count == saltLength, nonce.count == nonceLength else { throw KeyTokenError.badToken }

        let wrapKey = derivedKey(passphrase: passphrase, salt: salt)
        let box = try AES.GCM.seal(raw, using: wrapKey,
                                   nonce: try AES.GCM.Nonce(data: nonce),
                                   authenticating: associatedData)
        var payload = Data()
        payload.append(salt)
        payload.append(nonce)
        payload.append(box.ciphertext)
        payload.append(box.tag)
        guard payload.count == payloadLength else { throw KeyTokenError.badToken }
        return prefix + payload.base64EncodedString() + suffix
    }

    // MARK: Ouvrir (import)

    /// Retrouve la clé (base64, 32 octets) contenue dans `token`. `token` peut
    /// être un texte plus long (message d'invitation collé en entier) : on y
    /// cherche le premier jeton `[[BROCOLIS-CLE:v1:…]]`.
    static func open(token: String, passphrase: String) throws -> String {
        guard let b64 = extractBase64(token),
              let payload = Data(base64Encoded: b64),
              payload.count == payloadLength else {
            throw KeyTokenError.badToken
        }
        let bytes = [UInt8](payload)
        let salt = Data(bytes[0..<16])
        let nonceBytes = Data(bytes[16..<28])
        let ciphertext = Data(bytes[28..<60])
        let tag = Data(bytes[60..<76])

        let wrapKey = derivedKey(passphrase: passphrase, salt: salt)
        let raw: Data
        do {
            let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonceBytes),
                                            ciphertext: ciphertext, tag: tag)
            raw = try AES.GCM.open(box, using: wrapKey, authenticating: associatedData)
        } catch {
            throw KeyTokenError.wrongPassphrase
        }
        guard raw.count == keyLength else { throw KeyTokenError.badToken }
        return raw.base64EncodedString()
    }

    /// Le base64 du premier jeton trouvé dans `text`, sans les blancs qu'une
    /// messagerie aurait pu insérer (retours à la ligne). `nil` si absent ou
    /// non refermé.
    static func extractBase64(_ text: String) -> String? {
        guard let start = text.range(of: prefix) else { return nil }
        let rest = text[start.upperBound...]
        guard let end = rest.range(of: suffix) else { return nil }
        let inner = rest[rest.startIndex..<end.lowerBound]
        return String(inner.filter { !$0.isWhitespace })
    }

    // MARK: Hors du fil principal (600 000 itérations ≈ une seconde)

    static func sealInBackground(keyBase64: String, passphrase: String) async -> Result<String, Error> {
        await Task.detached(priority: .userInitiated) {
            Result { try seal(keyBase64: keyBase64, passphrase: passphrase) }
        }.value
    }

    static func openInBackground(token: String, passphrase: String) async -> Result<String, Error> {
        await Task.detached(priority: .userInitiated) {
            Result { try open(token: token, passphrase: passphrase) }
        }.value
    }

    // MARK: PBKDF2-HMAC-SHA256

    private static func derivedKey(passphrase: String, salt: Data) -> SymmetricKey {
        SymmetricKey(data: pbkdf2SHA256(password: Data(passphrase.utf8), salt: salt,
                                        iterations: iterations))
    }

    /// PBKDF2-HMAC-SHA256 (RFC 8018) pour une sortie de 32 octets = un seul
    /// bloc : T1 = U1 ⊕ U2 ⊕ … ⊕ Uc, avec U1 = HMAC(P, S ‖ INT(1)) et
    /// Uj = HMAC(P, Uj-1).
    ///
    /// L'état HMAC « clé déjà absorbée » est calculé UNE fois puis copié à chaque
    /// itération (`HMAC` est un type valeur) : on évite de rehacher la phrase
    /// 600 000 fois.
    static func pbkdf2SHA256(password: Data, salt: Data, iterations: Int) -> Data {
        precondition(iterations >= 1)
        let keyed = HMAC<SHA256>(key: SymmetricKey(data: password))

        var first = keyed
        first.update(data: salt)
        first.update(data: Data([0, 0, 0, 1]))
        var u = first.finalize()

        var t = [UInt8](repeating: 0, count: SHA256.byteCount)
        u.withUnsafeBytes { buf in
            for i in 0..<t.count { t[i] = buf[i] }
        }
        if iterations > 1 {
            for _ in 1..<iterations {
                var h = keyed
                u.withUnsafeBytes { buf in h.update(data: buf) }
                u = h.finalize()
                u.withUnsafeBytes { buf in
                    for i in 0..<t.count { t[i] ^= buf[i] }
                }
            }
        }
        return Data(t)
    }
}
