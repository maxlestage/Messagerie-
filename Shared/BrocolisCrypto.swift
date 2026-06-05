//
//  BrocolisCrypto.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Chiffrement sélectif AES-256-GCM, compatible « au format de jeton » près
//  avec le proxy Rust brocolis (https://github.com/maxlestage/brocolis).
//
//  - Tout segment `((texte secret))` est chiffré et remplacé par un jeton
//    `[[BROCOLIS:v1:<base64>]]`.
//  - Tout jeton `[[BROCOLIS:v1:<base64>]]` est déchiffré en clair.
//
//  Le jeton encode `nonce (12) || ciphertext || tag (16)`, ce qui correspond à
//  la représentation `combined` de CryptoKit (`AES.GCM.SealedBox`) et à
//  l'empaquetage de la crate Rust `aes-gcm`. Interopérable avec brocolis.
//

import Foundation
import CryptoKit

enum BrocolisCrypto {

    static let tokenPrefix = "[[BROCOLIS:v1:"
    static let tokenSuffix = "]]"
    static let plainOpen = "(("
    static let plainClose = "))"

    static let keyLength = 32
    private static let nonceLength = 12
    private static let tagLength = 16

    enum CryptoError: LocalizedError {
        case badKeyLength(Int)
        case badKeyBase64
        case badToken
        case aead

        var errorDescription: String? {
            switch self {
            case .badKeyLength(let n):
                return "La clé doit faire \(BrocolisCrypto.keyLength) octets, reçu \(n)."
            case .badKeyBase64: return "Clé base64 invalide."
            case .badToken: return "Jeton chiffré corrompu."
            case .aead: return "Échec du (dé)chiffrement AES-256-GCM."
            }
        }
    }

    // MARK: Clé

    static func generateKeyBase64() -> String {
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { Data(Array($0)).base64EncodedString() }
    }

    static func symmetricKey(fromBase64 s: String) throws -> SymmetricKey {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let raw = Data(base64Encoded: trimmed) else { throw CryptoError.badKeyBase64 }
        guard raw.count == keyLength else { throw CryptoError.badKeyLength(raw.count) }
        return SymmetricKey(data: raw)
    }

    // MARK: Jeton unitaire

    static func encryptToken(_ plaintext: Data, key: SymmetricKey) throws -> String {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else { throw CryptoError.aead }
        return tokenPrefix + combined.base64EncodedString() + tokenSuffix
    }

    static func decryptToken(base64 b64: String, key: SymmetricKey) throws -> Data {
        guard let packed = Data(base64Encoded: b64) else { throw CryptoError.badToken }
        guard packed.count >= nonceLength + tagLength else { throw CryptoError.badToken }
        guard let box = try? AES.GCM.SealedBox(combined: packed) else { throw CryptoError.badToken }
        do { return try AES.GCM.open(box, using: key) }
        catch { throw CryptoError.aead }
    }

    // MARK: Sélectif (best effort)

    @discardableResult
    static func encryptMarked(_ input: String, key: SymmetricKey) -> (text: String, count: Int) {
        var out = ""
        var count = 0
        var rest = Substring(input)

        while let open = rest.range(of: plainOpen) {
            let afterOpen = rest[open.upperBound...]
            guard let close = afterOpen.range(of: plainClose) else { break }
            let secret = afterOpen[afterOpen.startIndex..<close.lowerBound]

            out += rest[rest.startIndex..<open.lowerBound]
            if let token = try? encryptToken(Data(secret.utf8), key: key) {
                out += token
                count += 1
            } else {
                out += plainOpen + secret + plainClose
            }
            rest = afterOpen[close.upperBound...]
        }
        out += rest
        return (out, count)
    }

    @discardableResult
    static func decryptTokens(_ input: String, key: SymmetricKey) -> (text: String, count: Int) {
        var out = ""
        var count = 0
        var rest = Substring(input)

        while let start = rest.range(of: tokenPrefix) {
            let afterPrefix = rest[start.upperBound...]
            guard let end = afterPrefix.range(of: tokenSuffix) else { break }
            let b64 = String(afterPrefix[afterPrefix.startIndex..<end.lowerBound])

            out += rest[rest.startIndex..<start.lowerBound]
            if let plain = try? decryptToken(base64: b64, key: key) {
                out += String(decoding: plain, as: UTF8.self)
                count += 1
            } else {
                out += tokenPrefix + b64 + tokenSuffix
            }
            rest = afterPrefix[end.upperBound...]
        }
        out += rest
        return (out, count)
    }

    static func containsToken(_ text: String) -> Bool { text.contains(tokenPrefix) }
}
