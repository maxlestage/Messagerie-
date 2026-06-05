//
//  BrocolisCrypto.swift
//  Messagerie 🥦
//
//  Chiffrement sélectif AES-256-GCM, compatible « au format de jeton » près
//  avec le proxy Rust brocolis (https://github.com/maxlestage/brocolis).
//
//  Schéma sélectif : seul le contenu explicitement marqué est chiffré.
//   - À l'envoi, tout segment `((texte secret))` est chiffré et remplacé par un
//     jeton `[[BROCOLIS:v1:<base64>]]`.
//   - À l'affichage, tout jeton `[[BROCOLIS:v1:<base64>]]` est déchiffré et
//     remplacé par son texte clair.
//
//  Le jeton encode `nonce (12 octets) || ciphertext || tag (16 octets)`, ce qui
//  correspond exactement à la représentation `combined` de CryptoKit
//  (`AES.GCM.SealedBox`) et à l'empaquetage de la crate `aes-gcm` côté Rust.
//  Deux appareils partageant la même clé symétrique voient donc le clair, alors
//  qu'un transport/serveur intermédiaire ne voit que le jeton chiffré.
//

import Foundation
import CryptoKit

enum BrocolisCrypto {

    // MARK: Format du jeton (identique à brocolis)

    static let tokenPrefix = "[[BROCOLIS:v1:"
    static let tokenSuffix = "]]"
    static let plainOpen = "(("
    static let plainClose = "))"

    /// Longueur de la clé AES-256 en octets.
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
            case .badKeyBase64:
                return "Clé base64 invalide."
            case .badToken:
                return "Jeton chiffré corrompu."
            case .aead:
                return "Échec du (dé)chiffrement AES-256-GCM."
            }
        }
    }

    // MARK: Gestion de la clé

    /// Génère une nouvelle clé AES-256 (CSPRNG) et la renvoie en base64.
    static func generateKeyBase64() -> String {
        let key = SymmetricKey(size: .bits256)
        return key.withUnsafeBytes { Data(Array($0)).base64EncodedString() }
    }

    /// Construit une `SymmetricKey` à partir d'une clé base64 (32 octets).
    static func symmetricKey(fromBase64 s: String) throws -> SymmetricKey {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let raw = Data(base64Encoded: trimmed) else {
            throw CryptoError.badKeyBase64
        }
        guard raw.count == keyLength else {
            throw CryptoError.badKeyLength(raw.count)
        }
        return SymmetricKey(data: raw)
    }

    // MARK: Jeton unitaire

    /// Chiffre `plaintext` et renvoie un jeton `[[BROCOLIS:v1:<base64>]]`.
    static func encryptToken(_ plaintext: Data, key: SymmetricKey) throws -> String {
        let sealed = try AES.GCM.seal(plaintext, using: key)
        // `combined` = nonce (12) || ciphertext || tag (16) — identique à brocolis.
        guard let combined = sealed.combined else { throw CryptoError.aead }
        return tokenPrefix + combined.base64EncodedString() + tokenSuffix
    }

    /// Déchiffre la partie base64 d'un jeton (sans préfixe/suffixe).
    static func decryptToken(base64 b64: String, key: SymmetricKey) throws -> Data {
        guard let packed = Data(base64Encoded: b64) else { throw CryptoError.badToken }
        guard packed.count >= nonceLength + tagLength else { throw CryptoError.badToken }
        guard let box = try? AES.GCM.SealedBox(combined: packed) else {
            throw CryptoError.badToken
        }
        do {
            return try AES.GCM.open(box, using: key)
        } catch {
            throw CryptoError.aead
        }
    }

    // MARK: Chiffrement / déchiffrement sélectif (best effort)

    /// Remplace chaque `((secret))` par un jeton chiffré.
    /// Renvoie `(texte transformé, nombre de segments chiffrés)`. Un segment
    /// dont le chiffrement échoue est laissé tel quel.
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

    /// Remplace chaque jeton `[[BROCOLIS:v1:...]]` par son texte clair.
    /// Renvoie `(texte transformé, nombre de segments déchiffrés)`. Un jeton
    /// illisible (mauvaise clé, corruption) est laissé tel quel.
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

    /// Indique si un texte contient au moins un jeton chiffré.
    static func containsToken(_ text: String) -> Bool {
        text.contains(tokenPrefix)
    }
}
