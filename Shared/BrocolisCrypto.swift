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
//  Le jeton v1 encode `nonce (12) || ciphertext || tag (16)`, ce qui correspond
//  à la représentation `combined` de CryptoKit (`AES.GCM.SealedBox`) et à
//  l'empaquetage de la crate Rust `aes-gcm`. Interopérable avec brocolis.
//
//  MULTI-DESTINATAIRE (`[[BROCOLIS:v2:…]]`) : chiffrement d'enveloppe. Le texte
//  est chiffré une seule fois sous une clé de message aléatoire, elle-même
//  emballée sous chaque clé destinataire. Un seul jeton, lisible en clair par
//  tous les destinataires. Spécifique à Brocolis (non lu par le proxy v1).
//

import Foundation
import CryptoKit

enum BrocolisCrypto {

    static let tokenHead = "[[BROCOLIS:"
    static let tokenPrefix = "[[BROCOLIS:v1:"
    static let tokenPrefixV2 = "[[BROCOLIS:v2:"
    static let tokenSuffix = "]]"
    static let plainOpen = "(("
    static let plainClose = "))"

    static let keyLength = 32
    private static let nonceLength = 12
    private static let tagLength = 16
    /// Taille fixe d'une clé de message emballée : nonce(12) + clé(32) + tag(16).
    private static let wrappedKeyLength = 12 + 32 + 16

    enum CryptoError: LocalizedError {
        case badKeyLength(Int)
        case badKeyBase64
        case badToken
        case aead

        var errorDescription: String? {
            switch self {
            case .badKeyLength(let n):
                return loc("La clé doit faire \(BrocolisCrypto.keyLength) octets, reçu \(n).",
                           "The key must be \(BrocolisCrypto.keyLength) bytes, received \(n).",
                           "La clave debe ser de \(BrocolisCrypto.keyLength) bytes, recibido \(n).")
            case .badKeyBase64: return loc("Clé base64 invalide.", "Invalid base64 key.", "Clave base64 no válida.")
            case .badToken: return loc("Jeton chiffré corrompu.", "Corrupted encrypted token.", "Token cifrado dañado.")
            case .aead: return loc("Échec du (dé)chiffrement AES-256-GCM.", "AES-256-GCM (de)encryption failed.", "Fallo del (des)cifrado AES-256-GCM.")
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

    // MARK: Jeton multi-destinataire (v2, chiffrement d'enveloppe)

    // Un jeton v2 chiffre le texte UNE seule fois sous une « clé de message »
    // aléatoire, puis emballe cette clé sous CHAQUE clé destinataire. N'importe
    // quel destinataire ouvre l'emballage qui lui correspond, récupère la clé de
    // message et lit le texte. Un seul jeton, tout le monde lit en clair.
    //
    // Disposition du payload (puis base64) :
    //   [0]                     format = 0x01
    //   [1]                     N = nombre de destinataires (1…255)
    //   [2 .. 2+60N)            N clés de message emballées (60 octets chacune)
    //   [2+60N .. fin)          corps = AES-GCM(texte, cléDeMessage) « combined »

    /// Chiffre `plaintext` pour PLUSIEURS clés en un seul jeton `v2`.
    static func encryptTokenMulti(_ plaintext: Data, keys: [SymmetricKey]) throws -> String {
        guard !keys.isEmpty, keys.count <= 255 else { throw CryptoError.aead }

        let messageKey = SymmetricKey(size: .bits256)
        let messageKeyRaw = messageKey.withUnsafeBytes { Data(Array($0)) }

        let bodySealed = try AES.GCM.seal(plaintext, using: messageKey)
        guard let body = bodySealed.combined else { throw CryptoError.aead }

        var payload = Data([0x01, UInt8(keys.count)])
        for key in keys {
            let wrapSealed = try AES.GCM.seal(messageKeyRaw, using: key)
            guard let wrapped = wrapSealed.combined, wrapped.count == wrappedKeyLength else {
                throw CryptoError.aead
            }
            payload.append(wrapped)
        }
        payload.append(body)

        return tokenPrefixV2 + payload.base64EncodedString() + tokenSuffix
    }

    /// Tente d'ouvrir un jeton `v2` avec un jeu de clés. Renvoie `nil` si aucune
    /// des clés ne correspond (message « pour les autres »).
    static func decryptTokenV2(base64 b64: String, keys: [SymmetricKey]) -> Data? {
        guard let payload = Data(base64Encoded: b64), payload.count >= 2 else { return nil }
        let bytes = [UInt8](payload)
        guard bytes[0] == 0x01 else { return nil }

        let n = Int(bytes[1])
        let wrapsStart = 2
        let bodyStart = wrapsStart + n * wrappedKeyLength
        guard payload.count >= bodyStart + nonceLength + tagLength else { return nil }

        let body = payload.subdata(in: bodyStart..<payload.count)

        for i in 0..<n {
            let s = wrapsStart + i * wrappedKeyLength
            let wrapped = payload.subdata(in: s..<(s + wrappedKeyLength))
            guard let wrapBox = try? AES.GCM.SealedBox(combined: wrapped) else { continue }
            for key in keys {
                guard let messageKeyRaw = try? AES.GCM.open(wrapBox, using: key) else { continue }
                let messageKey = SymmetricKey(data: messageKeyRaw)
                if let bodyBox = try? AES.GCM.SealedBox(combined: body),
                   let plain = try? AES.GCM.open(bodyBox, using: messageKey) {
                    return plain
                }
            }
        }
        return nil
    }

    /// Scelle `plaintext` dans un jeton : `v1` pour une seule clé (compatible
    /// brocolis), `v2` (enveloppe) dès qu'il y a plusieurs destinataires.
    static func sealToken(_ plaintext: Data, keys: [SymmetricKey]) -> String? {
        guard let first = keys.first else { return nil }
        if keys.count == 1 { return try? encryptToken(plaintext, key: first) }
        return try? encryptTokenMulti(plaintext, keys: keys)
    }

    // MARK: Sélectif (best effort)

    @discardableResult
    static func encryptMarked(_ input: String, key: SymmetricKey) -> (text: String, count: Int) {
        encryptMarked(input, keys: [key])
    }

    /// Variante multi-destinataire : chaque `((segment))` est scellé pour TOUTES
    /// les clés (jeton `v2` si plusieurs, `v1` si une seule).
    @discardableResult
    static func encryptMarked(_ input: String, keys: [SymmetricKey]) -> (text: String, count: Int) {
        var out = ""
        var count = 0
        var rest = Substring(input)

        while let open = rest.range(of: plainOpen) {
            let afterOpen = rest[open.upperBound...]
            guard let close = afterOpen.range(of: plainClose) else { break }
            let secret = afterOpen[afterOpen.startIndex..<close.lowerBound]

            out += rest[rest.startIndex..<open.lowerBound]
            if let token = sealToken(Data(secret.utf8), keys: keys) {
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
        decryptTokens(input, keys: [key])
    }

    /// Déchiffre chaque jeton en **essayant plusieurs clés** : pour chaque jeton,
    /// la première clé qui réussit gagne. Idéal quand on a une clé par
    /// correspondant. Un jeton qu'aucune clé ne déchiffre est laissé tel quel.
    @discardableResult
    static func decryptTokens(_ input: String, keys: [SymmetricKey]) -> (text: String, count: Int) {
        var out = ""
        var count = 0
        var rest = Substring(input)

        // On cherche n'importe quel jeton `[[BROCOLIS:…]]` (v1 ou v2) et on
        // déchiffre selon sa version. Un jeton qu'aucune clé n'ouvre est laissé
        // tel quel (message « pour les autres »).
        while let start = rest.range(of: tokenHead) {
            let afterHead = rest[start.upperBound...]
            guard let end = afterHead.range(of: tokenSuffix) else { break }
            let inner = String(afterHead[afterHead.startIndex..<end.lowerBound]) // "v1:…" / "v2:…"

            out += rest[rest.startIndex..<start.lowerBound]

            var decrypted: String?
            if inner.hasPrefix("v1:") {
                let b64 = String(inner.dropFirst(3))
                for key in keys {
                    if let plain = try? decryptToken(base64: b64, key: key) {
                        decrypted = String(decoding: plain, as: UTF8.self)
                        break
                    }
                }
            } else if inner.hasPrefix("v2:") {
                let b64 = String(inner.dropFirst(3))
                if let plain = decryptTokenV2(base64: b64, keys: keys) {
                    decrypted = String(decoding: plain, as: UTF8.self)
                }
            }

            if let plain = decrypted {
                out += plain
                count += 1
            } else {
                out += tokenHead + inner + tokenSuffix
            }
            rest = afterHead[end.upperBound...]
        }
        out += rest
        return (out, count)
    }

    static func containsToken(_ text: String) -> Bool { text.contains(tokenHead) }
}
