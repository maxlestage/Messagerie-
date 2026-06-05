//
//  KeyStore.swift
//  Messagerie 🥦
//
//  Conserve la clé symétrique partagée (base64, 32 octets) dans le Trousseau
//  (Keychain) de l'appareil. C'est cette clé qui doit être transmise — par un
//  canal sûr — aux autres personnes de la conversation.
//

import Foundation
import CryptoKit
import Combine

@MainActor
final class KeyStore: ObservableObject {

    /// Clé partagée courante en base64, ou `nil` si aucune clé n'est configurée.
    @Published private(set) var keyBase64: String?

    private let service = "rs.brocolis.messagerie"
    private let account = "shared-aes-key"

    init() {
        keyBase64 = readKeychain()
    }

    var hasKey: Bool { keyBase64 != nil }

    /// Clé utilisable pour (dé)chiffrer, ou `nil` si absente/invalide.
    var symmetricKey: SymmetricKey? {
        guard let b64 = keyBase64 else { return nil }
        return try? BrocolisCrypto.symmetricKey(fromBase64: b64)
    }

    /// Génère une nouvelle clé aléatoire et la stocke.
    func generate() {
        save(BrocolisCrypto.generateKeyBase64())
    }

    /// Importe une clé base64 fournie par un correspondant (après validation).
    func importKey(_ candidate: String) throws {
        let trimmed = candidate.trimmingCharacters(in: .whitespacesAndNewlines)
        _ = try BrocolisCrypto.symmetricKey(fromBase64: trimmed) // valide longueur/format
        save(trimmed)
    }

    /// Supprime la clé du Trousseau.
    func clear() {
        deleteKeychain()
        keyBase64 = nil
    }

    // MARK: - Persistance

    private func save(_ b64: String) {
        writeKeychain(b64)
        keyBase64 = b64
    }

    // MARK: - Keychain

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    private func readKeychain() -> String? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let str = String(data: data, encoding: .utf8) else {
            return nil
        }
        return str
    }

    private func writeKeychain(_ value: String) {
        let data = Data(value.utf8)
        deleteKeychain()
        var query = baseQuery()
        query[kSecValueData as String] = data
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        SecItemAdd(query as CFDictionary, nil)
    }

    private func deleteKeychain() {
        SecItemDelete(baseQuery() as CFDictionary)
    }
}
