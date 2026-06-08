//
//  BrocolisKeyStore.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Gère PLUSIEURS clés nommées, partagées via l'App Group (lisibles par l'app
//  et l'extension). Une clé est « sélectionnée » : c'est elle qui chiffre. Au
//  déchiffrement, l'extension essaie TOUTES les clés (un message d'un
//  correspondant se déchiffre avec la clé correspondante).
//
//  Note sécurité : pour la démo, on utilise les `UserDefaults` de l'App Group.
//  Les clés ne quittent jamais l'appareil. En production, préférer un groupe
//  d'accès Trousseau (Keychain) partagé.
//

import Foundation
import CryptoKit

/// Une clé nommée.
struct NamedKey: Codable, Identifiable, Equatable {
    let id: String
    var name: String
    let base64: String
}

enum BrocolisKeyStore {

    /// ⚠️ Doit correspondre à l'App Group activé sur l'app ET l'extension.
    static let appGroup = "group.rs.brocolis.messagerie"

    private static let legacyKeyName = "shared_aes_key_b64" // ancienne clé unique
    private static let keysName = "keys_json"
    private static let selectedIdName = "selected_key_id"
    private static let activeName = "is_active"
    private static let serverURLName = "rendezvous_server_url"
    private static let privateKeyName = "x25519_private_b64"
    private static let fingerprintName = "pairing_fingerprint"
    private static let ttlName = "key_ttl_seconds"
    private static let expiresAtName = "key_expires_at"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroup)
    }

    // MARK: - Liste de clés

    /// Migration depuis l'ancienne clé unique, une seule fois.
    private static func migrateIfNeeded() {
        guard let d = defaults, d.data(forKey: keysName) == nil else { return }
        var initial: [NamedKey] = []
        if let legacy = d.string(forKey: legacyKeyName), !legacy.isEmpty {
            let k = NamedKey(id: UUID().uuidString, name: "Ma clé", base64: legacy)
            initial = [k]
            d.set(k.id, forKey: selectedIdName)
            d.removeObject(forKey: legacyKeyName)
        }
        saveKeys(initial)
    }

    private static func loadKeys() -> [NamedKey] {
        guard let data = defaults?.data(forKey: keysName),
              let arr = try? JSONDecoder().decode([NamedKey].self, from: data) else { return [] }
        return arr
    }

    private static func saveKeys(_ keys: [NamedKey]) {
        if let data = try? JSONEncoder().encode(keys) {
            defaults?.set(data, forKey: keysName)
        }
    }

    /// Toutes les clés enregistrées.
    static var keys: [NamedKey] {
        migrateIfNeeded()
        return loadKeys()
    }

    static var selectedKeyId: String? { defaults?.string(forKey: selectedIdName) }

    /// Clé sélectionnée (sert à chiffrer). À défaut, la première.
    static var selectedKey: NamedKey? {
        let ks = keys
        if let id = selectedKeyId, let k = ks.first(where: { $0.id == id }) { return k }
        return ks.first
    }

    static func selectKey(_ id: String) {
        defaults?.set(id, forKey: selectedIdName)
    }

    /// Ajoute une clé nommée, la sélectionne, et réarme l'expiration. Renvoie l'id.
    @discardableResult
    static func addKey(name: String, base64: String) -> String {
        var ks = loadKeysAfterMigration()
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let key = NamedKey(
            id: UUID().uuidString,
            name: trimmedName.isEmpty ? "Clé \(ks.count + 1)" : trimmedName,
            base64: base64.trimmingCharacters(in: .whitespacesAndNewlines)
        )
        ks.append(key)
        saveKeys(ks)
        selectKey(key.id)
        setKeyExpiresAt(computeExpiry(ttlSeconds: keyTTLSeconds, from: Date()))
        return key.id
    }

    static func renameKey(id: String, name: String) {
        var ks = loadKeysAfterMigration()
        if let i = ks.firstIndex(where: { $0.id == id }) {
            let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
            ks[i].name = trimmed.isEmpty ? ks[i].name : trimmed
            saveKeys(ks)
        }
    }

    static func deleteKey(id: String) {
        var ks = loadKeysAfterMigration()
        ks.removeAll { $0.id == id }
        saveKeys(ks)
        if selectedKeyId == id {
            if let first = ks.first {
                selectKey(first.id)
            } else {
                defaults?.removeObject(forKey: selectedIdName)
                defaults?.removeObject(forKey: fingerprintName)
                defaults?.removeObject(forKey: expiresAtName)
                setActive(false)
            }
        }
    }

    private static func loadKeysAfterMigration() -> [NamedKey] {
        migrateIfNeeded()
        return loadKeys()
    }

    // MARK: - Accès clé (compat + usage)

    static var hasKey: Bool { !keys.isEmpty }

    /// Base64 de la clé sélectionnée (compatibilité).
    static var keyBase64: String? { selectedKey?.base64 }

    /// Clé symétrique sélectionnée (pour chiffrer).
    static func symmetricKey() -> SymmetricKey? {
        guard let b64 = selectedKey?.base64 else { return nil }
        return try? BrocolisCrypto.symmetricKey(fromBase64: b64)
    }

    /// Toutes les clés symétriques (pour déchiffrer : on les essaie toutes).
    static func allSymmetricKeys() -> [SymmetricKey] {
        keys.compactMap { try? BrocolisCrypto.symmetricKey(fromBase64: $0.base64) }
    }

    /// Compat : remplace la clé sélectionnée, ou crée « Ma clé » s'il n'y en a pas.
    static func setKey(_ base64: String) {
        let trimmed = base64.trimmingCharacters(in: .whitespacesAndNewlines)
        if let sel = selectedKey {
            var ks = loadKeysAfterMigration()
            if let i = ks.firstIndex(where: { $0.id == sel.id }) {
                ks[i] = NamedKey(id: sel.id, name: sel.name, base64: trimmed)
                saveKeys(ks)
            }
            setKeyExpiresAt(computeExpiry(ttlSeconds: keyTTLSeconds, from: Date()))
        } else {
            addKey(name: "Ma clé", base64: trimmed)
        }
    }

    /// Supprime la clé sélectionnée (compat « Supprimer la clé »).
    static func clearKey() {
        if let sel = selectedKey { deleteKey(id: sel.id) }
        defaults?.removeObject(forKey: fingerprintName)
        defaults?.removeObject(forKey: expiresAtName)
    }

    // MARK: État « Actif »

    static var isActive: Bool {
        (defaults?.bool(forKey: activeName) ?? false) && hasKey
    }

    static func setActive(_ value: Bool) {
        defaults?.set(value, forKey: activeName)
    }

    // MARK: Appairage automatique (X25519)

    /// URL du serveur de rendez-vous. Par défaut : l'instance Heroku du projet.
    static let defaultServerURL = "https://brocolismessageriesiphone-de6b42e2c835.herokuapp.com"

    static var serverURL: String {
        defaults?.string(forKey: serverURLName) ?? defaultServerURL
    }

    static func setServerURL(_ value: String) {
        defaults?.set(value.trimmingCharacters(in: .whitespacesAndNewlines), forKey: serverURLName)
    }

    /// Clé privée X25519 locale (base64), persistée entre les appairages.
    static var privateKeyBase64: String? {
        defaults?.string(forKey: privateKeyName)
    }

    static func setPrivateKeyBase64(_ value: String) {
        defaults?.set(value, forKey: privateKeyName)
    }

    /// Empreinte du dernier appairage réussi (à comparer avec le correspondant).
    static var pairingFingerprint: String? {
        defaults?.string(forKey: fingerprintName)
    }

    static func setPairingFingerprint(_ value: String?) {
        if let value {
            defaults?.set(value, forKey: fingerprintName)
        } else {
            defaults?.removeObject(forKey: fingerprintName)
        }
    }

    // MARK: Rotation / expiration de la clé

    /// Durée de validité choisie, en secondes (0 = jamais d'expiration).
    static var keyTTLSeconds: Int {
        defaults?.integer(forKey: ttlName) ?? 0
    }

    /// Définit le TTL et réapplique l'expiration à la clé courante.
    static func setKeyTTL(_ seconds: Int) {
        defaults?.set(max(0, seconds), forKey: ttlName)
        reapplyExpiry()
    }

    /// Date d'expiration de la clé courante (nil = pas d'expiration).
    static var keyExpiresAt: Date? {
        guard let d = defaults, d.object(forKey: expiresAtName) != nil else { return nil }
        let t = d.double(forKey: expiresAtName)
        return t > 0 ? Date(timeIntervalSince1970: t) : nil
    }

    private static func setKeyExpiresAt(_ date: Date?) {
        if let date {
            defaults?.set(date.timeIntervalSince1970, forKey: expiresAtName)
        } else {
            defaults?.removeObject(forKey: expiresAtName)
        }
    }

    /// La clé courante est-elle expirée ?
    static var isExpired: Bool {
        isExpired(expiresAt: keyExpiresAt, now: Date())
    }

    /// Recalcule l'expiration de la clé courante à partir du TTL.
    static func reapplyExpiry() {
        guard hasKey else { setKeyExpiresAt(nil); return }
        setKeyExpiresAt(computeExpiry(ttlSeconds: keyTTLSeconds, from: Date()))
    }

    /// Si la clé sélectionnée est expirée, l'efface (et désactive si plus de clé).
    @discardableResult
    static func purgeExpiredKey() -> Bool {
        guard hasKey, isExpired else { return false }
        clearKey()
        return true
    }

    // MARK: Helpers purs (testables, sans App Group)

    static func computeExpiry(ttlSeconds: Int, from now: Date) -> Date? {
        ttlSeconds > 0 ? now.addingTimeInterval(TimeInterval(ttlSeconds)) : nil
    }

    static func isExpired(expiresAt: Date?, now: Date) -> Bool {
        guard let expiresAt else { return false }
        return now >= expiresAt
    }

    static func notificationLead(ttlSeconds: Int) -> TimeInterval? {
        guard ttlSeconds > 0 else { return nil }
        return min(3600, TimeInterval(ttlSeconds) / 2)
    }

    static func noticeFireDate(expiresAt: Date?, ttlSeconds: Int, now: Date) -> Date? {
        guard let expiresAt, let lead = notificationLead(ttlSeconds: ttlSeconds) else { return nil }
        let fire = expiresAt.addingTimeInterval(-lead)
        return fire > now ? fire : nil
    }
}
