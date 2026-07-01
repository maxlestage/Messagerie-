//
//  BrocolisKeyStore.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Gère PLUSIEURS clés nommées (chacune avec sa propre validité/expiration),
//  partagées via l'App Group. La clé « sélectionnée » chiffre ; au déchiffrement
//  l'extension essaie TOUTES les clés.
//
//  Note sécurité : pour la démo, `UserDefaults` de l'App Group. Les clés ne
//  quittent jamais l'appareil. En production, préférer un Trousseau partagé.
//

import Foundation
import CryptoKit

/// Une clé nommée, avec sa durée de validité propre.
struct NamedKey: Identifiable, Equatable {
    let id: String
    var name: String
    let base64: String
    var ttlSeconds: Int     // 0 = jamais d'expiration
    var expiresAt: Date?    // calculée à l'ajout / au changement de TTL

    init(
        id: String = UUID().uuidString,
        name: String,
        base64: String,
        ttlSeconds: Int = 0,
        expiresAt: Date? = nil
    ) {
        self.id = id
        self.name = name
        self.base64 = base64
        self.ttlSeconds = ttlSeconds
        self.expiresAt = expiresAt
    }
}

// Codable tolérant : les anciennes clés stockées (sans ttl/expiresAt) restent
// décodables.
extension NamedKey: Codable {
    enum CodingKeys: String, CodingKey { case id, name, base64, ttlSeconds, expiresAt }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        base64 = try c.decode(String.self, forKey: .base64)
        ttlSeconds = try c.decodeIfPresent(Int.self, forKey: .ttlSeconds) ?? 0
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(base64, forKey: .base64)
        try c.encode(ttlSeconds, forKey: .ttlSeconds)
        try c.encodeIfPresent(expiresAt, forKey: .expiresAt)
    }
}

enum BrocolisKeyStore {

    /// ⚠️ Doit correspondre à l'App Group activé sur l'app ET l'extension.
    static let appGroup = "group.rs.brocolis.messagerie"

    private static let legacyKeyName = "shared_aes_key_b64"
    private static let keysName = "keys_json"
    private static let selectedIdName = "selected_key_id"
    private static let activeName = "is_active"
    private static let encryptWholeName = "encrypt_whole_always"
    private static let privateKeyName = "x25519_private_b64"
    private static let fingerprintName = "pairing_fingerprint"
    private static let recipientIdsName = "recipient_key_ids"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroup)
    }

    // MARK: - Liste de clés

    private static func migrateIfNeeded() {
        guard let d = defaults, d.data(forKey: keysName) == nil else { return }
        var initial: [NamedKey] = []
        if let legacy = d.string(forKey: legacyKeyName), !legacy.isEmpty {
            let k = NamedKey(name: "Ma clé", base64: legacy)
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

    private static func loadKeysAfterMigration() -> [NamedKey] {
        migrateIfNeeded()
        return loadKeys()
    }

    /// Toutes les clés enregistrées.
    static var keys: [NamedKey] {
        migrateIfNeeded()
        return loadKeys()
    }

    static var selectedKeyId: String? { defaults?.string(forKey: selectedIdName) }

    static var selectedKey: NamedKey? {
        let ks = keys
        if let id = selectedKeyId, let k = ks.first(where: { $0.id == id }) { return k }
        return ks.first
    }

    static func selectKey(_ id: String) {
        defaults?.set(id, forKey: selectedIdName)
    }

    /// Ajoute une clé nommée (avec sa durée de validité), la sélectionne.
    @discardableResult
    static func addKey(name: String, base64: String, ttlSeconds: Int = 0) -> String {
        var ks = loadKeysAfterMigration()
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let ttl = max(0, ttlSeconds)
        let key = NamedKey(
            name: trimmedName.isEmpty ? "Clé \(ks.count + 1)" : trimmedName,
            base64: base64.trimmingCharacters(in: .whitespacesAndNewlines),
            ttlSeconds: ttl,
            expiresAt: computeExpiry(ttlSeconds: ttl, from: Date())
        )
        ks.append(key)
        saveKeys(ks)
        selectKey(key.id)
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
                setActive(false)
            }
        }
    }

    // MARK: - Accès clé (compat + usage)

    static var hasKey: Bool { !keys.isEmpty }
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

    // MARK: - Destinataires multiples (chiffrement pour plusieurs clés)

    /// IDs des clés destinataires choisies pour le CHIFFREMENT. Vide ⇒ on chiffre
    /// pour la seule clé sélectionnée (comportement historique). On filtre les
    /// ids qui ne correspondent plus à une clé existante.
    static var recipientKeyIds: [String] {
        guard let data = defaults?.data(forKey: recipientIdsName),
              let arr = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        let existing = Set(keys.map { $0.id })
        return arr.filter { existing.contains($0) }
    }

    static func setRecipientKeyIds(_ ids: [String]) {
        if ids.isEmpty {
            defaults?.removeObject(forKey: recipientIdsName)
        } else if let data = try? JSONEncoder().encode(ids) {
            defaults?.set(data, forKey: recipientIdsName)
        }
    }

    /// Les clés NOMMÉES retenues pour chiffrer (hors clés expirées). Repli sur la
    /// clé sélectionnée si aucun destinataire multiple n'est choisi.
    static func encryptionNamedKeys() -> [NamedKey] {
        let ids = recipientKeyIds
        let chosen: [NamedKey]
        if ids.isEmpty {
            chosen = selectedKey.map { [$0] } ?? []
        } else {
            let byId = Dictionary(keys.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
            chosen = ids.compactMap { byId[$0] }
        }
        let now = Date()
        return chosen.filter { !isExpired(expiresAt: $0.expiresAt, now: now) }
    }

    /// Clés symétriques pour CHIFFRER (multi-destinataire si plusieurs).
    static func encryptionKeys() -> [SymmetricKey] {
        encryptionNamedKeys().compactMap { try? BrocolisCrypto.symmetricKey(fromBase64: $0.base64) }
    }

    /// Y a-t-il au moins une clé valable (non expirée) parmi les destinataires
    /// choisis ? Sert à distinguer « aucune clé » de « toutes expirées ».
    static var hasUsableEncryptionKey: Bool { !encryptionNamedKeys().isEmpty }

    /// Compat : remplace la clé sélectionnée, ou crée « Ma clé ».
    static func setKey(_ base64: String) {
        let trimmed = base64.trimmingCharacters(in: .whitespacesAndNewlines)
        if let sel = selectedKey {
            var ks = loadKeysAfterMigration()
            if let i = ks.firstIndex(where: { $0.id == sel.id }) {
                ks[i] = NamedKey(id: sel.id, name: sel.name, base64: trimmed,
                                 ttlSeconds: sel.ttlSeconds,
                                 expiresAt: computeExpiry(ttlSeconds: sel.ttlSeconds, from: Date()))
                saveKeys(ks)
            }
        } else {
            addKey(name: "Ma clé", base64: trimmed)
        }
    }

    /// Supprime la clé sélectionnée (compat « Supprimer la clé »).
    static func clearKey() {
        if let sel = selectedKey { deleteKey(id: sel.id) }
        defaults?.removeObject(forKey: fingerprintName)
    }

    // MARK: État « Actif »

    static var isActive: Bool {
        (defaults?.bool(forKey: activeName) ?? false) && hasKey
    }

    static func setActive(_ value: Bool) {
        defaults?.set(value, forKey: activeName)
    }

    // MARK: Réglage « Tout chiffrer »

    /// Si vrai, l'extension chiffre TOUTE la sélection d'un bloc (sans avoir à
    /// marquer le texte avec `((…))`). Activé par défaut.
    static var encryptWholeAlways: Bool {
        guard let d = defaults else { return true }
        if d.object(forKey: encryptWholeName) == nil { return true }
        return d.bool(forKey: encryptWholeName)
    }

    static func setEncryptWholeAlways(_ value: Bool) {
        defaults?.set(value, forKey: encryptWholeName)
    }

    // MARK: Appairage automatique (X25519)

    /// URL du serveur de rendez-vous, en dur : l'instance Heroku du projet.
    static let serverURL = "https://brocolis-serveur-839b43057467.herokuapp.com"

    static var privateKeyBase64: String? {
        defaults?.string(forKey: privateKeyName)
    }

    static func setPrivateKeyBase64(_ value: String) {
        defaults?.set(value, forKey: privateKeyName)
    }

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

    // MARK: Push token de Live Activity (mises à jour à distance)

    // Clé sous laquelle l'app dépose le push token de la Live Activity (cf.
    // BrocolisLiveActivity). Chaîne en dur : ce type est partagé avec les
    // extensions, il ne peut pas référencer un symbole propre à l'app.
    private static let pushTokenName = "live_activity_push_token"
    private static let pairingCodeName = "pairing_code"
    private static let pairingPeerIdName = "pairing_peer_id"

    /// Push token courant de la Live Activity, à enregistrer côté serveur.
    static var liveActivityPushToken: String? {
        defaults?.string(forKey: pushTokenName)
    }

    /// Code + peerId du dernier appairage : sert à enregistrer le push token.
    static var pairingCode: String? { defaults?.string(forKey: pairingCodeName) }
    static var pairingPeerId: String? { defaults?.string(forKey: pairingPeerIdName) }

    static func setPairingIdentity(code: String, peerId: String) {
        defaults?.set(code, forKey: pairingCodeName)
        defaults?.set(peerId, forKey: pairingPeerIdName)
    }

    // peerId des CORRESPONDANTS appairés (ceux qu'on peut notifier via /update).
    private static let pairingPeerIdsName = "pairing_peer_ids"

    static var pairingPeerIds: [String] {
        guard let data = defaults?.data(forKey: pairingPeerIdsName),
              let arr = try? JSONDecoder().decode([String].self, from: data) else { return [] }
        return arr
    }

    static func setPairingPeerIds(_ ids: [String]) {
        if ids.isEmpty {
            defaults?.removeObject(forKey: pairingPeerIdsName)
        } else if let data = try? JSONEncoder().encode(ids) {
            defaults?.set(data, forKey: pairingPeerIdsName)
        }
    }

    // MARK: Validité / expiration — PAR CLÉ

    static func keyTTLSeconds(_ id: String) -> Int {
        keys.first(where: { $0.id == id })?.ttlSeconds ?? 0
    }

    /// Définit la validité d'une clé et recalcule son expiration (à partir de maintenant).
    static func setKeyTTL(_ seconds: Int, forKeyId id: String) {
        var ks = loadKeysAfterMigration()
        if let i = ks.firstIndex(where: { $0.id == id }) {
            let ttl = max(0, seconds)
            ks[i].ttlSeconds = ttl
            ks[i].expiresAt = computeExpiry(ttlSeconds: ttl, from: Date())
            saveKeys(ks)
        }
    }

    static func keyExpiresAt(_ id: String) -> Date? {
        keys.first(where: { $0.id == id })?.expiresAt
    }

    static func isKeyExpired(_ id: String) -> Bool {
        isExpired(expiresAt: keyExpiresAt(id), now: Date())
    }

    /// Réarme la validité d'une clé (renouvellement « Prolonger »).
    static func reapplyExpiry(forKeyId id: String) {
        var ks = loadKeysAfterMigration()
        if let i = ks.firstIndex(where: { $0.id == id }) {
            ks[i].expiresAt = computeExpiry(ttlSeconds: ks[i].ttlSeconds, from: Date())
            saveKeys(ks)
        }
    }

    /// La clé SÉLECTIONNÉE est-elle expirée ? (compat extension)
    static var isExpired: Bool {
        guard let sel = selectedKey else { return false }
        return isExpired(expiresAt: sel.expiresAt, now: Date())
    }

    /// Supprime TOUTES les clés expirées. Renvoie `true` si au moins une l'a été.
    @discardableResult
    static func purgeExpiredKey() -> Bool {
        let ks = loadKeysAfterMigration()
        let now = Date()
        let kept = ks.filter { !isExpired(expiresAt: $0.expiresAt, now: now) }
        guard kept.count != ks.count else { return false }
        saveKeys(kept)
        if let sel = selectedKeyId, !kept.contains(where: { $0.id == sel }) {
            if let first = kept.first { selectKey(first.id) }
            else { defaults?.removeObject(forKey: selectedIdName) }
        }
        if kept.isEmpty { setActive(false) }
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
