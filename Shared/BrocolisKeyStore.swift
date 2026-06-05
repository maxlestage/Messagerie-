//
//  BrocolisKeyStore.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  La clé symétrique partagée est stockée dans le conteneur de l'App Group, ce
//  qui la rend lisible à la fois par l'app hôte (où on la génère/importe) et par
//  l'Action Extension (qui chiffre/déchiffre dans les autres apps).
//
//  Note sécurité : pour un usage de démonstration, on utilise les
//  `UserDefaults` de l'App Group. La clé ne quitte jamais l'appareil. Pour un
//  usage en production, préférer un groupe d'accès Trousseau (Keychain) partagé.
//

import Foundation
import CryptoKit

enum BrocolisKeyStore {

    /// ⚠️ Doit correspondre à l'App Group activé sur l'app ET l'extension.
    static let appGroup = "group.rs.brocolis.messagerie"
    private static let keyName = "shared_aes_key_b64"
    private static let activeName = "is_active"
    private static let serverURLName = "rendezvous_server_url"
    private static let privateKeyName = "x25519_private_b64"
    private static let fingerprintName = "pairing_fingerprint"
    private static let ttlName = "key_ttl_seconds"
    private static let expiresAtName = "key_expires_at"

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroup)
    }

    static var keyBase64: String? {
        defaults?.string(forKey: keyName)
    }

    static var hasKey: Bool { keyBase64 != nil }

    static func setKey(_ base64: String) {
        defaults?.set(base64.trimmingCharacters(in: .whitespacesAndNewlines), forKey: keyName)
        // Une nouvelle clé réarme l'horloge d'expiration selon le TTL choisi.
        setKeyExpiresAt(computeExpiry(ttlSeconds: keyTTLSeconds, from: Date()))
    }

    static func clearKey() {
        defaults?.removeObject(forKey: keyName)
        defaults?.removeObject(forKey: fingerprintName)
        defaults?.removeObject(forKey: expiresAtName)
        // Sans clé, on ne peut pas rester actif.
        setActive(false)
    }

    // MARK: État « Actif »
    //
    // Quand `isActive == true`, l'extension chiffre/déchiffre. L'état persiste
    // (App Group) tant que l'utilisateur ne le désactive pas. Il est aussi remis
    // à `false` à la terminaison de l'app hôte (best effort, cf. AppDelegate).

    static var isActive: Bool {
        // Actif seulement si une clé est présente.
        (defaults?.bool(forKey: activeName) ?? false) && hasKey
    }

    static func setActive(_ value: Bool) {
        defaults?.set(value, forKey: activeName)
    }

    // MARK: Appairage automatique (X25519)

    /// URL du serveur de rendez-vous (ex. https://relais.example.com).
    static var serverURL: String {
        defaults?.string(forKey: serverURLName) ?? ""
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


    /// Clé utilisable, ou `nil` si absente/invalide.
    static func symmetricKey() -> SymmetricKey? {
        guard let b64 = keyBase64 else { return nil }
        return try? BrocolisCrypto.symmetricKey(fromBase64: b64)
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

    /// Si la clé courante est expirée, l'efface (et désactive Brocolis).
    /// Renvoie `true` si une purge a eu lieu. À appeler au lancement de l'app.
    @discardableResult
    static func purgeExpiredKey() -> Bool {
        guard hasKey, isExpired else { return false }
        clearKey() // efface clé + empreinte + expiration, et désactive
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
}
