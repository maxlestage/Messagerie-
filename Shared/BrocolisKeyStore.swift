//
//  BrocolisKeyStore.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Gère PLUSIEURS clés nommées (chacune avec sa propre validité/expiration),
//  partagées via l'App Group. La clé « sélectionnée » chiffre ; au déchiffrement
//  l'extension essaie TOUTES les clés.
//
//  Note sécurité : les SECRETS (la liste des clés, la clé privée X25519) sont
//  rangés dans le TROUSSEAU iOS — partagé entre l'app et ses extensions par le
//  groupe d'accès de l'App Group, lisible après le premier déverrouillage
//  (le clavier et les extensions en ont besoin en arrière-plan), et JAMAIS
//  synchronisé sur iCloud ni restauré sur un autre appareil
//  (`…ThisDeviceOnly`). Les réglages non secrets (sélection, « Actif »,
//  validités…) restent dans les `UserDefaults` de l'App Group.
//
//  Les versions précédentes gardaient ces secrets en clair dans les
//  `UserDefaults` : ils sont déplacés dans le Trousseau au premier accès (cf.
//  `BrocolisSecretStore`), et effacés de l'ancien emplacement SEULEMENT une
//  fois l'écriture dans le Trousseau réussie.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Security)
import Security
#endif

/// Une clé nommée, avec sa durée de validité propre.
struct NamedKey: Identifiable, Equatable {
    let id: String
    var name: String
    let base64: String
    var ttlSeconds: Int     // 0 = jamais d'expiration
    var expiresAt: Date?    // calculée à l'ajout / au changement de TTL

    // v3 (docs/SECURITE.md §8.4, §8.5) — données PUBLIQUES, rangées avec la
    // clé : le paquet de clés du correspondant reçu à l'appairage (base64)
    // et sa date d'arrivée ; `duo` : appairés à deux (`true`) ou clé de
    // groupe (`false`, jamais de v3), inconnu (`nil`) pour une clé créée ou
    // importée ; `psk` : l'utilisateur l'a marquée « à deux, double cliquet ».
    var v3Bundle: String?
    var v3Since: Date?
    var duo: Bool?
    var psk: Bool?
    // v4 (§9.6) — PUBLIQUE aussi : la capacité v4 signée du correspondant
    // (base64, 64 octets), reçue avec son paquet.
    var v3Caps: String?
    // §9.8 : l'identité (IK X25519 ‖ IK Ed25519, base64) qu'avait ce contact
    // avant un ré-appairage qui en a donné une autre, et l'alerte en attente
    // (rien ne part vers lui avant « J'ai comparé l'empreinte »).
    var v3PreviousIdentity: String?
    var identityChanged: Bool?

    init(
        id: String = UUID().uuidString,
        name: String,
        base64: String,
        ttlSeconds: Int = 0,
        expiresAt: Date? = nil,
        v3Bundle: String? = nil,
        v3Since: Date? = nil,
        duo: Bool? = nil,
        psk: Bool? = nil,
        v3Caps: String? = nil,
        v3PreviousIdentity: String? = nil,
        identityChanged: Bool? = nil
    ) {
        self.id = id
        self.name = name
        self.base64 = base64
        self.ttlSeconds = ttlSeconds
        self.expiresAt = expiresAt
        self.v3Bundle = v3Bundle
        self.v3Since = v3Since
        self.duo = duo
        self.psk = psk
        self.v3Caps = v3Caps
        self.v3PreviousIdentity = v3PreviousIdentity
        self.identityChanged = identityChanged
    }
}

// Codable tolérant : les anciennes clés stockées (sans ttl/expiresAt, sans
// champs v3) restent décodables ; une ancienne version de l'app ignore les
// champs v3.
extension NamedKey: Codable {
    enum CodingKeys: String, CodingKey { case id, name, base64, ttlSeconds, expiresAt, v3Bundle, v3Since, duo, psk, v3Caps, v3PreviousIdentity, identityChanged }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        name = try c.decode(String.self, forKey: .name)
        base64 = try c.decode(String.self, forKey: .base64)
        ttlSeconds = try c.decodeIfPresent(Int.self, forKey: .ttlSeconds) ?? 0
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        v3Bundle = try c.decodeIfPresent(String.self, forKey: .v3Bundle)
        v3Since = try c.decodeIfPresent(Date.self, forKey: .v3Since)
        duo = try c.decodeIfPresent(Bool.self, forKey: .duo)
        psk = try c.decodeIfPresent(Bool.self, forKey: .psk)
        v3Caps = try c.decodeIfPresent(String.self, forKey: .v3Caps)
        v3PreviousIdentity = try c.decodeIfPresent(String.self, forKey: .v3PreviousIdentity)
        identityChanged = try c.decodeIfPresent(Bool.self, forKey: .identityChanged)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(name, forKey: .name)
        try c.encode(base64, forKey: .base64)
        try c.encode(ttlSeconds, forKey: .ttlSeconds)
        try c.encodeIfPresent(expiresAt, forKey: .expiresAt)
        try c.encodeIfPresent(v3Bundle, forKey: .v3Bundle)
        try c.encodeIfPresent(v3Since, forKey: .v3Since)
        try c.encodeIfPresent(duo, forKey: .duo)
        try c.encodeIfPresent(psk, forKey: .psk)
        try c.encodeIfPresent(v3Caps, forKey: .v3Caps)
        try c.encodeIfPresent(v3PreviousIdentity, forKey: .v3PreviousIdentity)
        try c.encodeIfPresent(identityChanged, forKey: .identityChanged)
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

    /// Stockage partagé, défini À UN SEUL ENDROIT pour toutes les cibles.
    ///
    /// Sur iOS, c'est un **App Group** : l'app, le clavier, les extensions et
    /// le widget lisent le même trousseau — ils sont plusieurs processus.
    ///
    /// Sur **watchOS il n'y a qu'un seul processus** : l'app montre n'a aucune
    /// extension avec qui partager quoi que ce soit. L'App Group n'y apportait
    /// rien, mais il imposait la capacité « App Groups » sur l'identifiant
    /// `…watchkitapp` — capacité qu'il faut déclarer à la main sur le portail
    /// Apple, et dont l'absence faisait échouer la signature de l'archive
    /// (« No profiles for 'rs.brocolis.messagerie.watchkitapp' were found »).
    /// `standard` suffit donc au poignet, et la cible n'a plus besoin
    /// d'entitlements du tout.
    static var sharedDefaults: UserDefaults? {
        #if os(watchOS)
        UserDefaults.standard
        #else
        UserDefaults(suiteName: appGroup)
        #endif
    }

    private static var defaults: UserDefaults? { sharedDefaults }

    /// Service du Trousseau propre aux secrets Brocolis.
    static let keychainService = "rs.brocolis.messagerie.secrets"

    /// Les secrets : Trousseau d'abord, ancien emplacement (`UserDefaults`) en
    /// repli. Sur iOS, groupe d'accès = l'App Group (déjà déclaré par l'app ET
    /// chaque extension : aucun nouvel entitlement). Sur watchOS, processus
    /// unique et aucun entitlement (cf. `sharedDefaults`) : Trousseau propre à
    /// l'app, sans groupe d'accès.
    static let secrets: BrocolisSecretStore = {
        #if canImport(Security)
        #if os(watchOS)
        let vault = BrocolisKeychainVault(service: keychainService, accessGroup: nil)
        #else
        let vault = BrocolisKeychainVault(service: keychainService, accessGroup: appGroup)
        #endif
        return BrocolisSecretStore(vault: vault, defaults: sharedDefaults)
        #else
        // Hors plateformes Apple (vérifications sous Linux) : pas de Trousseau,
        // on reste sur l'ancien emplacement.
        return BrocolisSecretStore(vault: BrocolisUnavailableVault(), defaults: sharedDefaults)
        #endif
    }()

    // MARK: - Liste de clés

    /// Ancienne clé unique (`shared_aes_key_b64`, d'avant les clés nommées) :
    /// versée dans la liste, puis effacée des `UserDefaults` seulement si la
    /// liste a bien été enregistrée.
    private static func migrateIfNeeded() {
        guard let d = defaults, let legacy = d.string(forKey: legacyKeyName) else { return }
        let trimmed = legacy.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            var ks = loadKeys()
            if !ks.contains(where: { $0.base64 == trimmed }) {
                let k = NamedKey(name: loc("Ma clé", "My key", "Mi clave"), base64: trimmed)
                ks.insert(k, at: 0)
                if ks.count == 1 { d.set(k.id, forKey: selectedIdName) }
                guard saveKeys(ks) else { return }
            }
        }
        d.removeObject(forKey: legacyKeyName)
    }

    private static func loadKeys() -> [NamedKey] {
        guard let data = secrets.data(keysName, merge: mergeKeysJSON),
              let arr = try? JSONDecoder().decode([NamedKey].self, from: data) else { return [] }
        return arr
    }

    /// Enregistre la liste. `false` seulement si elle n'a pu être écrite NULLE
    /// PART (ni Trousseau, ni repli).
    @discardableResult
    private static func saveKeys(_ keys: [NamedKey]) -> Bool {
        guard let data = try? JSONEncoder().encode(keys) else { return false }
        return secrets.set(data, for: keysName)
    }

    /// Fusionne la liste du Trousseau et une copie restée dans les
    /// `UserDefaults` (écrite en repli pendant que le Trousseau refusait, donc
    /// la plus RÉCENTE). Union par identifiant, la copie de repli l'emporte :
    /// une clé ajoutée pendant la panne n'écrase pas celles qu'on ne pouvait pas
    /// lire. Revers assumé : une clé supprimée pendant la panne peut revenir —
    /// mieux vaut une clé de trop qu'une clé perdue.
    static func mergeKeysJSON(stored: Data, leftover: Data) -> Data {
        let decoder = JSONDecoder()
        guard let fresh = try? decoder.decode([NamedKey].self, from: leftover) else { return stored }
        guard let old = try? decoder.decode([NamedKey].self, from: stored) else { return leftover }
        let freshIds = Set(fresh.map(\.id))
        let merged = fresh + old.filter { !freshIds.contains($0.id) }
        return (try? JSONEncoder().encode(merged)) ?? leftover
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
            name: trimmedName.isEmpty ? loc("Clé \(ks.count + 1)", "Key \(ks.count + 1)", "Clave \(ks.count + 1)") : trimmedName,
            base64: base64.trimmingCharacters(in: .whitespacesAndNewlines),
            ttlSeconds: ttl,
            expiresAt: computeExpiry(ttlSeconds: ttl, from: Date())
        )
        ks.append(key)
        saveKeys(ks)
        selectKey(key.id)
        return key.id
    }

    // MARK: v3 (docs/SECURITE.md §8.4, §8.5)

    /// Le contact v3 d'une clé appairée : le paquet du correspondant (ou
    /// `nil` : un ancien client), sa capacité v4 (§9.6, ou `nil`) et « à
    /// deux » / « en groupe ».
    static func setV3Contact(keyId id: String, bundle: String?, caps: String? = nil, duo: Bool) {
        updateKey(id) { k in
            k.v3Bundle = bundle
            k.v3Caps = bundle == nil ? nil : caps
            k.v3Since = bundle == nil ? nil : Date()
            k.duo = duo
        }
    }

    /// Remplace une clé (même identifiant) : ré-appairage d'un contact
    /// (§9.8, `BrocolisV3.repairContact`).
    static func replaceKey(_ k: NamedKey) {
        var ks = loadKeysAfterMigration()
        guard let i = ks.firstIndex(where: { $0.id == k.id }) else { return }
        ks[i] = k
        saveKeys(ks)
    }

    /// « J'ai comparé l'empreinte » : lève l'alerte de changement
    /// d'identité (§9.8) ; l'envoi vers ce contact reprend.
    static func confirmIdentity(keyId id: String) {
        updateKey(id) { k in
            k.identityChanged = nil
            k.v3PreviousIdentity = nil
        }
    }

    /// Le contact appairé à deux de ce nom (pour un ré-appairage), s'il y en
    /// a un.
    static func pairedContact(named name: String) -> NamedKey? {
        let n = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !n.isEmpty else { return nil }
        return keys.first {
            $0.v3Bundle != nil && $0.duo != false
                && $0.name.compare(n, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame
        }
    }

    /// La clé devient une clé de groupe (une deuxième personne l'a reçue) :
    /// plus jamais de v3 avec elle.
    static func markGroup(keyId id: String) {
        updateKey(id) { k in k.duo = false }
    }

    /// « À deux, double cliquet » (PSK) pour une clé sans appairage v3.
    static func setPsk(_ on: Bool, forKeyId id: String) {
        updateKey(id) { k in k.psk = on ? true : nil }
    }

    private static func updateKey(_ id: String, _ change: (inout NamedKey) -> Void) {
        var ks = loadKeysAfterMigration()
        guard let i = ks.firstIndex(where: { $0.id == id }) else { return }
        change(&ks[i])
        saveKeys(ks)
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
        setKeyPhone(nil, forKeyId: id)
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

    // MARK: - Numéro de téléphone associé à une clé (issu des Contacts)

    private static let keyPhonesName = "key_phones_json" // { keyId: numéro }

    private static func loadPhones() -> [String: String] {
        guard let data = defaults?.data(forKey: keyPhonesName),
              let dict = try? JSONDecoder().decode([String: String].self, from: data) else { return [:] }
        return dict
    }

    private static func savePhones(_ dict: [String: String]) {
        if let data = try? JSONEncoder().encode(dict) {
            defaults?.set(data, forKey: keyPhonesName)
        }
    }

    /// Numéro (normalisé) rattaché à une clé, ou `nil`.
    static func keyPhone(_ id: String) -> String? { loadPhones()[id] }

    /// Rattache (ou retire, si `nil`) un numéro à une clé.
    static func setKeyPhone(_ phone: String?, forKeyId id: String) {
        var dict = loadPhones()
        if let phone, !phone.isEmpty { dict[id] = phone } else { dict.removeValue(forKey: id) }
        savePhones(dict)
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
            addKey(name: loc("Ma clé", "My key", "Mi clave"), base64: trimmed)
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

    /// Clé privée X25519 de l'appareil : un secret, donc au Trousseau.
    static var privateKeyBase64: String? {
        guard let data = secrets.data(privateKeyName) else { return nil }
        let s = String(decoding: data, as: UTF8.self)
        return s.isEmpty ? nil : s
    }

    static func setPrivateKeyBase64(_ value: String) {
        secrets.set(Data(value.utf8), for: privateKeyName)
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

    // MARK: Synchronisation montre (WatchConnectivity)

    /// Exporte les clés telles quelles (JSON brut du stockage) pour les envoyer
    /// à l'app montre via WatchConnectivity. La montre les importe à l'identique.
    static func exportKeysJSON() -> String? {
        migrateIfNeeded()
        guard let data = secrets.data(keysName, merge: mergeKeysJSON) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Importe (côté montre) le JSON de clés reçu de l'iPhone, en remplaçant le
    /// trousseau local. La sélection suit celle de l'iPhone si fournie. Un JSON
    /// illisible est ignoré : il n'écrase pas les clés déjà présentes.
    static func importKeysJSON(_ json: String, selectedId: String?) {
        let data = Data(json.utf8)
        guard (try? JSONDecoder().decode([NamedKey].self, from: data)) != nil else { return }
        secrets.set(data, for: keysName)
        if let selectedId, !selectedId.isEmpty {
            defaults?.set(selectedId, forKey: selectedIdName)
        }
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

// MARK: - Coffre des secrets (Trousseau, avec repli sur l'ancien emplacement)

/// Résultat d'une lecture dans un coffre.
enum BrocolisVaultRead: Equatable {
    case found(Data)
    /// Le coffre répond, mais n'a rien sous ce nom.
    case notFound
    /// Le coffre ne répond pas (entitlement absent, appareil jamais
    /// déverrouillé depuis le démarrage…) : on ne sait RIEN de son contenu.
    case failed
}

/// Coffre bas niveau : le Trousseau en vrai, un coffre en mémoire en test.
protocol BrocolisSecretVault {
    func read(_ account: String) -> BrocolisVaultRead
    /// `true` si la valeur est bien enregistrée.
    func write(_ data: Data, account: String) -> Bool
    /// `true` si plus rien n'est enregistré sous ce nom (absent compris).
    @discardableResult func delete(_ account: String) -> Bool
}

/// Les secrets Brocolis : Trousseau d'abord, `UserDefaults` (ancien
/// emplacement) seulement en repli. Règle d'or : ne jamais rien perdre.
///
/// - Lecture : une valeur encore présente dans les `UserDefaults` (version
///   précédente de l'app, ou écriture de repli pendant que le Trousseau
///   refusait) est versée dans le Trousseau, puis effacée des `UserDefaults`
///   SEULEMENT si l'écriture dans le Trousseau a réussi.
/// - Écriture : Trousseau ; s'il refuse, on écrit dans les `UserDefaults`
///   plutôt que de perdre la valeur (elle migrera à la lecture suivante).
/// - Trousseau illisible : on se rabat sur l'ancien emplacement, sans rien
///   effacer.
struct BrocolisSecretStore {
    let vault: BrocolisSecretVault
    let defaults: UserDefaults?

    /// Valeur restée dans les `UserDefaults` : `Data` (liste de clés), ou
    /// `String` (clé privée X25519, JSON importé de l'iPhone par la montre).
    private func leftover(_ name: String) -> Data? {
        guard let value = defaults?.object(forKey: name) else { return nil }
        if let data = value as? Data { return data }
        if let string = value as? String { return Data(string.utf8) }
        return nil
    }

    /// Lit le secret `name`. `merge(stored:leftover:)` réconcilie une valeur du
    /// Trousseau avec une copie de repli plus récente ; par défaut, la copie de
    /// repli (la plus récente) l'emporte.
    func data(_ name: String,
              merge: (_ stored: Data, _ leftover: Data) -> Data = { _, leftover in leftover }) -> Data? {
        let old = leftover(name)
        switch vault.read(name) {
        case .found(let stored):
            guard let old else { return stored }
            let merged = merge(stored, old)
            if vault.write(merged, account: name) { defaults?.removeObject(forKey: name) }
            return merged
        case .notFound:
            guard let old else { return nil }
            if vault.write(old, account: name) { defaults?.removeObject(forKey: name) }
            return old
        case .failed:
            return old
        }
    }

    /// Enregistre le secret `name`. `false` s'il n'a pu être écrit nulle part.
    ///
    /// Si le Trousseau est ILLISIBLE, on n'y écrit pas même s'il l'accepterait :
    /// la valeur à écrire a pu être calculée sans voir son contenu (une liste
    /// de clés amputée), elle l'écraserait. Elle va dans les `UserDefaults`, et
    /// la lecture suivante la fusionnera avec ce que le Trousseau contient.
    @discardableResult
    func set(_ data: Data, for name: String) -> Bool {
        if vault.read(name) != .failed, vault.write(data, account: name) {
            defaults?.removeObject(forKey: name)
            return true
        }
        guard let defaults else { return false }
        defaults.set(data, forKey: name)
        return true
    }

    /// Efface le secret `name` des DEUX emplacements.
    func remove(_ name: String) {
        vault.delete(name)
        defaults?.removeObject(forKey: name)
    }
}

/// Coffre toujours indisponible (hors plateformes Apple) : tout reste dans
/// l'ancien emplacement.
struct BrocolisUnavailableVault: BrocolisSecretVault {
    func read(_ account: String) -> BrocolisVaultRead { .failed }
    func write(_ data: Data, account: String) -> Bool { false }
    @discardableResult func delete(_ account: String) -> Bool { false }
}

#if canImport(Security)
/// Le Trousseau iOS / watchOS : mots de passe génériques d'un service dédié,
/// lisibles après le premier déverrouillage, jamais synchronisés ni restaurés
/// sur un autre appareil.
struct BrocolisKeychainVault: BrocolisSecretVault {
    let service: String
    /// Groupe d'accès partagé (l'App Group sur iOS) ; `nil` = celui de l'app.
    let accessGroup: String?

    private func query(_ account: String) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    func read(_ account: String) -> BrocolisVaultRead {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { return .failed }
            return .found(data)
        case errSecItemNotFound:
            return .notFound
        default:
            return .failed
        }
    }

    func write(_ data: Data, account: String) -> Bool {
        let q = query(account)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        var status = SecItemUpdate(q as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var add = q
            for (k, v) in attributes { add[k] = v }
            status = SecItemAdd(add as CFDictionary, nil)
        }
        return status == errSecSuccess
    }

    @discardableResult
    func delete(_ account: String) -> Bool {
        let status = SecItemDelete(query(account) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
#endif

/// Localisation par CODE, adaptée à la langue du téléphone, avec REPLI ANGLAIS.
/// Français et espagnol sont traduits ; toute autre langue retombe sur l'anglais.
/// Utilisé dans toute l'app et les extensions (défini dans un fichier partagé).
///
///   Text(loc("Bonjour", "Hello", "Hola"))
///
/// L'interpolation fonctionne dans chaque variante : loc("Salut \(n)", …).
func loc(_ fr: String, _ en: String, _ es: String) -> String {
    switch String((Locale.preferredLanguages.first ?? "en").prefix(2)).lowercased() {
    case "fr": return fr
    case "es": return es
    default:   return en
    }
}

// MARK: - Réglages du clavier Brocolis

/// Choix du clavier, réglés dans l'app et lus par l'extension clavier (App
/// Group). Chaque valeur a un défaut sensé si rien n'a été choisi.
enum BrocolisKeyboardPrefs {
    enum Haptics: Int, CaseIterable, Identifiable {
        case off, light, medium, strong
        var id: Int { rawValue }
        var title: String {
            switch self {
            case .off: return loc("Aucune", "None", "Ninguna")
            case .light: return loc("Légères", "Light", "Ligeras")
            case .medium: return loc("Moyennes", "Medium", "Medias")
            case .strong: return loc("Fortes", "Strong", "Fuertes")
            }
        }
    }

    enum Layout: Int, CaseIterable, Identifiable {
        case azerty, qwerty, qwertz
        var id: Int { rawValue }
        var title: String { ["AZERTY", "QWERTY", "QWERTZ"][rawValue] }
    }

    enum KeySize: Int, CaseIterable, Identifiable {
        case compact, normal, large
        var id: Int { rawValue }
        var title: String {
            switch self {
            case .compact: return loc("Compactes", "Compact", "Compactas")
            case .normal: return loc("Normales", "Normal", "Normales")
            case .large: return loc("Grandes", "Large", "Grandes")
            }
        }
        var height: CGFloat { [36, 42, 50][rawValue] }
    }

    private static var d: UserDefaults? { BrocolisKeyStore.sharedDefaults }

    private static func int(_ key: String, _ fallback: Int) -> Int {
        guard let d, d.object(forKey: key) != nil else { return fallback }
        return d.integer(forKey: key)
    }

    private static func bool(_ key: String, _ fallback: Bool) -> Bool {
        guard let d, d.object(forKey: key) != nil else { return fallback }
        return d.bool(forKey: key)
    }

    static var haptics: Haptics {
        get { Haptics(rawValue: int("kb_haptics", Haptics.light.rawValue)) ?? .light }
        set { d?.set(newValue.rawValue, forKey: "kb_haptics") }
    }

    static var layout: Layout {
        get { Layout(rawValue: int("kb_layout", Layout.azerty.rawValue)) ?? .azerty }
        set { d?.set(newValue.rawValue, forKey: "kb_layout") }
    }

    static var keySize: KeySize {
        get { KeySize(rawValue: int("kb_key_size", KeySize.normal.rawValue)) ?? .normal }
        set { d?.set(newValue.rawValue, forKey: "kb_key_size") }
    }

    /// Clic sonore des touches (suit aussi le réglage « Clics du clavier » d'iOS).
    static var sound: Bool {
        get { bool("kb_sound", true) }
        set { d?.set(newValue, forKey: "kb_sound") }
    }

    static var autoCapitalize: Bool {
        get { bool("kb_autocap", true) }
        set { d?.set(newValue, forKey: "kb_autocap") }
    }

    /// Double espace → « . ».
    static var doubleSpacePeriod: Bool {
        get { bool("kb_double_space", true) }
        set { d?.set(newValue, forKey: "kb_double_space") }
    }

    enum Theme: Int, CaseIterable, Identifiable {
        case system, brocoli, light, dark
        var id: Int { rawValue }
        var title: String {
            switch self {
            case .system: return loc("Système", "System", "Sistema")
            case .brocoli: return loc("Brocoli 🥦", "Broccoli 🥦", "Brócoli 🥦")
            case .light: return loc("Clair", "Light", "Claro")
            case .dark: return loc("Sombre", "Dark", "Oscuro")
            }
        }
    }

    static var theme: Theme {
        get { Theme(rawValue: int("kb_theme", Theme.system.rawValue)) ?? .system }
        set { d?.set(newValue.rawValue, forKey: "kb_theme") }
    }

    /// Glisser sur la barre d'espace déplace le curseur.
    static var spaceCursor: Bool {
        get { bool("kb_space_cursor", true) }
        set { d?.set(newValue, forKey: "kb_space_cursor") }
    }

    /// Appui long sur une lettre → ses accents (e → é è ê ë…).
    static var longPressAccents: Bool {
        get { bool("kb_long_accents", true) }
        set { d?.set(newValue, forKey: "kb_long_accents") }
    }

    /// Touche 😀 (page d'emojis) sur la rangée du bas.
    static var emojiKey: Bool {
        get { bool("kb_emoji", true) }
        set { d?.set(newValue, forKey: "kb_emoji") }
    }

    /// Le menu ⚙️ du clavier fait défiler chaque réglage à la valeur suivante.
    static func cycle<T: CaseIterable & Equatable>(_ value: T) -> T {
        let all = Array(T.allCases)
        let i = all.firstIndex(of: value) ?? 0
        return all[(i + 1) % all.count]
    }

    /// Accents (é è / ê â / û ü) sur la rangée du bas.
    static var accentKeys: Bool {
        get { bool("kb_accents", true) }
        set { d?.set(newValue, forKey: "kb_accents") }
    }
}
