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

    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: appGroup)
    }

    static var keyBase64: String? {
        defaults?.string(forKey: keyName)
    }

    static var hasKey: Bool { keyBase64 != nil }

    static func setKey(_ base64: String) {
        defaults?.set(base64.trimmingCharacters(in: .whitespacesAndNewlines), forKey: keyName)
    }

    static func clearKey() {
        defaults?.removeObject(forKey: keyName)
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


    /// Clé utilisable, ou `nil` si absente/invalide.
    static func symmetricKey() -> SymmetricKey? {
        guard let b64 = keyBase64 else { return nil }
        return try? BrocolisCrypto.symmetricKey(fromBase64: b64)
    }
}
