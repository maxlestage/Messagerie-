//
//  BrocolisPlan.swift
//  Brocolis 🥦 (partagé)
//
//  Ce qui est gratuit, ce qui demande Brocolis+, et les identifiants des deux
//  offres App Store. La DÉCISION est ici, pure et testable ; l'achat lui-même
//  vit dans `BrocolisStore` (StoreKit, app seulement).
//
//  Trois règles qui ne doivent jamais bouger :
//
//  1. Le chiffrement reste gratuit, pour tout le monde, sans limite. C'est la
//     promesse du produit : la vendre la viderait de son sens.
//  2. RECEVOIR est toujours gratuit. Seul l'ENVOI de médias est payant — sinon
//     un abonné enverrait une photo qu'un non-abonné ne pourrait pas ouvrir, et
//     la messagerie se casserait en deux.
//  3. Aucune clé existante n'est jamais retirée. La limite ne s'applique qu'à
//     l'AJOUT : qui a déjà dix clés les garde toutes, il ne peut simplement pas
//     en créer une onzième sans Brocolis+.
//

import Foundation

/// Ce qu'une action réclame comme droit.
enum BrocolisGate: Equatable {
    case allowed
    case needsPlus(BrocolisPaidFeature)

    var isAllowed: Bool { self == .allowed }
}

/// Les fonctions qu'ouvre Brocolis+. Sert aussi à dire à l'utilisateur
/// POURQUOI on lui propose de payer, au lieu d'un mur générique.
enum BrocolisPaidFeature: String, Equatable, CaseIterable, Identifiable {
    var id: String { rawValue }

    /// Au-delà des clés offertes.
    case moreKeys
    /// Envoyer une photo chiffrée.
    case photo
    /// Envoyer un message vocal chiffré.
    case voiceNote
    /// Faire expirer une clé automatiquement.
    case keyExpiry
}

enum BrocolisPlan {

    // MARK: Les deux offres

    /// Identifiants des produits App Store. Doivent correspondre EXACTEMENT à
    /// ceux créés dans App Store Connect, sinon StoreKit ne renvoie rien.
    /// Voir docs/ios-achats-integres.md.
    static let monthlyProductId = "rs.brocolis.messagerie.plus.monthly"
    static let lifetimeProductId = "rs.brocolis.messagerie.plus.lifetime"

    /// L'ordre d'affichage dans l'écran d'offres.
    static let productIds = [monthlyProductId, lifetimeProductId]

    // MARK: Ce qui est offert

    /// Nombre de correspondants sans payer. Généreux à dessein : on veut que
    /// l'app soit réellement utilisable gratuitement, pas une démo.
    static let freeKeyLimit = 3

    // MARK: État de l'abonnement

    private static let plusName = "plan_is_plus"

    /// Vrai si Brocolis+ est actif (abonnement en cours ou achat à vie).
    /// Rangé avec le reste : App Group sur iOS, local au poignet.
    /// `BrocolisStore` est seul à l'écrire, d'après StoreKit.
    static var isPlus: Bool {
        get { BrocolisKeyStore.sharedDefaults?.bool(forKey: plusName) ?? false }
        set { BrocolisKeyStore.sharedDefaults?.set(newValue, forKey: plusName) }
    }

    // MARK: Décisions — pures, sans état global, donc testables

    /// Ajouter une clé. La limite porte sur l'ajout, jamais sur l'existant :
    /// un trousseau déjà au-dessus de la limite reste intact.
    static func gateForAddingKey(currentKeyCount: Int, isPlus: Bool) -> BrocolisGate {
        if isPlus { return .allowed }
        return currentKeyCount < freeKeyLimit ? .allowed : .needsPlus(.moreKeys)
    }

    /// Envoyer une photo chiffrée.
    static func gateForSendingPhoto(isPlus: Bool) -> BrocolisGate {
        isPlus ? .allowed : .needsPlus(.photo)
    }

    /// Envoyer un message vocal chiffré.
    static func gateForSendingVoiceNote(isPlus: Bool) -> BrocolisGate {
        isPlus ? .allowed : .needsPlus(.voiceNote)
    }

    /// Donner une durée de vie à une clé. `ttlSeconds == 0` = pas d'expiration,
    /// donc toujours gratuit : on ne fait pas payer pour NE PAS utiliser une
    /// fonction.
    static func gateForKeyExpiry(ttlSeconds: Int, isPlus: Bool) -> BrocolisGate {
        if ttlSeconds <= 0 || isPlus { return .allowed }
        return .needsPlus(.keyExpiry)
    }

    /// Recevoir et déchiffrer : TOUJOURS gratuit, quel que soit le contenu.
    /// Exposé en fonction (plutôt qu'en commentaire) pour qu'un test le fige.
    static func gateForReceiving() -> BrocolisGate { .allowed }
}
