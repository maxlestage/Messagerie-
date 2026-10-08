//
//  BrocolisPlan.swift
//  Brocolis 🥦 (partagé)
//
//  Ce qui est gratuit, ce que chaque palier ouvre, et les identifiants des deux
//  abonnements. La DÉCISION est ici, pure et testable ; l'achat lui-même vit
//  dans `BrocolisStore` (StoreKit, app seulement).
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
//     en créer une onzième sans abonnement.
//

import Foundation

/// Les paliers, du moins au plus ouvert. L'ordre compte : `>=` sert à décider.
enum BrocolisTier: Int, Comparable, CaseIterable {
    case free = 0
    /// Clés illimitées et expiration automatique — ne coûte presque rien à servir.
    case plus = 1
    /// En plus : envoi de photos et de vocaux — là où le serveur paie vraiment.
    case pro = 2

    static func < (a: BrocolisTier, b: BrocolisTier) -> Bool { a.rawValue < b.rawValue }
}

/// Ce qu'une action réclame comme droit.
enum BrocolisGate: Equatable {
    case allowed
    /// Refusé, avec le palier minimal qui l'ouvrirait et la raison à montrer.
    case needs(BrocolisTier, BrocolisPaidFeature)

    var isAllowed: Bool { self == .allowed }
}

/// Les fonctions qu'ouvre un abonnement. Sert aussi à dire à l'utilisateur
/// POURQUOI on lui propose de payer, au lieu d'un mur générique.
enum BrocolisPaidFeature: String, Equatable, CaseIterable, Identifiable {
    var id: String { rawValue }

    /// Au-delà des clés offertes.
    case moreKeys
    /// Faire expirer une clé automatiquement.
    case keyExpiry
    /// Envoyer une photo chiffrée.
    case photo
    /// Envoyer un message vocal chiffré.
    case voiceNote

    /// Le palier minimal qui ouvre cette fonction.
    var requiredTier: BrocolisTier {
        switch self {
        case .moreKeys, .keyExpiry: return .plus
        case .photo, .voiceNote:    return .pro
        }
    }
}

enum BrocolisPlan {

    // MARK: Les deux offres — deux abonnements mensuels

    /// Identifiants des produits App Store. Doivent correspondre EXACTEMENT à
    /// ceux créés dans App Store Connect, sinon StoreKit ne renvoie rien.
    /// Voir docs/ios-achats-integres.md.
    static let plusProductId = "rs.brocolis.messagerie.plus.monthly"
    static let proProductId = "rs.brocolis.messagerie.pro.monthly"

    /// L'ordre d'affichage dans l'écran d'offres : du moins cher au plus cher.
    static let productIds = [plusProductId, proProductId]

    /// Le palier qu'ouvre un produit acheté. `nil` pour un identifiant inconnu
    /// — on ne débloque jamais sur un produit qu'on ne reconnaît pas.
    static func tier(forProductId id: String) -> BrocolisTier? {
        switch id {
        case plusProductId: return .plus
        case proProductId:  return .pro
        default:            return nil
        }
    }

    // MARK: Ce qui est offert

    /// Nombre de correspondants sans payer. Généreux à dessein : on veut que
    /// l'app soit réellement utilisable gratuitement, pas une démo.
    static let freeKeyLimit = 3

    // MARK: Palier courant — deux sources, jamais mélangées

    private static let purchasedName = "plan_tier"
    private static let grantedName = "plan_granted_tier"

    /// Ce que l'App Store accorde. `BrocolisStore` est seul à l'écrire, et
    /// toujours d'après `Transaction.currentEntitlements`.
    static var purchasedTier: BrocolisTier {
        get { storedTier(purchasedName) }
        set { BrocolisKeyStore.sharedDefaults?.set(newValue.rawValue, forKey: purchasedName) }
    }

    /// Ce que le SERVEUR offre (liste `BROCOLIS_PRO_IDS`, voir
    /// docs/acces-offerts.md). Sert aux comptes de l'auteur et de ses proches.
    /// Rangé séparément : un rafraîchissement StoreKit ne doit jamais l'effacer,
    /// ni l'inverse.
    static var grantedTier: BrocolisTier {
        get { storedTier(grantedName) }
        set { BrocolisKeyStore.sharedDefaults?.set(newValue.rawValue, forKey: grantedName) }
    }

    /// E-mail Apple rattaché à cet appareil par « Se connecter avec Apple »
    /// (accès offert par `BROCOLIS_PRO_EMAILS`), tel que le serveur l'a vu.
    static var linkedEmail: String? {
        get { BrocolisKeyStore.sharedDefaults?.string(forKey: "plan_linked_email") }
        set { BrocolisKeyStore.sharedDefaults?.set(newValue, forKey: "plan_linked_email") }
    }

    private static func storedTier(_ key: String) -> BrocolisTier {
        let raw = BrocolisKeyStore.sharedDefaults?.integer(forKey: key) ?? 0
        return BrocolisTier(rawValue: raw) ?? .free
    }

    /// Traduit le nom renvoyé par le serveur (`/v1/plan`). `nil` pour un nom
    /// inconnu — un serveur plus récent que l'app ne doit rien débloquer par
    /// surprise.
    static func tier(forServerName name: String) -> BrocolisTier? {
        switch name {
        case "free": return .free
        case "plus": return .plus
        case "pro":  return .pro
        default:     return nil
        }
    }

    /// Le palier qui s'applique réellement. Pur, donc testable.
    /// Le plus ouvert des deux l'emporte : un accès offert ne retire rien à
    /// qui a payé, et un abonnement ne retire rien à qui a reçu un accès.
    static func effectiveTier(purchased: BrocolisTier, granted: BrocolisTier) -> BrocolisTier {
        max(purchased, granted)
    }

    /// Palier appliqué partout dans l'app. Lecture seule : il se déduit des
    /// deux sources, on ne l'écrit jamais directement.
    static var tier: BrocolisTier {
        effectiveTier(purchased: purchasedTier, granted: grantedTier)
    }

    // MARK: Décisions — pures, sans état global, donc testables

    /// Porte générique : la fonction est-elle ouverte à ce palier ?
    static func gate(for feature: BrocolisPaidFeature, tier: BrocolisTier) -> BrocolisGate {
        tier >= feature.requiredTier ? .allowed : .needs(feature.requiredTier, feature)
    }

    /// Ajouter une clé. La limite porte sur l'ajout, jamais sur l'existant :
    /// un trousseau déjà au-dessus de la limite reste intact.
    static func gateForAddingKey(currentKeyCount: Int, tier: BrocolisTier) -> BrocolisGate {
        if currentKeyCount < freeKeyLimit { return .allowed }
        return gate(for: .moreKeys, tier: tier)
    }

    /// Envoyer une photo chiffrée.
    static func gateForSendingPhoto(tier: BrocolisTier) -> BrocolisGate {
        gate(for: .photo, tier: tier)
    }

    /// Envoyer un message vocal chiffré.
    static func gateForSendingVoiceNote(tier: BrocolisTier) -> BrocolisGate {
        gate(for: .voiceNote, tier: tier)
    }

    /// Donner une durée de vie à une clé. `ttlSeconds == 0` = pas d'expiration,
    /// donc toujours gratuit : on ne fait pas payer pour NE PAS utiliser une
    /// fonction.
    static func gateForKeyExpiry(ttlSeconds: Int, tier: BrocolisTier) -> BrocolisGate {
        if ttlSeconds <= 0 { return .allowed }
        return gate(for: .keyExpiry, tier: tier)
    }

    /// Recevoir et déchiffrer : TOUJOURS gratuit, quel que soit le contenu et
    /// le palier. Exposé en fonction (plutôt qu'en commentaire) pour qu'un test
    /// le fige.
    static func gateForReceiving() -> BrocolisGate { .allowed }
}
