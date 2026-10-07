//
//  BrocolisPlanTests.swift
//  BrocolisTests
//
//  Ce qui est gratuit, ce qu'ouvre chaque palier. Ces tests existent surtout
//  pour verrouiller les trois règles qu'un ajout de fonctionnalité pourrait
//  casser sans qu'on s'en aperçoive : le chiffrement gratuit, la réception
//  toujours gratuite, et aucune clé existante jamais perdue.
//

import XCTest
@testable import Brocolis

final class BrocolisPlanTests: XCTestCase {

    // MARK: La règle qui protège les utilisateurs existants

    /// Un trousseau DÉJÀ au-dessus de la limite n'est pas amputé : la porte ne
    /// ferme que l'ajout. Personne ne se réveille avec des conversations
    /// verrouillées parce qu'on a introduit un tarif.
    func testExistingKeysAreNeverTakenAway() {
        XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: 10, tier: .free),
                       .needs(.plus, .moreKeys))
        // Rien dans le plan ne demande d'en supprimer, et lire reste ouvert.
        XCTAssertEqual(BrocolisPlan.gateForReceiving(), .allowed)
    }

    /// Les clés offertes sont utilisables jusqu'à la dernière.
    func testFreeKeysAreUsableUpToTheLimit() {
        for count in 0..<BrocolisPlan.freeKeyLimit {
            XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: count, tier: .free),
                           .allowed, "la clé n°\(count + 1) doit rester gratuite")
        }
        XCTAssertEqual(
            BrocolisPlan.gateForAddingKey(currentKeyCount: BrocolisPlan.freeKeyLimit, tier: .free),
            .needs(.plus, .moreKeys))
    }

    /// Le palier le moins cher suffit pour les clés : on ne force personne vers
    /// Pro pour une fonction qui ne coûte rien à servir.
    func testUnlimitedKeysComeWithTheCheapestTier() {
        XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: 9_999, tier: .plus),
                       .allowed)
        XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: 9_999, tier: .pro),
                       .allowed)
    }

    // MARK: La règle qui protège la messagerie

    /// RECEVOIR est toujours gratuit, à tous les paliers. Sans ça, un abonné
    /// enverrait une photo qu'un non-abonné ne pourrait pas ouvrir, et la
    /// messagerie se casserait en deux.
    func testReceivingIsAlwaysFree() {
        XCTAssertEqual(BrocolisPlan.gateForReceiving(), .allowed)
    }

    /// Les médias — ce qui coûte vraiment au serveur — demandent Pro.
    func testSendingMediaNeedsPro() {
        for tier in [BrocolisTier.free, .plus] {
            XCTAssertEqual(BrocolisPlan.gateForSendingPhoto(tier: tier), .needs(.pro, .photo))
            XCTAssertEqual(BrocolisPlan.gateForSendingVoiceNote(tier: tier),
                           .needs(.pro, .voiceNote))
        }
        XCTAssertEqual(BrocolisPlan.gateForSendingPhoto(tier: .pro), .allowed)
        XCTAssertEqual(BrocolisPlan.gateForSendingVoiceNote(tier: .pro), .allowed)
    }

    // MARK: L'expiration de clé

    /// Ne PAS faire expirer une clé reste gratuit : on ne fait pas payer pour
    /// l'absence de fonction.
    func testNoExpiryIsFree() {
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: 0, tier: .free), .allowed)
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: -1, tier: .free), .allowed)
    }

    func testSettingAnExpiryNeedsPlus() {
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: 3600, tier: .free),
                       .needs(.plus, .keyExpiry))
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: 3600, tier: .plus), .allowed)
    }

    // MARK: Les paliers

    /// Un palier ouvre tout ce qu'ouvre le palier en dessous. Sans cette
    /// propriété, payer plus cher pourrait retirer une fonction.
    func testHigherTierOpensEverythingTheLowerOneDoes() {
        for feature in BrocolisPaidFeature.allCases {
            XCTAssertEqual(BrocolisPlan.gate(for: feature, tier: .pro), .allowed,
                           "Pro doit ouvrir \(feature.rawValue)")
        }
    }

    /// Le palier gratuit n'ouvre aucune fonction payante — sinon elle ne
    /// serait pas payante.
    func testFreeTierOpensNoPaidFeature() {
        for feature in BrocolisPaidFeature.allCases {
            XCTAssertFalse(BrocolisPlan.gate(for: feature, tier: .free).isAllowed,
                           "\(feature.rawValue) ne devrait pas être gratuit")
        }
    }

    // MARK: Les deux offres

    /// Deux abonnements mensuels distincts, préfixés par l'identifiant de
    /// l'app — App Store Connect ne renverrait rien sinon — et chacun lié au
    /// bon palier.
    func testTwoDistinctMonthlyProducts() {
        XCTAssertEqual(BrocolisPlan.productIds.count, 2)
        XCTAssertEqual(Set(BrocolisPlan.productIds).count, 2)
        for id in BrocolisPlan.productIds {
            XCTAssertTrue(id.hasPrefix("rs.brocolis.messagerie."), "identifiant inattendu : \(id)")
            XCTAssertTrue(id.hasSuffix(".monthly"), "les deux offres sont mensuelles : \(id)")
        }
        XCTAssertEqual(BrocolisPlan.tier(forProductId: BrocolisPlan.plusProductId), .plus)
        XCTAssertEqual(BrocolisPlan.tier(forProductId: BrocolisPlan.proProductId), .pro)
    }

    /// Un identifiant inconnu ne débloque RIEN. Protège d'un produit renommé
    /// côté App Store Connect sans que le code suive.
    func testUnknownProductUnlocksNothing() {
        XCTAssertNil(BrocolisPlan.tier(forProductId: "rs.brocolis.messagerie.autre"))
        XCTAssertNil(BrocolisPlan.tier(forProductId: ""))
    }

    /// Le chiffrement n'apparaît dans AUCUNE fonction payante. Si quelqu'un
    /// ajoute un jour un cas pour le vendre, ce test doit être supprimé
    /// sciemment — pas contourné par distraction.
    func testEncryptionIsNeverSold() {
        let paid = Set(BrocolisPaidFeature.allCases)
        XCTAssertEqual(paid, [.moreKeys, .keyExpiry, .photo, .voiceNote])
    }
}
