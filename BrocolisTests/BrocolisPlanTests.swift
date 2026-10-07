//
//  BrocolisPlanTests.swift
//  BrocolisTests
//
//  Ce qui est gratuit et ce qui demande Brocolis+. Ces tests existent surtout
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
        // Dix clés, sans abonnement : on ne peut pas en ajouter une onzième…
        XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: 10, isPlus: false),
                       .needsPlus(.moreKeys))
        // …mais rien dans le plan ne demande d'en supprimer.
        XCTAssertEqual(BrocolisPlan.gateForReceiving(), .allowed)
    }

    /// Les clés offertes sont utilisables jusqu'à la dernière.
    func testFreeKeysAreUsableUpToTheLimit() {
        for count in 0..<BrocolisPlan.freeKeyLimit {
            XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: count, isPlus: false),
                           .allowed, "la clé n°\(count + 1) doit rester gratuite")
        }
        XCTAssertEqual(
            BrocolisPlan.gateForAddingKey(currentKeyCount: BrocolisPlan.freeKeyLimit,
                                          isPlus: false),
            .needsPlus(.moreKeys))
    }

    /// Avec Brocolis+, aucune limite de correspondants.
    func testPlusHasNoKeyLimit() {
        XCTAssertEqual(BrocolisPlan.gateForAddingKey(currentKeyCount: 9_999, isPlus: true),
                       .allowed)
    }

    // MARK: La règle qui protège la messagerie

    /// RECEVOIR est toujours gratuit. Sans ça, un abonné enverrait une photo
    /// qu'un non-abonné ne pourrait pas ouvrir, et la messagerie se casserait
    /// en deux.
    func testReceivingIsAlwaysFree() {
        XCTAssertEqual(BrocolisPlan.gateForReceiving(), .allowed)
    }

    /// Seul l'ENVOI de médias est payant.
    func testSendingMediaNeedsPlus() {
        XCTAssertEqual(BrocolisPlan.gateForSendingPhoto(isPlus: false), .needsPlus(.photo))
        XCTAssertEqual(BrocolisPlan.gateForSendingVoiceNote(isPlus: false), .needsPlus(.voiceNote))

        XCTAssertEqual(BrocolisPlan.gateForSendingPhoto(isPlus: true), .allowed)
        XCTAssertEqual(BrocolisPlan.gateForSendingVoiceNote(isPlus: true), .allowed)
    }

    // MARK: L'expiration de clé

    /// Ne PAS faire expirer une clé reste gratuit : on ne fait pas payer pour
    /// l'absence de fonction.
    func testNoExpiryIsFree() {
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: 0, isPlus: false), .allowed)
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: -1, isPlus: false), .allowed)
    }

    func testSettingAnExpiryNeedsPlus() {
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: 3600, isPlus: false),
                       .needsPlus(.keyExpiry))
        XCTAssertEqual(BrocolisPlan.gateForKeyExpiry(ttlSeconds: 3600, isPlus: true), .allowed)
    }

    // MARK: Les deux offres

    /// Deux produits, distincts, et préfixés par l'identifiant de l'app —
    /// App Store Connect ne renverrait rien avec un identifiant qui ne
    /// correspond pas.
    func testTwoDistinctProductsArePublished() {
        XCTAssertEqual(BrocolisPlan.productIds.count, 2)
        XCTAssertEqual(Set(BrocolisPlan.productIds).count, 2)
        for id in BrocolisPlan.productIds {
            XCTAssertTrue(id.hasPrefix("rs.brocolis.messagerie."), "identifiant inattendu : \(id)")
        }
    }

    /// Le chiffrement n'apparaît dans AUCUNE fonction payante. Si quelqu'un
    /// ajoute un jour un cas pour le vendre, ce test doit être supprimé
    /// sciemment — pas contourné par distraction.
    func testEncryptionIsNeverSold() {
        let paid = Set(BrocolisPaidFeature.allCases)
        XCTAssertEqual(paid, [.moreKeys, .photo, .voiceNote, .keyExpiry])
    }
}
