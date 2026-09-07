//
//  BrocolisWatchSyncTests.swift
//  BrocolisTests
//
//  Contrat de synchronisation iPhone → montre (`WatchSyncPayload`). Ce test
//  existe à cause d'un vrai bug : l'iPhone poussait bien `active` dans le
//  contexte WatchConnectivity, mais la montre ne le relisait jamais — elle
//  affichait « En pause » même Brocolis activé. Un aller-retour complet
//  empêche qu'un champ soit à nouveau écrit d'un côté et oublié de l'autre.
//

import XCTest
@testable import Brocolis

final class BrocolisWatchSyncTests: XCTestCase {

    /// Tout ce que l'iPhone met dans le contexte doit revenir à l'identique.
    func testRoundTripKeepsEveryField() throws {
        let sent = WatchSyncPayload(
            keysJSON: #"[{"id":"A","name":"Alice"}]"#,
            selectedKeyId: "A",
            deviceId: "DEVICE-1",
            serverURL: "https://exemple.test",
            active: true,
            sentAt: Date(timeIntervalSince1970: 1_700_000_000)
        )

        let received = try XCTUnwrap(WatchSyncPayload(context: sent.context))

        XCTAssertEqual(received, sent)
    }

    /// Le cas du bug : « actif » doit traverser, dans les deux positions.
    func testActiveCrossesTheWire() throws {
        for active in [true, false] {
            let context = WatchSyncPayload(deviceId: "D", active: active).context
            XCTAssertEqual(WatchSyncPayload(context: context)?.active, active)
        }
    }

    /// Un champ absent vaut « ne touche à rien » (et non « remets à zéro ») :
    /// un iPhone d'une version antérieure ne doit pas effacer un réglage que la
    /// montre possède déjà.
    func testMissingFieldsStayNil() throws {
        let received = try XCTUnwrap(WatchSyncPayload(context: ["deviceId": "D"]))

        XCTAssertEqual(received.deviceId, "D")
        XCTAssertNil(received.active)
        XCTAssertNil(received.keysJSON)
        XCTAssertNil(received.selectedKeyId)
        XCTAssertNil(received.serverURL)
    }

    /// Un contexte vide = rien n'est encore arrivé de l'iPhone.
    func testEmptyContextIsNothing() {
        XCTAssertNil(WatchSyncPayload(context: [:]))
    }

    /// `updateApplicationContext` n'accepte que des types property-list :
    /// un `Date` brut ferait échouer l'envoi à l'exécution.
    func testContextOnlyContainsPropertyListTypes() {
        let context = WatchSyncPayload(
            keysJSON: "[]", selectedKeyId: "A", deviceId: "D",
            serverURL: "https://exemple.test", active: true
        ).context

        XCTAssertTrue(PropertyListSerialization.propertyList(context, isValidFor: .binary))
        // `sentAt` voyage en secondes, pas en `Date` (non property-list).
        XCTAssertNotNil(context["sentAt"] as? TimeInterval)
    }

    /// Deux envois successifs diffèrent, même à contenu identique : sinon le
    /// système ne relivrerait pas le contexte après réinstallation de la montre.
    func testSentAtMakesEachPushDistinct() {
        let a = WatchSyncPayload(deviceId: "D", sentAt: Date(timeIntervalSince1970: 1))
        let b = WatchSyncPayload(deviceId: "D", sentAt: Date(timeIntervalSince1970: 2))

        XCTAssertNotEqual(a.context["sentAt"] as? TimeInterval,
                          b.context["sentAt"] as? TimeInterval)
    }
}
