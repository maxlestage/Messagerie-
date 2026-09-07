//
//  BrocolisLiveActivityTests.swift
//  BrocolisTests
//
//  Choix de la ligne affichée sous le titre de la Live Activity
//  (`BrocolisLastLine`). Ce test existe à cause d'un vrai bug : la ligne
//  n'apparaissait que si le NOM de l'expéditeur ET l'heure étaient présents.
//  Or une mise à jour poussée par APNs vient de l'expéditeur, qui ignore
//  comment le destinataire l'a nommé : elle apporte une heure SANS nom. App
//  fermée — le cas même pour lequel la Live Activity existe — l'heure reçue
//  était donc ignorée, et le sous-titre retombait sur « Chiffrement prêt
//  depuis… » sous un titre « 1 nouveau message ».
//

import XCTest
@testable import Brocolis

final class BrocolisLiveActivityTests: XCTestCase {

    private let since = Date(timeIntervalSince1970: 1_700_000_000)
    private let at = Date(timeIntervalSince1970: 1_700_003_600)

    /// Le cas du bug : heure sans nom (mise à jour push) doit rester affichée.
    func testTimeWithoutNameIsStillShown() {
        let line = BrocolisLastLine.choose(lastFrom: nil, lastAt: at, since: since)

        XCTAssertEqual(line, .receivedAt(at))
    }

    /// Message reçu d'un correspondant connu : nom + heure.
    func testNameAndTime() {
        let line = BrocolisLastLine.choose(lastFrom: "Alice", lastAt: at, since: since)

        XCTAssertEqual(line, .from(name: "Alice", at: at))
    }

    /// Un nom sans heure reste affichable.
    func testNameWithoutTime() {
        let line = BrocolisLastLine.choose(lastFrom: "Alice", lastAt: nil, since: since)

        XCTAssertEqual(line, .fromOnly(name: "Alice"))
    }

    /// Aucun message : la Live Activity redevient le simple indicateur d'état.
    func testNothingReceivedFallsBackToActiveSince() {
        let line = BrocolisLastLine.choose(lastFrom: nil, lastAt: nil, since: since)

        XCTAssertEqual(line, .activeSince(since))
    }

    /// Un nom vide (clé « Sans nom ») compte comme absent — sinon la ligne
    /// afficherait « De  · il y a 2 min ».
    func testEmptyNameCountsAsAbsent() {
        XCTAssertEqual(BrocolisLastLine.choose(lastFrom: "", lastAt: at, since: since),
                       .receivedAt(at))
        XCTAssertEqual(BrocolisLastLine.choose(lastFrom: "", lastAt: nil, since: since),
                       .activeSince(since))
    }

    /// L'instant d'activation n'est jamais affiché quand un message est arrivé :
    /// une mise à jour push remet forcément `since` à l'instant courant (elle
    /// ignore le vrai « actif depuis » du destinataire), ce qui afficherait
    /// « Chiffrement prêt depuis 0 s » à chaque message.
    func testSinceIsIgnoredOnceAMessageArrived() {
        let pushed = Date()
        let line = BrocolisLastLine.choose(lastFrom: nil, lastAt: at, since: pushed)

        XCTAssertEqual(line, .receivedAt(at))
        XCTAssertNotEqual(line, .activeSince(pushed))
    }
}
