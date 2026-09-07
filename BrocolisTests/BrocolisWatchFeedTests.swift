//
//  BrocolisWatchFeedTests.swift
//  BrocolisTests
//
//  Accumulation d'une conversation au poignet (`WatchFeedState`) et les deux
//  décisions qui coûtent cher là-bas : re-rendre (donc re-déchiffrer TOUT le
//  fil en AES-GCM) et accuser réception (une requête réseau).
//
//  Ces tests existent à cause d'un vrai défaut : la montre refaisait les deux
//  à CHAQUE tour de sondage — toutes les 4 secondes, écran allumé — même
//  quand rien n'était arrivé.
//

import XCTest
@testable import Brocolis

final class BrocolisWatchFeedTests: XCTestCase {

    /// `RawMessage` est `Decodable` : on le construit par le JSON du serveur,
    /// ce qui vérifie au passage que ce format continue de se décoder.
    private func message(_ id: String,
                         seq: UInt64) throws -> BrocolisMessagingClient.RawMessage {
        let json = #"{"id":"\#(id)","senderId":"peer","ciphertext":"x","seq":\#(seq)}"#
        return try JSONDecoder().decode(BrocolisMessagingClient.RawMessage.self,
                                        from: Data(json.utf8))
    }

    /// Une page qui apporte du neuf : on rend, et on accuse.
    func testNewMessagesTriggerRenderAndReceipt() throws {
        var feed = WatchFeedState(floor: 0)

        let step = feed.ingest([try message("m1", seq: 1), try message("m2", seq: 2)], cursor: 2)

        XCTAssertEqual(step, .init(shouldRender: true, readReceiptUpTo: 2))
        XCTAssertEqual(feed.messages.count, 2)
        XCTAssertEqual(feed.cursor, 2)
    }

    /// Le cas du bug : un tour de sondage sans rien de neuf ne doit RIEN
    /// déclencher — ni déchiffrement, ni requête réseau.
    func testIdlePollDoesNothing() throws {
        var feed = WatchFeedState(floor: 0)
        _ = feed.ingest([try message("m1", seq: 1)], cursor: 1)

        let step = feed.ingest([], cursor: 1)

        XCTAssertEqual(step, .init(shouldRender: false, readReceiptUpTo: nil))
    }

    /// Même message renvoyé par le serveur : dédupliqué, donc aucun travail.
    func testDuplicateMessageIsIgnored() throws {
        var feed = WatchFeedState(floor: 0)
        _ = feed.ingest([try message("m1", seq: 1)], cursor: 1)

        let step = feed.ingest([try message("m1", seq: 1)], cursor: 1)

        XCTAssertEqual(step, .init(shouldRender: false, readReceiptUpTo: nil))
        XCTAssertEqual(feed.messages.count, 1)
    }

    /// Un message de plus : on rend, et on accuse le nouveau `seq` — une fois.
    func testReceiptIsSentOncePerNewSeq() throws {
        var feed = WatchFeedState(floor: 0)
        _ = feed.ingest([try message("m1", seq: 1)], cursor: 1)

        let arrival = feed.ingest([try message("m2", seq: 5)], cursor: 5)
        let idle = feed.ingest([], cursor: 5)

        XCTAssertEqual(arrival.readReceiptUpTo, 5)
        XCTAssertNil(idle.readReceiptUpTo)
    }

    /// Le curseur ne recule jamais, même si le serveur renvoie plus bas.
    func testCursorNeverGoesBackwards() throws {
        var feed = WatchFeedState(floor: 0)
        _ = feed.ingest([try message("m1", seq: 9)], cursor: 9)

        _ = feed.ingest([], cursor: 3)

        XCTAssertEqual(feed.cursor, 9)
    }

    /// Le plancher de confidentialité est le point de départ : ce que l'iPhone
    /// a effacé n'est pas redemandé au serveur.
    func testFloorIsTheStartingCursor() throws {
        let feed = WatchFeedState(floor: 128)

        XCTAssertEqual(feed.cursor, 128)
        XCTAssertTrue(feed.messages.isEmpty)
    }

    /// Messages arrivés dans le désordre : c'est le plus haut `seq` qui est
    /// accusé, pas le dernier reçu.
    func testReceiptUsesHighestSeqNotLastArrived() throws {
        var feed = WatchFeedState(floor: 0)

        let step = feed.ingest([try message("m2", seq: 7), try message("m1", seq: 3)], cursor: 7)

        XCTAssertEqual(step.readReceiptUpTo, 7)
    }
}
