//
//  BrocolisConversationTests.swift
//  BrocolisTests
//
//  Tests du rendu « à la volée » d'une conversation : déchiffrement automatique
//  avec tes clés, jetons étrangers laissés chiffrés (« pour les autres »).
//

import XCTest
import CryptoKit
@testable import Brocolis

final class BrocolisConversationTests: XCTestCase {

    private func newKey() throws -> SymmetricKey {
        try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
    }

    func testClearLineStaysClear() throws {
        let r = BrocolisConversation.render("bonjour", keys: [try newKey()])
        XCTAssertEqual(r.lines.count, 1)
        XCTAssertEqual(r.lines[0].status, .clear)
        XCTAssertEqual(r.lines[0].display, "bonjour")
        XCTAssertEqual(r.decryptedCount, 0)
        XCTAssertEqual(r.lockedCount, 0)
    }

    func testDecryptsLineWithOwnKey() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("coucou".utf8), key: key)
        let r = BrocolisConversation.render(token, keys: [key])
        XCTAssertEqual(r.lines[0].status, .decrypted)
        XCTAssertEqual(r.lines[0].display, "coucou")
        XCTAssertEqual(r.decryptedCount, 1)
        XCTAssertEqual(r.lockedCount, 0)
    }

    func testForeignTokenStaysLocked() throws {
        let mine = try newKey()
        let theirs = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("secret des autres".utf8), key: theirs)
        let r = BrocolisConversation.render(token, keys: [mine])
        XCTAssertEqual(r.lines[0].status, .locked)
        // Toujours chiffré : le jeton d'origine est conservé tel quel.
        XCTAssertTrue(r.lines[0].display.contains(BrocolisCrypto.tokenPrefix))
        XCTAssertFalse(r.lines[0].display.contains("secret des autres"))
        XCTAssertEqual(r.decryptedCount, 0)
        XCTAssertEqual(r.lockedCount, 1)
    }

    func testMixedConversationPreservesOrderAndCounts() throws {
        let mine = try newKey()
        let theirs = try newKey()
        let a = try BrocolisCrypto.encryptToken(Data("à moi".utf8), key: mine)
        let b = try BrocolisCrypto.encryptToken(Data("aux autres".utf8), key: theirs)
        let input = "salut\n\(a)\n\(b)"
        let r = BrocolisConversation.render(input, keys: [mine])

        XCTAssertEqual(r.lines.count, 3)
        XCTAssertEqual(r.lines[0].status, .clear)
        XCTAssertEqual(r.lines[0].display, "salut")
        XCTAssertEqual(r.lines[1].status, .decrypted)
        XCTAssertEqual(r.lines[1].display, "à moi")
        XCTAssertEqual(r.lines[2].status, .locked)
        XCTAssertEqual(r.decryptedCount, 1)
        XCTAssertEqual(r.lockedCount, 1)
    }

    func testMixedLineWithBothKindsIsMixed() throws {
        let mine = try newKey()
        let theirs = try newKey()
        let a = try BrocolisCrypto.encryptToken(Data("ok".utf8), key: mine)
        let b = try BrocolisCrypto.encryptToken(Data("non".utf8), key: theirs)
        let (_, status, decrypted, locked) =
            BrocolisConversation.renderLine("\(a) et \(b)", keys: [mine])
        XCTAssertEqual(status, .mixed)
        XCTAssertEqual(decrypted, 1)
        XCTAssertEqual(locked, 1)
    }

    func testTriesAllKeys() throws {
        let k1 = try newKey()
        let k2 = try newKey()
        let t1 = try BrocolisCrypto.encryptToken(Data("un".utf8), key: k1)
        let t2 = try BrocolisCrypto.encryptToken(Data("deux".utf8), key: k2)
        let r = BrocolisConversation.render("\(t1)\n\(t2)", keys: [k1, k2])
        XCTAssertEqual(r.lines[0].display, "un")
        XCTAssertEqual(r.lines[1].display, "deux")
        XCTAssertEqual(r.decryptedCount, 2)
        XCTAssertEqual(r.lockedCount, 0)
    }

    func testCountTokens() throws {
        let key = try newKey()
        let t = try BrocolisCrypto.encryptToken(Data("x".utf8), key: key)
        XCTAssertEqual(BrocolisConversation.countTokens(""), 0)
        XCTAssertEqual(BrocolisConversation.countTokens("rien"), 0)
        XCTAssertEqual(BrocolisConversation.countTokens(t), 1)
        XCTAssertEqual(BrocolisConversation.countTokens("\(t) \(t)"), 2)
    }

    func testEmptyLinesArePreserved() throws {
        let r = BrocolisConversation.render("a\n\nb", keys: [])
        XCTAssertEqual(r.lines.count, 3)
        XCTAssertEqual(r.lines[1].display, "")
    }
}
