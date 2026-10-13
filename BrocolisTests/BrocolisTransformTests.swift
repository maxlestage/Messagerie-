//
//  BrocolisTransformTests.swift
//  BrocolisTests
//
//  Tests de la transformation « intelligente » utilisée par l'Action Extension.
//

import XCTest
import CryptoKit
@testable import Brocolis

final class BrocolisTransformTests: XCTestCase {

    private func newKey() throws -> SymmetricKey {
        try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
    }

    func testAutoEncryptsWholeSelectionWhenNoMarkers() throws {
        let key = try newKey()
        let result = BrocolisTransform.auto("message tout simple", key: key)
        if case .encryptedWhole = result.outcome {
            XCTAssertTrue(result.text.hasPrefix(BrocolisCrypto.tokenPrefix))
            XCTAssertTrue(result.text.hasSuffix(BrocolisCrypto.tokenSuffix))
        } else {
            XCTFail("attendu .encryptedWhole, obtenu \(result.outcome)")
        }
    }

    func testAutoEncryptsMarkedSegments() throws {
        let key = try newKey()
        let result = BrocolisTransform.auto("avant ((secret)) après", key: key)
        if case .encryptedMarked(let n) = result.outcome {
            XCTAssertEqual(n, 1)
        } else {
            XCTFail("attendu .encryptedMarked, obtenu \(result.outcome)")
        }
        XCTAssertTrue(result.text.contains("avant "))
        XCTAssertTrue(result.text.contains(" après"))
        XCTAssertFalse(result.text.contains("secret"))
    }

    func testAutoDecryptsTokens() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("salut".utf8), key: key)
        let result = BrocolisTransform.auto("re: \(token)", key: key)
        if case .decrypted(let n) = result.outcome {
            XCTAssertEqual(n, 1)
        } else {
            XCTFail("attendu .decrypted, obtenu \(result.outcome)")
        }
        XCTAssertEqual(result.text, "re: salut")
    }

    func testAutoWholeThenAutoDecryptRoundtrip() throws {
        let key = try newKey()
        let original = "secret entier 🥦"
        let enc = BrocolisTransform.auto(original, key: key)
        let dec = BrocolisTransform.auto(enc.text, key: key)
        XCTAssertEqual(dec.text, original)
        if case .decrypted = dec.outcome {} else {
            XCTFail("le 2e passage doit déchiffrer")
        }
    }

    func testAutoMarkedThenAutoDecryptRoundtrip() throws {
        let key = try newKey()
        let enc = BrocolisTransform.auto("code: ((4291)) ok", key: key)
        let dec = BrocolisTransform.auto(enc.text, key: key)
        XCTAssertEqual(dec.text, "code: 4291 ok")
    }

    func testDecryptionTakesPrecedenceOverMarkers() throws {
        // Si le texte contient un jeton, on déchiffre même s'il y a aussi des
        // marqueurs `((...))` autour.
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("X".utf8), key: key)
        let result = BrocolisTransform.auto("\(token) ((pas touché))", key: key)
        if case .decrypted = result.outcome {} else {
            XCTFail("présence d'un jeton → doit déchiffrer")
        }
        XCTAssertTrue(result.text.contains("X"))
        XCTAssertTrue(result.text.contains("((pas touché))"))
    }

    func testMarkersWinEvenWithEncryptWholeAlways() throws {
        // Des ((…)) sont une demande explicite : seuls ces passages sont
        // chiffrés, même avec « Tout chiffrer » (partage, clavier, iMessage).
        let key = try newKey()
        let result = BrocolisTransform.auto("avant ((secret)) après", key: key, encryptWholeAlways: true)
        if case .encryptedMarked(let n) = result.outcome {
            XCTAssertEqual(n, 1)
            XCTAssertTrue(result.text.hasPrefix("avant "))
            XCTAssertTrue(result.text.hasSuffix(" après"))
            XCTAssertFalse(result.text.contains("secret"))
        } else {
            XCTFail("attendu .encryptedMarked, obtenu \(result.outcome)")
        }
        // Round-trip : le passage revient en clair.
        let dec = BrocolisTransform.auto(result.text, key: key)
        XCTAssertEqual(dec.text, "avant secret après")
    }

    func testEncryptWholeAlwaysStillDecryptsTokens() throws {
        // Même en mode tout-chiffrer, un jeton présent est déchiffré (priorité).
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("z".utf8), key: key)
        let r = BrocolisTransform.auto(token, key: key, encryptWholeAlways: true)
        if case .decrypted = r.outcome {} else {
            XCTFail("présence d'un jeton → doit déchiffrer même en mode tout-chiffrer")
        }
        XCTAssertEqual(r.text, "z")
    }

    func testLabelsAreHumanReadable() throws {
        let key = try newKey()
        XCTAssertTrue(BrocolisTransform.auto("simple", key: key).label.contains("🔒"))
        XCTAssertTrue(BrocolisTransform.auto("a ((b)) c", key: key).label.contains("🔒"))
        let token = try BrocolisCrypto.encryptToken(Data("y".utf8), key: key)
        XCTAssertTrue(BrocolisTransform.auto(token, key: key).label.contains("🔓"))
    }
}
