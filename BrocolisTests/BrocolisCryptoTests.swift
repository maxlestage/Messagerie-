//
//  BrocolisCryptoTests.swift
//  BrocolisTests
//
//  Batterie de tests du chiffrement sélectif et du format de jeton (compatible
//  brocolis). Lancer avec Cmd+U.
//

import XCTest
import CryptoKit
@testable import Brocolis

final class BrocolisCryptoTests: XCTestCase {

    private func newKey() throws -> SymmetricKey {
        try BrocolisCrypto.symmetricKey(fromBase64: BrocolisCrypto.generateKeyBase64())
    }

    // MARK: Clé

    func testKeyBase64RoundtripIs256Bits() throws {
        let key = try newKey()
        XCTAssertEqual(key.bitCount, 256)
    }

    func testGeneratedKeyDecodesTo32Bytes() {
        let b64 = BrocolisCrypto.generateKeyBase64()
        let raw = Data(base64Encoded: b64)
        XCTAssertEqual(raw?.count, BrocolisCrypto.keyLength)
    }

    func testTwoGeneratedKeysDiffer() {
        XCTAssertNotEqual(BrocolisCrypto.generateKeyBase64(), BrocolisCrypto.generateKeyBase64())
    }

    func testBadKeyLengthRejected() {
        let short = Data(repeating: 0, count: 16).base64EncodedString()
        XCTAssertThrowsError(try BrocolisCrypto.symmetricKey(fromBase64: short))
    }

    func testBadKeyBase64Rejected() {
        XCTAssertThrowsError(try BrocolisCrypto.symmetricKey(fromBase64: "pas du base64 !!!"))
    }

    func testKeyImportTrimsWhitespace() throws {
        let b64 = BrocolisCrypto.generateKeyBase64()
        let padded = "  \n\(b64)\t "
        XCTAssertNoThrow(try BrocolisCrypto.symmetricKey(fromBase64: padded))
    }

    // MARK: Jeton unitaire

    func testTokenRoundtrip() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("hello world".utf8), key: key)
        XCTAssertTrue(token.hasPrefix(BrocolisCrypto.tokenPrefix))
        XCTAssertTrue(token.hasSuffix(BrocolisCrypto.tokenSuffix))
        let inner = innerOf(token)
        let plain = try BrocolisCrypto.decryptToken(base64: inner, key: key)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), "hello world")
    }

    func testEmptyPlaintextToken() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("".utf8), key: key)
        let plain = try BrocolisCrypto.decryptToken(base64: innerOf(token), key: key)
        XCTAssertEqual(plain.count, 0)
    }

    func testUnicodeEmojiRoundtrip() throws {
        let key = try newKey()
        let secret = "Rendez-vous 🥦 à 18h — café ☕️, code 4291 €"
        let token = try BrocolisCrypto.encryptToken(Data(secret.utf8), key: key)
        let plain = try BrocolisCrypto.decryptToken(base64: innerOf(token), key: key)
        XCTAssertEqual(String(decoding: plain, as: UTF8.self), secret)
    }

    func testWireFormatLengthMatchesBrocolis() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("brocolis".utf8), key: key)
        let packed = Data(base64Encoded: innerOf(token))
        // nonce(12) + 8 octets "brocolis" + tag(16) = 36
        XCTAssertEqual(packed?.count, 12 + 8 + 16)
    }

    func testNonceMakesCiphertextNonDeterministic() throws {
        let key = try newKey()
        let a = try BrocolisCrypto.encryptToken(Data("même secret".utf8), key: key)
        let b = try BrocolisCrypto.encryptToken(Data("même secret".utf8), key: key)
        XCTAssertNotEqual(a, b, "le nonce aléatoire doit rendre deux chiffrés différents")
    }

    func testDecryptTokenRejectsTooShort() throws {
        let key = try newKey()
        let tiny = Data(repeating: 1, count: 4).base64EncodedString()
        XCTAssertThrowsError(try BrocolisCrypto.decryptToken(base64: tiny, key: key))
    }

    func testDecryptTokenRejectsBadBase64() throws {
        let key = try newKey()
        XCTAssertThrowsError(try BrocolisCrypto.decryptToken(base64: "@@@notb64@@@", key: key))
    }

    func testDecryptWithWrongKeyThrows() throws {
        let k1 = try newKey()
        let k2 = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("secret".utf8), key: k1)
        XCTAssertThrowsError(try BrocolisCrypto.decryptToken(base64: innerOf(token), key: k2))
    }

    func testTamperedCiphertextThrows() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("secret".utf8), key: key)
        var packed = Array(Data(base64Encoded: innerOf(token))!)
        packed[packed.count - 1] ^= 0xFF // corrompt le tag
        let tampered = Data(packed).base64EncodedString()
        XCTAssertThrowsError(try BrocolisCrypto.decryptToken(base64: tampered, key: key))
    }

    // MARK: Chiffrement sélectif (marqueurs)

    func testMarkedRoundtrip() throws {
        let key = try newKey()
        let src = "Coucou ((mon secret)) et ((un autre)) fin"
        let (enc, n) = BrocolisCrypto.encryptMarked(src, key: key)
        XCTAssertEqual(n, 2)
        XCTAssertFalse(enc.contains("mon secret"))
        XCTAssertFalse(enc.contains("un autre"))
        XCTAssertTrue(enc.contains(BrocolisCrypto.tokenPrefix))

        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 2)
        XCTAssertEqual(dec, "Coucou mon secret et un autre fin")
    }

    func testNoMarkersLeavesTextUnchanged() throws {
        let key = try newKey()
        let (enc, n) = BrocolisCrypto.encryptMarked("aucun secret ici", key: key)
        XCTAssertEqual(n, 0)
        XCTAssertEqual(enc, "aucun secret ici")
    }

    func testUnclosedMarkerIsNoop() throws {
        let key = try newKey()
        let (enc, n) = BrocolisCrypto.encryptMarked("debut ((pas ferme", key: key)
        XCTAssertEqual(n, 0)
        XCTAssertEqual(enc, "debut ((pas ferme")
    }

    func testEmptyMarkerRoundtrip() throws {
        let key = try newKey()
        let (enc, n) = BrocolisCrypto.encryptMarked("a(())b", key: key)
        XCTAssertEqual(n, 1)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 1)
        XCTAssertEqual(dec, "ab")
    }

    func testAdjacentMarkersRoundtrip() throws {
        let key = try newKey()
        let src = "((a))((b))((c))"
        let (enc, n) = BrocolisCrypto.encryptMarked(src, key: key)
        XCTAssertEqual(n, 3)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 3)
        XCTAssertEqual(dec, "abc")
    }

    func testWrongKeyKeepsTokenIntact() throws {
        let k1 = try newKey()
        let k2 = try newKey()
        let (enc, _) = BrocolisCrypto.encryptMarked("x ((s)) y", key: k1)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: k2)
        XCTAssertEqual(m, 0)
        XCTAssertEqual(dec, enc) // jeton conservé, pas de crash
    }

    func testDecryptNonTokenTextUnchanged() throws {
        let key = try newKey()
        let (dec, m) = BrocolisCrypto.decryptTokens("texte normal sans jeton", key: key)
        XCTAssertEqual(m, 0)
        XCTAssertEqual(dec, "texte normal sans jeton")
    }

    func testDecryptUnclosedTokenIsNoop() throws {
        let key = try newKey()
        let input = "avant [[BROCOLIS:v1:abc sans fin"
        let (dec, m) = BrocolisCrypto.decryptTokens(input, key: key)
        XCTAssertEqual(m, 0)
        XCTAssertEqual(dec, input)
    }

    func testCorruptedTokenInTextIsKept() throws {
        let key = try newKey()
        let input = "salut [[BROCOLIS:v1:not-valid-base64!!]] bye"
        let (dec, m) = BrocolisCrypto.decryptTokens(input, key: key)
        XCTAssertEqual(m, 0)
        XCTAssertEqual(dec, input)
    }

    func testInterleavedTextRoundtrip() throws {
        let key = try newKey()
        let src = "Salut ((Alice)), le code est ((1234)). Garde-le !"
        let (enc, n) = BrocolisCrypto.encryptMarked(src, key: key)
        XCTAssertEqual(n, 2)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 2)
        XCTAssertEqual(dec, "Salut Alice, le code est 1234. Garde-le !")
    }

    func testSameSecretTwiceProducesDistinctTokens() throws {
        let key = try newKey()
        let (enc, n) = BrocolisCrypto.encryptMarked("((x)) et ((x))", key: key)
        XCTAssertEqual(n, 2)
        // Récupère les deux jetons et vérifie qu'ils diffèrent (nonces distincts).
        let tokens = enc.components(separatedBy: BrocolisCrypto.tokenPrefix).dropFirst()
        XCTAssertEqual(tokens.count, 2)
        XCTAssertNotEqual(tokens.first, tokens.last)
    }

    func testLargeInputRoundtrip() throws {
        let key = try newKey()
        let chunk = "bla ((secret)) "
        let src = String(repeating: chunk, count: 500)
        let (enc, n) = BrocolisCrypto.encryptMarked(src, key: key)
        XCTAssertEqual(n, 500)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 500)
        XCTAssertEqual(dec, src.replacingOccurrences(of: "((secret))", with: "secret"))
    }

    func testContainsToken() throws {
        let key = try newKey()
        let token = try BrocolisCrypto.encryptToken(Data("x".utf8), key: key)
        XCTAssertTrue(BrocolisCrypto.containsToken("a \(token) b"))
        XCTAssertFalse(BrocolisCrypto.containsToken("aucun jeton ici"))
    }

    func testNewlinesAndTabsInsideSecret() throws {
        let key = try newKey()
        let src = "Note: ((ligne1\nligne2\tindent))"
        let (enc, n) = BrocolisCrypto.encryptMarked(src, key: key)
        XCTAssertEqual(n, 1)
        let (dec, m) = BrocolisCrypto.decryptTokens(enc, key: key)
        XCTAssertEqual(m, 1)
        XCTAssertEqual(dec, "Note: ligne1\nligne2\tindent")
    }

    // MARK: Multi-destinataire (jeton v2, enveloppe)

    func testMultiTokenReadableByEachRecipient() throws {
        let a = try newKey(); let b = try newKey(); let c = try newKey()
        let token = try BrocolisCrypto.encryptTokenMulti(Data("coucou".utf8), keys: [a, b, c])
        XCTAssertTrue(token.hasPrefix(BrocolisCrypto.tokenPrefixV2))
        // Chaque destinataire ouvre le message en clair, avec SA seule clé.
        for key in [a, b, c] {
            let (dec, n) = BrocolisCrypto.decryptTokens(token, keys: [key])
            XCTAssertEqual(n, 1)
            XCTAssertEqual(dec, "coucou")
        }
    }

    func testMultiTokenUnreadableByOutsider() throws {
        let a = try newKey(); let b = try newKey()
        let outsider = try newKey()
        let token = try BrocolisCrypto.encryptTokenMulti(Data("secret".utf8), keys: [a, b])
        let (dec, n) = BrocolisCrypto.decryptTokens(token, keys: [outsider])
        XCTAssertEqual(n, 0)
        XCTAssertEqual(dec, token, "le jeton est laissé intact si aucune clé ne l’ouvre")
    }

    func testMultiTokenLeavesNoLockedLeftoverForRecipient() throws {
        // Propriété clé du v2 : un seul jeton, pas de cadenas résiduel.
        let a = try newKey(); let b = try newKey()
        let token = try BrocolisCrypto.encryptTokenMulti(Data("salut".utf8), keys: [a, b])
        let (dec, _) = BrocolisCrypto.decryptTokens(token, keys: [a])
        XCTAssertFalse(dec.contains(BrocolisCrypto.tokenHead))
        XCTAssertEqual(dec, "salut")
    }

    func testSealTokenPicksV1ForSingleKey() throws {
        let a = try newKey()
        let token = BrocolisCrypto.sealToken(Data("x".utf8), keys: [a])
        XCTAssertNotNil(token)
        XCTAssertTrue(token!.hasPrefix(BrocolisCrypto.tokenPrefix)) // v1
    }

    func testSealTokenPicksV2ForMultipleKeys() throws {
        let a = try newKey(); let b = try newKey()
        let token = BrocolisCrypto.sealToken(Data("x".utf8), keys: [a, b])
        XCTAssertNotNil(token)
        XCTAssertTrue(token!.hasPrefix(BrocolisCrypto.tokenPrefixV2)) // v2
    }

    func testMixedV1AndV2TokensInSameTextDecrypt() throws {
        let a = try newKey(); let b = try newKey()
        let v1 = try BrocolisCrypto.encryptToken(Data("un".utf8), key: a)
        let v2 = try BrocolisCrypto.encryptTokenMulti(Data("deux".utf8), keys: [a, b])
        let input = "X \(v1) Y \(v2) Z"
        let (dec, n) = BrocolisCrypto.decryptTokens(input, keys: [a])
        XCTAssertEqual(n, 2)
        XCTAssertEqual(dec, "X un Y deux Z")
    }

    func testMultiTokenNonceMakesItNonDeterministic() throws {
        let a = try newKey(); let b = try newKey()
        let t1 = try BrocolisCrypto.encryptTokenMulti(Data("même".utf8), keys: [a, b])
        let t2 = try BrocolisCrypto.encryptTokenMulti(Data("même".utf8), keys: [a, b])
        XCTAssertNotEqual(t1, t2)
    }

    func testMultiTokenEmojiRoundtrip() throws {
        let a = try newKey(); let b = try newKey()
        let secret = "Plan 🥦 à 18h — code 4291 €"
        let token = try BrocolisCrypto.encryptTokenMulti(Data(secret.utf8), keys: [a, b])
        let (dec, n) = BrocolisCrypto.decryptTokens(token, keys: [b])
        XCTAssertEqual(n, 1)
        XCTAssertEqual(dec, secret)
    }

    func testMultiEncryptMarkedForTwoKeys() throws {
        let a = try newKey(); let b = try newKey()
        let (enc, n) = BrocolisCrypto.encryptMarked("code ((1234)) fin", keys: [a, b])
        XCTAssertEqual(n, 1)
        XCTAssertTrue(enc.contains(BrocolisCrypto.tokenPrefixV2))
        // Lisible par les deux.
        XCTAssertEqual(BrocolisCrypto.decryptTokens(enc, keys: [a]).text, "code 1234 fin")
        XCTAssertEqual(BrocolisCrypto.decryptTokens(enc, keys: [b]).text, "code 1234 fin")
    }

    func testMultiTokenTamperedBodyFails() throws {
        let a = try newKey(); let b = try newKey()
        let token = try BrocolisCrypto.encryptTokenMulti(Data("secret".utf8), keys: [a, b])
        let inner = String(token.dropFirst(BrocolisCrypto.tokenPrefixV2.count)
            .dropLast(BrocolisCrypto.tokenSuffix.count))
        var raw = Array(Data(base64Encoded: inner)!)
        raw[raw.count - 1] ^= 0xFF // corrompt le dernier octet du corps
        let tampered = BrocolisCrypto.tokenPrefixV2 + Data(raw).base64EncodedString() + BrocolisCrypto.tokenSuffix
        let (_, n) = BrocolisCrypto.decryptTokens(tampered, keys: [a, b])
        XCTAssertEqual(n, 0)
    }

    // MARK: Garanties de chiffrement (les messages sont bien cryptés)

    func testTokenNeverContainsPlaintext() throws {
        let key = try newKey()
        let secret = "RDV 18h — code 4291 — banque — secret"
        let token = try BrocolisCrypto.encryptToken(Data(secret.utf8), key: key)
        XCTAssertFalse(token.contains(secret))
        for leak in ["RDV", "4291", "banque", "secret", "18h"] {
            XCTAssertFalse(token.contains(leak), "le mot « \(leak) » ne doit jamais apparaître en clair")
        }
    }

    func testWholeMessageEncryptionHidesEveryWord() throws {
        // Chemin « Tout chiffrer » : c'est le défaut à l'envoi.
        let key = try newKey()
        let msg = "Salut Bob, on se voit demain à la banque à midi."
        let r = BrocolisTransform.auto(msg, keys: [key], encryptWholeAlways: true)
        XCTAssertTrue(r.isEncrypted)
        XCTAssertTrue(r.text.hasPrefix(BrocolisCrypto.tokenPrefix))
        for word in ["Salut", "Bob", "demain", "banque", "midi"] {
            XCTAssertFalse(r.text.contains(word), "« \(word) » a fuité")
        }
        XCTAssertEqual(BrocolisCrypto.decryptTokens(r.text, keys: [key]).text, msg)
    }

    func testMultiRecipientTokenHidesPlaintext() throws {
        let a = try newKey(); let b = try newKey()
        let secret = "message confidentiel 4291"
        let token = try BrocolisCrypto.encryptTokenMulti(Data(secret.utf8), keys: [a, b])
        XCTAssertFalse(token.contains(secret))
        XCTAssertFalse(token.contains("4291"))
        XCTAssertFalse(token.contains("confidentiel"))
    }

    func testFuzzNoPlaintextLeakAlwaysReversibleWrongKeyFails() throws {
        // 200 messages variés : (1) aucun clair ne fuit, (2) toujours réversible
        // avec la bonne clé, (3) illisible avec une autre clé.
        for i in 0..<200 {
            let key = try newKey()
            let wrong = try newKey()
            let secret = "msg#\(i) — secret-\(i * 7) — éàü🥦 \(i)"
            let token = try BrocolisCrypto.encryptToken(Data(secret.utf8), key: key)
            XCTAssertFalse(token.contains(secret), "fuite au message \(i)")
            XCTAssertFalse(token.contains("secret-\(i * 7)"), "fuite partielle au message \(i)")

            let back = try BrocolisCrypto.decryptToken(base64: innerOf(token), key: key)
            XCTAssertEqual(String(decoding: back, as: UTF8.self), secret)

            XCTAssertThrowsError(
                try BrocolisCrypto.decryptToken(base64: innerOf(token), key: wrong),
                "le message \(i) devrait être illisible avec une autre clé")
        }
    }

    func testWholeEncryptionIsAuthenticatedAgainstTampering() throws {
        // Le chiffrement est authentifié : modifier UN octet rend le jeton illisible.
        let key = try newKey()
        let token = BrocolisTransform.auto("virement à faire", keys: [key], encryptWholeAlways: true).text
        var raw = Array(Data(base64Encoded: innerOf(token))!)
        raw[raw.count / 2] ^= 0x01 // bascule un bit au milieu du chiffré
        let tampered = BrocolisCrypto.tokenPrefix + Data(raw).base64EncodedString() + BrocolisCrypto.tokenSuffix
        let (_, n) = BrocolisCrypto.decryptTokens(tampered, keys: [key])
        XCTAssertEqual(n, 0, "un jeton altéré ne doit jamais se déchiffrer")
    }

    func testTransformUnchangedIsNotMarkedEncrypted() throws {
        // Garde-fou : sans clé, auto() renvoie le clair → isEncrypted DOIT être faux,
        // pour que l'app n'affiche jamais du clair comme « chiffré ».
        let r = BrocolisTransform.auto("texte en clair", keys: [], encryptWholeAlways: true)
        XCTAssertFalse(r.isEncrypted)
        XCTAssertEqual(r.text, "texte en clair")
    }

    // MARK: Outils

    private func innerOf(_ token: String) -> String {
        String(token.dropFirst(BrocolisCrypto.tokenPrefix.count)
            .dropLast(BrocolisCrypto.tokenSuffix.count))
    }
}

/// Tests des helpers purs d'expiration (sans App Group).
final class BrocolisExpiryTests: XCTestCase {

    func testTTLZeroMeansNoExpiry() {
        XCTAssertNil(BrocolisKeyStore.computeExpiry(ttlSeconds: 0, from: Date()))
    }

    func testTTLProducesFutureExpiry() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let exp = BrocolisKeyStore.computeExpiry(ttlSeconds: 3600, from: now)
        XCTAssertEqual(exp, now.addingTimeInterval(3600))
    }

    func testNilExpiryIsNeverExpired() {
        XCTAssertFalse(BrocolisKeyStore.isExpired(expiresAt: nil, now: Date()))
    }

    func testFutureExpiryNotExpired() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let future = now.addingTimeInterval(60)
        XCTAssertFalse(BrocolisKeyStore.isExpired(expiresAt: future, now: now))
    }

    func testPastExpiryIsExpired() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let past = now.addingTimeInterval(-1)
        XCTAssertTrue(BrocolisKeyStore.isExpired(expiresAt: past, now: now))
    }

    func testExactBoundaryIsExpired() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        XCTAssertTrue(BrocolisKeyStore.isExpired(expiresAt: now, now: now))
    }

    // MARK: Préavis d'expiration

    func testNoLeadWithoutTTL() {
        XCTAssertNil(BrocolisKeyStore.notificationLead(ttlSeconds: 0))
    }

    func testLeadCappedAtOneHourForLongTTL() {
        XCTAssertEqual(BrocolisKeyStore.notificationLead(ttlSeconds: 86_400), 3600)
        XCTAssertEqual(BrocolisKeyStore.notificationLead(ttlSeconds: 604_800), 3600)
    }

    func testLeadIsHalfForShortTTL() {
        XCTAssertEqual(BrocolisKeyStore.notificationLead(ttlSeconds: 1800), 900)
    }

    func testNoticeFireDateIsLeadBeforeExpiry() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let expires = now.addingTimeInterval(86_400) // +24 h
        let fire = BrocolisKeyStore.noticeFireDate(expiresAt: expires, ttlSeconds: 86_400, now: now)
        XCTAssertEqual(fire, expires.addingTimeInterval(-3600)) // 1 h avant
    }

    func testNoticeFireDateNilWhenAlreadyPast() {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let expires = now.addingTimeInterval(5) // dans 5 s, lead 10 s -> préavis déjà passé
        XCTAssertNil(BrocolisKeyStore.noticeFireDate(expiresAt: expires, ttlSeconds: 20, now: now))
    }

    func testNoticeFireDateNilWithoutExpiry() {
        let now = Date()
        XCTAssertNil(BrocolisKeyStore.noticeFireDate(expiresAt: nil, ttlSeconds: 3600, now: now))
        XCTAssertNil(BrocolisKeyStore.noticeFireDate(expiresAt: now.addingTimeInterval(100), ttlSeconds: 0, now: now))
    }
}
