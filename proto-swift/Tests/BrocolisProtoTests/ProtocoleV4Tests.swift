// Le protocole v4 (§9) : les unitaires de jeton_v4.rs et session4.rs, et la
// robustesse de proto/tests/robustesse_v4.rs — entrées aléatoires,
// altération de chaque octet d'un jeton, sauts trop grands, désordre
// aléatoire sur de longues conversations. Aucune entrée ne doit faire
// planter, aucune altération ne doit être acceptée, et un échec laisse la
// session telle qu'elle était. Les scénarios sont tirés par un générateur
// déterministe (graines fixes) : un échec se rejoue à l'identique.
//
// Le v4 exige ML-KEM : là où il manque (iOS/macOS < 26), les tests de
// session sont sautés ; ceux du jeton passent partout.

import XCTest
@testable import BrocolisProto

/// Saute le test si ML-KEM manque ici.
func exigerMlKem() throws {
    guard MlKem.isAvailable else { throw XCTSkip("ML-KEM-768 indisponible ici (iOS/macOS < 26) : v4 sauté") }
}

/// Alice et Bob, session v4 établie et confirmée (un aller-retour).
func duo4(_ seed: String) throws -> (Session4, Session4, Device, Deterministic) {
    let rng = Deterministic(seed)
    let alice = Device.generate(rng: rng, now: 0, pq: true)
    let bob = Device.generate(rng: rng, now: 0, pq: true)
    let a = try alice.initiate4(bundle: try bob.bundle(), rng: rng)
    let t = try a.encryptToken("bonjour")
    let (b, c) = try bob.accept4(t, now: 0, rng: rng)
    XCTAssertEqual(texte(c), "bonjour")
    let r = try b.encryptToken("re")
    XCTAssertEqual(texte(try a.decrypt(r, now: 0, rng: rng)), "re")
    return (a, b, bob, rng)
}

/// Une mutation : un bit, un octet, ou une coupe.
func muter(_ rng: Deterministic, _ data: [UInt8]) -> [UInt8] {
    var v = data
    for _ in 0..<(1 + Int(rng.nextU32() % 3)) {
        guard !v.isEmpty else { break }
        let i = Int(rng.nextU32()) % v.count
        switch rng.nextU32() % 3 {
        case 0: v[i] ^= 1 << (rng.nextU32() % 8)
        case 1: v[i] = UInt8(truncatingIfNeeded: rng.nextU32())
        default: v.removeSubrange(i...)
        }
    }
    return v
}

/// Une copie indépendante d'un appareil (le `clone` de la référence).
func copie(_ d: Device) -> Device {
    Device(state: d.state)
}

final class ProtocoleV4Tests: XCTestCase {
    // MARK: Jeton (jeton_v4.rs)

    func corps(_ ct: Bool) -> Body4 {
        Body4(
            headerNonce: [UInt8](repeating: 3, count: 12),
            header: [UInt8](repeating: 4, count: (ct ? JetonV4.headerLengthCt : JetonV4.headerLength) + 16),
            ciphertext: [UInt8](repeating: 5, count: 176))
    }

    func testJetonV4AllerRetour() throws {
        let preamble = Preamble4(
            ephemeral: [UInt8](repeating: 1, count: 32), kemCiphertext: [UInt8](repeating: 2, count: JetonV4.kemCtLength),
            sealedIdentity: [UInt8](repeating: 6, count: JetonV4.preambleLength))
        for t in [Token4.message(corps(false)), Token4.message(corps(true)), Token4.initial(preamble, corps(false))] {
            XCTAssertEqual(try Token4.decode(t.encode()), t)
            XCTAssertEqual(try Token4.fromBytes(t.toBytes()), t)
        }
        XCTAssertEqual(JetonV4.headerLength + 16, 1_241)
        XCTAssertEqual(JetonV4.headerLengthCt + 16, 2_329)
        // Dans un texte collé.
        let t = Token4.message(corps(false)).encode()
        let found = JetonV4.findAll("avant \(t) après [[BROCOLIS:v4:AAAA]]")
        XCTAssertEqual(found.count, 2)
        XCTAssertEqual(found.first?.text, t)
        XCTAssertEqual(try found[0].token.get(), Token4.message(corps(false)))
        if case .success = found[1].token { XCTFail("jeton tronqué accepté") }
    }

    func testJetonV4RefusStricts() {
        let ok = Token4.message(corps(false)).toBytes()
        // Type inconnu.
        var b = ok
        b[0] = 0x03
        attendreErreur(.format) { try Token4.fromBytes(b) }
        // Longueur d'en-tête non permise.
        b = ok
        b[13] = 0x00
        b[14] = 0x10
        attendreErreur(.format) { try Token4.fromBytes(b) }
        // Chiffré tronqué, ou de longueur non permise.
        attendreErreur(.format) { try Token4.fromBytes(Array(ok.dropLast())) }
        attendreErreur(.format) { try Token4.fromBytes(ok + [0]) }
        attendreErreur(.format) { try Token4.fromBytes([]) }
        attendreErreur(.format) { try Token4.fromBytes([0x01] + [UInt8](repeating: 0, count: 100)) }
        attendreErreur(.tropGrand) { try Token4.fromBytes([UInt8](repeating: 2, count: JetonV4.maxTokenBytes + 1)) }
        attendreErreur(.jetonAbsent) { try Token4.decode("[[BROCOLIS:v3:AA==]]") }
        attendreErreur(.jetonAbsent) { try Token4.decode(" " + Token4.message(corps(false)).encode()) }
        attendreErreur(.base64) { try Token4.decode("[[BROCOLIS:v4:A]]") }
    }

    func testEnTeteStrict() {
        let h = Header4(
            dh: [UInt8](repeating: 7, count: 32), pn: 1, n: 2, ek: [UInt8](repeating: 8, count: Paquet.pqpkLength),
            ct: [UInt8](repeating: 9, count: JetonV4.kemCtLength))
        let b = h.toBytes()
        XCTAssertEqual(b.count, JetonV4.headerLengthCt)
        XCTAssertEqual(try Header4.fromBytes(b), h)
        var bad = b
        bad[40] = 2
        attendreErreur(.format) { try Header4.fromBytes(bad) }
        attendreErreur(.format) { try Header4.fromBytes(Array(b[0..<JetonV4.headerLength])) }
        attendreErreur(.format) { try Header4.fromBytes(b + [0]) }
        let sans = Header4(dh: h.dh, pn: 0, n: 0, ek: h.ek, ct: nil)
        XCTAssertEqual(sans.toBytes().count, JetonV4.headerLength)
        XCTAssertEqual(try Header4.fromBytes(sans.toBytes()), sans)
    }

    // MARK: Session (session4.rs)

    func testPremierEchangeEtTripleCliquet() throws {
        try exigerMlKem()
        let rng = Deterministic("session4")
        let alice = Device.generate(rng: rng, now: 0, pq: true)
        let bob = Device.generate(rng: rng, now: 0, pq: true)
        let a = try alice.initiate4(bundle: try bob.bundle(), rng: rng)
        let t = try a.encryptToken("Salut 🥦")
        guard case .initial = t else { return XCTFail("0x01 attendu") }
        // L'identité d'Alice n'est pas dans le jeton.
        let ikA = alice.identity().dh
        XCTAssertNil(Octets.find(t.toBytes(), ikA))
        let (b, c) = try bob.accept4(t, now: 10, rng: rng)
        XCTAssertEqual(texte(c), "Salut 🥦")
        XCTAssertEqual(b.peerIdentity, ikA)
        XCTAssertEqual(b.sessionId, a.sessionId)
        XCTAssertEqual(b.mode, .bundle)
        attendreErreur(.rejoue) { try bob.accept4(t, now: 11, rng: rng) }
        attendreErreur(.rejoue) { try b.decrypt(t, now: 11, rng: rng) }
        // Plusieurs tours : chaque réponse porte une encapsulation.
        for i in 0..<4 {
            let r = try b.encryptToken("b\(i)")
            guard case .message(let body) = r else { return XCTFail("0x02 attendu") }
            XCTAssertEqual(body.header.count, JetonV4.headerLengthCt + 16)
            XCTAssertEqual(texte(try a.decrypt(r, now: 12, rng: rng)), "b\(i)")
            XCTAssertTrue(a.isConfirmed)
            let m = try a.encryptToken("a\(i)")
            guard case .message = m else { return XCTFail("0x02 attendu") }
            XCTAssertEqual(texte(try b.decrypt(m, now: 12, rng: rng)), "a\(i)")
        }
    }

    func testDesordreRejeuEtEcho() throws {
        try exigerMlKem()
        let rng = Deterministic("session4")
        let alice = Device.generate(rng: rng, now: 0, pq: true)
        let bob = Device.generate(rng: rng, now: 0, pq: true)
        let a = try alice.initiate4(bundle: try bob.bundle(), rng: rng)
        let (b, _) = try bob.accept4(try a.encryptToken("1"), now: 0, rng: rng)
        _ = try a.decrypt(try b.encryptToken("r"), now: 0, rng: rng)
        let m1 = try a.encryptToken("m1")
        let m2 = try a.encryptToken("m2")
        let m3 = try a.encryptToken("m3")
        XCTAssertEqual(texte(try b.decrypt(m3, now: 0, rng: rng)), "m3")
        XCTAssertEqual(b.skippedCount, 2)
        XCTAssertEqual(texte(try b.decrypt(m1, now: 0, rng: rng)), "m1")
        XCTAssertEqual(texte(try b.decrypt(m2, now: 0, rng: rng)), "m2")
        attendreErreur(.rejoue) { try b.decrypt(m2, now: 0, rng: rng) }
        // Notre propre message, renvoyé : rejeu, pas « inconnu ».
        attendreErreur(.rejoue) { try a.decrypt(m1, now: 0, rng: rng) }
        // Un message d'une autre session : inconnu.
        let other = try Device.generate(rng: rng, now: 0, pq: true)
            .initiate4(bundle: try Device.generate(rng: rng, now: 0, pq: true).bundle(), rng: rng)
        guard case .initial(_, let body) = try other.encryptToken("x") else { return XCTFail("0x01 attendu") }
        attendreErreur(.sessionInconnue) { try b.decrypt(.message(body), now: 0, rng: rng) }
    }

    func testAlterationRefuseeEtEtatIntact() throws {
        try exigerMlKem()
        let rng = Deterministic("session4")
        let alice = Device.generate(rng: rng, now: 0, pq: true)
        let bob = Device.generate(rng: rng, now: 0, pq: true)
        let a = try alice.initiate4(bundle: try bob.bundle(), rng: rng)
        let (b, _) = try bob.accept4(try a.encryptToken("1"), now: 0, rng: rng)
        let r = try b.encryptToken("r")
        let before = a.toJson()
        var bytes = r.toBytes()
        bytes[bytes.count - 1] ^= 1
        let bad = try Token4.fromBytes(bytes)
        attendreErreur(.dechiffrement) { try a.decrypt(bad, now: 0, rng: rng) }
        XCTAssertEqual(a.toJson(), before, "transactionnel")
        // L'en-tête altéré : aucune clé ne l'ouvre.
        bytes = r.toBytes()
        bytes[20] ^= 1
        let bad2 = try Token4.fromBytes(bytes)
        attendreErreur(.sessionInconnue) { try a.decrypt(bad2, now: 0, rng: rng) }
        XCTAssertEqual(a.toJson(), before)
        XCTAssertEqual(texte(try a.decrypt(r, now: 0, rng: rng)), "r")
    }

    func testPskV4() throws {
        try exigerMlKem()
        let rng = Deterministic("psk4")
        let key = [UInt8](repeating: 7, count: 32)
        let a = try Session4.initiatePsk(key: key, rng: rng)
        XCTAssertEqual(a.mode, .psk)
        XCTAssertNil(a.peerIdentity)
        let t = try a.encryptToken("par la clé")
        guard case .message = t else { return XCTFail("0x02 attendu") }
        var g = ReplayGuard()
        attendreErreur(.sessionInconnue) {
            try Session4.acceptPsk(keys: [[UInt8](repeating: 1, count: 32)], token: t, guard: &g, now: 0, rng: rng)
        }
        let (b, c) = try Session4.acceptPsk(
            keys: [[UInt8](repeating: 1, count: 32), key], token: t, guard: &g, now: 0, rng: rng)
        XCTAssertEqual(texte(c), "par la clé")
        XCTAssertEqual(b.mode, .psk)
        XCTAssertEqual(b.sessionId, a.sessionId)
        attendreErreur(.rejoue) { try Session4.acceptPsk(keys: [key], token: t, guard: &g, now: 0, rng: rng) }
        let r = try b.encrypt("réponse")
        XCTAssertEqual(texte(try a.decryptText(r, now: 0, rng: rng)), "réponse")
        let m = try a.encrypt("encore")
        XCTAssertEqual(texte(try b.decryptText(m, now: 0, rng: rng)), "encore")
    }

    func testDistributionV4() throws {
        try exigerMlKem()
        let (a, b, _, rng) = try duo4("distribution4")
        let chain = try SenderKeyState.generate(groupId: [UInt8](repeating: 5, count: 16), rng: rng)
        let d = chain.distribution()
        let t = try a.encryptDistribution(d)
        XCTAssertEqual(try b.decryptText(t, now: 0, rng: rng), .distribution(d))
    }

    func testJsonAllerRetour() throws {
        try exigerMlKem()
        let rng = Deterministic("session4")
        let alice = Device.generate(rng: rng, now: 0, pq: true)
        let bob = Device.generate(rng: rng, now: 0, pq: true)
        let a = try alice.initiate4(bundle: try bob.bundle(), rng: rng)
        let t = try a.encryptToken("x")
        let (b, _) = try bob.accept4(t, now: 0, rng: rng)
        let b2 = try Session4.fromJson(b.toJson())
        let a2 = try Session4.fromJson(a.toJson())
        XCTAssertEqual(b2.toJson(), b.toJson())
        XCTAssertEqual(a2.toJson(), a.toJson())
        let r = try b2.encrypt("y")
        XCTAssertEqual(texte(try a2.decryptText(r, now: 0, rng: rng)), "y")
        attendreErreur(.etat) { try Session4.fromJson("{}") }
        // Un état v3 n'est pas un état v4.
        let s3 = try Session.initiatePsk(key: [UInt8](repeating: 1, count: 32), rng: rng)
        attendreErreur(.etat) { try Session4.fromJson(s3.toJson()) }
    }

    func testCapaciteV4Signee() throws {
        try exigerMlKem()
        let rng = Deterministic("caps")
        let a = Device.generate(rng: rng, now: 0, pq: true)
        let b = Device.generate(rng: rng, now: 0, pq: true)
        let caps = try XCTUnwrap(a.caps4())
        XCTAssertEqual(caps.count, 64)
        XCTAssertNoThrow(try Paquet.verifyCaps4(identity: a.identity(), signature: caps))
        // Sur une autre identité, ou altérée : refusée.
        attendreErreur(.signature) { try Paquet.verifyCaps4(identity: b.identity(), signature: caps) }
        var bad = caps
        bad[0] ^= 1
        attendreEchec { try Paquet.verifyCaps4(identity: a.identity(), signature: bad) }
        attendreEchec { try Paquet.verifyCaps4(identity: a.identity(), signature: Array(caps.dropLast())) }
        // Sans ML-KEM, pas de capacité v4.
        XCTAssertNil(Device.generate(rng: rng, now: 0, pq: false).caps4())
    }

    func testUnPaquetSansMlKemEstRefuse() throws {
        try exigerMlKem()
        let rng = Deterministic("classique")
        let alice = Device.generate(rng: rng, now: 0, pq: true)
        let bob = Device.generate(rng: rng, now: 0, pq: false)
        attendreErreur(.pqIndisponible) { try alice.initiate4(bundle: try bob.bundle(), rng: rng) }
    }

    // MARK: Robustesse (robustesse_v4.rs)

    func testEntreesAleatoires() throws {
        try exigerMlKem()
        let (a, b, bob, rng) = try duo4("aleatoire4")
        for i in 0..<3_000 {
            let n = Int(rng.nextU32() % 3_000)
            var data = rng.bytes(n)
            if !data.isEmpty { data[0] = UInt8(1 + i % 2) }
            // Une longueur d'en-tête plausible pour atteindre le déchiffrement.
            if data.count > 15 && i % 3 == 0 {
                let len = i % 2 == 0 ? JetonV4.headerLength + 16 : JetonV4.headerLengthCt + 16
                data[13] = UInt8(len >> 8)
                data[14] = UInt8(len & 0xFF)
            }
            let text = String(decoding: data, as: UTF8.self)
            _ = try? Token4.decode(text)
            _ = try? Session4.fromJson(text)
            _ = JetonV4.findAll(text)
            _ = try? Token4.decode("[[BROCOLIS:v4:\(Base64.encode(data))]]")
            guard let t = try? Token4.fromBytes(data) else { continue }
            for s in [a, b] {
                let c = s.copie()
                let before = c.toJson()
                attendreEchec { try c.decrypt(t, now: 0, rng: rng) }
                XCTAssertEqual(c.toJson(), before)
            }
            _ = try? copie(bob).accept4(t, now: 0, rng: rng)
            var g = ReplayGuard()
            _ = try? Session4.acceptPsk(keys: [[UInt8](repeating: 1, count: 32)], token: t, guard: &g, now: 0, rng: rng)
        }
    }

    func testChaqueOctetAltereEstRefuse() throws {
        try exigerMlKem()
        let (a, b, _, rng) = try duo4("alteration4")
        // Un message avec encapsulation (nouvelle chaîne d'Alice).
        let t = try a.encryptToken("secret").toBytes()
        // Tout l'en-tête et le chiffré, sans 2 500 essais ML-KEM.
        for i in stride(from: 0, to: t.count, by: 7) {
            var m = t
            m[i] ^= 0x01
            guard let tok = try? Token4.fromBytes(m) else { continue }
            let s = b.copie()
            let before = s.toJson()
            attendreEchec("octet \(i) altéré accepté") { try s.decrypt(tok, now: 0, rng: rng) }
            XCTAssertEqual(s.toJson(), before, "octet \(i) : état modifié")
        }
        XCTAssertEqual(texte(try b.copie().decrypt(try Token4.fromBytes(t), now: 0, rng: rng)), "secret")
    }

    func testPremierMessageAltereOuRejoue() throws {
        try exigerMlKem()
        let rng = Deterministic("premier4")
        let alice = Device.generate(rng: rng, now: 0, pq: true)
        let bob = Device.generate(rng: rng, now: 0, pq: true)
        let a = try alice.initiate4(bundle: try bob.bundle(), rng: rng)
        let t = try a.encryptToken("x").toBytes()
        // EK, CT, préambule, en-tête, chiffré : un octet de chaque.
        for i in [1, 40, 1_200, 1_170, 1_190, 1_250, t.count - 1] {
            var m = t
            m[i] ^= 0x01
            guard let tok = try? Token4.fromBytes(m) else { continue }
            let d = copie(bob)
            attendreEchec("octet \(i)") { try d.accept4(tok, now: 0, rng: rng) }
            XCTAssertTrue(d.replayGuard.isEmpty)
        }
        // Un appareil tiers : aucune clé n'ouvre le préambule.
        let carole = Device.generate(rng: rng, now: 0, pq: true)
        attendreErreur(.cleInconnue) { try carole.accept4(try Token4.fromBytes(t), now: 0, rng: rng) }
        // L'original passe, une fois.
        let (_, c) = try bob.accept4(try Token4.fromBytes(t), now: 0, rng: rng)
        XCTAssertEqual(texte(c), "x")
        attendreErreur(.rejoue) { try bob.accept4(try Token4.fromBytes(t), now: 1, rng: rng) }
    }

    func testTropDeSauts() throws {
        try exigerMlKem()
        let (a, b, _, rng) = try duo4("sauts4")
        var last: Token4? = nil
        for i in 0..<1_002 {
            last = try a.encryptToken("\(i)")
        }
        let t = try XCTUnwrap(last)
        attendreErreur(.tropDeClesSautees) { try b.decrypt(t, now: 0, rng: rng) }
    }

    func testLongueConversationDansLeDesordre() throws {
        try exigerMlKem()
        let (a, b, _, rng) = try duo4("desordre4")
        for round in 0..<12 {
            let (from, to) = round % 2 == 0 ? (a, b) : (b, a)
            let n = 1 + Int(rng.nextU32() % 5)
            var batch: [(String, Token4)] = []
            for i in 0..<n {
                let t = "r\(round)m\(i)"
                batch.append((t, try from.encryptToken(t)))
            }
            // Mélange (Fisher-Yates déterministe).
            for i in stride(from: batch.count - 1, to: 0, by: -1) {
                let j = Int(rng.nextU32()) % (i + 1)
                batch.swapAt(i, j)
            }
            for (t, tok) in batch {
                XCTAssertEqual(texte(try to.decrypt(tok, now: 0, rng: rng)), t)
                attendreErreur(.rejoue) { try to.decrypt(tok, now: 0, rng: rng) }
            }
            XCTAssertEqual(to.skippedCount, 0)
        }
    }

    func testUnRetardataireDUneChainePassee() throws {
        try exigerMlKem()
        let (a, b, _, rng) = try duo4("retard4")
        let x1 = try a.encryptToken("x1")
        let x2 = try a.encryptToken("x2")
        XCTAssertEqual(texte(try b.decrypt(x2, now: 0, rng: rng)), "x2")
        let y = try b.encryptToken("y")
        XCTAssertEqual(texte(try a.decrypt(y, now: 0, rng: rng)), "y")
        // Nouvelle chaîne d'Alice (encapsulation vers la clé ML-KEM de Bob).
        let x3 = try a.encryptToken("x3")
        XCTAssertEqual(texte(try b.decrypt(x3, now: 0, rng: rng)), "x3")
        // x1, de la chaîne d'avant, arrive enfin.
        XCTAssertEqual(texte(try b.decrypt(x1, now: 0, rng: rng)), "x1")
        attendreErreur(.rejoue) { try b.decrypt(x1, now: 0, rng: rng) }
        XCTAssertEqual(b.skippedCount, 0)
    }

    func testMutationsDEtatsJsonV4() throws {
        try exigerMlKem()
        let (a, b, _, rng) = try duo4("json4")
        let texts = [a.toJson(), b.toJson()]
        for k in 0..<500 {
            let m = muter(rng, Array(texts[k % 2].utf8))
            if let s = try? Session4.fromJson(String(decoding: m, as: UTF8.self)) {
                // Un état relu, même altéré, ne fait jamais planter.
                _ = try? s.encrypt("y")
                _ = try? s.decryptText("[[BROCOLIS:v4:AAAA]]", now: 0, rng: rng)
            }
        }
    }
}
