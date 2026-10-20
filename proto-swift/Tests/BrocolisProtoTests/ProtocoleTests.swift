// Les tests de propriétés du protocole v3 (proto/tests/protocole.rs et les
// unitaires de session.rs, paquet.rs, groupe.rs, jeton_v3.rs, jetons.rs) :
// aller-retour, désordre, pertes, rejeu, sessions croisées, altérations d'un
// bit, MAX_SKIP, persistance JSON. Les scénarios sont tirés par un
// générateur déterministe (graines fixes) : un échec se rejoue à l'identique.
//
// Là où ML-KEM manque (iOS/macOS < 26), les cas hybrides passent en X25519
// seul (`pq(...)`), sauf ceux qui portent sur ML-KEM lui-même.

import XCTest
@testable import BrocolisProto

/// `pq` si ML-KEM est disponible ici.
func pq(_ wanted: Bool) -> Bool { wanted && MlKem.isAvailable }

/// Une session établie et confirmée (B a répondu).
func established(_ seed: String, pq wanted: Bool) throws -> (Session, Session, Deterministic) {
    let rng = Deterministic(seed)
    let usePq = pq(wanted)
    let alice = Device.generate(rng: rng, now: T0, pq: usePq)
    let bob = Device.generate(rng: rng, now: T0, pq: usePq)
    let a = try alice.initiate(bundle: try bob.bundle(), pq: usePq, rng: rng)
    let i = try XCTUnwrap(try a.encryptToken("bonjour").initialMessage)
    let (b, c) = try bob.accept(i, now: T0, rng: rng)
    XCTAssertEqual(texte(c), "bonjour")
    let r = try b.encryptToken("re")
    XCTAssertEqual(texte(try a.decrypt(r, now: T0, rng: rng)), "re")
    return (a, b, rng)
}

func below(_ rng: Deterministic, _ n: Int) -> Int {
    Int(rng.nextU32()) % n
}

final class ProtocoleTests: XCTestCase {
    // MARK: Session (session.rs)

    func testPremierEchange() throws {
        for wanted in [false, true] {
            let usePq = pq(wanted)
            let rng = Deterministic("session")
            let alice = Device.generate(rng: rng, now: 0, pq: usePq)
            let bob = Device.generate(rng: rng, now: 0, pq: usePq)
            let a = try alice.initiate(bundle: try bob.bundle(), pq: usePq, rng: rng)
            let t = try a.encryptToken("Salut 🥦")
            let i = try XCTUnwrap(t.initialMessage)
            XCTAssertEqual(i.mode, usePq ? .hybrid : .classic)
            let (b, c) = try bob.accept(i, now: 10, rng: rng)
            XCTAssertEqual(texte(c), "Salut 🥦")
            XCTAssertEqual(b.sessionId, a.sessionId)
            XCTAssertEqual(b.isPostQuantum, usePq)
            // Le même premier message une seconde fois : rejeu.
            attendreErreur(.rejoue) { try bob.accept(i, now: 11, rng: rng) }
            attendreErreur(.rejoue) { try b.decrypt(t, now: 11, rng: rng) }
            let r = try b.encrypt("Bien reçu")
            XCTAssertFalse(a.isConfirmed)
            XCTAssertEqual(texte(try a.decryptText(r, now: 12, rng: rng)), "Bien reçu")
            XCTAssertTrue(a.isConfirmed)
            guard case .message = try a.encryptToken("ok") else { return XCTFail("0x02 attendu") }
        }
    }

    func testJsonAllerRetour() throws {
        let usePq = pq(true)
        let rng = Deterministic("session")
        let alice = Device.generate(rng: rng, now: 0, pq: usePq)
        let bob = Device.generate(rng: rng, now: 0, pq: usePq)
        let a = try alice.initiate(bundle: try bob.bundle(), pq: usePq, rng: rng)
        let i = try XCTUnwrap(try a.encryptToken("x").initialMessage)
        let (b, _) = try bob.accept(i, now: 0, rng: rng)
        let b2 = try Session.fromJson(b.toJson())
        let a2 = try Session.fromJson(a.toJson())
        let t = try b2.encrypt("y")
        XCTAssertEqual(texte(try a2.decryptText(t, now: 0, rng: rng)), "y")
        attendreErreur(.etat) { try Session.fromJson("{}") }
        // L'état relu se réécrit à l'identique.
        XCTAssertEqual(try Session.fromJson(a2.toJson()).toJson(), a2.toJson())
        XCTAssertEqual(try Device.fromJson(bob.toJson()).toJson(), bob.toJson())
    }

    func testPskUnitaire() throws {
        let rng = Deterministic("psk")
        let key = [UInt8](repeating: 7, count: 32)
        let a = try Session.initiatePsk(key: key, rng: rng)
        let i = try XCTUnwrap(try a.encryptToken("par la clé").initialMessage)
        var g = ReplayGuard()
        attendreErreur(.sessionInconnue) {
            try Session.acceptPsk(keys: [[UInt8](repeating: 1, count: 32)], message: i, guard: &g, now: 0, rng: rng)
        }
        let (b, c) = try Session.acceptPsk(keys: [[UInt8](repeating: 1, count: 32), key], message: i, guard: &g, now: 0, rng: rng)
        XCTAssertEqual(texte(c), "par la clé")
        XCTAssertEqual(b.mode, .psk)
        attendreErreur(.rejoue) { try Session.acceptPsk(keys: [key], message: i, guard: &g, now: 0, rng: rng) }
        let r = try b.encrypt("réponse")
        XCTAssertEqual(texte(try a.decryptText(r, now: 0, rng: rng)), "réponse")
    }

    // MARK: Propriétés (protocole.rs)

    /// Un échange au hasard : envois des deux côtés, livraisons dans le
    /// désordre, pertes, rejeux et sauvegardes JSON. Chaque message livré est
    /// lu une fois, exactement ; un rejeu ne l'est jamais.
    func testEchangesAleatoires() throws {
        var horsDes16 = 0
        for seed in 0..<24 {
            var (a, b, rng) = try established("échanges/\(seed)", pq: seed % 2 == 0)
            var inFlight: [(fromA: Bool, token: Token, text: String)] = []
            var delivered: [(fromA: Bool, token: Token)] = []
            var now = T0
            for step in 0..<300 {
                now += 7
                switch below(rng, 10) {
                case 0...3:
                    let fromA = below(rng, 2) == 0
                    let msg = "\(seed)/\(step) " + String(repeating: "é", count: below(rng, 200))
                    inFlight.append((fromA, try (fromA ? a : b).encryptToken(msg), msg))
                case 4...7 where !inFlight.isEmpty:
                    let k = below(rng, inFlight.count)
                    let m = inFlight.remove(at: k)
                    XCTAssertEqual(texte(try (m.fromA ? b : a).decrypt(m.token, now: now, rng: rng)), m.text, "graine \(seed)")
                    delivered.append((m.fromA, m.token))
                case 8 where !inFlight.isEmpty:
                    inFlight.remove(at: below(rng, inFlight.count)) // perdu
                case 9 where !delivered.isEmpty:
                    let d = delivered[below(rng, delivered.count)]
                    let r = d.fromA ? b : a
                    let before = r.toJson()
                    // Rejeu : `.rejoue`, sauf si la clé de cliquet du message est
                    // sortie des 16 dernières retenues (§7.5) : alors le message
                    // est refusé autrement (`.dechiffrement`). La référence fait
                    // pareil, au même endroit (graine 6, étape 297 : vérifié en
                    // rejouant ce scénario avec brocolis-proto).
                    do {
                        _ = try r.decrypt(d.token, now: now, rng: rng)
                        XCTFail("rejeu accepté : graine \(seed) étape \(step)")
                    } catch let e as Erreur {
                        XCTAssertTrue(e == .rejoue || e == .dechiffrement, "graine \(seed) étape \(step) : \(e)")
                        if e == .dechiffrement { horsDes16 += 1 }
                    }
                    XCTAssertEqual(r.toJson(), before)
                default:
                    a = try Session.fromJson(a.toJson())
                    b = try Session.fromJson(b.toJson())
                }
                XCTAssertLessThanOrEqual(a.skippedCount, Int(Protocole.maxSkip))
                XCTAssertLessThanOrEqual(b.skippedCount, Int(Protocole.maxSkip))
            }
            // Tout ce qui reste en vol arrive encore.
            while let m = inFlight.popLast() {
                XCTAssertEqual(texte(try (m.fromA ? b : a).decrypt(m.token, now: now, rng: rng)), m.text)
            }
        }
        XCTAssertEqual(horsDes16, 1)
    }

    /// Un bit modifié n'importe où dans un jeton : refusé, et la session est
    /// exactement celle d'avant.
    func testAlterationsDUnBit() throws {
        let (a, b, rng) = try established("bits", pq: true)
        let token = try a.encryptToken("un message à ne pas modifier")
        let bytes = token.toBytes()
        let before = b.toJson()
        for i in 0..<bytes.count {
            for bit in 0..<8 {
                var x = bytes
                x[i] ^= 1 << bit
                if let t = try? Token.fromBytes(x) {
                    attendreEchec("octet \(i) bit \(bit)") { try b.decrypt(t, now: T0, rng: rng) }
                }
            }
        }
        XCTAssertEqual(b.toJson(), before)
        XCTAssertEqual(texte(try b.decrypt(token, now: T0, rng: rng)), "un message à ne pas modifier")
    }

    /// Un bit modifié dans un premier message (préambule, CT ML-KEM
    /// compris) : aucune session n'est ouverte, l'appareil ne retient rien.
    func testAlterationsDuPremierMessage() throws {
        let rng = Deterministic("premier")
        let usePq = pq(true)
        let alice = Device.generate(rng: rng, now: T0, pq: usePq)
        let bob = Device.generate(rng: rng, now: T0, pq: usePq)
        let a = try alice.initiate(bundle: try bob.bundle(), pq: usePq, rng: rng)
        let token = try a.encryptToken("établir")
        let bytes = token.toBytes()
        let before = bob.toJson()
        for i in stride(from: 0, to: bytes.count, by: 3) {
            for bit in 0..<8 {
                var x = bytes
                x[i] ^= 1 << bit
                if let m = (try? Token.fromBytes(x))?.initialMessage {
                    attendreEchec("octet \(i) bit \(bit)") { try bob.accept(m, now: T0, rng: rng) }
                }
            }
        }
        XCTAssertEqual(bob.toJson(), before)
        XCTAssertEqual(texte(try bob.accept(try XCTUnwrap(token.initialMessage), now: T0, rng: rng).1), "établir")
    }

    func testMaxSkipEtAgeDesClesSautees() throws {
        let (a, b, rng) = try established("skip", pq: false)
        let max = Int(Protocole.maxSkip)
        let tokens = try (0...(max + 1)).map { try a.encryptToken(String($0)) }
        // Le message n = MAX_SKIP + 1 demanderait 1 001 clés sautées : refusé.
        let before = b.toJson()
        attendreErreur(.tropDeClesSautees) { try b.decrypt(tokens[max + 1], now: T0, rng: rng) }
        XCTAssertEqual(b.toJson(), before)
        XCTAssertEqual(texte(try b.decrypt(tokens[max], now: T0, rng: rng)), "1000")
        XCTAssertEqual(b.skippedCount, max)
        XCTAssertEqual(texte(try b.decrypt(tokens[max + 1], now: T0, rng: rng)), "1001")
        // Un retardataire, encore dans les 30 jours.
        XCTAssertEqual(texte(try b.decrypt(tokens[5], now: T0 + Protocole.maxSkipAge - 1, rng: rng)), "5")
        attendreErreur(.rejoue) { try b.decrypt(tokens[5], now: T0, rng: rng) }
        // Après 30 jours, les clés sautées sont effacées : le message est perdu.
        attendreEchec { try b.decrypt(tokens[6], now: T0 + Protocole.maxSkipAge, rng: rng) }
        b.purge(now: T0 + Protocole.maxSkipAge)
        XCTAssertEqual(b.skippedCount, 0)
    }

    func testLePlafondDeClesSauteesEffaceLesPlusVieilles() throws {
        let (a, b, rng) = try established("plafond", pq: false)
        let first = try (0..<600).map { try a.encryptToken(String($0)) }
        let second = try (600..<1200).map { try a.encryptToken(String($0)) }
        _ = try b.decrypt(first[599], now: T0, rng: rng)
        _ = try b.decrypt(second[599], now: T0, rng: rng)
        XCTAssertEqual(b.skippedCount, Int(Protocole.maxSkip))
        // Les plus vieilles (0..198) sont parties ; 198 et suivantes restent.
        attendreEchec { try b.decrypt(first[0], now: T0, rng: rng) }
        XCTAssertEqual(texte(try b.decrypt(first[198], now: T0, rng: rng)), "198")
    }

    func testSessionsCroisees() throws {
        let (a1, b1, rng) = try established("croise-1", pq: true)
        let (a2, b2, _) = try established("croise-2", pq: true)
        let t1 = try a1.encryptToken("pour b1")
        let t2 = try a2.encryptToken("pour b2")
        let before = b2.toJson()
        attendreErreur(.sessionInconnue) { try b2.decrypt(t1, now: T0, rng: rng) }
        XCTAssertEqual(b2.toJson(), before)
        // Même identifiant forcé : la clé ne correspond pas.
        guard case .message(var e) = t1 else { return XCTFail("0x02 attendu") }
        e.sessionId = b2.sessionId
        attendreEchec { try b2.decrypt(.message(e), now: T0, rng: rng) }
        XCTAssertEqual(b2.toJson(), before)
        XCTAssertEqual(texte(try b1.decrypt(t1, now: T0, rng: rng)), "pour b1")
        XCTAssertEqual(texte(try b2.decrypt(t2, now: T0, rng: rng)), "pour b2")
        // Ses propres messages renvoyés : ignorés.
        let own = try a1.encryptToken("à moi")
        attendreErreur(.rejoue) { try a1.decrypt(own, now: T0, rng: rng) }
    }

    func testNouvelleSessionMemeIdentifiant() throws {
        let rng = Deterministic("nouvelle")
        let usePq = pq(true)
        let alice = Device.generate(rng: rng, now: T0, pq: usePq)
        let bob = Device.generate(rng: rng, now: T0, pq: usePq)
        let bundle = try bob.bundle()
        let a1 = try alice.initiate(bundle: bundle, pq: usePq, rng: rng)
        let i1 = try XCTUnwrap(try a1.encryptToken("un").initialMessage)
        let (b1, _) = try bob.accept(i1, now: T0, rng: rng)
        // Alice a perdu sa session et en ouvre une autre : même AD, même id.
        let a2 = try alice.initiate(bundle: bundle, pq: usePq, rng: rng)
        let t = try a2.encryptToken("deux")
        XCTAssertEqual(t.sessionId, b1.sessionId)
        attendreErreur(.nouvelleSession) { try b1.decrypt(t, now: T0, rng: rng) }
        let (b2, c) = try bob.accept(try XCTUnwrap(t.initialMessage), now: T0, rng: rng)
        XCTAssertEqual(texte(c), "deux")
        let r = try b2.encryptToken("ok")
        XCTAssertEqual(texte(try a2.decrypt(r, now: T0, rng: rng)), "ok")
    }

    func testSansPqEtPaquetSansMlKem() throws {
        let rng = Deterministic("sans-pq")
        let alice = Device.generate(rng: rng, now: T0, pq: pq(true))
        let bob = Device.generate(rng: rng, now: T0, pq: false)
        let bundle = try bob.bundle()
        XCTAssertNil(bundle.pq)
        attendreErreur(.pqIndisponible) { try alice.initiate(bundle: bundle, pq: true, rng: rng) }
        let a = try alice.initiate(bundle: bundle, pq: false, rng: rng)
        XCTAssertFalse(a.isPostQuantum)
        let i = try XCTUnwrap(try a.encryptToken("classique").initialMessage)
        let (b, _) = try bob.accept(i, now: T0, rng: rng)
        XCTAssertFalse(b.isPostQuantum)
        XCTAssertEqual(b.peerIdentity, alice.identity().dh)
        // `initiateBest` retombe en X25519 seul.
        XCTAssertFalse(try alice.initiateBest(bundle: bundle, rng: rng).isPostQuantum)
    }

    func testInitiateBestHybrideSiPossible() throws {
        guard MlKem.isAvailable else {
            // iOS < 26 : même un paquet avec ML-KEM donne une session classique.
            return
        }
        let rng = Deterministic("meilleur")
        let alice = Device.generate(rng: rng, now: T0, pq: true)
        let bob = Device.generate(rng: rng, now: T0, pq: true)
        XCTAssertTrue(try alice.initiateBest(bundle: try bob.bundle(), rng: rng).isPostQuantum)
    }

    func testAncienneSpkGardeeUnMois() throws {
        let rng = Deterministic("spk")
        let usePq = pq(true)
        let alice = Device.generate(rng: rng, now: T0, pq: usePq)
        let bob = Device.generate(rng: rng, now: T0, pq: usePq)
        let old = try bob.bundle()
        let a = try alice.initiate(bundle: old, pq: usePq, rng: rng)
        let late = try a.encryptToken("en retard")
        bob.rotate(rng: rng, now: T0 + Paquet.prekeyRotation)
        XCTAssertNotEqual(try bob.bundle().spkId, old.spkId)
        let i = try XCTUnwrap(late.initialMessage)
        // Encore acceptée pendant le mois de grâce…
        let copy = try Device.fromJson(bob.toJson())
        XCTAssertNoThrow(try copy.accept(i, now: T0 + Paquet.prekeyRotation + 1, rng: rng))
        // … puis effacée.
        bob.purge(now: T0 + Paquet.prekeyRotation + Paquet.prekeyGrace)
        attendreErreur(.cleInconnue) { try bob.accept(i, now: T0, rng: rng) }
    }

    func testPskAllerRetourEtConfidentialiteApresReponse() throws {
        let rng = Deterministic("psk")
        let key = [UInt8](repeating: 9, count: 32)
        let a = try Session.initiatePsk(key: key, rng: rng)
        var g = ReplayGuard()
        let t1 = try a.encryptToken("un")
        let t2 = try a.encryptToken("deux")
        let (b, c) = try Session.acceptPsk(keys: [key], message: try XCTUnwrap(t2.initialMessage), guard: &g, now: T0, rng: rng)
        XCTAssertEqual(texte(c), "deux")
        XCTAssertEqual(texte(try b.decrypt(t1, now: T0, rng: rng)), "un")
        let r = try b.encryptToken("trois")
        XCTAssertEqual(texte(try a.decrypt(r, now: T0, rng: rng)), "trois")
        XCTAssertTrue(a.isConfirmed)
        // Après la réponse, quelqu'un qui n'a que la clé partagée ne lit plus
        // rien.
        let next = try a.encryptToken("quatre")
        var g2 = ReplayGuard()
        let (spy, _) = try Session.acceptPsk(
            keys: [key], message: try XCTUnwrap(t1.initialMessage), guard: &g2, now: T0, rng: Deterministic("espion"))
        attendreEchec { try spy.decrypt(next, now: T0, rng: rng) }
        XCTAssertEqual(texte(try b.decrypt(next, now: T0, rng: rng)), "quatre")
    }

    func testTexteTropLongRefuse() throws {
        let (a, _, _) = try established("long", pq: false)
        attendreErreur(.tropGrand) { try a.encrypt(String(repeating: "x", count: Session.maxPlaintext + 1)) }
        let t = try a.encrypt(String(repeating: "x", count: Session.maxPlaintext))
        XCTAssertNoThrow(try Token.decode(t))
        XCTAssertNotNil(Base64.decode(String(t.dropFirst(JetonV3.head.count).dropLast(2))))
    }

    // MARK: Groupes (protocole.rs, groupe.rs)

    func testGroupeParSessionsADeux() throws {
        let (a, b, rng) = try established("groupe", pq: true)
        let gid = Groupe.newGroupId(rng: rng)
        let chain = try SenderKeyState.generate(groupId: gid, rng: rng)
        let dist = try a.encryptDistribution(chain.distribution())
        guard case .distribution = try Token.decode(dist) else { return XCTFail("0x03 attendu") }
        guard case .distribution(let d) = try b.decryptText(dist, now: T0, rng: rng) else { return XCTFail() }
        let recv = try ReceivedSenderKey.fromDistribution(d)
        // Un 0x02 relu comme 0x03 est refusé : le type est authentifié.
        guard case .message(let e) = try a.encryptToken("texte") else { return XCTFail() }
        let before = b.toJson()
        attendreEchec { try b.decrypt(.distribution(e), now: T0, rng: rng) }
        XCTAssertEqual(b.toJson(), before)
        XCTAssertEqual(texte(try b.decrypt(.message(e), now: T0, rng: rng)), "texte")
        let msgs = try (0..<50).map { try chain.encrypt("g\($0)") }
        var order = Array(0..<50)
        for i in stride(from: order.count - 1, through: 1, by: -1) { order.swapAt(i, below(rng, i + 1)) }
        for (k, i) in order.enumerated() where k % 7 != 3 {
            let g = try XCTUnwrap(try Token.decode(msgs[i]).groupMessage)
            XCTAssertEqual(try recv.decrypt(g, now: T0), "g\(i)")
            attendreErreur(.rejoue) { try recv.decrypt(g, now: T0) }
        }
        // Un membre qui n'a que l'ancienne chaîne ne lit pas la nouvelle.
        let renewed = try SenderKeyState.generate(groupId: gid, rng: rng)
        let g = try XCTUnwrap(try renewed.encryptToken("après départ").groupMessage)
        attendreErreur(.expediteurInconnu) { try recv.decrypt(g, now: T0) }
    }

    func testGroupeAlterationsEtSaut() throws {
        let rng = Deterministic("groupe-bits")
        let chain = try SenderKeyState.generate(groupId: [UInt8](repeating: 3, count: 16), rng: rng)
        let recv = try ReceivedSenderKey.fromDistribution(chain.distribution())
        let t = try chain.encryptToken("signé")
        let bytes = t.toBytes()
        for i in 0..<bytes.count {
            var x = bytes
            x[i] ^= 0x40
            if let g = (try? Token.fromBytes(x))?.groupMessage {
                attendreEchec("octet \(i)") { try recv.decrypt(g, now: T0) }
            }
        }
        XCTAssertEqual(try recv.decrypt(try XCTUnwrap(t.groupMessage), now: T0), "signé")
        for _ in 0...Protocole.maxSkip { _ = try chain.encryptToken("x") }
        let far = try XCTUnwrap(try chain.encryptToken("trop loin").groupMessage)
        attendreErreur(.tropDeClesSautees) { try recv.decrypt(far, now: T0) }
    }

    func testGroupeDesordreRejeuJson() throws {
        let rng = Deterministic("groupe")
        let gid = Groupe.newGroupId(rng: rng)
        let s = try SenderKeyState.generate(groupId: gid, rng: rng)
        let d = try SenderKeyDistribution.fromBytes(s.distribution().toBytes())
        let r = try ReceivedSenderKey.fromDistribution(d)
        let msgs = try (0..<5).map { try s.encrypt("m\($0)") }
        for i in [3, 0, 4, 1, 2] {
            XCTAssertEqual(try r.decrypt(try XCTUnwrap(try Token.decode(msgs[i]).groupMessage), now: 0), "m\(i)")
        }
        XCTAssertEqual(r.skippedCount, 0)
        attendreErreur(.rejoue) { try r.decrypt(try XCTUnwrap(try Token.decode(msgs[2]).groupMessage), now: 0) }
        var bad = try XCTUnwrap(try Token.decode(msgs[1]).groupMessage)
        bad.ciphertext[0] ^= 1
        attendreErreur(.signature) { try r.decrypt(bad, now: 0) }
        XCTAssertEqual(try ReceivedSenderKey.fromJson(r.toJson()).senderId, s.senderId)
        let s2 = try SenderKeyState.fromJson(s.toJson())
        XCTAssertEqual(s2.iteration, 5)
        XCTAssertEqual(s2.senderId, s.senderId)
        // La distribution est vérifiée.
        var bytes = s.distribution().toBytes()
        bytes[16] ^= 1
        attendreErreur(.format) { try SenderKeyDistribution.fromBytes(bytes) }
        attendreErreur(.format) { try SenderKeyDistribution.fromBytes(Array(bytes[0..<91])) }
    }

    // MARK: Paquet (paquet.rs)

    func testPaquetAllerRetourEtSignatures() throws {
        for wanted in [false, true] {
            let usePq = pq(wanted)
            let d = Device.generate(rng: Deterministic("paquet"), now: 1_000, pq: usePq)
            let b = try d.bundle()
            let bytes = b.toBytes()
            XCTAssertEqual(bytes.count, usePq ? Paquet.bundleLengthPq : Paquet.bundleLengthClassic)
            XCTAssertEqual(try KeyBundle.fromBytes(bytes), b)
            XCTAssertEqual(try KeyBundle.fromBase64(b.toBase64()), b)
            // Chaque bit modifié est refusé.
            for i in 0..<bytes.count {
                var x = bytes
                x[i] ^= 0x01
                attendreEchec("octet \(i)") { try KeyBundle.fromBytes(x) }
            }
        }
    }

    func testRotationEtPurge() throws {
        let rng = Deterministic("rotation")
        let usePq = pq(true)
        let d = Device.generate(rng: rng, now: 0, pq: usePq)
        let first = try d.bundle()
        XCTAssertFalse(d.needsRotation(now: Paquet.prekeyRotation - 1))
        XCTAssertTrue(d.needsRotation(now: Paquet.prekeyRotation))
        d.rotate(rng: rng, now: Paquet.prekeyRotation)
        let second = try d.bundle()
        XCTAssertEqual(second.spkId, max(first.spkId &+ 1, 1))
        XCTAssertNoThrow(try d.spkSecret(first.spkId))
        if usePq { XCTAssertNoThrow(try d.pqSeed(try XCTUnwrap(first.pq).id)) }
        d.purge(now: Paquet.prekeyRotation + Paquet.prekeyGrace)
        attendreErreur(.cleInconnue) { try d.spkSecret(first.spkId) }
        XCTAssertNoThrow(try d.spkSecret(second.spkId))
        let back = try Device.fromJson(d.toJson())
        if ed25519Deterministe { XCTAssertEqual(try back.bundle(), second) }
        XCTAssertEqual(try back.bundle().spkId, second.spkId)
        attendreErreur(.etat) { try Device.fromJson("{}") }
    }

    func testReplayGuardBorne() {
        var g = ReplayGuard()
        for i in 0..<(ReplayGuard.max + 10) {
            g.insert(Octets.u64be(UInt64(i)) + [UInt8](repeating: 0, count: 24), now: 0)
        }
        XCTAssertEqual(g.count, ReplayGuard.max)
        XCTAssertFalse(g.seen([UInt8](repeating: 0, count: 32)))
        g.purge(now: ReplayGuard.maxAge)
        XCTAssertTrue(g.isEmpty)
    }

    // MARK: Jeton v3 (jeton_v3.rs)

    func env() -> Envelope {
        Envelope(
            sessionId: [UInt8](repeating: 1, count: 8),
            header: Header(dh: [UInt8](repeating: 2, count: 32), pn: 3, n: 0x0102_0304),
            ciphertext: [UInt8](repeating: 9, count: 176))
    }

    func testJetonV3AllerRetourDeChaqueType() throws {
        let tokens: [Token] = [
            .message(env()), .distribution(env()),
            .initial(Initial(
                identity: [UInt8](repeating: 4, count: 32), ephemeral: [UInt8](repeating: 5, count: 32), mode: .hybrid,
                kemCiphertext: [UInt8](repeating: 6, count: JetonV3.kemCtLength), spkId: 7, pqId: 8, envelope: env())),
            .initial(Initial(
                identity: [UInt8](repeating: 4, count: 32), ephemeral: [UInt8](repeating: 5, count: 32), mode: .classic,
                kemCiphertext: nil, spkId: 7, pqId: 0, envelope: env())),
            .initial(Initial(
                identity: [UInt8](repeating: 0, count: 32), ephemeral: [UInt8](repeating: 5, count: 32), mode: .psk,
                kemCiphertext: nil, spkId: 0, pqId: 0, envelope: env())),
            .group(GroupMessage(
                groupId: [UInt8](repeating: 1, count: 16), senderId: [UInt8](repeating: 2, count: 8), iteration: 3,
                ciphertext: [UInt8](repeating: 4, count: 176), signature: [UInt8](repeating: 5, count: 64))),
        ]
        for t in tokens {
            XCTAssertEqual(try Token.decode(t.encode()), t)
            // Toute troncature est refusée.
            let bytes = t.toBytes()
            for n in 0..<bytes.count {
                attendreEchec("\(n)") { try Token.fromBytes(Array(bytes[0..<n])) }
            }
        }
    }

    func testJetonV3RefusStricts() {
        var b = Token.message(env()).toBytes()
        b.append(0)
        attendreErreur(.format) { try Token.fromBytes(b) }
        b = Token.message(env()).toBytes()
        b[0] = 0x05
        attendreErreur(.format) { try Token.fromBytes(b) }
        let classicWithPq = Token.initial(Initial(
            identity: [UInt8](repeating: 4, count: 32), ephemeral: [UInt8](repeating: 5, count: 32), mode: .classic,
            kemCiphertext: nil, spkId: 7, pqId: 1, envelope: env()))
        attendreErreur(.format) { try Token.fromBytes(classicWithPq.toBytes()) }
        attendreErreur(.jetonAbsent) { try Token.decode("[[BROCOLIS:v3:AAAA]] ") }
        attendreErreur(.base64) { try Token.decode("[[BROCOLIS:v3:A===]]") }
        attendreErreur(.format) { try Token.fromBytes([]) }
        attendreErreur(.tropGrand) { try Token.fromBytes([UInt8](repeating: 2, count: JetonV3.maxTokenBytes + 1)) }
    }

    func testJetonsDansUnTexte() {
        let a = Token.message(env()).encode()
        let text = "avant \(a) milieu [[BROCOLIS:v3:AAAA]] fin [[BROCOLIS:v3:"
        let found = JetonV3.findAll(text)
        XCTAssertEqual(found.count, 2)
        XCTAssertEqual(found[0].text, a)
        XCTAssertNotNil(try? found[0].token.get())
        XCTAssertNil(try? found[1].token.get())
    }

    // MARK: Jetons v1/v2 (jetons.rs)

    func key(_ n: UInt8) -> [UInt8] { [UInt8](repeating: n, count: 32) }

    func testUneCleDonneV1() {
        let token = Jetons.seal("Salut 🥦", keys: [key(1)])
        XCTAssertTrue(token.hasPrefix("[[BROCOLIS:v1:") && token.hasSuffix("]]"))
        let o = Jetons.open(token, keys: [key(9), key(1)])
        XCTAssertEqual(o.text, "Salut 🥦")
        XCTAssertEqual(o.opened, 1)
        XCTAssertEqual(o.locked, 0)
    }

    func testPlusieursClesDonnentUnV2() {
        let token = Jetons.seal("À tous", keys: [key(1), key(2), key(3)])
        XCTAssertTrue(token.hasPrefix("[[BROCOLIS:v2:"))
        for k in UInt8(1)...3 { XCTAssertEqual(Jetons.open(token, keys: [key(k)]).text, "À tous") }
        let other = Jetons.open(token, keys: [key(4)])
        XCTAssertEqual(other.text, token)
        XCTAssertEqual(other.opened, 0)
        XCTAssertEqual(other.locked, 1)
    }

    func testSeulsLesPassagesMarques() {
        let text = Jetons.seal("Rendez-vous ((au parc)) à ((18 h)) !", keys: [key(1)])
        XCTAssertTrue(text.hasPrefix("Rendez-vous [[BROCOLIS:v1:"))
        XCTAssertTrue(text.hasSuffix("]] !") && !text.contains("parc"))
        let o = Jetons.open(text, keys: [key(1)])
        XCTAssertEqual(o.text, "Rendez-vous au parc à 18 h !")
        XCTAssertEqual(o.opened, 2)
        // Un accent combinant collé aux parenthèses ne change rien (octets).
        let combining = Jetons.seal("a((\u{301}x))", keys: [key(1)])
        XCTAssertEqual(Jetons.open(combining, keys: [key(1)]).text, "a\u{301}x")
    }

    func testJetonsExistantsEtTexteVide() {
        let token = Jetons.seal("x", keys: [key(1)])
        XCTAssertEqual(Jetons.seal(token, keys: [key(2)]), token)
        XCTAssertEqual(Jetons.seal("", keys: [key(1)]), "")
        XCTAssertEqual(Jetons.seal("clair", keys: []), "clair")
        XCTAssertTrue(Jetons.seal("pas fermé ((", keys: [key(1)]).hasPrefix("[[BROCOLIS:v1:"))
    }

    func testOuvreUnV2DeLAppBrocolis() {
        // Fait par `BrocolisCrypto.encryptTokenMulti` (l'app Brocolis) pour
        // deux clés ; la seconde suffit à l'ouvrir.
        let token = "[[BROCOLIS:v2:AQLvnoxtj3mqrlMIb1HabsfA84XQ4aZVWz8VLKLbBBRDFX2RZlp6az6BeW8WOMl5FTYB94D0rDj6fDJYoNN7ChsNt7sw0O9LKxrI0KCf7Mc0w0x7mIAiuEK2GEtWrVaagyR3wxedqSiL4QrBphtW7PNxDrLzxNe53E58AnsGGchl3SjQ5700f6rruRdr66oPOJOMYxtHEHd7nqKZ1PAEoDBJD9w=]]"
        let k = Jetons.keyFromB64("Ie2Z71cbvIw+OLOnnmIdfTenOUIxKShDsFQhDH5C7Uw=")!
        XCTAssertEqual(Jetons.open(token, keys: [key(1), k]).text, "Pour vous deux")
    }

    func testOuvreUnJetonFaitALaMain() throws {
        let k = key(7)
        let nonce = [UInt8](repeating: 3, count: 12)
        let combined = nonce + (try Kdf.aesGcmSeal(key: k, nonce: nonce, aad: [], message: Array("brocolis".utf8)))
        let token = "avant [[BROCOLIS:v1:\(Base64.encode(combined))]] après"
        XCTAssertEqual(Jetons.open(token, keys: [k]).text, "avant brocolis après")
    }

    func testTrouveUneCleDansUneInvitation() {
        let k = Jetons.generateKey(rng: Hasard.system())
        let invite = "3) Colle CETTE clé :\n\n\(k)\n\n(C'est notre clé commune.)"
        XCTAssertEqual(Jetons.findKey(invite), k)
        XCTAssertEqual(Jetons.findKey("«\(k)»"), k)
        XCTAssertNil(Jetons.findKey("pas de clé ici"))
        XCTAssertEqual(Jetons.keyFromB64("\u{3000} \(k)\u{85}"), Base64.decode(k))
    }

    func testEmpreintesCourtesEtStables() {
        let k = Base64.encode(key(7))
        let f = Jetons.fingerprint(keyB64: k)
        XCTAssertEqual(f?.count, 19)
        XCTAssertEqual(f, Jetons.fingerprint(keyB64: k))
        XCTAssertNotEqual(f, Jetons.fingerprint(keyB64: Base64.encode(key(8))))
        XCTAssertNil(Jetons.fingerprint(keyB64: "pas une clé"))
    }

    func testJetonsVerrouillesMasques() {
        let token = Jetons.seal("secret", keys: [key(1)])
        XCTAssertEqual(Jetons.masked("Voici \(token) !"), "Voici 🔒🥦 !")
        XCTAssertEqual(Jetons.masked("rien à cacher"), "rien à cacher")
    }

    func testJetonsAbimesRestentTelsQuels() {
        for text in ["[[BROCOLIS:v1:pas-du-base64]]", "[[BROCOLIS:v3:AAAA]]", "[[BROCOLIS:v1:AAAA"] {
            let o = Jetons.open(text, keys: [key(1)])
            XCTAssertEqual(o.text, text)
            XCTAssertEqual(o.opened, 0)
        }
    }
}

