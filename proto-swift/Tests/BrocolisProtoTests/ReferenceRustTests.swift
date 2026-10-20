// Interopérabilité avec la référence Rust au-delà de vectors.json :
// Fixtures/reference-rust.json a été produit par la référence elle-même
// (programme Fixtures/reference-rust.rs, qui dépend de proto/ par chemin) :
//
// - des états JSON écrits par Rust (appareils, sessions hybride et PSK,
//   chaînes de groupe, mémoire des premiers messages) : Swift les relit, les
//   réécrit sous la même forme JSON, et continue les conversations ;
// - le décodage des points Ed25519 de curve25519-dalek (point ou non, petit
//   ordre ou non), comparé à `Ed25519Strict` ;
// - Argon2id de la crate `argon2` (plusieurs voies, sortie longue).
//
// Le sens inverse (Rust relit les états et les jetons écrits par Swift) se
// vérifie en lançant ces tests avec `BROCOLIS_INTEROP_OUT=<fichier>`, puis
// `reference-rust phase3 <fichier>`.

import Foundation
import XCTest
@testable import BrocolisProto

final class ReferenceRustTests: XCTestCase {
    func fixture() throws -> [String: Any] {
        try Depot.json("proto-swift/Tests/BrocolisProtoTests/Fixtures/reference-rust.json")
    }

    func jsonText(_ v: Any?) throws -> String {
        let data = try JSONSerialization.data(withJSONObject: try XCTUnwrap(v), options: [.sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    /// Même forme JSON : les deux textes donnent le même objet.
    func memeForme(_ a: String, _ b: String, _ quoi: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let x = try JSONSerialization.jsonObject(with: Data(a.utf8)) as? NSDictionary
        let y = try JSONSerialization.jsonObject(with: Data(b.utf8)) as? NSDictionary
        XCTAssertEqual(x, y, quoi, file: file, line: line)
        Compteur.shared.ajouter("rust")
    }

    func testArgon2idCommeLaCrateArgon2() throws {
        for c in try XCTUnwrap(try fixture()["argon2id"] as? [[String: Any]]) {
            let m = UInt32(try XCTUnwrap(c["m"] as? Int)), t = UInt32(try XCTUnwrap(c["t"] as? Int))
            let p = UInt32(try XCTUnwrap(c["p"] as? Int)), len = try XCTUnwrap(c["len"] as? Int)
            let out = try Argon2.hash(
                variant: .id, password: Array("brocoli".utf8), salt: [UInt8](repeating: 0x55, count: 16),
                memoryKiB: m, passes: t, lanes: p, length: len)
            egal(hex(out), c["out"] as? String, "Argon2id m=\(m) t=\(t) p=\(p) \(len) octets", categorie: "rust")
        }
    }

    func testPointsEd25519CommeDalek() throws {
        let cases = try XCTUnwrap(try fixture()["ed25519_points"] as? [[String: Any]])
        var points = 0, small = 0
        for c in cases {
            let enc = unhex(c["enc"])
            let isPoint = try XCTUnwrap(c["point"] as? Bool), isSmall = try XCTUnwrap(c["small"] as? Bool)
            let decoded = Ed25519Strict.decode(enc)
            XCTAssertEqual(decoded != nil, isPoint, hex(enc))
            if let d = decoded { XCTAssertEqual(Ed25519Strict.isSmallOrder(d), isSmall, hex(enc)) }
            // Une clé publique utilisable : un point, pas de petit ordre.
            XCTAssertEqual(Kdf.ed25519IsValidPublic(enc), isPoint && !isSmall, hex(enc))
            points += isPoint ? 1 : 0
            small += isSmall ? 1 : 0
            Compteur.shared.ajouter("rust")
        }
        print("Points Ed25519 comparés à curve25519-dalek : \(cases.count) (\(points) points, \(small) de petit ordre)")
    }

    func testEtatsEtJetonsDeLaReference() throws {
        let e = try XCTUnwrap(try fixture()["etats"] as? [String: Any])
        let rng = Deterministic("phase2")
        let texts = try XCTUnwrap(e["texts"] as? [String])
        let tokens = try XCTUnwrap(e["tokens"] as? [String])
        let hybride = MlKem.isAvailable

        // Les états relus se réécrivent sous la même forme JSON.
        let bobJson = try jsonText(e["bob_device"])
        let bob = try Device.fromJson(bobJson)
        try memeForme(bob.toJson(), bobJson, "appareil")
        try memeForme(try Device.fromJson(try jsonText(e["alice_device"])).toJson(), try jsonText(e["alice_device"]), "appareil")
        let aliceJson = try jsonText(e["alice_session"])
        let alice = try Session.fromJson(aliceJson)
        try memeForme(alice.toJson(), aliceJson, "session (préambule hybride compris)")
        let pskJson = try jsonText(e["psk_session"])
        let pskA = try Session.fromJson(pskJson)
        try memeForme(pskA.toJson(), pskJson, "session PSK")
        let chainJson = try jsonText(e["chain"])
        let chain = try SenderKeyState.fromJson(chainJson)
        try memeForme(chain.toJson(), chainJson, "chaîne de groupe")
        let receivedJson = try jsonText(e["received"])
        let received = try ReceivedSenderKey.fromJson(receivedJson)
        try memeForme(received.toJson(), receivedJson, "chaîne reçue")
        let guardJson = try jsonText(e["replay_guard"])
        let replay = try ReplayGuard.fromJson(guardJson)
        try memeForme(replay.toJson(), guardJson, "mémoire des premiers messages")
        XCTAssertTrue(replay.seen([UInt8](repeating: 9, count: 32)))

        // Une session riche (clés sautées, cliquets passés) : même forme, et
        // le message en retard s'ouvre par sa clé sautée gardée par Rust.
        let rich = try XCTUnwrap(e["rich"] as? [String: Any])
        let dJson = try jsonText(rich["d"]), cJson = try jsonText(rich["c"])
        let dSession = try Session.fromJson(dJson), cSession = try Session.fromJson(cJson)
        try memeForme(dSession.toJson(), dJson, "session avec clés sautées")
        try memeForme(cSession.toJson(), cJson, "session avec cliquets passés")
        try memeForme(try Device.fromJson(try jsonText(rich["dave_device"])).toJson(), try jsonText(rich["dave_device"]), "appareil après un premier message")
        XCTAssertEqual(dSession.skippedCount, 2)
        egal(texte(try dSession.decryptText(try XCTUnwrap(rich["pending"] as? String), now: T0, rng: rng)),
             rich["pending_text"] as? String, "clé sautée gardée par Rust", categorie: "rust")
        XCTAssertEqual(dSession.skippedCount, 1)
        egal(texte(try cSession.decryptText(try dSession.encrypt("d2"), now: T0, rng: rng)), "d2", "suite", categorie: "rust")
        let richRecvJson = try jsonText(rich["received"])
        let richRecv = try ReceivedSenderKey.fromJson(richRecvJson)
        try memeForme(richRecv.toJson(), richRecvJson, "chaîne reçue avec clé sautée")
        egal(try richRecv.decrypt(try XCTUnwrap(try Token.decode(try XCTUnwrap(rich["late_group"] as? String)).groupMessage), now: T0),
             rich["late_group_text"] as? String, "message de groupe en retard", categorie: "rust")

        // Le paquet de Bob (signé par Rust) se vérifie ; Swift le refait.
        let bundle = try KeyBundle.fromBase64(try XCTUnwrap(e["bob_bundle"] as? String))
        if hybride && ed25519Deterministe {
            egal(try bob.bundle(), bundle, "paquet refait par Swift", categorie: "rust")
        }

        guard hybride else {
            print("ML-KEM indisponible : la session hybride de la référence n'est pas rejouée")
            return
        }
        // Bob (Swift, état Rust) accepte les premiers messages d'Alice (Rust),
        // dans le désordre.
        let i2 = try XCTUnwrap(try Token.decode(tokens[1]).initialMessage)
        let (b, c2) = try bob.accept(i2, now: T0, rng: rng)
        egal(texte(c2), texts[1], "Rust → Swift (2)", categorie: "rust")
        egal(texte(try b.decryptText(tokens[0], now: T0, rng: rng)), texts[0], "Rust → Swift (1)", categorie: "rust")
        XCTAssertTrue(b.isPostQuantum)
        // La distribution (0x03) envoyée par Alice, puis le groupe.
        guard case .distribution(let d) = try b.decryptText(try XCTUnwrap(e["distribution"] as? String), now: T0, rng: rng)
        else { return XCTFail("distribution attendue") }
        let recv = try ReceivedSenderKey.fromDistribution(d)
        for (i, g) in try XCTUnwrap(e["group_tokens"] as? [String]).enumerated() {
            egal(try recv.decrypt(try XCTUnwrap(try Token.decode(g).groupMessage), now: T0), "groupe \(i + 1)", "groupe", categorie: "rust")
        }
        // La chaîne Rust (relue) continue ; la chaîne reçue Rust (relue) lit.
        let g3 = try XCTUnwrap(try chain.encryptToken("groupe 3").groupMessage)
        egal(try received.decrypt(g3, now: T0), "groupe 3", "chaîne relue", categorie: "rust")
        egal(try recv.decrypt(g3, now: T0), "groupe 3", "chaîne reçue", categorie: "rust")
        // Alice (Swift, session Rust) lit la réponse de Bob (Swift).
        let r1 = try b.encrypt("Swift → Rust 1")
        egal(texte(try alice.decryptText(r1, now: T0, rng: rng)), "Swift → Rust 1", "réponse", categorie: "rust")
        XCTAssertTrue(alice.isConfirmed)
        // PSK : le premier message de Rust, accepté par Swift.
        var g = ReplayGuard()
        let pskKey = unhex(e["psk_key"])
        let (pskB, pc) = try Session.acceptPsk(
            keys: [pskKey], message: try XCTUnwrap(try Token.decode(try XCTUnwrap(e["psk_token"] as? String)).initialMessage),
            guard: &g, now: T0, rng: rng)
        egal(texte(pc), "PSK de Rust", "PSK", categorie: "rust")
        egal(texte(try pskA.decryptText(try pskB.encrypt("PSK de Swift"), now: T0, rng: rng)), "PSK de Swift", "PSK retour", categorie: "rust")

        // Pour le sens inverse (manuel) : ce que Rust relira.
        if let out = ProcessInfo.processInfo.environment["BROCOLIS_INTEROP_OUT"] {
            let toAlice = ["Swift → Rust 2", "Swift → Rust 3 🥦"]
            let pending = try toAlice.map { try b.encrypt($0) }
            let dev = Device.generate(rng: Hasard.system(), now: T0, pq: true)
            let initiator = Device.generate(rng: Hasard.system(), now: T0, pq: true)
            let sInit = try initiator.initiate(bundle: try dev.bundle(), pq: true, rng: Hasard.system())
            let swiftChain = try SenderKeyState.generate(groupId: Groupe.newGroupId(rng: Hasard.system()), rng: Hasard.system())
            let swiftRecv = try ReceivedSenderKey.fromDistribution(swiftChain.distribution())
            var swiftGuard = ReplayGuard()
            swiftGuard.insert([UInt8](repeating: 7, count: 32), now: T0)
            let v: [String: Any] = [
                "alice_session": alice.toJson(), "bob_session": b.toJson(),
                "to_alice": pending, "to_alice_texts": toAlice,
                "swift_device": dev.toJson(), "swift_bundle": try dev.bundle().toBase64(),
                "swift_initial": try sInit.encrypt("Swift initie"), "swift_initial_text": "Swift initie",
                "swift_initial_pq": sInit.isPostQuantum,
                "received": swiftRecv.toJson(), "chain": swiftChain.toJson(),
                "group_token": try swiftChain.encrypt("groupe Swift"), "group_text": "groupe Swift",
                "replay_guard": swiftGuard.toJson(),
            ]
            try JSONSerialization.data(withJSONObject: v).write(to: URL(fileURLWithPath: out))
            print("États Swift écrits pour la référence : \(out)")
        }
    }

    override class func tearDown() {
        print("Valeurs comparées à la référence Rust (états, points, Argon2) : \(Compteur.shared.total("rust"))")
        super.tearDown()
    }
}
