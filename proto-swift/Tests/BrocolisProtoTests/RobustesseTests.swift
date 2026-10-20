// Fuzzing « du pauvre » (proto/tests/robustesse.rs) : des milliers d'entrées
// aléatoires et de mutations de jetons valides passent par chaque décodeur et
// par le déchiffrement v3. Aucune ne doit faire planter ni boucler, et aucune
// entrée mutée ne doit être acceptée par le déchiffrement.

import XCTest
@testable import BrocolisProto

final class RobustesseTests: XCTestCase {
    func randomBytes(_ rng: Deterministic, _ max: Int) -> [UInt8] {
        rng.bytes(Int(rng.nextU32()) % (max + 1))
    }

    /// Une mutation : bits, octets, coupe, insertion, duplication.
    func mutate(_ rng: Deterministic, _ data: [UInt8]) -> [UInt8] {
        var v = data
        for _ in 0..<(1 + Int(rng.nextU32() % 4)) {
            let i = Int(rng.nextU32()) % Swift.max(v.count, 1)
            switch rng.nextU32() % 6 {
            case 0 where !v.isEmpty: v[i] ^= 1 << (rng.nextU32() % 8)
            case 1 where !v.isEmpty: v[i] = UInt8(truncatingIfNeeded: rng.nextU32())
            case 2: v.removeSubrange(Swift.min(i, v.count)...)
            case 3: v.insert(UInt8(truncatingIfNeeded: rng.nextU32()), at: Swift.min(i, v.count))
            case 4 where !v.isEmpty:
                let j = Int(rng.nextU32()) % v.count
                let (a, b) = (Swift.min(i, j), Swift.max(i, j))
                v.insert(contentsOf: Array(v[a..<b]), at: a)
            default: v += randomBytes(rng, 8)
            }
        }
        return v
    }

    func testDecodeursEntreesAleatoires() {
        let rng = Deterministic("aleatoire")
        for i in 0..<3_000 {
            var data = randomBytes(rng, 2_000)
            if !data.isEmpty && i % 2 == 0 { data[0] = UInt8(1 + i % 4) }
            _ = try? Token.fromBytes(data)
            _ = try? KeyBundle.fromBytes(data)
            _ = try? SenderKeyDistribution.fromBytes(data)
            _ = try? Remplissage.unpad(data)
            let text = String(decoding: data, as: UTF8.self)
            _ = try? Token.decode(text)
            _ = Jetons.open(text, keys: [[UInt8](repeating: 1, count: 32)])
            _ = Jetons.masked(text)
            _ = Jetons.findKey(text)
            _ = try? CleProtegee.v2Params(text)
            let b64 = Base64.encode(data)
            _ = try? Token.decode("[[BROCOLIS:v3:\(b64)]]")
            _ = Jetons.open("[[BROCOLIS:v1:\(b64)]] [[BROCOLIS:v2:\(b64)]]", keys: [[UInt8](repeating: 1, count: 32)])
            _ = try? CleProtegee.v2Params("[[BROCOLIS-CLE:v2:\(b64)]]")
            _ = try? Session.fromJson(text)
            _ = try? Device.fromJson(text)
            _ = JetonV3.findAll(text)
        }
    }

    func testMutationsDeJetonsV3() throws {
        let rng = Deterministic("mutations")
        let usePq = pq(true)
        let alice = Device.generate(rng: rng, now: T0, pq: usePq)
        let bob = Device.generate(rng: rng, now: T0, pq: usePq)
        let a = try alice.initiate(bundle: try bob.bundle(), pq: usePq, rng: rng)
        let first = try a.encryptToken("premier")
        let (b, _) = try bob.accept(try XCTUnwrap(first.initialMessage), now: T0, rng: rng)
        let reply = try b.encryptToken("réponse")
        let chain = try SenderKeyState.generate(groupId: [UInt8](repeating: 5, count: 16), rng: rng)
        let recv = try ReceivedSenderKey.fromDistribution(chain.distribution())
        let group = try chain.encryptToken("groupe")
        let dist = try Token.decode(try b.encryptDistribution(chain.distribution()))
        let samples = [first.toBytes(), reply.toBytes(), group.toBytes(), dist.toBytes()]
        let bobBefore = bob.toJson(), aBefore = a.toJson()
        var decoded = 0
        for k in 0..<2_000 {
            let base = samples[k % samples.count]
            let m = mutate(rng, base)
            guard m != base, let t = try? Token.fromBytes(m) else { continue }
            decoded += 1
            // Le jeton muté peut rester bien formé : il ne doit jamais être lu.
            if t.toBytes() == base { continue }
            switch t {
            case .initial(let i):
                attendreEchec { try bob.accept(i, now: T0, rng: rng) }
                var g = ReplayGuard()
                attendreEchec {
                    try Session.acceptPsk(keys: [[UInt8](repeating: 1, count: 32)], message: i, guard: &g, now: T0, rng: rng)
                }
                attendreEchec { try b.decrypt(t, now: T0, rng: rng) }
            case .message, .distribution:
                attendreEchec { try a.decrypt(t, now: T0, rng: rng) }
            case .group(let g):
                attendreEchec { try recv.decrypt(g, now: T0) }
            }
        }
        XCTAssertGreaterThan(decoded, 50)
        XCTAssertEqual(bob.toJson(), bobBefore)
        XCTAssertEqual(a.toJson(), aBefore)
        // Les originaux passent toujours.
        XCTAssertNoThrow(try a.decrypt(reply, now: T0, rng: rng))
        XCTAssertNoThrow(try recv.decrypt(try XCTUnwrap(group.groupMessage), now: T0))
    }

    func testMutationsDEtatsJson() throws {
        let rng = Deterministic("json")
        let alice = Device.generate(rng: rng, now: T0, pq: false)
        let bob = Device.generate(rng: rng, now: T0, pq: false)
        let a = try alice.initiate(bundle: try bob.bundle(), pq: false, rng: rng)
        let (b, _) = try bob.accept(try XCTUnwrap(try a.encryptToken("x").initialMessage), now: T0, rng: rng)
        let texts = [b.toJson(), bob.toJson()]
        for k in 0..<1_500 {
            let m = mutate(rng, Array(texts[k % 2].utf8))
            let text = String(decoding: m, as: UTF8.self)
            if let s = try? Session.fromJson(text) {
                // Un état relu, même altéré, ne fait jamais planter.
                _ = try? s.encrypt("y")
                _ = try? s.decryptText("[[BROCOLIS:v3:AAAA]]", now: T0, rng: rng)
            }
            if let d = try? Device.fromJson(text) {
                _ = try? d.bundle()
            }
        }
    }

    func testMutationsDAnciensJetons() throws {
        let rng = Deterministic("anciens")
        let key = [UInt8](repeating: 3, count: 32)
        let v1 = Jetons.sealWith("ancien", keys: [key], rng: rng)
        let v2 = Jetons.sealWith("ancien", keys: [key, [UInt8](repeating: 4, count: 32)], rng: rng)
        for k in 0..<2_000 {
            let m = mutate(rng, Array((k % 2 == 0 ? v1 : v2).utf8))
            let o = Jetons.open(String(decoding: m, as: UTF8.self), keys: [key])
            // Une altération qui garde l'enveloppe ne s'ouvre jamais en un
            // autre texte.
            // (En octets : un accent combinant collé derrière changerait les
            // graphèmes de Swift, pas le texte.)
            if o.opened > 0 { XCTAssertNotNil(Octets.find(Array(o.text.utf8), Array("ancien".utf8)), o.text) }
        }
    }
}
