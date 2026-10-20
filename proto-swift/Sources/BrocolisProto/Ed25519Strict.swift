// Les contrôles de la vérification Ed25519 **stricte** (RFC 8032 §5.1.7,
// `verify_strict` d'ed25519-dalek) que CryptoKit ne garantit pas :
//
// - A (la clé publique) et R (la première moitié de la signature) doivent
//   être des points de la courbe ;
// - ni A ni R ne doivent être de petit ordre ([8]P = identité) ;
// - S doit être canonique : S < L = 2²⁵² + 27742317777372353535851937790883648493.
//
// L'équation de vérification elle-même reste celle de CryptoKit (ou de
// swift-crypto/BoringSSL sous Linux). Ici, seulement de quoi décoder un point
// et le doubler : l'arithmétique de GF(2²⁵⁵ − 19) de TweetNaCl (16 membres de
// 16 bits), en temps variable — elle ne voit que des données publiques.

enum Ed25519Strict {
    // MARK: Corps GF(p), p = 2²⁵⁵ − 19

    typealias FE = [Int64]

    static let zero: FE = [Int64](repeating: 0, count: 16)
    static let one: FE = { var o = zero; o[0] = 1; return o }()

    static func car(_ o: inout FE) {
        for i in 0..<16 {
            o[i] += 1 << 16
            let c = o[i] >> 16
            if i < 15 {
                o[i + 1] += c - 1
            } else {
                o[0] += 38 * (c - 1)
            }
            o[i] -= c << 16
        }
    }

    static func add(_ a: FE, _ b: FE) -> FE {
        var o = zero
        for i in 0..<16 { o[i] = a[i] + b[i] }
        return o
    }

    static func sub(_ a: FE, _ b: FE) -> FE {
        var o = zero
        for i in 0..<16 { o[i] = a[i] - b[i] }
        return o
    }

    static func mul(_ a: FE, _ b: FE) -> FE {
        var t = [Int64](repeating: 0, count: 31)
        for i in 0..<16 {
            for j in 0..<16 { t[i + j] += a[i] * b[j] }
        }
        for i in 0..<15 { t[i] += 38 * t[i + 16] }
        var o = Array(t[0..<16])
        car(&o)
        car(&o)
        return o
    }

    static func sq(_ a: FE) -> FE { mul(a, a) }

    /// L'écriture canonique (réduite modulo p), 32 octets petit-boutistes.
    static func pack(_ n: FE) -> [UInt8] {
        var t = n
        car(&t)
        car(&t)
        car(&t)
        for _ in 0..<2 {
            var m = zero
            m[0] = t[0] - 0xffed
            for i in 1..<15 {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1)
                m[i - 1] &= 0xffff
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1)
            let b = (m[15] >> 16) & 1
            m[14] &= 0xffff
            if b == 0 { t = m }
        }
        var o = [UInt8](repeating: 0, count: 32)
        for i in 0..<16 {
            o[2 * i] = UInt8(truncatingIfNeeded: t[i] & 0xff)
            o[2 * i + 1] = UInt8(truncatingIfNeeded: t[i] >> 8)
        }
        return o
    }

    /// Lit 32 octets petit-boutistes, bit 255 ignoré (non réduit : les
    /// opérations travaillent modulo p).
    static func unpack(_ b: [UInt8]) -> FE {
        var o = zero
        for i in 0..<16 { o[i] = Int64(b[2 * i]) + (Int64(b[2 * i + 1]) << 8) }
        o[15] &= 0x7fff
        return o
    }

    static func fromInt(_ v: Int64) -> FE {
        var o = zero
        o[0] = v & 0xffff
        o[1] = v >> 16
        return o
    }

    /// aᵉ, l'exposant en octets petit-boutistes.
    static func pow(_ a: FE, _ e: [UInt8]) -> FE {
        var r = one
        for i in stride(from: e.count * 8 - 1, through: 0, by: -1) {
            r = sq(r)
            if (e[i / 8] >> (i % 8)) & 1 == 1 { r = mul(r, a) }
        }
        return r
    }

    static func le(_ low: UInt8, _ high: UInt8) -> [UInt8] {
        var e = [UInt8](repeating: 0xff, count: 32)
        e[0] = low
        e[31] = high
        return e
    }

    /// p − 2 (inverse), (p − 5)/8 = 2²⁵² − 3 (racine carrée), (p − 1)/4 =
    /// 2²⁵³ − 5 (√−1).
    static let pMinus2 = le(0xeb, 0x7f)
    static let pMinus5Over8 = le(0xfd, 0x0f)
    static let pMinus1Over4 = le(0xfb, 0x1f)

    static func inv(_ a: FE) -> FE { pow(a, pMinus2) }

    static func equal(_ a: FE, _ b: FE) -> Bool { pack(a) == pack(b) }

    static func isNegative(_ a: FE) -> Bool { pack(a)[0] & 1 == 1 }

    /// d = −121665/121666, la constante de la courbe d'Edwards.
    static let d: FE = mul(sub(zero, fromInt(121_665)), inv(fromInt(121_666)))
    static let d2: FE = add(d, d)
    /// √−1 = 2^((p−1)/4).
    static let sqrtM1: FE = pow(fromInt(2), pMinus1Over4)

    // MARK: Points (coordonnées étendues X, Y, Z, T)

    struct Point {
        var x: FE, y: FE, z: FE, t: FE
    }

    /// Décode un point (RFC 8032 §5.1.3, y réduit modulo p comme
    /// curve25519-dalek) ; `nil` si ce n'est pas un point de la courbe.
    static func decode(_ s: [UInt8]) -> Point? {
        guard s.count == 32 else { return nil }
        let y = unpack(s)
        let yy = sq(y)
        let u = sub(yy, one)            // y² − 1
        let v = add(mul(yy, d), one)    // d·y² + 1
        // x = u·v³·(u·v⁷)^((p−5)/8)
        let v3 = mul(sq(v), v)
        let v7 = mul(sq(v3), v)
        var x = mul(mul(u, v3), pow(mul(u, v7), pMinus5Over8))
        let vxx = mul(v, sq(x))
        if !equal(vxx, u) {
            guard equal(vxx, sub(zero, u)) else { return nil }
            x = mul(x, sqrtM1)
        }
        if isNegative(x) != (s[31] >> 7 == 1) {
            x = sub(zero, x)
        }
        return Point(x: x, y: y, z: one, t: mul(x, y))
    }

    /// P + Q (formule unifiée, complète sur Ed25519).
    static func add(_ p: Point, _ q: Point) -> Point {
        let a = mul(sub(p.y, p.x), sub(q.y, q.x))
        let b = mul(add(p.x, p.y), add(q.x, q.y))
        let c = mul(mul(p.t, q.t), d2)
        var dd = mul(p.z, q.z)
        dd = add(dd, dd)
        let e = sub(b, a), f = sub(dd, c), g = add(dd, c), h = add(b, a)
        return Point(x: mul(e, f), y: mul(h, g), z: mul(g, f), t: mul(e, h))
    }

    /// Vrai si [8]P est l'identité (0, 1).
    static func isSmallOrder(_ p: Point) -> Bool {
        var q = p
        for _ in 0..<3 { q = add(q, q) }
        return pack(q.x) == pack(zero) && equal(q.y, q.z)
    }

    /// Vrai si l'écriture désigne un point de petit ordre (aussi vrai pour
    /// une écriture qui n'est pas un point : à refuser de toute façon).
    static func isWeak(_ s: [UInt8]) -> Bool {
        guard let p = decode(s) else { return true }
        return isSmallOrder(p)
    }

    // MARK: Scalaires

    /// L, l'ordre du sous-groupe, en octets petit-boutistes.
    static let order: [UInt8] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]

    /// Vrai si S < L (32 octets petit-boutistes).
    static func isCanonicalScalar(_ s: [UInt8]) -> Bool {
        guard s.count == 32 else { return false }
        for i in stride(from: 31, through: 0, by: -1) {
            if s[i] < order[i] { return true }
            if s[i] > order[i] { return false }
        }
        return false // S = L
    }
}
