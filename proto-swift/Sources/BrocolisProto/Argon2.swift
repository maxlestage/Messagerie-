// Argon2 (RFC 9106, version 0x13) et BLAKE2b (RFC 7693), en Swift pur :
// CryptoKit n'a pas Argon2id. Vérifiés par les vecteurs de RFC 7693 (« abc »),
// de RFC 9106 §5 (Argon2d, Argon2i, Argon2id, avec secret et données
// associées) et par ceux de proto/vectors.json (19 Mio et 64 Mio).
//
// La mémoire (64 Mio par défaut) est un seul tableau de mots de 64 bits,
// alloué une fois, rempli bloc par bloc sans copie, effacé à la fin. Les
// voies (p) sont calculées l'une après l'autre : le résultat est le même
// qu'en parallèle (les tranches sont synchronisées par la spécification).

/// BLAKE2b sans clé (RFC 7693), sortie de 1 à 64 octets.
enum Blake2b {
    static let iv: [UInt64] = [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ]

    static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    @inline(__always)
    static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { (x >> n) | (x << (64 - n)) }

    static func compress(_ h: inout [UInt64], _ block: ArraySlice<UInt8>, _ t: UInt64, last: Bool) {
        var m = [UInt64](repeating: 0, count: 16)
        let base = block.startIndex
        for i in 0..<16 {
            var w: UInt64 = 0
            for j in 0..<8 { w |= UInt64(block[base + 8 * i + j]) << (8 * UInt64(j)) }
            m[i] = w
        }
        var v = h + iv
        v[12] ^= t
        if last { v[14] = ~v[14] }
        func g(_ a: Int, _ b: Int, _ c: Int, _ d: Int, _ x: UInt64, _ y: UInt64) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotr(v[d] ^ v[a], 32)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 24)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 63)
        }
        for r in 0..<12 {
            let s = sigma[r % 10]
            g(0, 4, 8, 12, m[s[0]], m[s[1]])
            g(1, 5, 9, 13, m[s[2]], m[s[3]])
            g(2, 6, 10, 14, m[s[4]], m[s[5]])
            g(3, 7, 11, 15, m[s[6]], m[s[7]])
            g(0, 5, 10, 15, m[s[8]], m[s[9]])
            g(1, 6, 11, 12, m[s[10]], m[s[11]])
            g(2, 7, 8, 13, m[s[12]], m[s[13]])
            g(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
        effacer(&v)
        effacer(&m)
    }

    /// BLAKE2b(données) en `outLength` octets (1 à 64).
    static func hash(_ data: [UInt8], outLength: Int) -> [UInt8] {
        precondition(outLength >= 1 && outLength <= 64)
        var h = iv
        h[0] ^= 0x0101_0000 ^ UInt64(outLength)
        var offset = 0
        // Tous les blocs complets sauf le dernier (le dernier, même complet,
        // est traité avec le drapeau de fin).
        while data.count - offset > 128 {
            compress(&h, data[offset..<offset + 128], UInt64(offset + 128), last: false)
            offset += 128
        }
        var last = [UInt8](repeating: 0, count: 128)
        for i in offset..<data.count { last[i - offset] = data[i] }
        compress(&h, last[0..<128], UInt64(data.count), last: true)
        effacer(&last)
        var out = [UInt8](repeating: 0, count: 64)
        for i in 0..<8 {
            for j in 0..<8 { out[8 * i + j] = UInt8(truncatingIfNeeded: h[i] >> (8 * UInt64(j))) }
        }
        effacer(&h)
        let result = Array(out[0..<outLength])
        effacer(&out)
        return result
    }
}

/// Argon2 (RFC 9106), version 0x13.
public enum Argon2 {
    /// La variante.
    public enum Variant: UInt32, Sendable {
        /// Argon2d (adressage dépendant des données).
        case d = 0
        /// Argon2i (adressage indépendant des données).
        case i = 1
        /// Argon2id (le protocole : i pour la première moitié de la première
        /// passe, d ensuite).
        case id = 2
    }

    static let version: UInt32 = 0x13
    static let syncPoints = 4
    static let blockWords = 128

    static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(v & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 24)]
    }

    /// H' (RFC 9106 §3.3) : BLAKE2b de longueur variable.
    static func hPrime(_ input: [UInt8], _ length: Int) -> [UInt8] {
        let x = le32(UInt32(length)) + input
        if length <= 64 { return Blake2b.hash(x, outLength: length) }
        let r = (length + 31) / 32 - 2
        var out = [UInt8]()
        out.reserveCapacity(length)
        var v = Blake2b.hash(x, outLength: 64)
        out += v[0..<32]
        for _ in 1..<r {
            v = Blake2b.hash(v, outLength: 64)
            out += v[0..<32]
        }
        let tail = Blake2b.hash(v, outLength: length - 32 * r)
        out += tail
        return out
    }

    /// Argon2(mot de passe, sel, m Kio, t passes, p voies, longueur),
    /// avec un secret et des données associées optionnels (le protocole n'en
    /// a pas ; RFC 9106 §5 si). Paramètres : p ≥ 1, m ≥ 8p, t ≥ 1, longueur
    /// ≥ 4 (sinon `.parametres`).
    public static func hash(
        variant: Variant, password: [UInt8], salt: [UInt8], secret: [UInt8] = [], associatedData: [UInt8] = [],
        memoryKiB m: UInt32, passes t: UInt32, lanes p: UInt32, length: Int
    ) throws -> [UInt8] {
        guard p >= 1, p <= 0xFF_FFFF, t >= 1, m >= 8 * p, length >= 4 else { throw Erreur.parametres }
        // H0 (RFC 9106 §3.2).
        var h0Input = le32(p) + le32(UInt32(length)) + le32(m) + le32(t) + le32(version) + le32(variant.rawValue)
        h0Input += le32(UInt32(password.count)) + password
        h0Input += le32(UInt32(salt.count)) + salt
        h0Input += le32(UInt32(secret.count)) + secret
        h0Input += le32(UInt32(associatedData.count)) + associatedData
        var h0 = Blake2b.hash(h0Input, outLength: 64)
        effacer(&h0Input)
        defer { effacer(&h0) }

        let lanes = Int(p)
        let segmentLength = Int(m) / (4 * lanes)
        let laneLength = segmentLength * syncPoints
        let blocks = laneLength * lanes
        let memory = UnsafeMutablePointer<UInt64>.allocate(capacity: blocks * blockWords)
        memory.initialize(repeating: 0, count: blocks * blockWords)
        defer {
            effacer(memory, count: blocks * blockWords)
            memory.deallocate()
        }
        // Les blocs de travail de la compression : R, Z (copie), et pour
        // l'adressage indépendant, le bloc d'entrée, le bloc d'adresses et le
        // bloc nul.
        let scratch = UnsafeMutablePointer<UInt64>.allocate(capacity: 5 * blockWords)
        scratch.initialize(repeating: 0, count: 5 * blockWords)
        defer {
            effacer(scratch, count: 5 * blockWords)
            scratch.deallocate()
        }
        let r = scratch, z = scratch + blockWords
        let input = scratch + 2 * blockWords, address = scratch + 3 * blockWords, zero = scratch + 4 * blockWords

        // Les deux premiers blocs de chaque voie.
        for lane in 0..<lanes {
            for j in 0..<2 {
                var b = hPrime(h0 + le32(UInt32(j)) + le32(UInt32(lane)), 1024)
                let dst = memory + (lane * laneLength + j) * blockWords
                for w in 0..<blockWords {
                    var word: UInt64 = 0
                    for k in 0..<8 { word |= UInt64(b[8 * w + k]) << (8 * UInt64(k)) }
                    dst[w] = word
                }
                effacer(&b)
            }
        }

        for pass in 0..<Int(t) {
            for slice in 0..<syncPoints {
                for lane in 0..<lanes {
                    let independent = variant == .i || (variant == .id && pass == 0 && slice < syncPoints / 2)
                    if independent {
                        for w in 0..<blockWords { input[w] = 0 }
                        input[0] = UInt64(pass)
                        input[1] = UInt64(lane)
                        input[2] = UInt64(slice)
                        input[3] = UInt64(blocks)
                        input[4] = UInt64(t)
                        input[5] = UInt64(variant.rawValue)
                    }
                    var start = 0
                    if pass == 0 && slice == 0 {
                        start = 2
                        if independent { nextAddresses(input, address, zero, r, z) }
                    }
                    var current = lane * laneLength + slice * segmentLength + start
                    var previous = current % laneLength == 0 ? current + laneLength - 1 : current - 1
                    for index in start..<segmentLength {
                        if current % laneLength == 1 { previous = current - 1 }
                        let pseudoRandom: UInt64
                        if independent {
                            if index % blockWords == 0 { nextAddresses(input, address, zero, r, z) }
                            pseudoRandom = address[index % blockWords]
                        } else {
                            pseudoRandom = memory[previous * blockWords]
                        }
                        var refLane = Int((pseudoRandom >> 32) % UInt64(lanes))
                        if pass == 0 && slice == 0 { refLane = lane }
                        let refIndex = indexAlpha(
                            pass: pass, slice: slice, index: index, segmentLength: segmentLength,
                            laneLength: laneLength, pseudoRandom: UInt32(truncatingIfNeeded: pseudoRandom),
                            sameLane: refLane == lane)
                        fillBlock(
                            memory + previous * blockWords, memory + (refLane * laneLength + refIndex) * blockWords,
                            memory + current * blockWords, withXor: pass != 0, r, z)
                        current += 1
                        previous += 1
                    }
                }
            }
        }

        // C = XOR des derniers blocs de chaque voie, puis H'.
        for w in 0..<blockWords { r[w] = memory[(laneLength - 1) * blockWords + w] }
        for lane in 1..<max(lanes, 1) {
            let last = memory + (lane * laneLength + laneLength - 1) * blockWords
            for w in 0..<blockWords { r[w] ^= last[w] }
        }
        var c = [UInt8](repeating: 0, count: 1024)
        for w in 0..<blockWords {
            for k in 0..<8 { c[8 * w + k] = UInt8(truncatingIfNeeded: r[w] >> (8 * UInt64(k))) }
        }
        defer { effacer(&c) }
        return hPrime(c, length)
    }

    /// La position du bloc de référence dans sa voie (RFC 9106 §3.4.1.2).
    static func indexAlpha(
        pass: Int, slice: Int, index: Int, segmentLength: Int, laneLength: Int, pseudoRandom: UInt32, sameLane: Bool
    ) -> Int {
        let areaSize: Int
        if pass == 0 {
            if slice == 0 {
                areaSize = index - 1
            } else if sameLane {
                areaSize = slice * segmentLength + index - 1
            } else {
                areaSize = slice * segmentLength + (index == 0 ? -1 : 0)
            }
        } else if sameLane {
            areaSize = laneLength - segmentLength + index - 1
        } else {
            areaSize = laneLength - segmentLength + (index == 0 ? -1 : 0)
        }
        var relative = UInt64(pseudoRandom)
        relative = (relative &* relative) >> 32
        let area = UInt64(areaSize)
        let relativePosition = area - 1 - ((area &* relative) >> 32)
        let startPosition = pass == 0 ? 0 : (slice == syncPoints - 1 ? 0 : (slice + 1) * segmentLength)
        return Int((UInt64(startPosition) + relativePosition) % UInt64(laneLength))
    }

    /// Le bloc d'adresses suivant : G(0, G(0, entrée)), compteur + 1.
    static func nextAddresses(
        _ input: UnsafeMutablePointer<UInt64>, _ address: UnsafeMutablePointer<UInt64>,
        _ zero: UnsafeMutablePointer<UInt64>, _ r: UnsafeMutablePointer<UInt64>, _ z: UnsafeMutablePointer<UInt64>
    ) {
        input[6] &+= 1
        fillBlock(zero, input, address, withXor: false, r, z)
        fillBlock(zero, address, address, withXor: false, r, z)
    }

    @inline(__always)
    static func fBlaMka(_ x: UInt64, _ y: UInt64) -> UInt64 {
        let m: UInt64 = 0xFFFF_FFFF
        return x &+ y &+ 2 &* ((x & m) &* (y & m))
    }

    @inline(__always)
    static func rotr(_ x: UInt64, _ n: UInt64) -> UInt64 { (x >> n) | (x << (64 - n)) }

    @inline(__always)
    static func g(_ v: UnsafeMutablePointer<UInt64>, _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
        var va = v[a], vb = v[b], vc = v[c], vd = v[d]
        va = fBlaMka(va, vb)
        vd = rotr(vd ^ va, 32)
        vc = fBlaMka(vc, vd)
        vb = rotr(vb ^ vc, 24)
        va = fBlaMka(va, vb)
        vd = rotr(vd ^ va, 16)
        vc = fBlaMka(vc, vd)
        vb = rotr(vb ^ vc, 63)
        v[a] = va
        v[b] = vb
        v[c] = vc
        v[d] = vd
    }

    /// La permutation P de BLAKE2b sans message, sur 16 mots d'indices
    /// `i0 + k·stride` regroupés deux à deux.
    @inline(__always)
    static func round(
        _ v: UnsafeMutablePointer<UInt64>,
        _ i0: Int, _ i1: Int, _ i2: Int, _ i3: Int, _ i4: Int, _ i5: Int, _ i6: Int, _ i7: Int,
        _ i8: Int, _ i9: Int, _ i10: Int, _ i11: Int, _ i12: Int, _ i13: Int, _ i14: Int, _ i15: Int
    ) {
        g(v, i0, i4, i8, i12)
        g(v, i1, i5, i9, i13)
        g(v, i2, i6, i10, i14)
        g(v, i3, i7, i11, i15)
        g(v, i0, i5, i10, i15)
        g(v, i1, i6, i11, i12)
        g(v, i2, i7, i8, i13)
        g(v, i3, i4, i9, i14)
    }

    /// La compression G (RFC 9106 §3.5) : `next = P(prev ⊕ ref) ⊕ (prev ⊕
    /// ref) [⊕ next]`. `next` peut être `ref` (bloc d'adresses).
    static func fillBlock(
        _ prev: UnsafeMutablePointer<UInt64>, _ ref: UnsafeMutablePointer<UInt64>,
        _ next: UnsafeMutablePointer<UInt64>, withXor: Bool,
        _ r: UnsafeMutablePointer<UInt64>, _ z: UnsafeMutablePointer<UInt64>
    ) {
        for w in 0..<128 {
            let x = ref[w] ^ prev[w]
            r[w] = x
            z[w] = withXor ? x ^ next[w] : x
        }
        for i in 0..<8 {
            let b = 16 * i
            round(r, b, b + 1, b + 2, b + 3, b + 4, b + 5, b + 6, b + 7,
                  b + 8, b + 9, b + 10, b + 11, b + 12, b + 13, b + 14, b + 15)
        }
        for i in 0..<8 {
            let b = 2 * i
            round(r, b, b + 1, b + 16, b + 17, b + 32, b + 33, b + 48, b + 49,
                  b + 64, b + 65, b + 80, b + 81, b + 96, b + 97, b + 112, b + 113)
        }
        for w in 0..<128 { next[w] = z[w] ^ r[w] }
    }
}
