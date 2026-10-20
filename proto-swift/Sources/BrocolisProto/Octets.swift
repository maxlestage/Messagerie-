// Les outils sur les octets : base64 strict, entiers gros-boutistes,
// comparaison en temps constant, recherche d'un motif, UTF-8 validé et
// effacement des secrets.
//
// Tout le texte est traité en octets UTF-8, comme la référence Rust (`str`
// et ses `find`) : les `String` de Swift comparent par équivalence Unicode,
// ce qui ferait trouver (ou manquer) un `((` collé à un accent combinant là
// où Rust ne le ferait pas.

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

// MARK: - Base64 standard strict

/// Le base64 standard (RFC 4648 §4, `+` `/`, avec `=`) **strict**, comme le
/// moteur `STANDARD` de la crate `base64` : remplissage canonique exigé, bits
/// de fin nuls, aucun espace. Le même texte est donc accepté ou refusé sur
/// toutes les plateformes (le décodeur de Foundation ne l'est pas autant).
public enum Base64 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".utf8)
    private static let table: [UInt8] = {
        var t = [UInt8](repeating: 0xFF, count: 256)
        for (i, c) in alphabet.enumerated() { t[Int(c)] = UInt8(i) }
        return t
    }()

    /// Encode en base64 standard avec `=`.
    public static func encode<C: Collection>(_ data: C) -> String where C.Element == UInt8 {
        let bytes = Array(data)
        var out = [UInt8]()
        out.reserveCapacity((bytes.count + 2) / 3 * 4)
        var i = 0
        while i + 3 <= bytes.count {
            let n = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8 | UInt32(bytes[i + 2])
            out.append(alphabet[Int(n >> 18 & 63)])
            out.append(alphabet[Int(n >> 12 & 63)])
            out.append(alphabet[Int(n >> 6 & 63)])
            out.append(alphabet[Int(n & 63)])
            i += 3
        }
        let rest = bytes.count - i
        if rest == 1 {
            let n = UInt32(bytes[i]) << 16
            out.append(alphabet[Int(n >> 18 & 63)])
            out.append(alphabet[Int(n >> 12 & 63)])
            out.append(UInt8(ascii: "="))
            out.append(UInt8(ascii: "="))
        } else if rest == 2 {
            let n = UInt32(bytes[i]) << 16 | UInt32(bytes[i + 1]) << 8
            out.append(alphabet[Int(n >> 18 & 63)])
            out.append(alphabet[Int(n >> 12 & 63)])
            out.append(alphabet[Int(n >> 6 & 63)])
            out.append(UInt8(ascii: "="))
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Décode du base64 standard strict, ou `nil`.
    public static func decode(_ text: String) -> [UInt8]? {
        decode(bytes: Array(text.utf8))
    }

    /// Décode les octets ASCII d'un base64 standard strict, ou `nil`.
    public static func decode<C: Collection>(bytes input: C) -> [UInt8]? where C.Element == UInt8 {
        let s = Array(input)
        guard s.count % 4 == 0 else { return nil }
        var out = [UInt8]()
        out.reserveCapacity(s.count / 4 * 3)
        var i = 0
        while i < s.count {
            let last = i + 4 == s.count
            let c0 = table[Int(s[i])], c1 = table[Int(s[i + 1])]
            guard c0 != 0xFF, c1 != 0xFF else { return nil }
            let p2 = s[i + 2] == UInt8(ascii: "="), p3 = s[i + 3] == UInt8(ascii: "=")
            if p2 || p3 {
                // Le remplissage n'est permis qu'au dernier quartet, et `=`
                // en position 2 impose `=` en position 3.
                guard last, p3 else { return nil }
                if p2 {
                    // Un octet : les 4 bits de fin de c1 doivent être nuls.
                    guard c1 & 0x0F == 0 else { return nil }
                    out.append(c0 << 2 | c1 >> 4)
                } else {
                    let c2 = table[Int(s[i + 2])]
                    guard c2 != 0xFF, c2 & 0x03 == 0 else { return nil }
                    out.append(c0 << 2 | c1 >> 4)
                    out.append(c1 << 4 | c2 >> 2)
                }
            } else {
                let c2 = table[Int(s[i + 2])], c3 = table[Int(s[i + 3])]
                guard c2 != 0xFF, c3 != 0xFF else { return nil }
                out.append(c0 << 2 | c1 >> 4)
                out.append(c1 << 4 | c2 >> 2)
                out.append(c2 << 6 | c3)
            }
            i += 4
        }
        return out
    }
}

// MARK: - Octets

enum Octets {
    /// Un `u32` gros-boutiste.
    static func u32be(_ v: UInt32) -> [UInt8] {
        [UInt8(v >> 24), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)]
    }

    /// Lit un `u32` gros-boutiste à l'indice `i` (4 octets présents).
    static func readU32(_ b: [UInt8], _ i: Int) -> UInt32 {
        UInt32(b[i]) << 24 | UInt32(b[i + 1]) << 16 | UInt32(b[i + 2]) << 8 | UInt32(b[i + 3])
    }

    /// Un `u64` gros-boutiste.
    static func u64be(_ v: UInt64) -> [UInt8] {
        (0..<8).map { UInt8(truncatingIfNeeded: v >> (56 - 8 * UInt64($0))) }
    }

    /// Égalité en temps constant (la longueur, elle, n'est pas secrète).
    static func ctEq(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var d: UInt8 = 0
        for i in 0..<a.count { d |= a[i] ^ b[i] }
        return d == 0
    }

    /// Vrai si tous les octets sont nuls (temps constant).
    static func isZero(_ a: [UInt8]) -> Bool {
        var d: UInt8 = 0
        for x in a { d |= x }
        return d == 0
    }

    /// La première position de `needle` dans `hay` à partir de `from`.
    static func find(_ hay: [UInt8], _ needle: [UInt8], from: Int = 0) -> Int? {
        guard !needle.isEmpty, hay.count >= needle.count, from <= hay.count - needle.count else { return nil }
        var i = from
        let first = needle[0]
        while i <= hay.count - needle.count {
            if hay[i] == first {
                var j = 1
                while j < needle.count && hay[i + j] == needle[j] { j += 1 }
                if j == needle.count { return i }
            }
            i += 1
        }
        return nil
    }

    /// Vrai si `hay` commence par `prefix`.
    static func hasPrefix(_ hay: [UInt8], _ prefix: [UInt8]) -> Bool {
        hay.count >= prefix.count && Array(hay[0..<prefix.count]) == prefix
    }

    /// Vrai si `hay` finit par `suffix`.
    static func hasSuffix(_ hay: [UInt8], _ suffix: [UInt8]) -> Bool {
        hay.count >= suffix.count && Array(hay[(hay.count - suffix.count)...]) == suffix
    }

    /// Le texte de ces octets s'ils sont de l'UTF-8 valide (comme
    /// `String::from_utf8`), sinon `nil`. Le décodage de Swift remplace
    /// toute séquence invalide par U+FFFD : un aller-retour différent trahit
    /// donc une entrée invalide.
    static func utf8<C: Collection>(_ bytes: C) -> String? where C.Element == UInt8 {
        let s = String(decoding: bytes, as: UTF8.self)
        return s.utf8.elementsEqual(bytes) ? s : nil
    }

    /// Le texte d'octets découpés à des frontières ASCII d'un texte valide.
    static func string<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        String(decoding: bytes, as: UTF8.self)
    }

    /// Hexadécimal minuscule.
    static func hex<C: Collection>(_ bytes: C) -> String where C.Element == UInt8 {
        let digits = Array("0123456789abcdef".utf8)
        var out = [UInt8]()
        out.reserveCapacity(bytes.count * 2)
        for b in bytes {
            out.append(digits[Int(b >> 4)])
            out.append(digits[Int(b & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }
}

/// `a + b` saturé (`u64::saturating_add`).
func satAdd(_ a: UInt64, _ b: UInt64) -> UInt64 {
    let (r, overflow) = a.addingReportingOverflow(b)
    return overflow ? .max : r
}

// MARK: - Effacement

/// Efface des octets en mémoire (au mieux : un tableau Swift a pu être copié
/// ailleurs par copie à l'écriture, et ces copies-là échappent à
/// l'effacement). La fonction n'est ni inlinée ni optimisée, pour que
/// l'écriture ne soit pas supprimée comme « inutile ».
@inline(never) @_optimize(none)
func effacer<T: FixedWidthInteger>(_ bytes: inout [T]) {
    bytes.withUnsafeMutableBytes { p in
        guard let base = p.baseAddress, p.count > 0 else { return }
        _ = memset(base, 0, p.count)
    }
}

/// Efface puis vide un tableau d'octets optionnel.
func effacer(_ bytes: inout [UInt8]?) {
    if var b = bytes {
        bytes = nil
        effacer(&b)
    }
}

/// Efface des mots de 64 bits (Argon2).
@inline(never) @_optimize(none)
func effacer(_ p: UnsafeMutablePointer<UInt64>, count: Int) {
    _ = memset(p, 0, count * MemoryLayout<UInt64>.stride)
}
