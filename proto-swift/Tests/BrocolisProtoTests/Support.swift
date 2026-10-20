// Les outils des tests : les fichiers du dépôt (proto/vectors.json et
// proto/tests/wycheproof/, lus sur place : une seule source, jamais de copie
// périmée), l'hexadécimal, un générateur qui note ce qu'il donne, et un
// compteur des valeurs vérifiées.

import Foundation
import XCTest
@testable import BrocolisProto

enum Depot {
    /// La racine du dépôt : ce fichier est dans
    /// proto-swift/Tests/BrocolisProtoTests/.
    static let racine: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().deletingLastPathComponent()

    static func json(_ chemin: String) throws -> [String: Any] {
        let url = racine.appendingPathComponent(chemin)
        let data = try Data(contentsOf: url)
        return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any], chemin)
    }

    static func vecteurs() throws -> [String: Any] {
        try json("proto/vectors.json")
    }

    static func wycheproof(_ nom: String) throws -> [String: Any] {
        try json("proto/tests/wycheproof/\(nom)")
    }
}

/// Les valeurs comparées aux vecteurs (pour le compte rendu).
final class Compteur: @unchecked Sendable {
    static let shared = Compteur()
    private let lock = NSLock()
    private var valeurs: [String: Int] = [:]

    func ajouter(_ categorie: String, _ n: Int = 1) {
        lock.lock()
        valeurs[categorie, default: 0] += n
        lock.unlock()
    }

    func total(_ categorie: String) -> Int {
        lock.lock()
        defer { lock.unlock() }
        return valeurs[categorie, default: 0]
    }
}

func unhex(_ v: Any?, file: StaticString = #filePath, line: UInt = #line) -> [UInt8] {
    guard let s = v as? String else {
        XCTFail("hexadécimal attendu", file: file, line: line)
        return []
    }
    let c = Array(s.utf8)
    var out = [UInt8]()
    out.reserveCapacity(c.count / 2)
    func nib(_ x: UInt8) -> UInt8 {
        switch x {
        case 0x30...0x39: return x - 0x30
        case 0x61...0x66: return x - 0x61 + 10
        case 0x41...0x46: return x - 0x41 + 10
        default: return 0
        }
    }
    var i = 0
    while i + 1 < c.count {
        out.append(nib(c[i]) << 4 | nib(c[i + 1]))
        i += 2
    }
    return out
}

func hex(_ b: [UInt8]) -> String {
    Octets.hex(b)
}

/// `SHA-256(étiquette UTF-8)`, le `h32` du générateur de vecteurs.
func h32(_ label: String) -> [UInt8] {
    Kdf.sha256(Array(label.utf8))
}

/// Une comparaison à un vecteur, comptée.
func egal<T: Equatable>(
    _ a: T, _ b: T, _ quoi: String, categorie: String = "vecteurs", file: StaticString = #filePath, line: UInt = #line
) {
    XCTAssertEqual(a, b, quoi, file: file, line: line)
    Compteur.shared.ajouter(categorie)
}

/// Un générateur déterministe qui note tout ce qu'il donne (pour les
/// secrets tirés pendant le cliquet, `*_drawn`).
final class Recorder: CryptoRng {
    let inner: Deterministic
    var drawn: [UInt8] = []

    init(_ label: String) {
        inner = Deterministic(label)
    }

    func fill(_ buffer: inout [UInt8]) {
        inner.fill(&buffer)
        drawn += buffer
    }

    func take() -> [UInt8] {
        defer { drawn = [] }
        return drawn
    }
}

/// Vrai si les signatures Ed25519 de cette plateforme sont celles de RFC
/// 8032 (déterministes) : BoringSSL (Linux) oui ; CryptoKit peut les
/// rendre aléatoires. Les vecteurs comparent alors tout sauf la signature,
/// qui est vérifiée.
let ed25519Deterministe: Bool = {
    let seed = [UInt8](repeating: 7, count: 32)
    return Kdf.ed25519Sign(seed: seed, message: [1, 2, 3]) == Kdf.ed25519Sign(seed: seed, message: [1, 2, 3])
}()

func texte(_ c: Content, file: StaticString = #filePath, line: UInt = #line) -> String {
    guard case .text(let t) = c else {
        XCTFail("texte attendu", file: file, line: line)
        return ""
    }
    return t
}

extension Token {
    var initialMessage: Initial? {
        if case .initial(let i) = self { return i }
        return nil
    }

    var groupMessage: GroupMessage? {
        if case .group(let g) = self { return g }
        return nil
    }
}

/// Attend une erreur précise.
func attendreErreur<T>(
    _ attendue: Erreur, _ quoi: String = "", file: StaticString = #filePath, line: UInt = #line,
    _ bloc: () throws -> T
) {
    do {
        _ = try bloc()
        XCTFail("erreur \(attendue) attendue \(quoi)", file: file, line: line)
    } catch let e as Erreur {
        XCTAssertEqual(e, attendue, quoi, file: file, line: line)
    } catch {
        XCTFail("erreur inattendue \(error) \(quoi)", file: file, line: line)
    }
}

/// Attend une erreur, quelle qu'elle soit.
func attendreEchec<T>(_ quoi: String = "", file: StaticString = #filePath, line: UInt = #line, _ bloc: () throws -> T) {
    if (try? bloc()) != nil {
        XCTFail("échec attendu \(quoi)", file: file, line: line)
    }
}

let T0: UInt64 = 1_790_000_000
