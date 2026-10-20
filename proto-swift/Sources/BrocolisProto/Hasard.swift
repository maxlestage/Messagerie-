// Le hasard. En production : le CSPRNG du système, et rien d'autre
// (`Hasard.system()` : `SecRandomCopyBytes` sur les plateformes Apple,
// `SystemRandomNumberGenerator` — getrandom — ailleurs). Toutes les fonctions
// qui tirent du hasard le reçoivent en paramètre (`some CryptoRng`), ce qui
// permet aux vecteurs de test d'injecter `Deterministic` : **jamais en
// production**.

#if canImport(Security)
import Security
#endif

#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Une source d'octets aléatoires. Les fonctions du protocole tirent leurs
/// octets **dans l'ordre documenté** de la référence Rust (« Ordre de
/// tirage »), ce qui permet de rejouer les vecteurs avec `Deterministic`.
public protocol CryptoRng: AnyObject {
    /// Remplit `buffer` d'octets aléatoires.
    func fill(_ buffer: inout [UInt8])
}

extension CryptoRng {
    /// `count` octets aléatoires.
    public func bytes(_ count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        fill(&out)
        return out
    }

    /// Un `u32` gros-boutiste (4 octets).
    public func nextU32() -> UInt32 {
        Octets.readU32(bytes(4), 0)
    }
}

/// Le hasard du protocole.
public enum Hasard {
    /// Le CSPRNG du système.
    public static func system() -> SystemRng { SystemRng() }
}

/// Le CSPRNG du système. S'arrête (`preconditionFailure`) seulement si le
/// système ne peut plus fournir de hasard (aucune entrée ne le provoque).
public final class SystemRng: CryptoRng {
    public init() {}

    public func fill(_ buffer: inout [UInt8]) {
        guard !buffer.isEmpty else { return }
        #if canImport(Security)
        let status = buffer.withUnsafeMutableBytes { p in
            SecRandomCopyBytes(kSecRandomDefault, p.count, p.baseAddress!)
        }
        precondition(status == errSecSuccess, "SecRandomCopyBytes : plus de hasard")
        #else
        var g = SystemRandomNumberGenerator()
        var i = 0
        while i < buffer.count {
            var word = g.next()
            for _ in 0..<8 where i < buffer.count {
                buffer[i] = UInt8(truncatingIfNeeded: word)
                word >>= 8
                i += 1
            }
        }
        #endif
    }
}

/// Un générateur **déterministe**, pour les vecteurs de test et les tests :
/// le bloc `i` (32 octets) vaut `SHA-256("Brocolis_vecteurs" ‖ graine ‖
/// i u64 gros-boutiste)`, `i` partant de 0, et les octets sont servis dans
/// l'ordre, sans en jeter (`hasard::Deterministic` de la référence). Il ne
/// doit **jamais** servir en production.
public final class Deterministic: CryptoRng {
    private var seed: [UInt8]
    private var counter: UInt64 = 0
    private var block = [UInt8](repeating: 0, count: 32)
    private var used = 32

    /// Un générateur à partir d'une graine (une étiquette lisible suffit).
    public init(seed: [UInt8]) {
        self.seed = seed
    }

    /// Un générateur à partir d'une étiquette (ses octets UTF-8).
    public convenience init(_ label: String) {
        self.init(seed: Array(label.utf8))
    }

    private func refill() {
        var input = Array("Brocolis_vecteurs".utf8)
        input += seed
        input += Octets.u64be(counter)
        block = Array(SHA256.hash(data: input))
        counter &+= 1
        used = 0
    }

    public func fill(_ buffer: inout [UInt8]) {
        for i in 0..<buffer.count {
            if used == 32 { refill() }
            buffer[i] = block[used]
            used += 1
        }
    }

    deinit {
        effacer(&block)
        effacer(&seed)
    }
}
