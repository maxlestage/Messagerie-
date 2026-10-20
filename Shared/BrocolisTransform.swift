//
//  BrocolisTransform.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Transformation « intelligente » d'une sélection de texte, en un seul geste :
//   - si le texte contient des jetons `[[BROCOLIS:…]]` (v1, v2, v3) → on déchiffre ;
//   - sinon, en mode « tout chiffrer » → on chiffre TOUTE la sélection d'un bloc ;
//   - sinon s'il contient des `((marqueurs))` → on chiffre ces segments ;
//   - sinon → on chiffre toute la sélection comme un unique secret.
//

import Foundation
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

/// Ce qui chiffre et ce qui lit un texte (clavier, Partager, Conversation,
/// iMessage) : `BrocolisV3.codec` (v3 quand la clé le permet, sinon v1/v2),
/// ou `legacy` (v1/v2 seulement).
struct BrocolisCodec {
    let seal: (String) -> String?
    let open: (String) -> (text: String, count: Int)

    /// v1 (une clé) ou v2 (plusieurs), et la lecture v1/v2.
    static func legacy(keys: [SymmetricKey]) -> BrocolisCodec {
        BrocolisCodec(seal: { BrocolisCrypto.sealToken(Data($0.utf8), keys: keys) },
                      open: { BrocolisCrypto.decryptTokens($0, keys: keys) })
    }
}

struct BrocolisTransform {

    enum Outcome {
        case decrypted(count: Int)
        case encryptedMarked(count: Int)
        case encryptedWhole
        case unchanged
    }

    struct Result {
        let text: String
        let outcome: Outcome

        /// Libellé court à afficher à l'utilisateur.
        var label: String {
            switch outcome {
            case .decrypted(let n): return "🔓 \(n) segment(s) déchiffré(s)"
            case .encryptedMarked(let n): return "🔒 \(n) segment(s) chiffré(s)"
            case .encryptedWhole: return "🔒 Sélection chiffrée"
            case .unchanged: return "Aucune transformation"
            }
        }

        /// Vrai uniquement si le texte produit est RÉELLEMENT du chiffré. Sert de
        /// garde-fou : on ne doit jamais présenter du clair comme « prêt à
        /// envoyer ». De plus, on vérifie qu'il ne reste plus aucun clair marqué.
        var isEncrypted: Bool {
            switch outcome {
            case .encryptedWhole: return true
            case .encryptedMarked(let n): return n > 0
            case .decrypted, .unchanged: return false
            }
        }
    }

    /// - Parameter encryptWholeAlways: si `true`, une sélection SANS marqueurs
    ///   `((…))` est chiffrée d'un bloc (réglage « Tout chiffrer »). Des `((…))`
    ///   fermés sont une demande explicite : seuls ces passages sont chiffrés,
    ///   quel que soit le réglage. Le déchiffrement d'un jeton reste toujours
    ///   prioritaire.
    static func auto(_ input: String, key: SymmetricKey, encryptWholeAlways: Bool = false) -> Result {
        auto(input, keys: [key], encryptWholeAlways: encryptWholeAlways)
    }

    /// Variante multi-destinataire : le chiffrement produit un jeton lisible par
    /// TOUTES les clés fournies (`v2` si plusieurs, `v1` si une seule). Le
    /// déchiffrement essaie toutes les clés.
    static func auto(_ input: String, keys: [SymmetricKey], encryptWholeAlways: Bool = false) -> Result {
        auto(input, codec: .legacy(keys: keys), encryptWholeAlways: encryptWholeAlways)
    }

    /// Avec un `codec` : le v3 pour une clé destinataire qui le permet
    /// (`BrocolisV3.codec`), sinon v1/v2. Même ordre de décision.
    static func auto(_ input: String, codec: BrocolisCodec, encryptWholeAlways: Bool = false) -> Result {
        if BrocolisCrypto.containsToken(input) {
            let (text, n) = codec.open(input)
            return Result(text: text, outcome: .decrypted(count: n))
        }

        if input.contains(BrocolisCrypto.plainOpen) && input.contains(BrocolisCrypto.plainClose) {
            let (text, n) = BrocolisCrypto.encryptMarked(input, seal: codec.seal)
            if n > 0 { return Result(text: text, outcome: .encryptedMarked(count: n)) }
        }

        // Pas de passage marqué : tout le texte part chiffré d'un bloc.
        if let token = codec.seal(input) {
            return Result(text: token, outcome: .encryptedWhole)
        }

        return Result(text: input, outcome: .unchanged)
    }
}
