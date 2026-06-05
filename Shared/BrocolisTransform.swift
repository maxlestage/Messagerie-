//
//  BrocolisTransform.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Transformation « intelligente » d'une sélection de texte, en un seul geste :
//   - si le texte contient des jetons `[[BROCOLIS:v1:...]]` → on déchiffre ;
//   - sinon s'il contient des `((marqueurs))` → on chiffre ces segments ;
//   - sinon → on chiffre toute la sélection comme un unique secret.
//

import Foundation
import CryptoKit

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
    }

    static func auto(_ input: String, key: SymmetricKey) -> Result {
        if BrocolisCrypto.containsToken(input) {
            let (text, n) = BrocolisCrypto.decryptTokens(input, key: key)
            return Result(text: text, outcome: .decrypted(count: n))
        }

        if input.contains(BrocolisCrypto.plainOpen) && input.contains(BrocolisCrypto.plainClose) {
            let (text, n) = BrocolisCrypto.encryptMarked(input, key: key)
            if n > 0 { return Result(text: text, outcome: .encryptedMarked(count: n)) }
        }

        if let token = try? BrocolisCrypto.encryptToken(Data(input.utf8), key: key) {
            return Result(text: token, outcome: .encryptedWhole)
        }

        return Result(text: input, outcome: .unchanged)
    }
}
