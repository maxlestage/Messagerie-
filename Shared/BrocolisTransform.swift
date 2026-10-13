//
//  BrocolisTransform.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Transformation « intelligente » d'une sélection de texte, en un seul geste :
//   - si le texte contient des jetons `[[BROCOLIS:v1:...]]` → on déchiffre ;
//   - sinon, en mode « tout chiffrer » → on chiffre TOUTE la sélection d'un bloc ;
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
        if BrocolisCrypto.containsToken(input) {
            let (text, n) = BrocolisCrypto.decryptTokens(input, keys: keys)
            return Result(text: text, outcome: .decrypted(count: n))
        }

        if input.contains(BrocolisCrypto.plainOpen) && input.contains(BrocolisCrypto.plainClose) {
            let (text, n) = BrocolisCrypto.encryptMarked(input, keys: keys)
            if n > 0 { return Result(text: text, outcome: .encryptedMarked(count: n)) }
        }

        // Pas de passage marqué : tout le texte part chiffré d'un bloc.
        if let token = BrocolisCrypto.sealToken(Data(input.utf8), keys: keys) {
            return Result(text: token, outcome: .encryptedWhole)
        }

        return Result(text: input, outcome: .unchanged)
    }
}
