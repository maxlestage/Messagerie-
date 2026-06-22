//
//  BrocolisConversation.swift
//  Brocolis 🥦 (partagé app + extension)
//
//  Rendu « à la volée » d'une conversation entière : on colle (ou on partage)
//  tout un fil de discussion, et chaque ligne est rendue automatiquement :
//   - en clair si elle ne contenait aucun jeton ;
//   - DÉCHIFFRÉE (🔓) si un de tes jetons `[[BROCOLIS:v1:…]]` s'ouvre avec
//     l'une de tes clés (on les essaie toutes) ;
//   - LAISSÉE CHIFFRÉE (🔒) si le jeton ne s'ouvre avec aucune de tes clés —
//     c'est un message « pour les autres », qu'on n'a pas la clé de lire.
//
//  Logique PURE (sans App Group, sans UI) pour rester testable.
//

import Foundation
import CryptoKit

enum BrocolisConversation {

    /// Statut de lecture d'une ligne de la conversation.
    enum Status: Equatable {
        case clear        // aucune partie chiffrée
        case decrypted    // au moins un jeton ouvert avec une de tes clés
        case locked       // au moins un jeton qu'aucune de tes clés n'ouvre
        case mixed        // contient à la fois du déchiffré ET du resté-chiffré
    }

    /// Une ligne rendue de la conversation.
    struct Line: Identifiable, Equatable {
        let id: Int
        /// Texte à afficher (jetons ouverts remplacés par le clair, jetons
        /// étrangers laissés tels quels).
        let display: String
        /// Texte d'origine (avant rendu), utile pour re-copier/partager.
        let raw: String
        let status: Status
    }

    /// Résultat global du rendu d'une conversation.
    struct Rendered: Equatable {
        let lines: [Line]
        /// Nombre de jetons ouverts avec tes clés.
        let decryptedCount: Int
        /// Nombre de jetons restés chiffrés (clé inconnue).
        let lockedCount: Int

        /// Texte entièrement rendu (toutes les lignes recollées).
        var fullText: String { lines.map(\.display).joined(separator: "\n") }
    }

    /// Rend une conversation collée, ligne par ligne, en essayant TOUTES les clés.
    /// L'ordre des lignes est préservé (séparateur `\n`).
    static func render(_ input: String, keys: [SymmetricKey]) -> Rendered {
        var lines: [Line] = []
        var totalDecrypted = 0
        var totalLocked = 0

        // On découpe en lignes pour garder une présentation « fil de discussion ».
        // `omittingEmptySubsequences: false` garde les lignes vides telles quelles.
        let rawLines = input.split(separator: "\n", omittingEmptySubsequences: false)

        for (index, rawSub) in rawLines.enumerated() {
            let raw = String(rawSub)
            let (display, status, decrypted, locked) = renderLine(raw, keys: keys)
            totalDecrypted += decrypted
            totalLocked += locked
            lines.append(Line(id: index, display: display, raw: raw, status: status))
        }

        return Rendered(lines: lines, decryptedCount: totalDecrypted, lockedCount: totalLocked)
    }

    /// Rend une seule ligne et renvoie aussi le détail des compteurs.
    static func renderLine(
        _ raw: String, keys: [SymmetricKey]
    ) -> (display: String, status: Status, decrypted: Int, locked: Int) {
        guard BrocolisCrypto.containsToken(raw) else {
            return (raw, .clear, 0, 0)
        }

        // On compte d'abord le nombre total de jetons présents, puis combien on
        // arrive à ouvrir : la différence donne ceux restés chiffrés.
        let totalTokens = countTokens(raw)
        let (display, opened) = BrocolisCrypto.decryptTokens(raw, keys: keys)
        let locked = max(0, totalTokens - opened)

        let status: Status
        switch (opened, locked) {
        case (0, _):           status = .locked
        case (_, 0):           status = .decrypted
        default:               status = .mixed
        }
        return (display, status, opened, locked)
    }

    /// Compte les jetons `[[BROCOLIS:v1:…]]` bien formés dans le texte.
    static func countTokens(_ input: String) -> Int {
        var count = 0
        var rest = Substring(input)
        while let start = rest.range(of: BrocolisCrypto.tokenPrefix) {
            let afterPrefix = rest[start.upperBound...]
            guard let end = afterPrefix.range(of: BrocolisCrypto.tokenSuffix) else { break }
            count += 1
            rest = afterPrefix[end.upperBound...]
        }
        return count
    }
}
