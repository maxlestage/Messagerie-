//
//  BrocolisActivityAttributes.swift
//  Brocolis 🥦 (app + extension BrocolisStatus)
//
//  Attributs de la Live Activity « Brocolis actif » : le petit 🥦 affiché dans
//  la Dynamic Island / sur l'écran verrouillé tant que Brocolis est activé.
//  Le type doit être compilé À L'IDENTIQUE dans l'app et dans l'extension.
//

import Foundation

#if canImport(ActivityKit)
import ActivityKit

@available(iOS 16.1, *)
struct BrocolisActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        /// Instant d'activation, pour afficher « actif depuis… ».
        var since: Date
        /// Messages reçus non lus (tous fils confondus) depuis la dernière
        /// ouverture d'une conversation. Optionnel : les mises à jour push
        /// existantes (`{"since": …}` seul) restent décodables.
        var unread: Int?
        /// Nom du correspondant du DERNIER message reçu (jamais le contenu :
        /// le texte reste chiffré de bout en bout, la Live Activity n'en voit rien).
        var lastFrom: String?
        /// Heure du dernier message reçu, pour « il y a X min ».
        var lastAt: Date?
    }
}
#endif
