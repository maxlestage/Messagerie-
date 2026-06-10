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
    }
}
#endif
