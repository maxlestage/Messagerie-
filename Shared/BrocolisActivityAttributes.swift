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

// MARK: - Ce qu'affiche la ligne sous le titre

/// Décide de la ligne affichée sous le titre de la Live Activity. Logique
/// PURE — ni ActivityKit ni SwiftUI : c'est la seule partie du rendu qui prend
/// une décision, donc la seule qui mérite un test (une vue d'extension widget
/// est hors d'atteinte de la cible de tests).
///
/// Le cas qui a motivé ce type : une mise à jour poussée par APNs vient de
/// l'expéditeur, qui ignore comment le destinataire l'a nommé. Elle apporte
/// donc une heure SANS nom, et c'est justement le cas app fermée — celui pour
/// lequel la Live Activity existe.
enum BrocolisLastLine: Equatable {
    /// « De X · il y a … » : message reçu, expéditeur connu.
    case from(name: String, at: Date)
    /// « Reçu il y a … » : heure connue, expéditeur inconnu (mise à jour push).
    case receivedAt(Date)
    /// « De X » : nom connu, sans horodatage.
    case fromOnly(name: String)
    /// « Chiffrement prêt depuis … » : aucun message, juste l'état actif.
    case activeSince(Date)

    static func choose(lastFrom: String?, lastAt: Date?, since: Date) -> BrocolisLastLine {
        // Un nom vide compte comme absent : une clé peut être « Sans nom ».
        var name = lastFrom
        if name?.isEmpty == true { name = nil }

        if let at = lastAt {
            if let name { return .from(name: name, at: at) }
            return .receivedAt(at)          // mise à jour push : heure sans nom
        }
        if let name { return .fromOnly(name: name) }
        return .activeSince(since)
    }
}
