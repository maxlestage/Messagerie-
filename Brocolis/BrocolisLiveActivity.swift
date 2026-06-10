//
//  BrocolisLiveActivity.swift
//  Brocolis 🥦 (app uniquement)
//
//  Pilote la Live Activity « Brocolis actif » : démarrée quand l'interrupteur
//  passe sur Actif, terminée quand il repasse sur Inactif. iOS ne permet pas
//  d'icône dans la barre de statut elle-même : la Dynamic Island (🥦) est
//  l'équivalent officiel. Nécessite iOS 16.1 ; sans Dynamic Island, le 🥦
//  apparaît sur l'écran verrouillé.
//

import Foundation
import WidgetKit

#if canImport(ActivityKit)
import ActivityKit
#endif

enum BrocolisLiveActivity {

    /// Aligne la Live Activity sur l'état « Actif ». Idempotent : ne démarre
    /// rien si elle tourne déjà, ne termine rien s'il n'y a rien à terminer.
    /// Recharge aussi le widget d'écran d'accueil, qui lit le même état.
    static func sync(active: Bool) {
        WidgetCenter.shared.reloadAllTimelines()
        #if canImport(ActivityKit)
        guard #available(iOS 16.1, *) else { return }
        Task {
            if active {
                await start()
            } else {
                await endAll()
            }
        }
        #endif
    }

    #if canImport(ActivityKit)
    @available(iOS 16.1, *)
    private static func start() async {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        guard Activity<BrocolisActivityAttributes>.activities.isEmpty else { return }
        let state = BrocolisActivityAttributes.ContentState(since: Date())
        _ = try? Activity.request(
            attributes: BrocolisActivityAttributes(),
            contentState: state
        )
    }

    @available(iOS 16.1, *)
    private static func endAll() async {
        for activity in Activity<BrocolisActivityAttributes>.activities {
            await activity.end(dismissalPolicy: .immediate)
        }
    }
    #endif
}
