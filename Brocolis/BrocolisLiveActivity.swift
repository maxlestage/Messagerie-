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
    /// Clé (App Group) où l'on dépose le push token de la Live Activity : c'est
    /// ce token qu'un serveur APNs cible pour mettre à jour / terminer le 🥦 à
    /// distance. Voir docs/ios-push-live-activity.md.
    static let pushTokenDefaultsKey = "live_activity_push_token"

    @available(iOS 16.1, *)
    private static func start() async {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else { return }
        guard Activity<BrocolisActivityAttributes>.activities.isEmpty else { return }
        let state = BrocolisActivityAttributes.ContentState(since: Date())
        do {
            // `pushType: .token` demande un push token APNs pour piloter la
            // Live Activity à distance (mises à jour push).
            let activity = try Activity.request(
                attributes: BrocolisActivityAttributes(),
                contentState: state,
                pushType: .token
            )
            if #available(iOS 16.2, *) {
                observePushToken(for: activity)
            }
        } catch {
            // La Live Activity reste facultative : on n'interrompt rien si iOS
            // refuse (autorisation, budget…).
        }
    }

    /// Suit les évolutions du push token de la Live Activity et le range dans
    /// l'App Group (hex), à disposition d'un serveur APNs.
    @available(iOS 16.2, *)
    private static func observePushToken(for activity: Activity<BrocolisActivityAttributes>) {
        Task {
            for await tokenData in activity.pushTokenUpdates {
                let hex = tokenData.map { String(format: "%02x", $0) }.joined()
                UserDefaults(suiteName: BrocolisKeyStore.appGroup)?
                    .set(hex, forKey: pushTokenDefaultsKey)
            }
        }
    }

    @available(iOS 16.1, *)
    private static func endAll() async {
        for activity in Activity<BrocolisActivityAttributes>.activities {
            await activity.end(dismissalPolicy: .immediate)
        }
    }
    #endif
}

/// Enregistrement du push token de la Live Activity auprès du serveur de
/// rendez-vous, après un appairage. Le token (déposé dans l'App Group par
/// `BrocolisLiveActivity`) arrive de façon asynchrone : on réessaie brièvement
/// avant d'abandonner (iOS < 16.2, push refusé…).
enum BrocolisPush {
    static func registerLiveActivityToken() async {
        guard let code = BrocolisKeyStore.pairingCode,
              let peerId = BrocolisKeyStore.pairingPeerId else { return }
        let client = PairingClient(baseURL: BrocolisKeyStore.serverURL)
        for _ in 0..<20 {
            if let token = BrocolisKeyStore.liveActivityPushToken, !token.isEmpty {
                try? await client.registerLiveActivityToken(
                    code: code, peerId: peerId, token: token)
                return
            }
            try? await Task.sleep(nanoseconds: 1_500_000_000)
        }
    }

    /// Notifie chaque correspondant appairé : déclenche une mise à jour de sa
    /// Live Activity via le serveur (event "update"). Renvoie le nombre d'envois
    /// réussis. Un correspondant dont la Live Activity n'est pas active, ou dont
    /// le push n'est pas configuré côté serveur, est simplement ignoré.
    @discardableResult
    static func notifyPeers() async -> Int {
        guard let code = BrocolisKeyStore.pairingCode else { return 0 }
        let peerIds = BrocolisKeyStore.pairingPeerIds
        guard !peerIds.isEmpty else { return 0 }

        let client = PairingClient(baseURL: BrocolisKeyStore.serverURL)
        let contentState: [String: Any] = ["since": Int(Date().timeIntervalSince1970)]
        var sent = 0
        for peerId in peerIds {
            do {
                try await client.updateLiveActivity(
                    code: code, peerId: peerId, event: "update", contentState: contentState)
                sent += 1
            } catch {
                // On poursuit avec les autres correspondants.
            }
        }
        return sent
    }
}
