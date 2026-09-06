//
//  WatchSyncReceiver.swift
//  BrocolisWatch ⌚️
//
//  Réception de la synchronisation iPhone → montre (WatchConnectivity) : les
//  clés 🔑, l'identité d'appareil et l'URL du serveur arrivent dans
//  l'`applicationContext` et sont rangées dans l'App Group LOCAL de la montre.
//  Ensuite, la montre parle directement au serveur — comme l'iPhone.
//

import Foundation
import WatchConnectivity

final class WatchSyncReceiver: NSObject, ObservableObject, WCSessionDelegate {
    static let shared = WatchSyncReceiver()

    /// Dernière synchronisation reçue (persistée), pour l'afficher à l'écran.
    @Published private(set) var lastSyncAt: Date?
    /// Change à chaque synchro : force les vues à relire le KeyStore.
    @Published private(set) var revision = 0

    private static let lastSyncName = "watch_last_sync_at"

    private override init() {
        super.init()
        if let t = UserDefaults(suiteName: BrocolisKeyStore.appGroup)?
            .object(forKey: Self.lastSyncName) as? TimeInterval {
            lastSyncAt = Date(timeIntervalSince1970: t)
        }
    }

    func start() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        session.delegate = self
        session.activate()
    }

    private func apply(_ context: [String: Any]) {
        guard !context.isEmpty else { return }
        if let keysJSON = context["keysJSON"] as? String {
            BrocolisKeyStore.importKeysJSON(keysJSON,
                                            selectedId: context["selectedKeyId"] as? String)
        }
        // Même identité que l'iPhone : la montre envoie et lit comme « toi ».
        if let id = context["deviceId"] as? String { MessagingPrefs.adoptDeviceId(id) }
        if let url = context["serverURL"] as? String, !url.isEmpty {
            MessagingPrefs.serverURL = url
        }
        let now = Date()
        UserDefaults(suiteName: BrocolisKeyStore.appGroup)?
            .set(now.timeIntervalSince1970, forKey: Self.lastSyncName)
        DispatchQueue.main.async {
            self.lastSyncAt = now
            self.revision += 1
        }
    }

    // MARK: WCSessionDelegate (montre)

    func session(_ session: WCSession,
                 activationDidCompleteWith activationState: WCSessionActivationState,
                 error: Error?) {
        // Contexte déjà livré pendant que l'app était fermée : on le rejoue.
        if activationState == .activated {
            apply(session.receivedApplicationContext)
        }
    }

    func session(_ session: WCSession,
                 didReceiveApplicationContext applicationContext: [String: Any]) {
        apply(applicationContext)
    }
}
