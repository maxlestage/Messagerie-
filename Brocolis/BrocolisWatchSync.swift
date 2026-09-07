//
//  BrocolisWatchSync.swift
//  Brocolis 🥦 (app iPhone uniquement)
//
//  Synchronisation iPhone → Apple Watch via WatchConnectivity : l'iPhone pousse
//  ses clés 🔑, son identité d'appareil et l'URL du serveur dans le
//  `applicationContext` (transport chiffré par Apple, livré même montre
//  éteinte). La montre range tout dans SON App Group local et peut alors
//  discuter directement avec le serveur — mêmes clés, mêmes conversations.
//

import Foundation
import UIKit
#if canImport(WatchConnectivity)
import WatchConnectivity

final class BrocolisWatchSync: NSObject, WCSessionDelegate {
    static let shared = BrocolisWatchSync()
    private override init() { super.init() }

    /// Active la session et pousse l'état à chaque retour/départ de l'app :
    /// couvre le lancement, la fin d'un appairage, l'ajout/suppression de clé…
    func start() {
        guard WCSession.isSupported() else { return } // pas de montre (iPad…)
        let session = WCSession.default
        session.delegate = self
        session.activate()
        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(pushNow),
                           name: UIApplication.didBecomeActiveNotification, object: nil)
        center.addObserver(self, selector: #selector(pushNow),
                           name: UIApplication.willResignActiveNotification, object: nil)
        // `didEnterBackground` AUSSI, et pas seulement `willResignActive` :
        // « effacer à la fermeture » monte le plancher de confidentialité sur
        // `.background`, donc APRÈS la première notification. Sans ce second
        // point de passage, le plancher partirait avec un cycle de retard et la
        // montre afficherait encore, tout ce temps, ce que le téléphone vient
        // d'effacer.
        center.addObserver(self, selector: #selector(pushNow),
                           name: UIApplication.didEnterBackgroundNotification, object: nil)
    }

    /// Pousse l'état courant vers la montre. Sans danger d'appeler trop souvent :
    /// seul le DERNIER contexte est conservé/livré par le système.
    @objc func pushNow() {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        guard session.activationState == .activated, session.isPaired,
              session.isWatchAppInstalled else { return }

        // `WatchSyncPayload` (partagé avec la montre) décrit le contenu du
        // contexte : ce qu'on écrit ici est exactement ce que la montre relit.
        let payload = WatchSyncPayload(
            keysJSON: BrocolisKeyStore.exportKeysJSON(),
            selectedKeyId: BrocolisKeyStore.selectedKeyId,
            deviceId: MessagingPrefs.deviceId,
            serverURL: MessagingPrefs.serverURL,
            active: BrocolisKeyStore.isActive,
            floors: MessagingPrefs.allFloors()
        )
        try? session.updateApplicationContext(payload.context)
    }

    // MARK: WCSessionDelegate

    func session(_ session: WCSession,
                 activationDidCompleteWith activationState: WCSessionActivationState,
                 error: Error?) {
        if activationState == .activated { pushNow() }
    }

    func sessionDidBecomeInactive(_ session: WCSession) {}

    func sessionDidDeactivate(_ session: WCSession) {
        // L'utilisateur a changé de montre : on réactive pour la nouvelle.
        session.activate()
    }

    func sessionWatchStateDidChange(_ session: WCSession) {
        // L'app montre vient d'être installée : on pousse tout de suite.
        pushNow()
    }
}
#endif
