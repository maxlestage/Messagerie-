//
//  BrocolisWatchApp.swift
//  BrocolisWatch ⌚️
//
//  VRAIE app Apple Watch : tes conversations chiffrées au poignet. Les clés 🔑
//  sont synchronisées depuis l'iPhone (WatchConnectivity) ; la montre parle
//  ensuite directement au serveur — qui ne voit toujours que du chiffré.
//

import SwiftUI

@main
struct BrocolisWatchApp: App {
    init() {
        // Démarre l'écoute de la synchronisation iPhone → montre.
        WatchSyncReceiver.shared.start()
    }

    var body: some Scene {
        WindowGroup {
            WatchRootView()
        }
    }
}
