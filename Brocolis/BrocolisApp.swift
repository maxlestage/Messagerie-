//
//  BrocolisApp.swift
//  Brocolis 🥦
//
//  App hôte minimale : elle sert à gérer la clé partagée et l'état « Actif ».
//  Le vrai travail se fait dans l'Action Extension, qui se greffe sur les apps
//  de messagerie via le menu Partager.
//

import SwiftUI
import UIKit

/// Désactive Brocolis quand l'app est *terminée* (best effort : non appelé en
/// cas de force-quit par balayage). L'interrupteur de l'app reste le contrôle
/// fiable.
final class AppDelegate: NSObject, UIApplicationDelegate {
    func applicationWillTerminate(_ application: UIApplication) {
        BrocolisKeyStore.setActive(false)
    }
}

@main
struct BrocolisApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        WindowGroup {
            RootView()
                .tint(.green)
        }
    }
}
