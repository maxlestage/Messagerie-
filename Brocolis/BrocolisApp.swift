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
import UserNotifications

/// Routeur partagé pour déclencher une navigation depuis l'extérieur du graphe
/// de vues (ex. depuis une action de notification).
final class AppRouter: ObservableObject {
    static let shared = AppRouter()
    @Published var openPairing = false
    private init() {}
}

/// Gère le cycle de vie + les actions de notification (« Prolonger »).
/// Note : `applicationWillTerminate` n'est pas appelé en cas de force-quit par
/// balayage ; l'interrupteur de l'app reste le contrôle fiable.
final class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {
    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        // Purge automatique de la clé périmée dès le lancement.
        BrocolisKeyStore.purgeExpiredKey()
        // Notifications : devient le destinataire des actions + déclare l'action « Prolonger ».
        UNUserNotificationCenter.current().delegate = self
        BrocolisNotifications.registerCategories()
        // Push : s'enregistre auprès d'APNs (mises à jour push, y compris Live
        // Activity à distance). Le device token est rangé dans l'App Group.
        application.registerForRemoteNotifications()
        return true
    }

    /// APNs a délivré le device token de l'app : on le range (hex) dans l'App
    /// Group pour un éventuel serveur push.
    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
        UserDefaults(suiteName: BrocolisKeyStore.appGroup)?
            .set(hex, forKey: "apns_device_token")
    }

    /// Échec d'enregistrement APNs (attendu sur simulateur ou sans capability
    /// push provisionnée) : sans conséquence, on l'ignore silencieusement.
    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {}

    func applicationWillTerminate(_ application: UIApplication) {
        BrocolisKeyStore.setActive(false)
        BrocolisLiveActivity.sync(active: false)
    }

    /// Action « Prolonger » : réarme la validité de la clé courante (même clé),
    /// puis reprogramme le préavis. Fonctionne sans ouvrir l'app.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        switch response.actionIdentifier {
        case BrocolisNotifications.renewActionID:
            // Prolonge la clé concernée (id transporté dans la notification).
            if let keyId = response.notification.request.content.userInfo[BrocolisNotifications.keyIdInfoKey] as? String {
                BrocolisKeyStore.reapplyExpiry(forKeyId: keyId)
            }
            BrocolisNotifications.refresh()
        case BrocolisNotifications.openRenewActionID:
            // Ouvre l'app sur l'écran d'appairage pour une vraie rotation.
            DispatchQueue.main.async { AppRouter.shared.openPairing = true }
        default:
            break
        }
        completionHandler()
    }

    /// Affiche aussi les notifications quand l'app est au premier plan.
    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
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
