//
//  BrocolisNotifications.swift
//  Brocolis 🥦 (app uniquement)
//
//  Préavis d'expiration via notifications locales : une alerte « ta clé expire
//  bientôt » avant l'échéance (même app fermée), et une à l'expiration. Les
//  notifications sont reprogrammées à chaque changement de clé / de durée.
//

import Foundation
import UserNotifications

enum BrocolisNotifications {

    private static let noticeID = "brocolis.key.expiry.notice"
    private static let expiredID = "brocolis.key.expired"

    /// Catégorie + actions attachées aux notifications d'expiration.
    static let categoryID = "BROCOLIS_EXPIRY"
    static let renewActionID = "BROCOLIS_RENEW"
    static let openRenewActionID = "BROCOLIS_OPEN_RENEW"

    /// Déclare la catégorie de notification avec ses actions. À appeler au lancement.
    static func registerCategories() {
        let renew = UNNotificationAction(
            identifier: renewActionID,
            title: "Prolonger la clé",
            options: [] // s'exécute sans ouvrir l'app
        )
        let openRenew = UNNotificationAction(
            identifier: openRenewActionID,
            title: "Ouvrir pour renouveler",
            options: [.foreground] // ouvre l'app sur l'écran d'appairage
        )
        let category = UNNotificationCategory(
            identifier: categoryID,
            actions: [renew, openRenew],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    /// (Re)programme les notifications selon l'état actuel de la clé.
    /// À appeler après tout changement de clé/d'expiration et à l'ouverture.
    static func refresh() {
        let center = UNUserNotificationCenter.current()

        // Pas de clé ou pas d'expiration → on n'embête pas l'utilisateur.
        guard BrocolisKeyStore.hasKey, BrocolisKeyStore.keyTTLSeconds > 0 else {
            center.removePendingNotificationRequests(withIdentifiers: [noticeID, expiredID])
            return
        }

        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else {
                center.removePendingNotificationRequests(withIdentifiers: [noticeID, expiredID])
                return
            }
            schedule(center: center)
        }
    }

    private static func schedule(center: UNUserNotificationCenter) {
        center.removePendingNotificationRequests(withIdentifiers: [noticeID, expiredID])

        let now = Date()
        let ttl = BrocolisKeyStore.keyTTLSeconds
        let expiresAt = BrocolisKeyStore.keyExpiresAt

        if let fire = BrocolisKeyStore.noticeFireDate(expiresAt: expiresAt, ttlSeconds: ttl, now: now) {
            add(center: center, id: noticeID, fireDate: fire,
                body: "Ta clé de chiffrement expire bientôt. Pense à la renouveler.")
        }
        if let expiresAt, expiresAt > now {
            add(center: center, id: expiredID, fireDate: expiresAt,
                body: "Ta clé a expiré. Renouvelle-la ou ré-appaire-toi pour continuer.")
        }
    }

    private static func add(
        center: UNUserNotificationCenter,
        id: String,
        fireDate: Date,
        body: String
    ) {
        let content = UNMutableNotificationContent()
        content.title = "Brocolis 🥦"
        content.body = body
        content.sound = .default
        content.categoryIdentifier = categoryID // ajoute le bouton « Prolonger »

        let comps = Calendar.current.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: fireDate)
        let trigger = UNCalendarNotificationTrigger(dateMatching: comps, repeats: false)
        center.add(UNNotificationRequest(identifier: id, content: content, trigger: trigger))
    }
}
