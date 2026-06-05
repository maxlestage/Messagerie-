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

        let comps = Calendar.current.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: fireDate)
        let trigger = UNCalendarNotificationTrigger(dateMatching: comps, repeats: false)
        center.add(UNNotificationRequest(identifier: id, content: content, trigger: trigger))
    }
}
