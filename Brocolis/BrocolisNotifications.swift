//
//  BrocolisNotifications.swift
//  Brocolis 🥦 (app uniquement)
//
//  Préavis d'expiration PAR CLÉ via notifications locales : pour chaque clé
//  ayant une durée de vie, une alerte avant l'échéance + une à l'expiration.
//  L'action « Prolonger » porte l'id de la clé concernée.
//

import Foundation
import UserNotifications

enum BrocolisNotifications {

    static let categoryID = "BROCOLIS_EXPIRY"
    static let renewActionID = "BROCOLIS_RENEW"
    static let openRenewActionID = "BROCOLIS_OPEN_RENEW"
    static let keyIdInfoKey = "keyId"

    /// Déclare la catégorie avec ses actions. À appeler au lancement.
    static func registerCategories() {
        let renew = UNNotificationAction(
            identifier: renewActionID,
            title: loc("Prolonger la clé", "Extend the key", "Ampliar la clave"),
            options: []
        )
        let openRenew = UNNotificationAction(
            identifier: openRenewActionID,
            title: loc("Ouvrir pour renouveler", "Open to renew", "Abrir para renovar"),
            options: [.foreground]
        )
        let category = UNNotificationCategory(
            identifier: categoryID,
            actions: [renew, openRenew],
            intentIdentifiers: [],
            options: []
        )
        UNUserNotificationCenter.current().setNotificationCategories([category])
    }

    /// (Re)programme les notifications pour TOUTES les clés à durée de vie.
    static func refresh() {
        let center = UNUserNotificationCenter.current()
        center.removeAllPendingNotificationRequests()

        let keys = BrocolisKeyStore.keys.filter { $0.ttlSeconds > 0 && $0.expiresAt != nil }
        guard !keys.isEmpty else { return }

        center.requestAuthorization(options: [.alert, .sound]) { granted, _ in
            guard granted else { return }
            let now = Date()
            for k in keys {
                guard let exp = k.expiresAt else { continue }
                if let fire = BrocolisKeyStore.noticeFireDate(
                    expiresAt: exp, ttlSeconds: k.ttlSeconds, now: now) {
                    add(center: center, id: "brocolis.notice.\(k.id)", keyId: k.id, fireDate: fire,
                        body: loc("Ta clé « \(k.name) » expire bientôt. Pense à la renouveler.", "Your key “\(k.name)” is expiring soon. Remember to renew it.", "Tu clave «\(k.name)» caduca pronto. Recuerda renovarla."))
                }
                if exp > now {
                    add(center: center, id: "brocolis.expired.\(k.id)", keyId: k.id, fireDate: exp,
                        body: loc("Ta clé « \(k.name) » a expiré. Renouvelle-la pour continuer.", "Your key “\(k.name)” has expired. Renew it to continue.", "Tu clave «\(k.name)» ha caducado. Renuévala para continuar."))
                }
            }
        }
    }

    private static func add(
        center: UNUserNotificationCenter,
        id: String,
        keyId: String,
        fireDate: Date,
        body: String
    ) {
        let content = UNMutableNotificationContent()
        content.title = "Brocolis 🥦"
        content.body = body
        content.sound = .default
        content.categoryIdentifier = categoryID
        content.userInfo = [keyIdInfoKey: keyId]

        let comps = Calendar.current.dateComponents(
            [.year, .month, .day, .hour, .minute, .second], from: fireDate)
        let trigger = UNCalendarNotificationTrigger(dateMatching: comps, repeats: false)
        center.add(UNNotificationRequest(identifier: id, content: content, trigger: trigger))
    }
}
