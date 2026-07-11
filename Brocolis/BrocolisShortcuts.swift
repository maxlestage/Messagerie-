//
//  BrocolisShortcuts.swift
//  Brocolis 🥦 (app uniquement)
//
//  Raccourcis (App Intents) : activer / désactiver / basculer le chiffrement
//  Brocolis depuis l'app Raccourcis, Siri, ou le bouton Action — sans ouvrir
//  l'app. Chaque action met à jour l'état (App Group), la Live Activity et
//  recharge les widgets.
//

import AppIntents
import WidgetKit

@available(iOS 16.0, *)
struct ActivateBrocolisIntent: AppIntent {
    static var title: LocalizedStringResource = "Activer Brocolis"
    static var description = IntentDescription("Active le chiffrement Brocolis 🥦.")
    static var openAppWhenRun = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        BrocolisKeyStore.setActive(true)
        let on = BrocolisKeyStore.isActive
        BrocolisLiveActivity.sync(active: on)
        WidgetCenter.shared.reloadAllTimelines()
        return .result(dialog: on
            ? "Brocolis est activé 🥦"
            : "Ajoute d’abord une clé dans Brocolis pour l’activer.")
    }
}

@available(iOS 16.0, *)
struct DeactivateBrocolisIntent: AppIntent {
    static var title: LocalizedStringResource = "Désactiver Brocolis"
    static var description = IntentDescription("Désactive le chiffrement Brocolis.")
    static var openAppWhenRun = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        BrocolisKeyStore.setActive(false)
        BrocolisLiveActivity.sync(active: false)
        WidgetCenter.shared.reloadAllTimelines()
        return .result(dialog: "Brocolis est désactivé.")
    }
}

@available(iOS 16.0, *)
struct ToggleBrocolisIntent: AppIntent {
    static var title: LocalizedStringResource = "Basculer Brocolis"
    static var description = IntentDescription("Active ou désactive Brocolis selon l’état actuel.")
    static var openAppWhenRun = false

    func perform() async throws -> some IntentResult & ProvidesDialog {
        BrocolisKeyStore.setActive(!BrocolisKeyStore.isActive)
        let on = BrocolisKeyStore.isActive
        BrocolisLiveActivity.sync(active: on)
        WidgetCenter.shared.reloadAllTimelines()
        return .result(dialog: on ? "Brocolis est activé 🥦" : "Brocolis est désactivé.")
    }
}

/// Expose les raccourcis à Siri, à l'app Raccourcis et au bouton Action.
@available(iOS 16.0, *)
struct BrocolisAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: ToggleBrocolisIntent(),
            phrases: [
                "Basculer \(.applicationName)",
                "Change \(.applicationName)",
            ],
            shortTitle: "Basculer Brocolis",
            systemImageName: "lock.rotation"
        )
        AppShortcut(
            intent: ActivateBrocolisIntent(),
            phrases: [
                "Active \(.applicationName)",
                "Chiffre avec \(.applicationName)",
            ],
            shortTitle: "Activer Brocolis",
            systemImageName: "lock.shield.fill"
        )
        AppShortcut(
            intent: DeactivateBrocolisIntent(),
            phrases: [
                "Désactive \(.applicationName)",
                "Stoppe \(.applicationName)",
            ],
            shortTitle: "Désactiver Brocolis",
            systemImageName: "lock.open"
        )
    }
}
