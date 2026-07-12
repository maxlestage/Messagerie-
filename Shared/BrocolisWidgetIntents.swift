//
//  BrocolisWidgetIntents.swift
//  Brocolis 🥦 (partagé app + extension widget)
//
//  Intent utilisé par le BOUTON INTERACTIF du widget (iOS 17+) pour activer /
//  mettre en pause Brocolis sans ouvrir l'app.
//
//  ⚠️ Volontairement « widget-safe » : il ne touche QUE l'état de l'App Group et
//  recharge les widgets. Il ne référence PAS `BrocolisLiveActivity` (qui n'existe
//  que dans la cible app), pour pouvoir être compilé aussi dans l'extension
//  widget. La Live Activity se resynchronisera à la prochaine ouverture de l'app.
//

import AppIntents
import WidgetKit

@available(iOS 16.0, *)
struct ToggleActiveWidgetIntent: AppIntent {
    static var title: LocalizedStringResource = "Activer ou mettre en pause Brocolis"
    static var description = IntentDescription(
        "Bascule l'état de Brocolis directement depuis le widget, sans ouvrir l'app.")

    func perform() async throws -> some IntentResult {
        // On ne bascule que s'il y a une clé (sinon « actif » n'a pas de sens).
        if BrocolisKeyStore.hasKey {
            BrocolisKeyStore.setActive(!BrocolisKeyStore.isActive)
        }
        WidgetCenter.shared.reloadAllTimelines()
        return .result()
    }
}
