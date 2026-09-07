//
//  BrocolisStatusLiveActivity.swift
//  BrocolisStatus (extension widget)
//
//  Rendu de la Live Activity « Brocolis actif » : un 🥦 dans la Dynamic Island
//  (iPhone 14 Pro et suivants) et une bannière sur l'écran verrouillé. L'app
//  hôte démarre/termine l'activité via BrocolisLiveActivity.
//

import WidgetKit
import SwiftUI
import ActivityKit

@main
struct BrocolisStatusBundle: WidgetBundle {
    var body: some Widget {
        BrocolisStatusWidget()
        BrocolisStatusLiveActivity()
    }
}

struct BrocolisStatusLiveActivity: Widget {

    /// Nombre de non-lus (0 si absent) — pilote toute la mise en page.
    private func unread(_ context: ActivityViewContext<BrocolisActivityAttributes>) -> Int {
        context.state.unread ?? 0
    }

    /// Pastille verte « N » (compteur de messages non lus).
    @ViewBuilder
    private func badge(_ n: Int) -> some View {
        Text("\(min(n, 99))")
            .font(.caption2.bold())
            .foregroundStyle(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(Capsule().fill(.green))
    }

    /// Préfixe de l'horodatage : « De X · il y a » quand on sait de qui vient
    /// le message, « Reçu il y a » quand on ne le sait pas.
    private func lastPrefix(_ name: String?) -> String {
        guard let name, !name.isEmpty else {
            return loc("Reçu il y a ", "Received ", "Recibido hace ")
        }
        return loc("De \(name) · il y a ", "From \(name) · ", "De \(name) · hace ")
    }

    /// Sous-titre du dernier message reçu (jamais le contenu : il reste
    /// chiffré, la Live Activity n'en sait rien).
    ///
    /// Le NOM peut manquer sans que l'heure manque : une mise à jour poussée
    /// par APNs vient de l'expéditeur, qui ignore comment tu l'as nommé — il
    /// n'envoie donc que l'horodatage. C'est le cas app fermée, celui-là même
    /// pour lequel la Live Activity existe : l'heure doit s'afficher quand
    /// même, au lieu de retomber sur « Chiffrement prêt depuis… ».
    @ViewBuilder
    private func lastLine(_ context: ActivityViewContext<BrocolisActivityAttributes>) -> some View {
        if let at = context.state.lastAt {
            (Text(lastPrefix(context.state.lastFrom)) + Text(at, style: .relative))
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else if let from = context.state.lastFrom, !from.isEmpty {
            Text(loc("De \(from)", "From \(from)", "De \(from)"))
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            (Text(loc("Chiffrement prêt depuis ", "Encryption ready for ", "Cifrado listo desde hace "))
                + Text(context.state.since, style: .relative))
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    var body: some WidgetConfiguration {
        ActivityConfiguration(for: BrocolisActivityAttributes.self) { context in
            // Écran verrouillé / bannière
            let n = unread(context)
            HStack(spacing: 12) {
                Text("🥦").font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(n > 0
                         ? loc(n == 1 ? "1 nouveau message" : "\(n) nouveaux messages",
                               n == 1 ? "1 new message" : "\(n) new messages",
                               n == 1 ? "1 mensaje nuevo" : "\(n) mensajes nuevos")
                         : loc("Brocolis est actif", "Brocolis is active", "Brocolis está activo"))
                        .font(.headline)
                    lastLine(context)
                }
                Spacer()
                if n > 0 {
                    badge(n)
                } else {
                    Image(systemName: "lock.shield.fill")
                        .foregroundStyle(.green)
                }
            }
            .padding()
            .activityBackgroundTint(Color.green.opacity(0.15))
            .activitySystemActionForegroundColor(.green)
        } dynamicIsland: { context in
            DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Text("🥦").font(.title2)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    if unread(context) > 0 {
                        badge(unread(context))
                    } else {
                        Image(systemName: "lock.shield.fill")
                            .foregroundStyle(.green)
                    }
                }
                DynamicIslandExpandedRegion(.center) {
                    let n = unread(context)
                    Text(n > 0
                         ? loc(n == 1 ? "1 nouveau message" : "\(n) nouveaux messages",
                               n == 1 ? "1 new message" : "\(n) new messages",
                               n == 1 ? "1 mensaje nuevo" : "\(n) mensajes nuevos")
                         : loc("Brocolis est actif", "Brocolis is active", "Brocolis está activo"))
                        .font(.headline)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    if unread(context) > 0 {
                        lastLine(context)
                    } else {
                        Text(loc("Le chiffrement est prêt dans le menu Partager.", "Encryption is ready in the Share menu.", "El cifrado está listo en el menú Compartir."))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            } compactLeading: {
                Text("🥦")
            } compactTrailing: {
                if unread(context) > 0 {
                    badge(unread(context))
                } else {
                    Image(systemName: "lock.fill")
                        .foregroundStyle(.green)
                }
            } minimal: {
                if unread(context) > 0 {
                    badge(unread(context))
                } else {
                    Text("🥦")
                }
            }
        }
    }
}
