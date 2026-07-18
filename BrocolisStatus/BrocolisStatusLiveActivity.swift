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
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: BrocolisActivityAttributes.self) { context in
            // Écran verrouillé / bannière
            HStack(spacing: 12) {
                Text("🥦").font(.title2)
                VStack(alignment: .leading, spacing: 2) {
                    Text(loc("Brocolis est actif", "Brocolis is active", "Brocolis está activo")).font(.headline)
                    // Date relative auto-actualisée : Text séparé (n'existe pas
                    // dans une String via loc()).
                    (Text(loc("Chiffrement prêt depuis ", "Encryption ready for ", "Cifrado listo desde hace ")) + Text(context.state.since, style: .relative))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "lock.shield.fill")
                    .foregroundStyle(.green)
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
                    Image(systemName: "lock.shield.fill")
                        .foregroundStyle(.green)
                }
                DynamicIslandExpandedRegion(.center) {
                    Text(loc("Brocolis est actif", "Brocolis is active", "Brocolis está activo")).font(.headline)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    Text(loc("Le chiffrement est prêt dans le menu Partager.", "Encryption is ready in the Share menu.", "El cifrado está listo en el menú Compartir."))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            } compactLeading: {
                Text("🥦")
            } compactTrailing: {
                Image(systemName: "lock.fill")
                    .foregroundStyle(.green)
            } minimal: {
                Text("🥦")
            }
        }
    }
}
