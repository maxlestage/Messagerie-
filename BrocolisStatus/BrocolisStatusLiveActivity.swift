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
                    Text("Brocolis est actif").font(.headline)
                    Text("Chiffrement prêt depuis \(context.state.since, style: .relative)")
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
                    Text("Brocolis est actif").font(.headline)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    Text("Le chiffrement est prêt dans le menu Partager.")
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
