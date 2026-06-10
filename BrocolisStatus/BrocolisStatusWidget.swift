//
//  BrocolisStatusWidget.swift
//  BrocolisStatus (extension widget)
//
//  Widget d'écran d'accueil (et d'écran verrouillé) : montre d'un coup d'œil
//  si Brocolis est actif, la clé sélectionnée et son éventuelle expiration.
//  Lit l'état via l'App Group (BrocolisKeyStore), comme l'Action Extension.
//

import WidgetKit
import SwiftUI

struct BrocolisEntry: TimelineEntry {
    let date: Date
    let isActive: Bool
    let keyName: String?
    let expiresAt: Date?
}

struct BrocolisStatusProvider: TimelineProvider {

    private func currentEntry(at date: Date = Date()) -> BrocolisEntry {
        let selected = BrocolisKeyStore.selectedKey
        let expired = selected?.expiresAt.map { $0 <= date } ?? false
        return BrocolisEntry(
            date: date,
            isActive: BrocolisKeyStore.isActive && !expired,
            keyName: selected?.name,
            expiresAt: selected?.expiresAt
        )
    }

    func placeholder(in context: Context) -> BrocolisEntry {
        BrocolisEntry(date: Date(), isActive: true, keyName: "Maman", expiresAt: nil)
    }

    func getSnapshot(in context: Context, completion: @escaping (BrocolisEntry) -> Void) {
        completion(context.isPreview ? placeholder(in: context) : currentEntry())
    }

    func getTimeline(in context: Context, completion: @escaping (Timeline<BrocolisEntry>) -> Void) {
        let entry = currentEntry()
        // Si la clé expire, replanifie une entrée à l'échéance pour basculer
        // l'affichage ; sinon le widget n'a pas besoin de se rafraîchir seul
        // (l'app recharge les timelines à chaque changement d'état).
        if let exp = entry.expiresAt, exp > entry.date {
            completion(Timeline(entries: [entry, currentEntry(at: exp)], policy: .after(exp)))
        } else {
            completion(Timeline(entries: [entry], policy: .never))
        }
    }
}

struct BrocolisStatusWidgetView: View {
    @Environment(\.widgetFamily) private var family
    let entry: BrocolisEntry

    var body: some View {
        switch family {
        case .accessoryInline:
            Text(entry.isActive ? "🥦 Actif" : "🥦 Inactif")
        case .accessoryCircular:
            VStack(spacing: 0) {
                Text("🥦").font(.title3).opacity(entry.isActive ? 1 : 0.35)
                Image(systemName: entry.isActive ? "lock.fill" : "lock.open")
                    .font(.caption2)
            }
            .widgetBackgroundCompat(Color.clear)
        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.isActive ? "🥦 Brocolis actif" : "🥦 Brocolis inactif")
                    .font(.headline)
                detailLine
            }
            .widgetBackgroundCompat(Color.clear)
        default: // .systemSmall
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("🥦").font(.largeTitle).opacity(entry.isActive ? 1 : 0.4)
                    Spacer()
                    Image(systemName: entry.isActive ? "lock.shield.fill" : "lock.shield")
                        .foregroundStyle(entry.isActive ? .green : .secondary)
                }
                Spacer()
                Text(entry.isActive ? "Actif" : "Inactif")
                    .font(.headline)
                    .foregroundStyle(entry.isActive ? .green : .secondary)
                detailLine
            }
            .padding()
            .widgetBackgroundCompat(Color(.systemBackground))
        }
    }

    @ViewBuilder private var detailLine: some View {
        if let name = entry.keyName {
            if let exp = entry.expiresAt {
                if exp <= entry.date {
                    Text("« \(name) » — expirée")
                        .font(.caption).foregroundStyle(.orange)
                } else {
                    Text("« \(name) » — expire \(exp, style: .relative)")
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text("Clé « \(name) »")
                    .font(.caption).foregroundStyle(.secondary)
            }
        } else {
            Text("Aucune clé")
                .font(.caption).foregroundStyle(.secondary)
        }
    }
}

// iOS 17 exige containerBackground ; la cible vise 16.1, d'où ce pont.
private extension View {
    @ViewBuilder func widgetBackgroundCompat(_ color: Color) -> some View {
        if #available(iOSApplicationExtension 17.0, *) {
            containerBackground(for: .widget) { color }
        } else {
            background(color)
        }
    }
}

struct BrocolisStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "BrocolisStatusWidget", provider: BrocolisStatusProvider()) { entry in
            BrocolisStatusWidgetView(entry: entry)
        }
        .configurationDisplayName("Brocolis 🥦")
        .description("État du chiffrement : actif ou non, clé sélectionnée, expiration.")
        .supportedFamilies([.systemSmall, .accessoryInline, .accessoryCircular, .accessoryRectangular])
    }
}
