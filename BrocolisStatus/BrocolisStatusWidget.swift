//
//  BrocolisStatusWidget.swift
//  BrocolisStatus (extension widget)
//
//  Widget d'écran d'accueil ET d'écran verrouillé, en PLUSIEURS TAILLES :
//  petit, moyen, grand + accessoires (rond, ligne, rectangle). Montre d'un coup
//  d'œil si Brocolis est actif, la clé sélectionnée, son expiration et le nombre
//  de clés. Lit l'état via l'App Group (BrocolisKeyStore), comme l'extension.
//

import WidgetKit
import SwiftUI

struct BrocolisEntry: TimelineEntry {
    let date: Date
    let isActive: Bool
    let keyName: String?
    let expiresAt: Date?
    let keyCount: Int
}

struct BrocolisStatusProvider: TimelineProvider {

    private func currentEntry(at date: Date = Date()) -> BrocolisEntry {
        let selected = BrocolisKeyStore.selectedKey
        let expired = selected?.expiresAt.map { $0 <= date } ?? false
        return BrocolisEntry(
            date: date,
            isActive: BrocolisKeyStore.isActive && !expired,
            keyName: selected?.name,
            expiresAt: selected?.expiresAt,
            keyCount: BrocolisKeyStore.keys.count
        )
    }

    func placeholder(in context: Context) -> BrocolisEntry {
        BrocolisEntry(date: Date(), isActive: true, keyName: "Maman", expiresAt: nil, keyCount: 3)
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

    private var statusText: String { entry.isActive ? loc("Actif", "Active", "Activo") : loc("Inactif", "Inactive", "Inactivo") }
    private var statusColor: Color { entry.isActive ? .green : .secondary }

    // Bouton interactif (iOS 17+) : bascule actif/pause SANS ouvrir l'app.
    // Sur iOS 16, rien ne s'affiche (le widget reste tap-pour-ouvrir).
    @ViewBuilder private var toggleButton: some View {
        if #available(iOSApplicationExtension 17.0, *) {
            Button(intent: ToggleActiveWidgetIntent()) {
                Label(entry.isActive ? loc("Mettre en pause", "Pause", "Pausar") : loc("Activer", "Activate", "Activar"),
                      systemImage: entry.isActive ? "pause.fill" : "play.fill")
                    .font(.caption).fontWeight(.semibold)
                    .lineLimit(1).minimumScaleFactor(0.7)
            }
            .buttonStyle(.borderedProminent)
            .tint(entry.isActive ? .orange : .green)
            .disabled(entry.keyCount == 0)
        }
    }

    var body: some View {
        switch family {
        case .accessoryInline:
            Text(entry.isActive ? loc("🥦 Actif", "🥦 Active", "🥦 Activo") : loc("🥦 Inactif", "🥦 Inactive", "🥦 Inactivo"))

        case .accessoryCircular:
            VStack(spacing: 0) {
                Text("🥦").font(.title3).opacity(entry.isActive ? 1 : 0.35)
                Image(systemName: entry.isActive ? "lock.fill" : "lock.open")
                    .font(.caption2)
            }
            .widgetBackgroundCompat(Color.clear)

        case .accessoryRectangular:
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.isActive ? loc("🥦 Brocolis actif", "🥦 Brocolis active", "🥦 Brocolis activo") : loc("🥦 Brocolis inactif", "🥦 Brocolis inactive", "🥦 Brocolis inactivo"))
                    .font(.headline)
                detailLine
            }
            .widgetBackgroundCompat(Color.clear)

        case .systemMedium:
            HStack(spacing: 16) {
                VStack(alignment: .leading, spacing: 6) {
                    header
                    Spacer(minLength: 0)
                    Text(statusText).font(.title3).bold().foregroundStyle(statusColor)
                    toggleButton
                }
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    Text(loc("Clé sélectionnée", "Selected key", "Clave seleccionada"))
                        .font(.caption2).foregroundStyle(.secondary)
                    detailLine
                    Spacer(minLength: 0)
                    Text(loc("\(entry.keyCount) clé\(entry.keyCount > 1 ? "s" : "") enregistrée\(entry.keyCount > 1 ? "s" : "")", "\(entry.keyCount) key\(entry.keyCount > 1 ? "s" : "") saved", "\(entry.keyCount) clave\(entry.keyCount > 1 ? "s" : "") guardada\(entry.keyCount > 1 ? "s" : "")"))
                        .font(.caption2).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding()
            .brocoliCardBackground()

        case .systemLarge:
            VStack(alignment: .leading, spacing: 14) {
                header
                Text(statusText)
                    .font(.largeTitle).bold()
                    .foregroundStyle(statusColor)
                toggleButton
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    Text(loc("Clé sélectionnée", "Selected key", "Clave seleccionada"))
                        .font(.caption).foregroundStyle(.secondary)
                    detailLine.font(.body)
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text(loc("Trousseau", "Keychain", "Llavero"))
                        .font(.caption).foregroundStyle(.secondary)
                    Text(loc("\(entry.keyCount) clé\(entry.keyCount > 1 ? "s" : "") — au déchiffrement, toutes sont essayées.", "\(entry.keyCount) key\(entry.keyCount > 1 ? "s" : "") — all are tried when decrypting.", "\(entry.keyCount) clave\(entry.keyCount > 1 ? "s" : "") — al descifrar, se prueban todas."))
                        .font(.footnote).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
                Text(entry.isActive
                     ? loc("Prêt à chiffrer — clavier, Partager et Conversation.", "Ready to encrypt — keyboard, Share and Conversation.", "Listo para cifrar — teclado, Compartir y Conversación.")
                     : loc("Ouvre Brocolis 🥦 pour l’activer.", "Open Brocolis 🥦 to activate it.", "Abre Brocolis 🥦 para activarlo."))
                    .font(.footnote).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding()
            .brocoliCardBackground()

        default: // .systemSmall
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text("🥦").font(.largeTitle).opacity(entry.isActive ? 1 : 0.4)
                    Spacer()
                    Image(systemName: entry.isActive ? "lock.shield.fill" : "lock.shield")
                        .foregroundStyle(entry.isActive ? .green : .secondary)
                }
                Spacer()
                Text(statusText)
                    .font(.headline)
                    .foregroundStyle(statusColor)
                detailLine
                toggleButton
            }
            .padding()
            .brocoliCardBackground()
        }
    }

    // En-tête commun aux grandes tailles : logo + nom + cadenas.
    private var header: some View {
        HStack(spacing: 8) {
            Text("🥦").font(.title).opacity(entry.isActive ? 1 : 0.4)
            Text("Brocolis").font(.headline)
            Spacer()
            Image(systemName: entry.isActive ? "lock.shield.fill" : "lock.shield")
                .foregroundStyle(statusColor)
        }
    }

    @ViewBuilder private var detailLine: some View {
        if let name = entry.keyName {
            if let exp = entry.expiresAt {
                if exp <= entry.date {
                    Text(loc("« \(name) » — expirée", "« \(name) » — expired", "« \(name) » — caducada"))
                        .font(.caption).foregroundStyle(.orange)
                } else {
                    // La date relative auto-actualisée (Text(_:style:)) doit rester
                    // un Text séparé : elle n'existe pas dans une String via loc().
                    (Text(loc("« \(name) » — expire ", "« \(name) » — expires ", "« \(name) » — caduca ")) + Text(exp, style: .relative))
                        .font(.caption).foregroundStyle(.secondary)
                }
            } else {
                Text(loc("Clé « \(name) »", "Key « \(name) »", "Clave « \(name) »"))
                    .font(.caption).foregroundStyle(.secondary)
            }
        } else {
            Text(loc("Aucune clé", "No key", "Ninguna clave"))
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

    // Fond « carte brocoli » : la couleur de fond du logo (#E8F5DB), donc plus de
    // blanc. On force l'apparence claire pour que le texte reste lisible même en
    // thème sombre (sinon texte blanc sur vert pâle = illisible).
    func brocoliCardBackground() -> some View {
        environment(\.colorScheme, .light)
            .widgetBackgroundCompat(Color(red: 232.0 / 255, green: 245.0 / 255, blue: 219.0 / 255))
    }
}

struct BrocolisStatusWidget: Widget {
    var body: some WidgetConfiguration {
        StaticConfiguration(kind: "BrocolisStatusWidget", provider: BrocolisStatusProvider()) { entry in
            BrocolisStatusWidgetView(entry: entry)
        }
        .configurationDisplayName("Brocolis 🥦")
        .description(loc("État du chiffrement : actif ou non, clé sélectionnée, expiration.", "Encryption status: active or not, selected key, expiration.", "Estado del cifrado: activo o no, clave seleccionada, caducidad."))
        .supportedFamilies([
            .systemSmall, .systemMedium, .systemLarge,
            .accessoryInline, .accessoryCircular, .accessoryRectangular,
        ])
    }
}
