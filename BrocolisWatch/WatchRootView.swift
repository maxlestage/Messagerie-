//
//  WatchRootView.swift
//  BrocolisWatch ⌚️
//
//  Écran d'accueil de la montre : l'état 🥦, puis un correspondant par clé
//  (comme sur l'iPhone : une clé = une personne). Sans clé synchronisée, on
//  explique quoi faire sur l'iPhone.
//

import SwiftUI

struct WatchRootView: View {
    @ObservedObject private var sync = WatchSyncReceiver.shared

    // Couleurs de la marque (identiques à l'iPhone).
    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
    private let deepGreen = Color(red: 34.0 / 255, green: 96.0 / 255, blue: 48.0 / 255)

    var body: some View {
        // `sync.revision` force la relecture du KeyStore après chaque synchro.
        let keys = BrocolisKeyStore.keys
        let _ = sync.revision

        NavigationStack {
            List {
                Section {
                    HStack(spacing: 8) {
                        Text("🥦").font(.title3)
                        VStack(alignment: .leading, spacing: 1) {
                            Text("Brocolis")
                                .font(.headline)
                            Text(BrocolisKeyStore.isActive
                                 ? loc("Actif — chiffré de bout en bout",
                                       "Active — end-to-end encrypted",
                                       "Activo — cifrado de extremo a extremo")
                                 : loc("En pause", "Paused", "En pausa"))
                                .font(.footnote)
                                .foregroundStyle(BrocolisKeyStore.isActive ? brocoliGreen : .secondary)
                        }
                    }
                }

                if keys.isEmpty {
                    Section {
                        Text(loc("Aucune clé 🔑 pour l'instant.\nOuvre Brocolis sur ton iPhone : tes clés arrivent ici toutes seules.",
                                 "No key 🔑 yet.\nOpen Brocolis on your iPhone: your keys arrive here automatically.",
                                 "Aún no hay clave 🔑.\nAbre Brocolis en tu iPhone: tus claves llegan aquí solas."))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } else {
                    Section(loc("Conversations", "Conversations", "Conversaciones")) {
                        ForEach(keys) { key in
                            NavigationLink(value: key.id) {
                                HStack(spacing: 8) {
                                    Image(systemName: "key.fill")
                                        .foregroundStyle(brocoliGreen)
                                    Text(key.name.isEmpty
                                         ? loc("Sans nom", "Unnamed", "Sin nombre")
                                         : key.name)
                                        .lineLimit(1)
                                }
                            }
                        }
                    }
                }

                Section {
                    if let at = sync.lastSyncAt {
                        (Text(loc("Synchronisé il y a ", "Synced ", "Sincronizado hace "))
                            + Text(at, style: .relative))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    } else {
                        Text(loc("En attente de l'iPhone…", "Waiting for iPhone…", "Esperando el iPhone…"))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Brocolis 🥦")
            .navigationDestination(for: String.self) { keyId in
                if let key = BrocolisKeyStore.keys.first(where: { $0.id == keyId }) {
                    WatchConversationView(correspondent: key)
                } else {
                    Text(loc("Clé introuvable", "Key not found", "Clave no encontrada"))
                }
            }
        }
        .tint(deepGreen)
    }
}

#Preview {
    WatchRootView()
}
