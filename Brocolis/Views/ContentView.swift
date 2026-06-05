//
//  ContentView.swift
//  Messagerie 🥦
//
//  Liste des conversations + accès aux réglages de clé.
//

import SwiftUI
import CryptoKit

struct ContentView: View {
    @EnvironmentObject private var chatStore: ChatStore
    @EnvironmentObject private var keyStore: KeyStore

    @State private var showingSettings = false
    @State private var showingNewConversation = false
    @State private var newConversationTitle = ""

    var body: some View {
        NavigationStack {
            List {
                if !keyStore.hasKey {
                    Section {
                        NoKeyBanner { showingSettings = true }
                    }
                }

                Section {
                    ForEach(chatStore.sorted) { conversation in
                        NavigationLink(value: conversation.id) {
                            ConversationRow(conversation: conversation, key: keyStore.symmetricKey)
                        }
                    }
                    .onDelete(perform: chatStore.deleteConversations)
                }
            }
            .navigationTitle("Messagerie 🥦")
            .navigationDestination(for: UUID.self) { id in
                ChatView(conversationID: id)
            }
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    Button {
                        showingSettings = true
                    } label: {
                        Image(systemName: keyStore.hasKey ? "key.fill" : "key")
                    }
                    .accessibilityLabel("Clé de chiffrement")
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        newConversationTitle = ""
                        showingNewConversation = true
                    } label: {
                        Image(systemName: "square.and.pencil")
                    }
                    .accessibilityLabel("Nouvelle conversation")
                }
            }
            .sheet(isPresented: $showingSettings) {
                KeyView()
            }
            .alert("Nouvelle conversation", isPresented: $showingNewConversation) {
                TextField("Nom", text: $newConversationTitle)
                Button("Créer") {
                    chatStore.newConversation(title: newConversationTitle)
                }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("Donne un nom à ta conversation.")
            }
        }
    }
}

/// Bandeau affiché tant qu'aucune clé n'est configurée.
private struct NoKeyBanner: View {
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 12) {
                Image(systemName: "exclamationmark.lock.fill")
                    .font(.title2)
                    .foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Aucune clé de chiffrement")
                        .font(.headline)
                        .foregroundStyle(.primary)
                    Text("Touche ici pour en générer une ou en importer une.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Image(systemName: "chevron.right")
                    .foregroundStyle(.tertiary)
            }
        }
    }
}

/// Ligne de la liste : titre + aperçu (déchiffré si possible) du dernier message.
private struct ConversationRow: View {
    let conversation: Conversation
    let key: SymmetricKey?

    private var preview: String {
        guard let wire = conversation.lastWirePreview else { return "Aucun message" }
        guard let key else {
            return BrocolisCrypto.containsToken(wire) ? "🔒 Message chiffré" : wire
        }
        return BrocolisCrypto.decryptTokens(wire, key: key).text
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            HStack {
                Text(conversation.title)
                    .font(.headline)
                Spacer()
                if conversation.lastMessageDate != .distantPast {
                    Text(conversation.lastMessageDate, style: .time)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Text(preview)
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .lineLimit(1)
        }
        .padding(.vertical, 2)
    }
}

#Preview {
    ContentView()
        .environmentObject(KeyStore())
        .environmentObject(ChatStore())
}
