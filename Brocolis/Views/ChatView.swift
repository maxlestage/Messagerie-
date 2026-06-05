//
//  ChatView.swift
//  Messagerie 🥦
//
//  Fil de discussion : composition de messages (les `((secret))` sont chiffrés),
//  affichage déchiffré, et réception d'un message « sur le fil ».
//

import SwiftUI
import CryptoKit

struct ChatView: View {
    let conversationID: UUID

    @EnvironmentObject private var chatStore: ChatStore
    @EnvironmentObject private var keyStore: KeyStore

    @State private var draft = ""
    @State private var showRaw = false
    @State private var showingReceive = false
    @State private var incomingWire = ""

    private var conversation: Conversation? { chatStore.conversation(conversationID) }

    var body: some View {
        VStack(spacing: 0) {
            messageList
            Divider()
            composer
        }
        .navigationTitle(conversation?.title ?? "Conversation")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Toggle(isOn: $showRaw) {
                        Label("Voir le texte chiffré", systemImage: "lock.doc")
                    }
                    Button {
                        incomingWire = ""
                        showingReceive = true
                    } label: {
                        Label("Recevoir un message", systemImage: "tray.and.arrow.down")
                    }
                    Button(role: .destructive) {
                        chatStore.clearMessages(in: conversationID)
                    } label: {
                        Label("Effacer la conversation", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .alert("Recevoir un message", isPresented: $showingReceive) {
            TextField("Colle ici le message reçu", text: $incomingWire)
            Button("Ajouter") {
                chatStore.receiveWire(incomingWire, to: conversationID)
            }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("Colle un message reçu d'un correspondant (chiffré ou non). Il sera déchiffré avec ta clé.")
        }
    }

    private var messageList: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(conversation?.messages ?? []) { message in
                        MessageBubble(message: message, key: keyStore.symmetricKey, showRaw: showRaw)
                            .id(message.id)
                    }
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 10)
            }
            .onChange(of: conversation?.messages.count ?? 0) { _, _ in
                if let last = conversation?.messages.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
            .onAppear {
                if let last = conversation?.messages.last {
                    proxy.scrollTo(last.id, anchor: .bottom)
                }
            }
        }
    }

    private var composer: some View {
        VStack(spacing: 6) {
            if !keyStore.hasKey {
                Text("⚠️ Aucune clé : les secrets ne seront pas chiffrés.")
                    .font(.caption)
                    .foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                Text("Astuce : mets un secret entre ((doubles parenthèses)) pour le chiffrer.")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            HStack(alignment: .bottom, spacing: 8) {
                TextField("Message…", text: $draft, axis: .vertical)
                    .lineLimit(1...5)
                    .textFieldStyle(.roundedBorder)

                Button {
                    chatStore.send(draft, to: conversationID, key: keyStore.symmetricKey)
                    draft = ""
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 30))
                }
                .disabled(draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(.bar)
    }
}

#Preview {
    NavigationStack {
        ChatView(conversationID: Conversation.welcome.id)
            .environmentObject(KeyStore())
            .environmentObject(ChatStore())
    }
}
