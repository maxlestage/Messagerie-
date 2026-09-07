//
//  WatchConversationView.swift
//  BrocolisWatch ⌚️
//
//  Une conversation au poignet : les messages arrivent chiffrés du serveur et
//  sont déchiffrés SUR la montre avec la clé du correspondant. Réponse par
//  dictée/griffonnage ou réponses rapides. Les photos s'affichent ; les vocaux
//  s'écoutent sur l'iPhone.
//

import SwiftUI
import CryptoKit
#if canImport(UIKit)
import UIKit
#endif

/// Store minimal : rattrapage + rafraîchissement périodique (pas de SSE au
/// poignet — le sondage préserve la batterie et suffit à la montre).
@MainActor
final class WatchChatStore: ObservableObject {
    @Published private(set) var lines: [ChatLine] = []
    @Published private(set) var status: String?
    @Published var draft: String = ""

    let correspondent: NamedKey
    private let key: SymmetricKey
    private let conversationId: String
    private let client: BrocolisMessagingClient
    /// Accumulation + décisions (rendu, accusé de lecture) : logique pure et
    /// testée, voir `WatchFeedState`.
    private var feed: WatchFeedState

    /// Échoue si la clé est illisible ou le serveur non configuré.
    init?(correspondent: NamedKey) {
        guard let key = try? BrocolisCrypto.symmetricKey(fromBase64: correspondent.base64),
              let cid = BrocolisMessagingClient.conversationId(forKeyBase64: correspondent.base64),
              let base = URL(string: MessagingPrefs.serverURL), MessagingPrefs.isConfigured
        else { return nil }
        self.correspondent = correspondent
        self.key = key
        self.conversationId = cid
        self.client = BrocolisMessagingClient(baseURL: base, deviceId: MessagingPrefs.deviceId)
        // Même plancher de confidentialité que l'iPhone : il est synchronisé
        // depuis le téléphone, donc ce qui y a été effacé l'est aussi ici.
        self.feed = WatchFeedState(floor: MessagingPrefs.floor(for: cid))
    }

    /// Récupère ce qui manque depuis le curseur, déchiffre et affiche.
    func refresh() async {
        guard let (msgs, cur, _) = try? await client.fetch(conversationId: conversationId,
                                                           after: feed.cursor) else {
            if lines.isEmpty {
                status = loc("Hors ligne — réessaie", "Offline — retry", "Sin conexión — reintenta")
            }
            return
        }
        status = nil
        let step = feed.ingest(msgs, cursor: cur)

        // Rendre = re-déchiffrer tout le fil ; accuser = une requête réseau.
        // `WatchFeedState` ne les demande que quand c'est utile.
        if step.shouldRender { render() }
        if let upTo = step.readReceiptUpTo {
            let c = client
            let cid = conversationId
            Task { await c.markRead(conversationId: cid, upTo: upTo) }
        }
    }

    private func render() {
        let me = MessagingPrefs.deviceId
        lines = feed.messages
            .sorted { $0.seq < $1.seq }
            .map { m in
                let (text, opened) = BrocolisCrypto.decryptTokens(m.ciphertext, keys: [key])
                return ChatLine(
                    id: m.id,
                    body: opened > 0 ? MediaPayload.body(from: text) : .locked,
                    isMine: m.senderId == me,
                    seq: m.seq
                )
            }
    }

    /// Chiffre et envoie le brouillon (dictée, griffonnage ou réponse rapide).
    func send(_ text: String) async {
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !clean.isEmpty else { return }
        do {
            try await client.send(text: clean, conversationId: conversationId, key: key)
            draft = ""
            await refresh()
        } catch {
            status = loc("Envoi impossible", "Couldn’t send", "No se pudo enviar")
        }
    }
}

struct WatchConversationView: View {
    let correspondent: NamedKey
    @StateObject private var holder = StoreHolder()

    /// Le store dépend du correspondant : on le crée au premier affichage.
    @MainActor
    final class StoreHolder: ObservableObject {
        var store: WatchChatStore?
        func ensure(for key: NamedKey) -> WatchChatStore? {
            if let store, store.correspondent.id == key.id { return store }
            store = WatchChatStore(correspondent: key)
            return store
        }
    }

    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
    private let quickReplies = ["👍", "OK", "🥦", "❤️"]

    var body: some View {
        if let store = holder.ensure(for: correspondent) {
            ConversationBody(store: store, quickReplies: quickReplies,
                             brocoliGreen: brocoliGreen)
                .navigationTitle(correspondent.name.isEmpty
                                 ? loc("Discussion", "Chat", "Chat")
                                 : correspondent.name)
        } else {
            Text(loc("Clé illisible ou serveur non configuré.",
                     "Unreadable key or server not configured.",
                     "Clave ilegible o servidor sin configurar."))
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }
}

/// Corps de la conversation (séparé pour observer le bon store).
private struct ConversationBody: View {
    @ObservedObject var store: WatchChatStore
    let quickReplies: [String]
    let brocoliGreen: Color

    var body: some View {
        ScrollViewReader { proxy in
            List {
                if store.lines.isEmpty {
                    Text(store.status
                         ?? loc("Aucun message pour l'instant.", "No messages yet.", "Aún no hay mensajes."))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                ForEach(store.lines) { line in
                    bubble(for: line)
                        .id(line.id)
                        .listRowBackground(Color.clear)
                }

                // Zone de réponse : dictée/griffonnage + réponses rapides.
                Section {
                    TextField(loc("Répondre…", "Reply…", "Responder…"), text: $store.draft)
                        .onSubmit { Task { await store.send(store.draft) } }
                    HStack {
                        ForEach(quickReplies, id: \.self) { emoji in
                            Button(emoji) { Task { await store.send(emoji) } }
                                .buttonStyle(.borderless)
                        }
                    }
                    if let status = store.status {
                        Text(status).font(.footnote).foregroundStyle(.orange)
                    }
                }
            }
            .onChange(of: store.lines.count) { _ in
                if let last = store.lines.last { proxy.scrollTo(last.id, anchor: .bottom) }
            }
        }
        .task {
            // Rattrapage immédiat puis sondage tant que l'écran est affiché.
            await store.refresh()
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 4_000_000_000)
                await store.refresh()
            }
        }
    }

    @ViewBuilder
    private func bubble(for line: ChatLine) -> some View {
        HStack {
            if line.isMine { Spacer(minLength: 12) }
            content(for: line)
                .padding(.horizontal, 8)
                .padding(.vertical, 5)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(line.isMine ? brocoliGreen : Color.gray.opacity(0.25))
                )
                .foregroundStyle(line.isMine ? .white : .primary)
            if !line.isMine { Spacer(minLength: 12) }
        }
    }

    @ViewBuilder
    private func content(for line: ChatLine) -> some View {
        switch line.body {
        case .text(let text):
            Text(text).font(.footnote)
        case .image(let data):
            #if canImport(UIKit)
            if let image = UIImage(data: data) {
                Image(uiImage: image)
                    .resizable()
                    .scaledToFit()
                    .clipShape(RoundedRectangle(cornerRadius: 8))
            } else {
                Text("📷").font(.footnote)
            }
            #else
            Text("📷").font(.footnote)
            #endif
        case .audio:
            Text(loc("🎤 Vocal — à écouter sur l'iPhone",
                     "🎤 Voice note — listen on iPhone",
                     "🎤 Nota de voz — escúchala en el iPhone"))
                .font(.footnote)
        case .locked:
            Text(loc("🔒 Chiffré (autre clé)", "🔒 Encrypted (other key)", "🔒 Cifrado (otra clave)"))
                .font(.footnote)
        }
    }
}
