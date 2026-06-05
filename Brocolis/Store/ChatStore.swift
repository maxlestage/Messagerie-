//
//  ChatStore.swift
//  Messagerie 🥦
//
//  Stocke les conversations sur disque (JSON dans Documents). Les parties
//  secrètes des messages sont toujours conservées sous forme de jetons
//  chiffrés : le clair n'est jamais écrit sur disque.
//

import Foundation
import CryptoKit
import Combine

@MainActor
final class ChatStore: ObservableObject {

    @Published var conversations: [Conversation] = []

    private let fileURL: URL

    init() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        fileURL = docs.appendingPathComponent("conversations.json")
        load()
        if conversations.isEmpty {
            conversations = [.welcome]
            save()
        }
    }

    // MARK: - Lecture

    /// Conversations triées par message le plus récent.
    var sorted: [Conversation] {
        conversations.sorted { $0.lastMessageDate > $1.lastMessageDate }
    }

    func conversation(_ id: UUID) -> Conversation? {
        conversations.first { $0.id == id }
    }

    // MARK: - Écriture

    @discardableResult
    func newConversation(title: String) -> Conversation {
        let name = title.trimmingCharacters(in: .whitespacesAndNewlines)
        let conv = Conversation(title: name.isEmpty ? "Sans titre" : name)
        conversations.append(conv)
        save()
        return conv
    }

    /// Compose un message sortant. Les `((secret))` sont chiffrés si une clé est
    /// disponible ; sinon le texte est stocké tel quel.
    func send(_ rawInput: String, to id: UUID, key: SymmetricKey?) {
        let trimmed = rawInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let wire = key.map { BrocolisCrypto.encryptMarked(trimmed, key: $0).text } ?? trimmed
        append(Message(wireText: wire, sender: .me), to: id)
    }

    /// Enregistre un message entrant « sur le fil » (déjà chiffré le cas échéant),
    /// par exemple collé depuis un autre canal.
    func receiveWire(_ wireText: String, to id: UUID) {
        let trimmed = wireText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        append(Message(wireText: trimmed, sender: .them), to: id)
    }

    func deleteConversations(at offsets: IndexSet) {
        // `offsets` se réfère à la liste triée affichée.
        let ids = offsets.map { sorted[$0].id }
        conversations.removeAll { ids.contains($0.id) }
        save()
    }

    func clearMessages(in id: UUID) {
        guard let idx = conversations.firstIndex(where: { $0.id == id }) else { return }
        conversations[idx].messages.removeAll()
        save()
    }

    private func append(_ message: Message, to id: UUID) {
        guard let idx = conversations.firstIndex(where: { $0.id == id }) else { return }
        conversations[idx].messages.append(message)
        save()
    }

    // MARK: - Persistance

    private func load() {
        guard let data = try? Data(contentsOf: fileURL) else { return }
        if let decoded = try? JSONDecoder().decode([Conversation].self, from: data) {
            conversations = decoded
        }
    }

    private func save() {
        guard let data = try? JSONEncoder().encode(conversations) else { return }
        try? data.write(to: fileURL, options: [.atomic])
    }
}
