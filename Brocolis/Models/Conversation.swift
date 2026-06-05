//
//  Conversation.swift
//  Messagerie 🥦
//

import Foundation

struct Conversation: Identifiable, Codable, Equatable {
    let id: UUID
    var title: String
    var messages: [Message]

    init(id: UUID = UUID(), title: String, messages: [Message] = []) {
        self.id = id
        self.title = title
        self.messages = messages
    }

    /// Date du dernier message (pour trier les conversations).
    var lastMessageDate: Date { messages.last?.date ?? .distantPast }

    /// Texte du dernier message, sous forme « sur le fil » (chiffré).
    var lastWirePreview: String? { messages.last?.wireText }

    /// Conversation de démonstration insérée au premier lancement.
    static var welcome: Conversation {
        Conversation(
            title: "Brocolis 🥦",
            messages: [
                Message(
                    wireText: "Bienvenue ! Ici, tout ce que tu mets entre ((doubles parenthèses)) est chiffré avant d'être stocké.",
                    sender: .them,
                    date: Date().addingTimeInterval(-120)
                ),
                Message(
                    wireText: "Seuls les appareils qui partagent ta clé peuvent lire le clair. Pour les autres, ça reste un jeton [[BROCOLIS:v1:...]].",
                    sender: .them,
                    date: Date().addingTimeInterval(-60)
                ),
            ]
        )
    }
}
