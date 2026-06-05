//
//  MessageBubble.swift
//  Messagerie 🥦
//

import SwiftUI
import CryptoKit

struct MessageBubble: View {
    let message: Message
    let key: SymmetricKey?
    let showRaw: Bool

    private var isMine: Bool { message.sender == .me }

    /// Texte affiché : brut (sur le fil) si `showRaw`, sinon déchiffré.
    private var displayText: String {
        // Sans clé (ou en mode brut), on affiche le texte « sur le fil ».
        guard !showRaw, let key else { return message.wireText }
        return BrocolisCrypto.decryptTokens(message.wireText, key: key).text
    }

    /// Le message contient une partie chiffrée non lisible avec la clé courante.
    private var isLocked: Bool {
        guard message.isEncrypted else { return false }
        guard let key else { return true }
        return BrocolisCrypto.decryptTokens(message.wireText, key: key).count == 0
    }

    var body: some View {
        HStack {
            if isMine { Spacer(minLength: 40) }

            VStack(alignment: .leading, spacing: 4) {
                Text(displayText)
                    .font(showRaw ? .system(.footnote, design: .monospaced) : .body)
                    .foregroundStyle(isMine ? Color.white : Color.primary)
                    .textSelection(.enabled)

                HStack(spacing: 4) {
                    if message.isEncrypted {
                        Image(systemName: isLocked ? "lock.fill" : "lock.open.fill")
                            .font(.caption2)
                    }
                    Text(message.date, style: .time)
                        .font(.caption2)
                }
                .foregroundStyle(isMine ? Color.white.opacity(0.8) : Color.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(isMine ? Color.green : Color(.secondarySystemBackground))
            )

            if !isMine { Spacer(minLength: 40) }
        }
    }
}

#Preview {
    VStack {
        MessageBubble(
            message: Message(wireText: "Salut, ça va ?", sender: .them),
            key: nil, showRaw: false
        )
        MessageBubble(
            message: Message(wireText: "Oui ! Voici un [[BROCOLIS:v1:abc]] secret.", sender: .me),
            key: nil, showRaw: false
        )
    }
    .padding()
}
