//
//  ConversationView.swift
//  Brocolis 🥦
//
//  Écran « Conversation » : colle (ou partage) tout un fil de discussion et
//  Brocolis le rend EN CLAIR à la volée — chaque message chiffré avec une de
//  tes clés s'affiche déchiffré (🔓), les messages chiffrés avec d'autres clés
//  restent chiffrés (🔒, « pour les autres »). En dessous, un champ de saisie
//  chiffre ta réponse au fil de la frappe : copie en un tap, colle dans ta
//  vraie messagerie.
//
//  ⚠️ iOS interdit à une app de lire/modifier le contenu d'une AUTRE app
//  (sandbox). Brocolis ne peut donc pas réécrire WhatsApp/iMessage tout seul :
//  cet écran est l'endroit où la lecture/écriture devient automatique.
//

import SwiftUI
import UIKit
import CryptoKit

struct ConversationView: View {
    @State private var pasted: String = ""
    @State private var reply: String = ""
    @State private var copiedToast: String?

    // Recalculé à chaque frappe : clés essayées = toutes les clés connues.
    private var rendered: BrocolisConversation.Rendered {
        BrocolisConversation.render(pasted, keys: BrocolisKeyStore.allSymmetricKeys())
    }

    // Aperçu chiffré de la réponse (clé sélectionnée), recalculé à la volée.
    private var encryptedReply: String? {
        let trimmed = reply.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let key = BrocolisKeyStore.symmetricKey(),
              !BrocolisKeyStore.isExpired else { return nil }
        return try? BrocolisCrypto.encryptToken(Data(reply.utf8), key: key)
    }

    var body: some View {
        VStack(spacing: 0) {
            conversationList
            Divider()
            composer
        }
        .navigationTitle("Conversation")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Menu {
                    Button {
                        if let s = UIPasteboard.general.string { pasted = s }
                    } label: { Label("Coller la discussion", systemImage: "doc.on.clipboard") }
                    Button {
                        UIPasteboard.general.string = rendered.fullText
                        toast("Conversation en clair copiée")
                    } label: { Label("Copier tout en clair", systemImage: "doc.on.doc") }
                    Button(role: .destructive) { pasted = "" } label: {
                        Label("Effacer", systemImage: "trash")
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
            }
        }
        .overlay(alignment: .bottom) { toastView }
    }

    // MARK: Fil de discussion (lecture à la volée)

    private var conversationList: some View {
        ScrollView {
            if pasted.isEmpty {
                emptyState
            } else {
                VStack(alignment: .leading, spacing: 8) {
                    summaryBanner
                    ForEach(rendered.lines) { line in
                        if !line.display.isEmpty {
                            bubble(for: line)
                        }
                    }
                }
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
    }

    private var emptyState: some View {
        VStack(spacing: 12) {
            Image(systemName: "text.bubble")
                .font(.system(size: 44))
                .foregroundStyle(.secondary)
            Text("Colle ici toute ta discussion")
                .font(.headline)
            Text("Brocolis déchiffre à la volée tout ce qui est protégé par une de tes clés. Les messages chiffrés avec d'autres clés restent 🔒.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                if let s = UIPasteboard.general.string { pasted = s }
            } label: {
                Label("Coller la discussion", systemImage: "doc.on.clipboard")
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(40)
        .frame(maxWidth: .infinity)
    }

    @ViewBuilder private var summaryBanner: some View {
        let r = rendered
        if r.decryptedCount > 0 || r.lockedCount > 0 {
            HStack(spacing: 12) {
                if r.decryptedCount > 0 {
                    Label("\(r.decryptedCount) lu(s)", systemImage: "lock.open.fill")
                        .foregroundStyle(.green)
                }
                if r.lockedCount > 0 {
                    Label("\(r.lockedCount) pour les autres", systemImage: "lock.fill")
                        .foregroundStyle(.secondary)
                }
            }
            .font(.footnote)
            .padding(.bottom, 4)
        }
    }

    private func bubble(for line: BrocolisConversation.Line) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: icon(for: line.status))
                .foregroundStyle(color(for: line.status))
                .font(.footnote)
                .padding(.top, 3)
            Text(line.display)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(color(for: line.status).opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 12))
                .foregroundStyle(line.status == .locked ? .secondary : .primary)
        }
    }

    private func icon(for status: BrocolisConversation.Status) -> String {
        switch status {
        case .clear:     return "text.alignleft"
        case .decrypted: return "lock.open.fill"
        case .locked:    return "lock.fill"
        case .mixed:     return "lock.open.trianglebadge.exclamationmark"
        }
    }

    private func color(for status: BrocolisConversation.Status) -> Color {
        switch status {
        case .clear:     return .secondary
        case .decrypted: return .green
        case .locked:    return .gray
        case .mixed:     return .orange
        }
    }

    // MARK: Composer (chiffre la réponse à la volée)

    private var composer: some View {
        VStack(spacing: 8) {
            if let token = encryptedReply {
                HStack {
                    Image(systemName: "lock.fill").foregroundStyle(.green)
                    Text(token)
                        .font(.system(.caption2, design: .monospaced))
                        .lineLimit(2)
                        .truncationMode(.middle)
                    Spacer()
                    Button {
                        UIPasteboard.general.string = token
                        toast("Message chiffré copié")
                    } label: {
                        Image(systemName: "doc.on.doc")
                    }
                }
                .padding(.horizontal)
            } else if !reply.trimmingCharacters(in: .whitespaces).isEmpty {
                Text(BrocolisKeyStore.isExpired
                     ? "⌛️ Clé expirée — renouvelle-la pour chiffrer."
                     : "🔑 Aucune clé sélectionnée pour chiffrer.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
            }

            HStack(spacing: 8) {
                TextField("Écris ta réponse…", text: $reply, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1...4)
                Button {
                    if let token = encryptedReply {
                        UIPasteboard.general.string = token
                        toast("Message chiffré copié")
                        reply = ""
                    }
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.title)
                }
                .disabled(encryptedReply == nil)
            }
            .padding(.horizontal)
            .padding(.bottom, 8)
        }
        .padding(.top, 8)
        .background(.bar)
    }

    // MARK: Toast

    @ViewBuilder private var toastView: some View {
        if let msg = copiedToast {
            Text(msg)
                .font(.footnote.weight(.semibold))
                .padding(.horizontal, 14).padding(.vertical, 8)
                .background(.ultraThinMaterial, in: Capsule())
                .padding(.bottom, 90)
                .transition(.move(edge: .bottom).combined(with: .opacity))
        }
    }

    private func toast(_ message: String) {
        withAnimation { copiedToast = message }
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) {
            withAnimation { copiedToast = nil }
        }
    }
}

#Preview {
    NavigationStack { ConversationView() }
}
