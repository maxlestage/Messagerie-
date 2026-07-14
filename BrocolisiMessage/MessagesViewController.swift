//
//  MessagesViewController.swift
//  BrocolisiMessage (extension iMessage)
//
//  Brocolis DANS Messages : une mini-app dans le tiroir iMessage.
//   - ENVOYER : tape ton texte ici, il part chiffré (bulle « 🥦 Message
//     chiffré ») — sans changer de clavier.
//   - LIRE : le correspondant TOUCHE la bulle → ce panneau s'ouvre dans
//     Messages et affiche le texte EN CLAIR (déchiffré avec ses clés).
//
//  C'est le maximum autorisé par iOS : une app ne peut pas réécrire les bulles
//  d'iMessage, mais une extension iMessage peut afficher le clair dans son
//  panneau, au tap sur la bulle. Le réseau ne transporte que du chiffré.
//

import UIKit
import Messages
import SwiftUI

// MARK: - Modèle observé par la vue SwiftUI

@MainActor
final class BrocolisiMessageModel: ObservableObject {
    /// Texte en clair du message sélectionné (bulle touchée), si une de nos
    /// clés l'ouvre.
    @Published var selectedClear: String?
    /// Vrai si la bulle touchée est chiffrée avec une clé qu'on n'a PAS.
    @Published var selectedLocked = false
    @Published var isExpanded = false
    @Published var keys: [NamedKey] = []
    @Published var selectedKeyId: String?

    func refreshKeys() {
        keys = BrocolisKeyStore.keys
        selectedKeyId = BrocolisKeyStore.selectedKeyId ?? keys.first?.id
    }

    /// Décode la bulle sélectionnée : URL `?t=<jeton>` → déchiffre avec toutes
    /// nos clés.
    func update(selected: MSMessage?) {
        guard let url = selected?.url,
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let token = comps.queryItems?.first(where: { $0.name == "t" })?.value,
              !token.isEmpty else {
            selectedClear = nil
            selectedLocked = false
            return
        }
        let (text, opened) = BrocolisCrypto.decryptTokens(token, keys: BrocolisKeyStore.allSymmetricKeys())
        if opened > 0 {
            selectedClear = text
            selectedLocked = false
        } else {
            selectedClear = nil
            selectedLocked = true
        }
    }

    var selectedKey: NamedKey? {
        keys.first(where: { $0.id == selectedKeyId }) ?? keys.first
    }
}

// MARK: - Contrôleur iMessage

final class MessagesViewController: MSMessagesAppViewController {

    private let model = BrocolisiMessageModel()

    override func viewDidLoad() {
        super.viewDidLoad()
        let root = BrocolisiMessageRootView(
            model: model,
            onSend: { [weak self] text in self?.sendEncrypted(text) },
            onInsertPlainToken: { [weak self] text in self?.insertPlainToken(text) },
            onRequestExpand: { [weak self] in self?.requestPresentationStyle(.expanded) }
        )
        let host = UIHostingController(rootView: root)
        addChild(host)
        host.view.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(host.view)
        NSLayoutConstraint.activate([
            host.view.topAnchor.constraint(equalTo: view.topAnchor),
            host.view.bottomAnchor.constraint(equalTo: view.bottomAnchor),
            host.view.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            host.view.trailingAnchor.constraint(equalTo: view.trailingAnchor),
        ])
        host.didMove(toParent: self)
    }

    override func willBecomeActive(with conversation: MSConversation) {
        super.willBecomeActive(with: conversation)
        model.refreshKeys()
        model.update(selected: conversation.selectedMessage)
        model.isExpanded = presentationStyle == .expanded
    }

    // L'utilisateur touche une bulle Brocolis → on affiche le clair.
    override func didSelect(_ message: MSMessage, conversation: MSConversation) {
        model.update(selected: message)
    }

    override func didTransition(to presentationStyle: MSMessagesAppPresentationStyle) {
        super.didTransition(to: presentationStyle)
        model.isExpanded = presentationStyle == .expanded
    }

    /// Chiffre `text` avec la clé choisie et insère une bulle riche
    /// « 🥦 Message chiffré » (URL = jeton). Le correspondant touche la bulle
    /// pour lire — ou copie le jeton s'il n'a pas l'app.
    private func sendEncrypted(_ text: String) {
        guard let conversation = activeConversation,
              let key = model.selectedKey,
              let sym = try? BrocolisCrypto.symmetricKey(fromBase64: key.base64),
              let token = try? BrocolisCrypto.encryptToken(Data(text.utf8), key: sym)
        else { return }

        var comps = URLComponents()
        comps.scheme = "https"
        comps.host = "brocolis.invalid" // jamais résolu : simple support du jeton
        comps.queryItems = [URLQueryItem(name: "t", value: token)]

        let layout = MSMessageTemplateLayout()
        layout.caption = "🥦 Message chiffré"
        layout.subcaption = "Touche pour lire avec Brocolis"

        let message = MSMessage(session: MSSession())
        message.url = comps.url
        message.layout = layout
        message.summaryText = "🥦 Message chiffré"

        conversation.insert(message) { _ in }
        requestPresentationStyle(.compact)
    }

    /// Variante compatibilité : insère le jeton `[[BROCOLIS:v1:…]]` en texte
    /// brut (lisible par le clavier / l'écran Conversation / le proxy).
    private func insertPlainToken(_ text: String) {
        guard let conversation = activeConversation,
              let key = model.selectedKey,
              let sym = try? BrocolisCrypto.symmetricKey(fromBase64: key.base64),
              let token = try? BrocolisCrypto.encryptToken(Data(text.utf8), key: sym)
        else { return }
        conversation.insertText(token) { _ in }
        requestPresentationStyle(.compact)
    }
}

// MARK: - Vue SwiftUI

struct BrocolisiMessageRootView: View {
    @ObservedObject var model: BrocolisiMessageModel
    var onSend: (String) -> Void
    var onInsertPlainToken: (String) -> Void
    var onRequestExpand: () -> Void

    @State private var draft = ""

    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
    private let brocoliBg = Color(red: 232.0 / 255, green: 245.0 / 255, blue: 219.0 / 255)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                if let clear = model.selectedClear {
                    readCard(clear)
                } else if model.selectedLocked {
                    lockedCard
                }
                composer
            }
            .padding(14)
        }
        .background(brocoliBg.opacity(0.35))
    }

    // Bulle touchée → clair, bien visible.
    private func readCard(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Message déchiffré", systemImage: "lock.open.fill")
                .font(.caption).bold().foregroundStyle(brocoliGreen)
            Text(text)
                .font(.body)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 16).fill(Color(.systemBackground)))
        .overlay(RoundedRectangle(cornerRadius: 16).stroke(brocoliGreen.opacity(0.35)))
    }

    private var lockedCard: some View {
        Label("Ce message est chiffré avec une clé que tu n'as pas.",
              systemImage: "lock.fill")
            .font(.footnote).foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
    }

    @ViewBuilder private var composer: some View {
        if model.keys.isEmpty {
            Label("Ouvre Brocolis 🥦 pour créer une clé ou t'appairer.",
                  systemImage: "key.slash")
                .font(.footnote).foregroundStyle(.secondary)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label("Chiffrer pour", systemImage: "key.fill")
                        .font(.caption).foregroundStyle(.secondary)
                    Spacer()
                    Menu {
                        ForEach(model.keys) { key in
                            Button(key.name) { model.selectedKeyId = key.id }
                        }
                    } label: {
                        HStack(spacing: 4) {
                            Text(model.selectedKey?.name ?? "—").font(.caption).bold()
                            Image(systemName: "chevron.up.chevron.down").font(.caption2)
                        }
                        .foregroundStyle(brocoliGreen)
                    }
                }

                TextField("Message secret…", text: $draft, axis: .vertical)
                    .textFieldStyle(.roundedBorder)
                    .lineLimit(1...4)
                    .onTapGesture {
                        // En présentation compacte, le clavier n'est pas
                        // autorisé : on demande le plein écran d'abord.
                        if !model.isExpanded { onRequestExpand() }
                    }

                HStack(spacing: 10) {
                    Button {
                        send(via: onSend)
                    } label: {
                        Label("Envoyer chiffré", systemImage: "paperplane.fill")
                            .font(.subheadline).bold()
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(brocoliGreen)
                    .disabled(trimmedDraft.isEmpty)

                    Button {
                        send(via: onInsertPlainToken)
                    } label: {
                        Image(systemName: "textformat.abc.dottedunderline")
                            .font(.subheadline)
                    }
                    .buttonStyle(.bordered)
                    .tint(brocoliGreen)
                    .disabled(trimmedDraft.isEmpty)
                    .accessibilityLabel("Insérer en texte brut")
                }

                Text("La bulle « 🥦 » se lit d'un tap avec Brocolis. Le bouton de droite insère le jeton en texte (compatible clavier/app).")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 16).fill(Color(.systemBackground)))
        }
    }

    private var trimmedDraft: String {
        draft.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func send(via action: (String) -> Void) {
        let text = trimmedDraft
        guard !text.isEmpty else { return }
        action(text)
        draft = ""
    }
}
