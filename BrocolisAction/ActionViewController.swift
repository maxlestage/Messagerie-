//
//  ActionViewController.swift
//  Brocolis 🥦 — Action Extension
//
//  Apparaît dans le menu Partager quand du texte est sélectionné dans n'importe
//  quelle app (WhatsApp, iMessage, Messenger, Notes…). Chiffre les ((secrets))
//  ou déchiffre les jetons [[BROCOLIS:v1:...]] avec la clé partagée (App Group),
//  puis affiche le résultat avec un bouton « Copier ».
//

import UIKit
import UniformTypeIdentifiers

final class ActionViewController: UIViewController {

    private let titleLabel = UILabel()
    private let statusLabel = UILabel()
    private let textView = UITextView()
    private var resultText = ""

    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
        loadSelectedText { [weak self] text in
            self?.process(text)
        }
    }

    // MARK: UI

    private func setupUI() {
        view.backgroundColor = .systemBackground

        let nav = UINavigationBar()
        nav.translatesAutoresizingMaskIntoConstraints = false
        let item = UINavigationItem(title: "Brocolis 🥦")
        item.leftBarButtonItem = UIBarButtonItem(
            barButtonSystemItem: .done, target: self, action: #selector(done)
        )
        item.rightBarButtonItem = UIBarButtonItem(
            title: "Copier", style: .done, target: self, action: #selector(copyResult)
        )
        nav.items = [item]
        view.addSubview(nav)

        statusLabel.translatesAutoresizingMaskIntoConstraints = false
        statusLabel.font = .preferredFont(forTextStyle: .subheadline)
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 0
        view.addSubview(statusLabel)

        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.font = .preferredFont(forTextStyle: .body)
        textView.isEditable = false
        textView.layer.cornerRadius = 10
        textView.backgroundColor = .secondarySystemBackground
        textView.textContainerInset = UIEdgeInsets(top: 12, left: 12, bottom: 12, right: 12)
        view.addSubview(textView)

        NSLayoutConstraint.activate([
            nav.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            nav.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            nav.trailingAnchor.constraint(equalTo: view.trailingAnchor),

            statusLabel.topAnchor.constraint(equalTo: nav.bottomAnchor, constant: 12),
            statusLabel.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            statusLabel.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),

            textView.topAnchor.constraint(equalTo: statusLabel.bottomAnchor, constant: 12),
            textView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 16),
            textView.trailingAnchor.constraint(equalTo: view.trailingAnchor, constant: -16),
            textView.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor, constant: -16),
        ])
    }

    // MARK: Lecture du texte sélectionné

    private func loadSelectedText(completion: @escaping (String) -> Void) {
        let items = (extensionContext?.inputItems as? [NSExtensionItem]) ?? []

        // 1) Texte sélectionné directement disponible.
        for item in items {
            if let text = item.attributedContentText?.string, !text.isEmpty {
                completion(text)
                return
            }
        }

        // 2) Sinon, via une pièce jointe texte.
        let textType = UTType.plainText.identifier
        for item in items {
            for provider in item.attachments ?? [] where provider.hasItemConformingToTypeIdentifier(textType) {
                provider.loadItem(forTypeIdentifier: textType, options: nil) { data, _ in
                    let text: String
                    if let s = data as? String {
                        text = s
                    } else if let url = data as? URL, let s = try? String(contentsOf: url, encoding: .utf8) {
                        text = s
                    } else if let d = data as? Data, let s = String(data: d, encoding: .utf8) {
                        text = s
                    } else {
                        text = ""
                    }
                    DispatchQueue.main.async { completion(text) }
                }
                return
            }
        }

        completion("")
    }

    // MARK: Transformation

    private func process(_ input: String) {
        guard !input.isEmpty else {
            statusLabel.text = "Aucun texte sélectionné."
            textView.text = ""
            return
        }
        guard BrocolisKeyStore.isActive else {
            statusLabel.text = "⏸ Brocolis est désactivé."
            textView.text = "Ouvre l’app Brocolis 🥦 et active-le pour chiffrer/déchiffrer."
            resultText = ""
            return
        }
        guard let key = BrocolisKeyStore.symmetricKey() else {
            statusLabel.text = "🔑 Aucune clé configurée."
            textView.text = "Ouvre l’app Brocolis 🥦 pour générer ou importer une clé, puis réessaie."
            resultText = ""
            return
        }
        guard !BrocolisKeyStore.isExpired else {
            statusLabel.text = "⌛️ Clé expirée."
            textView.text = "Renouvelle la clé dans l’app Brocolis 🥦 (ou ré-appaire-toi), puis réessaie."
            resultText = ""
            return
        }

        let result = BrocolisTransform.auto(input, key: key)
        resultText = result.text
        textView.text = result.text

        // Brocolis étant actif, on copie directement le résultat pour réduire
        // les gestes : il n'y a plus qu'à coller EN REMPLAÇANT le texte d'origine.
        UIPasteboard.general.string = result.text
        statusLabel.text = result.label + " — ✅ Copié. Colle en remplaçant ton texte (n'envoie pas le clair)."
    }

    // MARK: Actions

    @objc private func copyResult() {
        guard !resultText.isEmpty else { return }
        UIPasteboard.general.string = resultText
        statusLabel.text = "✅ Copié. Colle en remplaçant ton texte d'origine (n'envoie pas le clair)."
    }

    @objc private func done() {
        extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
    }
}
