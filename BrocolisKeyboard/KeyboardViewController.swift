//
//  KeyboardViewController.swift
//  Brocolis 🥦 — Clavier (extension clavier personnalisé)
//
//  Un clavier « action » : tu tapes ton message avec ton clavier habituel, tu
//  bascules sur Brocolis (🌐) et tu touches « Chiffrer » → le texte du champ est
//  remplacé chiffré DIRECTEMENT, sur place, sans rien copier. « Déchiffrer »
//  fait l'inverse sur un brouillon. Marche dans toutes les apps qui ont un champ
//  de saisie (WhatsApp, iMessage, Notes…).
//
//  ⚠️ Pour lire la clé partagée (App Group), le clavier a besoin de
//  « Autoriser l'accès complet » (Réglages → Général → Clavier → Claviers →
//  Brocolis 🥦). Sans ça, iOS isole le clavier et il ne voit pas tes clés.
//

import UIKit

final class KeyboardViewController: UIInputViewController {

    private let statusLabel = UILabel()
    private let readout = UITextView()
    private var actionButtons: [UIButton] = []

    override func viewDidLoad() {
        super.viewDidLoad()
        setupUI()
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        refreshState()
    }

    override func textDidChange(_ textInput: UITextInput?) {
        refreshState()
    }

    // MARK: UI

    private func setupUI() {
        let bg = UIInputView(frame: .zero, inputViewStyle: .keyboard)
        bg.translatesAutoresizingMaskIntoConstraints = false

        // Zone de lecture : affiche le message reçu EN CLAIR, sur le clavier,
        // sans quitter l'app. Lecture seule, défilable pour les longs messages.
        readout.font = .preferredFont(forTextStyle: .body)
        readout.isEditable = false
        readout.isScrollEnabled = true
        readout.backgroundColor = .systemBackground
        readout.layer.cornerRadius = 10
        readout.textContainerInset = UIEdgeInsets(top: 8, left: 8, bottom: 8, right: 8)
        readout.translatesAutoresizingMaskIntoConstraints = false
        readout.heightAnchor.constraint(greaterThanOrEqualToConstant: 64).isActive = true
        showReadout("", placeholder: true)

        statusLabel.font = .preferredFont(forTextStyle: .footnote)
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 2
        statusLabel.textAlignment = .center
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        let globe = makeButton(title: "🌐", action: #selector(nextKeyboard))
        globe.titleLabel?.font = .systemFont(ofSize: 22)
        let read = makeButton(title: "📋 Lire", action: #selector(readClipboardTapped))
        let encrypt = makeButton(title: "🔒 Chiffrer", action: #selector(encryptTapped))
        let decrypt = makeButton(title: "🔓 Déchiffrer", action: #selector(decryptTapped))
        actionButtons = [read, encrypt, decrypt]

        let row = UIStackView(arrangedSubviews: [globe, read, encrypt, decrypt])
        row.axis = .horizontal
        row.distribution = .fillProportionally
        row.spacing = 8
        row.translatesAutoresizingMaskIntoConstraints = false
        globe.widthAnchor.constraint(equalToConstant: 48).isActive = true

        let stack = UIStackView(arrangedSubviews: [readout, statusLabel, row])
        stack.axis = .vertical
        stack.spacing = 10
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(bg)
        bg.addSubview(stack)

        NSLayoutConstraint.activate([
            bg.topAnchor.constraint(equalTo: view.topAnchor),
            bg.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            bg.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            bg.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            stack.topAnchor.constraint(equalTo: bg.topAnchor, constant: 12),
            stack.leadingAnchor.constraint(equalTo: bg.leadingAnchor, constant: 12),
            stack.trailingAnchor.constraint(equalTo: bg.trailingAnchor, constant: -12),
            stack.bottomAnchor.constraint(equalTo: bg.bottomAnchor, constant: -12),

            view.heightAnchor.constraint(greaterThanOrEqualToConstant: 210),
        ])
    }

    private func makeButton(title: String, action: Selector) -> UIButton {
        let b = UIButton(type: .system)
        b.setTitle(title, for: .normal)
        b.titleLabel?.font = .preferredFont(forTextStyle: .headline)
        b.titleLabel?.adjustsFontSizeToFitWidth = true
        b.titleLabel?.minimumScaleFactor = 0.7
        b.backgroundColor = .secondarySystemBackground
        b.layer.cornerRadius = 10
        b.contentEdgeInsets = UIEdgeInsets(top: 12, left: 10, bottom: 12, right: 10)
        b.addTarget(self, action: action, for: .touchUpInside)
        return b
    }

    // MARK: État

    private func refreshState() {
        guard hasFullAccess else {
            setEnabled(false)
            statusLabel.text = "⚠️ Active « Accès complet » pour ce clavier\n(Réglages → Général → Clavier → Brocolis 🥦)"
            return
        }
        guard BrocolisKeyStore.isActive else {
            setEnabled(false)
            statusLabel.text = "⏸ Brocolis est désactivé — ouvre l’app et active-le."
            return
        }
        guard BrocolisKeyStore.hasKey else {
            setEnabled(false)
            statusLabel.text = "🔑 Aucune clé — ajoute-en une dans l’app Brocolis 🥦."
            return
        }
        setEnabled(true)
        statusLabel.text = "Lire un reçu : copie-le, touche « Lire ». Envoyer : tape, puis « Chiffrer »."
    }

    /// Affiche du texte (ou un mode d'emploi) dans la zone de lecture.
    private func showReadout(_ text: String, placeholder: Bool) {
        if placeholder || text.isEmpty {
            readout.text = "Pour lire un message reçu : appui long dessus → Copier, puis reviens ici et touche « 📋 Lire » — il s’affiche en clair, sans quitter l’app."
            readout.textColor = .secondaryLabel
        } else {
            readout.text = text
            readout.textColor = .label
            readout.setContentOffset(.zero, animated: false)
        }
    }

    private func setEnabled(_ enabled: Bool) {
        for b in actionButtons {
            b.isEnabled = enabled
            b.alpha = enabled ? 1 : 0.4
        }
    }

    // MARK: Lecture / réécriture du champ EN PLACE

    private func currentFieldText() -> String {
        let before = textDocumentProxy.documentContextBeforeInput ?? ""
        let after = textDocumentProxy.documentContextAfterInput ?? ""
        return before + after
    }

    /// Remplace TOUT le contenu du champ (autour du curseur) par `newText`.
    private func replaceFieldText(with newText: String) {
        let before = textDocumentProxy.documentContextBeforeInput ?? ""
        let after = textDocumentProxy.documentContextAfterInput ?? ""
        // Place le curseur à la fin du texte connu.
        textDocumentProxy.adjustTextPosition(byCharacterOffset: after.count)
        // Efface tout ce qui est avant le curseur.
        let total = before.count + after.count
        for _ in 0..<total { textDocumentProxy.deleteBackward() }
        textDocumentProxy.insertText(newText)
    }

    // MARK: Actions

    @objc private func nextKeyboard() {
        advanceToNextInputMode()
    }

    /// Lit le message reçu COPIÉ et l'affiche en clair sur le clavier, sans
    /// changer d'application. (Accès complet requis pour lire le presse-papiers.)
    @objc private func readClipboardTapped() {
        guard guardReady() else { return }
        let clip = UIPasteboard.general.string ?? ""
        guard !clip.isEmpty else {
            statusLabel.text = "Presse-papiers vide — copie d’abord le message reçu (appui long → Copier)."
            showReadout("", placeholder: true)
            return
        }
        let keys = BrocolisKeyStore.allSymmetricKeys()
        guard !keys.isEmpty else {
            statusLabel.text = "🔑 Aucune clé configurée."
            return
        }
        guard BrocolisCrypto.containsToken(clip) else {
            statusLabel.text = "Aucun message chiffré dans le presse-papiers."
            showReadout(clip, placeholder: false)
            return
        }
        let (text, n) = BrocolisCrypto.decryptTokens(clip, keys: keys)
        showReadout(text, placeholder: false)
        statusLabel.text = n > 0
            ? "🔓 \(n) message(s) lu(s) — tu n’as pas quitté l’app."
            : "Message chiffré avec une clé que tu n’as pas."
    }

    @objc private func encryptTapped() {
        guard guardReady() else { return }
        let input = currentFieldText()
        guard !input.isEmpty else {
            statusLabel.text = "Le champ est vide — écris d’abord ton message."
            return
        }
        // Si le champ contient déjà un jeton, on déchiffre plutôt (évite de
        // re-chiffrer du chiffré). Sinon on chiffre.
        if BrocolisCrypto.containsToken(input) {
            decrypt(input)
            return
        }
        let encKeys = BrocolisKeyStore.encryptionKeys()
        guard !encKeys.isEmpty else {
            statusLabel.text = BrocolisKeyStore.hasKey
                ? "⌛️ Clé(s) destinataire(s) expirée(s) — prolonge-les dans l’app."
                : "🔑 Aucune clé — ajoute-en une dans l’app."
            return
        }
        let result = BrocolisTransform.auto(
            input, keys: encKeys, encryptWholeAlways: BrocolisKeyStore.encryptWholeAlways)
        // Garde-fou : on ne remplace le champ QUE si c'est vraiment chiffré.
        guard result.isEncrypted else {
            statusLabel.text = "⚠️ Rien n'a été chiffré — le champ est laissé tel quel."
            return
        }
        replaceFieldText(with: result.text)
        let recipients = encKeys.count > 1 ? " · \(encKeys.count) destinataires" : ""
        statusLabel.text = result.label + recipients + " — prêt à envoyer."
    }

    @objc private func decryptTapped() {
        guard guardReady() else { return }
        let input = currentFieldText()
        guard !input.isEmpty else {
            statusLabel.text = "Le champ est vide."
            return
        }
        decrypt(input)
    }

    private func decrypt(_ input: String) {
        let keys = BrocolisKeyStore.allSymmetricKeys()
        guard !keys.isEmpty else {
            statusLabel.text = "🔑 Aucune clé configurée."
            return
        }
        guard BrocolisCrypto.containsToken(input) else {
            statusLabel.text = "Aucun message chiffré dans le champ."
            return
        }
        let (text, n) = BrocolisCrypto.decryptTokens(input, keys: keys)
        replaceFieldText(with: text)
        statusLabel.text = n > 0
            ? "🔓 \(n) message(s) déchiffré(s)."
            : "Aucun message lisible avec tes clés (clé d’un autre)."
    }

    /// Vérifie l'accès complet + l'état actif avant d'agir.
    private func guardReady() -> Bool {
        guard hasFullAccess else {
            statusLabel.text = "⚠️ Active « Accès complet » pour ce clavier."
            return false
        }
        guard BrocolisKeyStore.isActive else {
            statusLabel.text = "⏸ Brocolis est désactivé — ouvre l’app et active-le."
            return false
        }
        return true
    }
}
