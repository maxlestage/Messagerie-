//
//  KeyboardViewController.swift
//  Brocolis 🥦 — Clavier (extension clavier personnalisé)
//
//  Un vrai clavier AZERTY (lettres, chiffres, accents) avec une barre Brocolis :
//  tu écris ton message, tu touches « Chiffrer » → le texte du champ est
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
        // Les réglages ont pu changer dans l'app depuis la dernière fois.
        applyPrefs()
        refreshState()
    }

    override func textDidChange(_ textInput: UITextInput?) {
        refreshState()
        autoShift()
    }

    // MARK: UI

    /// Les touches du clavier, reconstruites à chaque changement de page
    /// (lettres / chiffres / symboles) ou de majuscule.
    private let keysStack = UIStackView()
    private enum Page { case letters, numbers, symbols }
    private var page: Page = .letters
    private var shifted = true
    private var capsLock = false
    private var deleteTimer: Timer?
    private var lastSpaceAt: Date?
    private var keysHeight: NSLayoutConstraint?
    private var haptic: UIImpactFeedbackGenerator?

    /// Recharge les choix faits dans l'app (vibrations, disposition, taille…).
    private func applyPrefs() {
        let size = BrocolisKeyboardPrefs.keySize.height
        keysHeight?.constant = 4 * size + 3 * 8
        switch BrocolisKeyboardPrefs.haptics {
        case .off: haptic = nil
        case .light: haptic = UIImpactFeedbackGenerator(style: .light)
        case .medium: haptic = UIImpactFeedbackGenerator(style: .medium)
        case .strong: haptic = UIImpactFeedbackGenerator(style: .heavy)
        }
        haptic?.prepare()
        if !BrocolisKeyboardPrefs.autoCapitalize, !capsLock { shifted = false }
        buildKeys()
        autoShift()
    }

    /// Retour d'une touche : vibration et clic, selon les réglages. (iOS ne
    /// laisse vibrer un clavier que s'il a l'accès complet.)
    private func feedback() {
        haptic?.impactOccurred()
        haptic?.prepare()
        if BrocolisKeyboardPrefs.sound { UIDevice.current.playInputClick() }
    }

    private func setupUI() {
        let bg = KeyboardBackground(frame: .zero, inputViewStyle: .keyboard)
        bg.translatesAutoresizingMaskIntoConstraints = false

        // Zone de lecture : affiche le message reçu EN CLAIR, sur le clavier,
        // sans quitter l'app. Cachée tant qu'il n'y a rien à lire, pour laisser
        // la place aux touches.
        readout.font = .preferredFont(forTextStyle: .body)
        readout.isEditable = false
        readout.isScrollEnabled = true
        readout.backgroundColor = .systemBackground
        readout.layer.cornerRadius = 10
        readout.textContainerInset = UIEdgeInsets(top: 6, left: 8, bottom: 6, right: 8)
        readout.translatesAutoresizingMaskIntoConstraints = false
        readout.heightAnchor.constraint(equalToConstant: 72).isActive = true
        showReadout("", placeholder: true)

        statusLabel.font = .preferredFont(forTextStyle: .caption1)
        statusLabel.textColor = .secondaryLabel
        statusLabel.numberOfLines = 2
        statusLabel.textAlignment = .center
        statusLabel.translatesAutoresizingMaskIntoConstraints = false

        let read = makeButton(title: loc("📋 Lire", "📋 Read", "📋 Leer"), action: #selector(readClipboardTapped))
        let encrypt = makeButton(title: loc("🔒 Chiffrer", "🔒 Encrypt", "🔒 Cifrar"), action: #selector(encryptTapped))
        let decrypt = makeButton(title: loc("🔓 Déchiffrer", "🔓 Decrypt", "🔓 Descifrar"), action: #selector(decryptTapped))
        actionButtons = [read, encrypt, decrypt]

        let row = UIStackView(arrangedSubviews: [read, encrypt, decrypt])
        row.axis = .horizontal
        row.distribution = .fillEqually
        row.spacing = 6
        row.translatesAutoresizingMaskIntoConstraints = false

        keysStack.axis = .vertical
        keysStack.spacing = 8
        keysStack.distribution = .fillEqually
        keysStack.translatesAutoresizingMaskIntoConstraints = false
        keysHeight = keysStack.heightAnchor.constraint(equalToConstant: 4 * BrocolisKeyboardPrefs.keySize.height + 3 * 8)
        keysHeight?.isActive = true
        buildKeys()

        let stack = UIStackView(arrangedSubviews: [readout, row, statusLabel, keysStack])
        stack.axis = .vertical
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false

        view.addSubview(bg)
        bg.addSubview(stack)

        NSLayoutConstraint.activate([
            bg.topAnchor.constraint(equalTo: view.topAnchor),
            bg.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            bg.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            bg.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            stack.topAnchor.constraint(equalTo: bg.topAnchor, constant: 6),
            stack.leadingAnchor.constraint(equalTo: bg.leadingAnchor, constant: 4),
            stack.trailingAnchor.constraint(equalTo: bg.trailingAnchor, constant: -4),
            stack.bottomAnchor.constraint(equalTo: bg.bottomAnchor, constant: -4),
        ])
    }

    private func makeButton(title: String, action: Selector) -> UIButton {
        let b = UIButton(type: .system)
        b.setTitle(title, for: .normal)
        b.titleLabel?.font = .preferredFont(forTextStyle: .subheadline)
        b.titleLabel?.adjustsFontSizeToFitWidth = true
        b.titleLabel?.minimumScaleFactor = 0.6
        b.backgroundColor = .secondarySystemBackground
        b.layer.cornerRadius = 8
        b.contentEdgeInsets = UIEdgeInsets(top: 8, left: 6, bottom: 8, right: 6)
        b.addTarget(self, action: action, for: .touchUpInside)
        return b
    }

    // MARK: Touches (AZERTY)

    private var rows: [[String]] {
        let accents = BrocolisKeyboardPrefs.accentKeys
        func bottom(_ left: String, _ a: String, _ b: String) -> [String] {
            accents ? [left, "🌐", a, "espace", b, "⏎"] : [left, "🌐", "espace", "⏎"]
        }
        switch page {
        case .letters:
            switch BrocolisKeyboardPrefs.layout {
            case .azerty:
                return [
                    ["a", "z", "e", "r", "t", "y", "u", "i", "o", "p"],
                    ["q", "s", "d", "f", "g", "h", "j", "k", "l", "m"],
                    ["⇧", "w", "x", "c", "v", "b", "n", "'", "⌫"],
                    bottom("123", "é", "è"),
                ]
            case .qwerty:
                return [
                    ["q", "w", "e", "r", "t", "y", "u", "i", "o", "p"],
                    ["a", "s", "d", "f", "g", "h", "j", "k", "l", "'"],
                    ["⇧", "z", "x", "c", "v", "b", "n", "m", "⌫"],
                    bottom("123", "é", "è"),
                ]
            case .qwertz:
                return [
                    ["q", "w", "e", "r", "t", "z", "u", "i", "o", "p"],
                    ["a", "s", "d", "f", "g", "h", "j", "k", "l", "'"],
                    ["⇧", "y", "x", "c", "v", "b", "n", "m", "⌫"],
                    bottom("123", "é", "è"),
                ]
            }
        case .numbers:
            return [
                ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
                ["-", "/", ":", ";", "(", ")", "€", "&", "@", "\""],
                ["#+=", ".", ",", "?", "!", "à", "ç", "ù", "⌫"],
                bottom("ABC", "ê", "â"),
            ]
        case .symbols:
            return [
                ["[", "]", "{", "}", "#", "%", "^", "*", "+", "="],
                ["_", "\\", "|", "~", "<", ">", "$", "£", "·", "«"],
                ["123", "»", "…", "ô", "î", "ï", "ë", "œ", "⌫"],
                bottom("ABC", "û", "ü"),
            ]
        }
    }

    private func buildKeys() {
        keysStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        for keys in rows {
            let line = UIStackView()
            line.axis = .horizontal
            line.spacing = 5
            line.distribution = .fill
            for key in keys {
                if key == "🌐" && !needsInputModeSwitchKey { continue }
                let b = keyButton(key)
                line.addArrangedSubview(b)
                // Une touche = 1/10e de la rangée (1,4 pour les touches de
                // fonction) ; espace prend le reste.
                if key == "espace" { continue }
                let wide = ["⇧", "⌫", "123", "ABC", "#+=", "⏎"].contains(key)
                let w = b.widthAnchor.constraint(equalTo: line.widthAnchor, multiplier: wide ? 0.14 : 0.1, constant: -4.5)
                w.priority = .defaultHigh
                w.isActive = true
            }
            keysStack.addArrangedSubview(line)
        }
    }

    private func label(for key: String) -> String {
        switch key {
        case "espace": return loc("espace", "space", "espacio")
        case "⇧": return capsLock ? "⇪" : "⇧"
        default:
            return page == .letters && shifted && key.count == 1 ? key.uppercased() : key
        }
    }

    private func keyButton(_ key: String) -> UIButton {
        let b = UIButton(type: .system)
        b.setTitle(label(for: key), for: .normal)
        b.accessibilityIdentifier = key
        let special = ["⇧", "⌫", "123", "ABC", "#+=", "🌐", "⏎"].contains(key)
        b.titleLabel?.font = special || key == "espace"
            ? .systemFont(ofSize: 16, weight: .medium)
            : .systemFont(ofSize: 22)
        b.setTitleColor(.label, for: .normal)
        b.tintColor = .label
        let highlighted = key == "⇧" && shifted && page == .letters
        b.backgroundColor = highlighted ? .systemGreen.withAlphaComponent(0.35)
            : special ? .tertiarySystemFill : .systemBackground
        b.layer.cornerRadius = 6
        b.layer.shadowColor = UIColor.black.cgColor
        b.layer.shadowOpacity = 0.25
        b.layer.shadowOffset = CGSize(width: 0, height: 1)
        b.layer.shadowRadius = 0
        if key == "🌐" {
            b.addTarget(self, action: #selector(handleInputModeList(from:with:)), for: .allTouchEvents)
        } else if key == "⌫" {
            b.addTarget(self, action: #selector(deleteDown), for: .touchDown)
            b.addTarget(self, action: #selector(deleteUp), for: [.touchUpInside, .touchUpOutside, .touchCancel])
        } else if key == "⇧" {
            b.addTarget(self, action: #selector(shiftTapped(_:event:)), for: .touchUpInside)
        } else {
            b.addTarget(self, action: #selector(keyTapped(_:)), for: .touchUpInside)
        }
        return b
    }

    @objc private func keyTapped(_ sender: UIButton) {
        guard let key = sender.accessibilityIdentifier else { return }
        feedback()
        switch key {
        case "123": page = .numbers; buildKeys()
        case "#+=": page = .symbols; buildKeys()
        case "ABC": page = .letters; buildKeys()
        case "⏎": textDocumentProxy.insertText("\n")
        case "espace":
            // Double espace → « . », comme le clavier d'Apple.
            let before = textDocumentProxy.documentContextBeforeInput ?? ""
            if BrocolisKeyboardPrefs.doubleSpacePeriod,
               let last = lastSpaceAt, Date().timeIntervalSince(last) < 0.4,
               before.hasSuffix(" "), before.dropLast().last?.isLetter == true || before.dropLast().last?.isNumber == true {
                textDocumentProxy.deleteBackward()
                textDocumentProxy.insertText(". ")
                lastSpaceAt = nil
            } else {
                textDocumentProxy.insertText(" ")
                lastSpaceAt = Date()
            }
            autoShift()
        default:
            textDocumentProxy.insertText(label(for: key))
            if page == .letters, shifted, !capsLock {
                shifted = false
                buildKeys()
            }
        }
    }

    @objc private func shiftTapped(_ sender: UIButton, event: UIEvent) {
        feedback()
        if let touch = event.allTouches?.first, touch.tapCount == 2 {
            capsLock = true
            shifted = true
        } else if capsLock {
            capsLock = false
            shifted = false
        } else {
            shifted.toggle()
        }
        buildKeys()
    }

    @objc private func deleteDown() {
        textDocumentProxy.deleteBackward()
        feedback()
        deleteTimer?.invalidate()
        // Maintenu : efface en continu après un court délai.
        deleteTimer = Timer.scheduledTimer(withTimeInterval: 0.45, repeats: false) { [weak self] _ in
            self?.deleteTimer = Timer.scheduledTimer(withTimeInterval: 0.08, repeats: true) { _ in
                self?.textDocumentProxy.deleteBackward()
            }
        }
    }

    @objc private func deleteUp() {
        deleteTimer?.invalidate()
        deleteTimer = nil
        autoShift()
    }

    /// Majuscule automatique en début de champ et après . ! ?
    private func autoShift() {
        guard page == .letters, !capsLock, BrocolisKeyboardPrefs.autoCapitalize else { return }
        let before = textDocumentProxy.documentContextBeforeInput ?? ""
        let trimmed = before.trimmingCharacters(in: .whitespaces)
        let want = before.isEmpty || before.hasSuffix("\n")
            || (before.hasSuffix(" ") && [".", "!", "?"].contains(trimmed.last.map(String.init) ?? ""))
        if want != shifted {
            shifted = want
            buildKeys()
        }
    }

    // MARK: État

    private func refreshState() {
        guard hasFullAccess else {
            setEnabled(false)
            statusLabel.text = loc("Pour chiffrer : Réglages → Général → Clavier → Claviers → Brocolis 🥦 → « Accès complet »", "To encrypt: Settings → General → Keyboard → Keyboards → Brocolis 🥦 → « Full Access »", "Para cifrar: Ajustes → General → Teclado → Teclados → Brocolis 🥦 → « Acceso completo »")
            return
        }
        guard BrocolisKeyStore.isActive else {
            setEnabled(false)
            statusLabel.text = loc("⏸ Brocolis est désactivé — ouvre l’app et active-le.", "⏸ Brocolis is disabled — open the app and enable it.", "⏸ Brocolis está desactivado — abre la app y actívalo.")
            return
        }
        guard BrocolisKeyStore.hasKey else {
            setEnabled(false)
            statusLabel.text = loc("🔑 Aucune clé — ajoute-en une dans l’app Brocolis 🥦.", "🔑 No key — add one in the Brocolis 🥦 app.", "🔑 Ninguna clave — añade una en la app Brocolis 🥦.")
            return
        }
        setEnabled(true)
        statusLabel.text = loc("Écris ton message puis « Chiffrer ». Reçu : copie-le, puis « Lire ».", "Type your message, then « Encrypt ». Got one: copy it, then « Read ».", "Escribe tu mensaje y luego « Cifrar ». Recibido: cópialo y luego « Leer ».")
    }

    /// Affiche du texte (ou un mode d'emploi) dans la zone de lecture.
    private func showReadout(_ text: String, placeholder: Bool) {
        if placeholder || text.isEmpty {
            readout.text = loc("Pour lire un message reçu : appui long dessus → Copier, puis reviens ici et touche « 📋 Lire » — il s’affiche en clair, sans quitter l’app.", "To read a message you got: long-press it → Copy, then come back here and tap « 📋 Read » — it shows in clear text, without leaving the app.", "Para leer un mensaje recibido: mantén pulsado → Copiar, luego vuelve aquí y toca « 📋 Leer » — se muestra en claro, sin salir de la app.")
            readout.textColor = .secondaryLabel
            readout.isHidden = true
        } else {
            readout.isHidden = false
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
            statusLabel.text = loc("Presse-papiers vide — copie d’abord le message reçu (appui long → Copier).", "Clipboard empty — first copy the message you got (long-press → Copy).", "Portapapeles vacío — copia primero el mensaje recibido (mantén pulsado → Copiar).")
            showReadout("", placeholder: true)
            return
        }
        let keys = BrocolisKeyStore.allSymmetricKeys()
        guard !keys.isEmpty else {
            statusLabel.text = loc("🔑 Aucune clé configurée.", "🔑 No key configured.", "🔑 Ninguna clave configurada.")
            return
        }
        guard BrocolisCrypto.containsToken(clip) else {
            statusLabel.text = loc("Aucun message chiffré dans le presse-papiers.", "No encrypted message in the clipboard.", "Ningún mensaje cifrado en el portapapeles.")
            showReadout(clip, placeholder: false)
            return
        }
        let (text, n) = BrocolisCrypto.decryptTokens(clip, keys: keys)
        showReadout(text, placeholder: false)
        statusLabel.text = n > 0
            ? loc("🔓 \(n) message(s) lu(s) — tu n’as pas quitté l’app.", "🔓 \(n) message(s) read — you didn’t leave the app.", "🔓 \(n) mensaje(s) leído(s) — no saliste de la app.")
            : loc("Message chiffré avec une clé que tu n’as pas.", "Message encrypted with a key you don’t have.", "Mensaje cifrado con una clave que no tienes.")
    }

    @objc private func encryptTapped() {
        guard guardReady() else { return }
        let input = currentFieldText()
        guard !input.isEmpty else {
            statusLabel.text = loc("Le champ est vide — écris d’abord ton message.", "The field is empty — type your message first.", "El campo está vacío — escribe primero tu mensaje.")
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
                ? loc("⌛️ Clé(s) destinataire(s) expirée(s) — prolonge-les dans l’app.", "⌛️ Recipient key(s) expired — extend them in the app.", "⌛️ Clave(s) de destinatario expirada(s) — renuévalas en la app.")
                : loc("🔑 Aucune clé — ajoute-en une dans l’app.", "🔑 No key — add one in the app.", "🔑 Ninguna clave — añade una en la app.")
            return
        }
        let result = BrocolisTransform.auto(
            input, keys: encKeys, encryptWholeAlways: BrocolisKeyStore.encryptWholeAlways)
        // Garde-fou : on ne remplace le champ QUE si c'est vraiment chiffré.
        guard result.isEncrypted else {
            statusLabel.text = loc("⚠️ Rien n'a été chiffré — le champ est laissé tel quel.", "⚠️ Nothing was encrypted — the field is left as is.", "⚠️ No se cifró nada — el campo se deja tal cual.")
            return
        }
        replaceFieldText(with: result.text)
        let recipients = encKeys.count > 1 ? loc(" · \(encKeys.count) destinataires", " · \(encKeys.count) recipients", " · \(encKeys.count) destinatarios") : ""
        statusLabel.text = result.label + recipients + loc(" — prêt à envoyer.", " — ready to send.", " — listo para enviar.")
    }

    @objc private func decryptTapped() {
        guard guardReady() else { return }
        let input = currentFieldText()
        guard !input.isEmpty else {
            statusLabel.text = loc("Le champ est vide.", "The field is empty.", "El campo está vacío.")
            return
        }
        decrypt(input)
    }

    private func decrypt(_ input: String) {
        let keys = BrocolisKeyStore.allSymmetricKeys()
        guard !keys.isEmpty else {
            statusLabel.text = loc("🔑 Aucune clé configurée.", "🔑 No key configured.", "🔑 Ninguna clave configurada.")
            return
        }
        guard BrocolisCrypto.containsToken(input) else {
            statusLabel.text = loc("Aucun message chiffré dans le champ.", "No encrypted message in the field.", "Ningún mensaje cifrado en el campo.")
            return
        }
        let (text, n) = BrocolisCrypto.decryptTokens(input, keys: keys)
        replaceFieldText(with: text)
        statusLabel.text = n > 0
            ? loc("🔓 \(n) message(s) déchiffré(s).", "🔓 \(n) message(s) decrypted.", "🔓 \(n) mensaje(s) descifrado(s).")
            : loc("Aucun message lisible avec tes clés (clé d’un autre).", "No message readable with your keys (someone else’s key).", "Ningún mensaje legible con tus claves (clave de otra persona).")
    }

    /// Vérifie l'accès complet + l'état actif avant d'agir.
    private func guardReady() -> Bool {
        guard hasFullAccess else {
            statusLabel.text = loc("⚠️ Active « Accès complet » pour ce clavier.", "⚠️ Enable « Full Access » for this keyboard.", "⚠️ Activa « Acceso completo » para este teclado.")
            return false
        }
        guard BrocolisKeyStore.isActive else {
            statusLabel.text = loc("⏸ Brocolis est désactivé — ouvre l’app et active-le.", "⏸ Brocolis is disabled — open the app and enable it.", "⏸ Brocolis está desactivado — abre la app y actívalo.")
            return false
        }
        return true
    }
}

/// Fond du clavier : déclare le clic sonore d'iOS (« Clics du clavier »).
final class KeyboardBackground: UIInputView, UIInputViewAudioFeedback {
    var enableInputClicksWhenVisible: Bool { true }
}
