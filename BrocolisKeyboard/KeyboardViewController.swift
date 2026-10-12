//
//  KeyboardViewController.swift
//  Brocolis 🥦 — Clavier (extension clavier personnalisé)
//
//  Un vrai clavier (AZERTY, QWERTY ou QWERTZ ; chiffres, symboles, emojis,
//  accents par appui long, curseur en glissant sur l'espace, menu ⚙️ de
//  réglages rapides) avec une barre Brocolis :
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
    /// (lettres / chiffres / symboles / emojis / menu ⚙️) ou de majuscule.
    private let keysStack = UIStackView()
    /// Accents proposés par un appui long sur une lettre (cachée sinon).
    private let accentBar = UIStackView()
    private var background: KeyboardBackground?
    private enum Page { case letters, numbers, symbols, emoji, menu }
    private var page: Page = .letters
    private var shifted = true
    private var capsLock = false
    private var deleteTimer: Timer?
    private var lastSpaceAt: Date?
    private var keysHeight: NSLayoutConstraint?
    private var haptic: UIImpactFeedbackGenerator?
    private var cursorPanCarry: CGFloat = 0

    /// Recharge les choix faits dans l'app ou dans le menu ⚙️.
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
        switch BrocolisKeyboardPrefs.theme {
        case .light: view.overrideUserInterfaceStyle = .light
        case .dark: view.overrideUserInterfaceStyle = .dark
        default: view.overrideUserInterfaceStyle = .unspecified
        }
        background?.backgroundColor = BrocolisKeyboardPrefs.theme == .brocoli
            ? UIColor { $0.userInterfaceStyle == .dark
                ? UIColor(red: 0.10, green: 0.20, blue: 0.12, alpha: 1)
                : UIColor(red: 0.85, green: 0.94, blue: 0.80, alpha: 1) }
            : nil
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
        background = bg

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
        let menu = makeButton(title: "⚙️", action: #selector(menuTapped))
        menu.widthAnchor.constraint(equalToConstant: 44).isActive = true

        let actions = UIStackView(arrangedSubviews: [read, encrypt, decrypt])
        actions.axis = .horizontal
        actions.distribution = .fillEqually
        actions.spacing = 6
        let row = UIStackView(arrangedSubviews: [actions, menu])
        row.axis = .horizontal
        row.spacing = 6
        row.translatesAutoresizingMaskIntoConstraints = false

        accentBar.axis = .horizontal
        accentBar.spacing = 6
        accentBar.distribution = .fillEqually
        accentBar.isHidden = true
        let accentHeight = accentBar.heightAnchor.constraint(equalToConstant: 40)
        accentHeight.priority = .defaultHigh
        accentHeight.isActive = true

        keysStack.axis = .vertical
        keysStack.spacing = 8
        keysStack.distribution = .fillEqually
        keysStack.translatesAutoresizingMaskIntoConstraints = false
        keysHeight = keysStack.heightAnchor.constraint(equalToConstant: 4 * BrocolisKeyboardPrefs.keySize.height + 3 * 8)
        keysHeight?.isActive = true
        buildKeys()

        let stack = UIStackView(arrangedSubviews: [readout, row, statusLabel, accentBar, keysStack])
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

    // MARK: Touches

    private static let emojis: [[String]] = [
        ["😀", "😂", "😍", "🥰", "😘", "😉", "😎", "🤔"],
        ["👍", "🙏", "👏", "🔥", "❤️", "💚", "🎉", "✨"],
        ["🥦", "🔒", "🔑", "😢", "😡", "😴", "🤫", "👋"],
    ]

    private static let accents: [String: [String]] = [
        "a": ["à", "â", "ä", "æ", "á"],
        "e": ["é", "è", "ê", "ë", "€"],
        "i": ["î", "ï", "í", "ì"],
        "o": ["ô", "ö", "œ", "ó", "ò"],
        "u": ["ù", "û", "ü", "ú"],
        "c": ["ç", "ć", "č"],
        "y": ["ÿ", "ý"],
        "n": ["ñ", "ń"],
        "s": ["ß", "ś", "š"],
        "'": ["’", "«", "»", "\""],
    ]

    private var rows: [[String]] {
        let accents = BrocolisKeyboardPrefs.accentKeys
        let emoji = BrocolisKeyboardPrefs.emojiKey
        func bottom(_ left: String, _ a: String, _ b: String) -> [String] {
            var r = [left, "🌐"]
            if emoji { r.append("😀") }
            if accents { r.append(a) }
            r.append("espace")
            if accents { r.append(b) }
            r.append("⏎")
            return r
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
        case .emoji:
            return Self.emojis + [["ABC", "🌐", "espace", "⌫"]]
        case .menu:
            return []
        }
    }

    private static let wideKeys: Set<String> = ["⇧", "⌫", "123", "ABC", "#+=", "⏎"]
    private static let specialKeys: Set<String> = ["⇧", "⌫", "123", "ABC", "#+=", "🌐", "⏎", "😀"]

    private func buildKeys() {
        keysStack.arrangedSubviews.forEach { $0.removeFromSuperview() }
        if page == .menu {
            buildMenu()
            return
        }
        for keys in rows {
            let line = UIStackView()
            line.axis = .horizontal
            line.spacing = 5
            let shown = keys.filter { $0 != "🌐" || needsInputModeSwitchKey }
            // Une rangée sans touche de largeur variable (emojis) : parts égales.
            let uniform = !shown.contains("espace") && !shown.contains { Self.wideKeys.contains($0) }
            line.distribution = uniform ? .fillEqually : .fill
            for key in shown {
                let b = keyButton(key)
                line.addArrangedSubview(b)
                // Une touche = 1/10e de la rangée (1,4 pour les touches de
                // fonction) ; espace prend le reste.
                if uniform || key == "espace" { continue }
                let w = b.widthAnchor.constraint(equalTo: line.widthAnchor,
                                                 multiplier: Self.wideKeys.contains(key) ? 0.14 : 0.1,
                                                 constant: -4.5)
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

    /// Couleurs du clavier d'Apple : touches blanches (grises en sombre),
    /// touches de fonction gris-bleu.
    private static let appleKey = UIColor { $0.userInterfaceStyle == .dark
        ? UIColor(white: 0.42, alpha: 1) : .white }
    private static let appleSpecial = UIColor { $0.userInterfaceStyle == .dark
        ? UIColor(white: 0.27, alpha: 1) : UIColor(red: 0.67, green: 0.70, blue: 0.74, alpha: 1) }
    private static let brocoliKey = UIColor { $0.userInterfaceStyle == .dark
        ? UIColor(red: 0.16, green: 0.30, blue: 0.18, alpha: 1) : UIColor(red: 0.97, green: 1.0, blue: 0.95, alpha: 1) }
    private static let brocoliSpecial = UIColor { $0.userInterfaceStyle == .dark
        ? UIColor(red: 0.10, green: 0.42, blue: 0.20, alpha: 1) : UIColor(red: 0.62, green: 0.82, blue: 0.60, alpha: 1) }

    private var keyColor: UIColor {
        BrocolisKeyboardPrefs.theme == .brocoli ? Self.brocoliKey : Self.appleKey
    }

    private func style(_ b: UIButton, special: Bool, highlighted: Bool = false) {
        let brocoli = BrocolisKeyboardPrefs.theme == .brocoli
        b.setTitleColor(.label, for: .normal)
        b.tintColor = .label
        if highlighted {
            b.backgroundColor = keyColor
        } else if special {
            b.backgroundColor = brocoli ? Self.brocoliSpecial : Self.appleSpecial
        } else {
            b.backgroundColor = keyColor
        }
        b.layer.cornerRadius = 5
        b.layer.shadowColor = UIColor.black.cgColor
        b.layer.shadowOpacity = 0.3
        b.layer.shadowOffset = CGSize(width: 0, height: 1)
        b.layer.shadowRadius = 0
    }

    /// Symboles d'Apple pour les touches de fonction.
    private func symbol(for key: String) -> String? {
        switch key {
        case "⇧": return capsLock ? "capslock.fill" : (shifted && page == .letters ? "shift.fill" : "shift")
        case "⌫": return "delete.left"
        case "🌐": return "globe"
        default: return nil
        }
    }

    private func keyButton(_ key: String) -> UIButton {
        let b = UIButton(type: .custom)
        b.accessibilityIdentifier = key
        let special = Self.specialKeys.contains(key)
        if let name = symbol(for: key) {
            b.setImage(UIImage(systemName: name, withConfiguration: UIImage.SymbolConfiguration(pointSize: 18, weight: .regular)), for: .normal)
        } else {
            b.setTitle(key == "⏎" ? loc("retour", "return", "intro") : label(for: key), for: .normal)
        }
        b.titleLabel?.font = special || key == "espace"
            ? .systemFont(ofSize: 16, weight: .regular)
            : .systemFont(ofSize: page == .emoji ? 26 : 23, weight: .regular)
        style(b, special: special, highlighted: key == "⇧" && (shifted || capsLock) && page == .letters)
        // Aperçu (« miniature ») de la touche au-dessus du doigt, comme chez Apple.
        if !special, key != "espace" {
            b.addTarget(self, action: #selector(showPreview(_:)), for: [.touchDown, .touchDragEnter])
            b.addTarget(self, action: #selector(hidePreview), for: [.touchUpInside, .touchUpOutside, .touchDragExit, .touchCancel])
        } else {
            // Touches de fonction : elles s'assombrissent sous le doigt.
            b.addTarget(self, action: #selector(pressDown(_:)), for: [.touchDown, .touchDragEnter])
            b.addTarget(self, action: #selector(pressUp(_:)), for: [.touchUpInside, .touchUpOutside, .touchDragExit, .touchCancel])
        }
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
        if key == "espace", BrocolisKeyboardPrefs.spaceCursor {
            b.addGestureRecognizer(UIPanGestureRecognizer(target: self, action: #selector(spacePanned(_:))))
        }
        if page == .letters || page == .numbers, BrocolisKeyboardPrefs.longPressAccents,
           Self.accents[key.lowercased()] != nil {
            let press = UILongPressGestureRecognizer(target: self, action: #selector(keyLongPressed(_:)))
            press.minimumPressDuration = 0.35
            b.addGestureRecognizer(press)
        }
        return b
    }

    @objc private func keyTapped(_ sender: UIButton) {
        guard let key = sender.accessibilityIdentifier else { return }
        feedback()
        hideAccents()
        switch key {
        case "123": page = .numbers; buildKeys()
        case "#+=": page = .symbols; buildKeys()
        case "ABC": page = .letters; buildKeys()
        case "😀": page = .emoji; buildKeys()
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
            insert(label(for: key))
        }
    }

    private func insert(_ text: String) {
        textDocumentProxy.insertText(text)
        if page == .letters, shifted, !capsLock {
            shifted = false
            buildKeys()
        }
    }

    // MARK: Aperçu des touches

    private let preview = KeyPreview()

    @objc private func showPreview(_ sender: UIButton) {
        guard let host = background, let text = sender.title(for: .normal) else { return }
        if preview.superview == nil {
            host.addSubview(preview)
        }
        preview.show(text: text, keyFrame: sender.convert(sender.bounds, to: host),
                     in: host.bounds, color: keyColor, emoji: page == .emoji)
    }

    @objc private func hidePreview() {
        preview.isHidden = true
    }

    @objc private func pressDown(_ sender: UIButton) {
        sender.alpha = 0.55
    }

    @objc private func pressUp(_ sender: UIButton) {
        UIView.animate(withDuration: 0.12) { sender.alpha = 1 }
    }

    // MARK: Appui long → accents

    @objc private func keyLongPressed(_ g: UILongPressGestureRecognizer) {
        guard g.state == .began, let b = g.view as? UIButton,
              let key = b.accessibilityIdentifier,
              let options = Self.accents[key.lowercased()] else { return }
        hidePreview()
        feedback()
        let upper = page == .letters && shifted
        accentBar.arrangedSubviews.forEach { $0.removeFromSuperview() }
        for option in [key] + options {
            let text = upper ? option.uppercased() : option
            let o = UIButton(type: .system)
            o.setTitle(text, for: .normal)
            o.accessibilityIdentifier = text
            o.titleLabel?.font = .systemFont(ofSize: 22)
            style(o, special: false, highlighted: option != key && option == options.first)
            o.addTarget(self, action: #selector(accentTapped(_:)), for: .touchUpInside)
            accentBar.addArrangedSubview(o)
        }
        statusLabel.isHidden = true
        accentBar.isHidden = false
    }

    @objc private func accentTapped(_ sender: UIButton) {
        guard let text = sender.accessibilityIdentifier else { return }
        feedback()
        hideAccents()
        insert(text)
    }

    private func hideAccents() {
        guard !accentBar.isHidden else { return }
        accentBar.isHidden = true
        statusLabel.isHidden = false
    }

    // MARK: Glisser sur l'espace → curseur

    @objc private func spacePanned(_ g: UIPanGestureRecognizer) {
        let step: CGFloat = 12
        switch g.state {
        case .began:
            cursorPanCarry = 0
        case .changed:
            cursorPanCarry += g.translation(in: g.view).x
            g.setTranslation(.zero, in: g.view)
            while abs(cursorPanCarry) >= step {
                let dir = cursorPanCarry > 0 ? 1 : -1
                textDocumentProxy.adjustTextPosition(byCharacterOffset: dir)
                cursorPanCarry -= CGFloat(dir) * step
                haptic?.impactOccurred(intensity: 0.4)
            }
        default:
            cursorPanCarry = 0
            autoShift()
        }
    }

    // MARK: Menu ⚙️ (réglages sans quitter le clavier)

    @objc private func menuTapped() {
        feedback()
        hideAccents()
        page = page == .menu ? .letters : .menu
        buildKeys()
    }

    private func onOff(_ v: Bool) -> String { v ? loc("oui", "on", "sí") : loc("non", "off", "no") }

    private func buildMenu() {
        let p = BrocolisKeyboardPrefs.self
        let items: [[(String, String)]] = [
            [("haptics", "📳 " + loc("Vibrations", "Haptics", "Vibración") + " : " + p.haptics.title),
             ("sound", "🔊 " + loc("Son", "Sound", "Sonido") + " : " + onOff(p.sound))],
            [("layout", "⌨️ " + p.layout.title),
             ("size", "🔠 " + p.keySize.title)],
            [("theme", "🎨 " + p.theme.title),
             ("emoji", "😀 " + loc("Emojis", "Emoji", "Emojis") + " : " + onOff(p.emojiKey))],
            [("cursor", "↔︎ " + loc("Curseur", "Cursor", "Cursor") + " : " + onOff(p.spaceCursor)),
             ("done", "✓ " + loc("Terminé", "Done", "Listo"))],
            [("recipient", "🔑 " + loc("Chiffrer pour", "Encrypt for", "Cifrar para") + " : " + recipientName)],
        ]
        for pair in items {
            let line = UIStackView()
            line.axis = .horizontal
            line.spacing = 6
            line.distribution = .fillEqually
            for (id, title) in pair {
                let b = UIButton(type: .system)
                b.setTitle(title, for: .normal)
                b.accessibilityIdentifier = id
                b.titleLabel?.font = .systemFont(ofSize: 15, weight: .medium)
                b.titleLabel?.adjustsFontSizeToFitWidth = true
                b.titleLabel?.minimumScaleFactor = 0.6
                style(b, special: id == "done")
                b.addTarget(self, action: #selector(menuItemTapped(_:)), for: .touchUpInside)
                line.addArrangedSubview(b)
            }
            keysStack.addArrangedSubview(line)
        }
        statusLabel.text = loc("Touche un réglage pour le changer. Tout le reste : app Brocolis → Clavier.", "Tap a setting to change it. Everything else: Brocolis app → Keyboard.", "Toca un ajuste para cambiarlo. Lo demás: app Brocolis → Teclado.")
    }

    @objc private func menuItemTapped(_ sender: UIButton) {
        typealias P = BrocolisKeyboardPrefs
        switch sender.accessibilityIdentifier {
        case "haptics": P.haptics = P.cycle(P.haptics)
        case "sound": P.sound.toggle()
        case "layout": P.layout = P.cycle(P.layout)
        case "size": P.keySize = P.cycle(P.keySize)
        case "theme": P.theme = P.cycle(P.theme)
        case "emoji": P.emojiKey.toggle()
        case "cursor": P.spaceCursor.toggle()
        case "recipient": nextRecipient()
        default:
            page = .letters
            refreshState()
        }
        applyPrefs()
        feedback()
    }

    /// Pour qui « Chiffrer » chiffre : la clé choisie, ou plusieurs
    /// destinataires réglés dans l'app.
    private var recipientName: String {
        guard hasFullAccess else { return loc("accès complet requis", "full access needed", "acceso completo necesario") }
        let named = BrocolisKeyStore.encryptionNamedKeys()
        switch named.count {
        case 0: return loc("aucune clé", "no key", "ninguna clave")
        case 1: return named[0].name
        default: return loc("\(named.count) personnes", "\(named.count) people", "\(named.count) personas")
        }
    }

    /// Passe à la clé suivante (un seul destinataire), sans ouvrir l'app.
    private func nextRecipient() {
        guard hasFullAccess else { return }
        let keys = BrocolisKeyStore.keys
        guard !keys.isEmpty else { return }
        let current = BrocolisKeyStore.recipientKeyIds.count > 1 ? nil : BrocolisKeyStore.selectedKey?.id
        let i = keys.firstIndex { $0.id == current }.map { ($0 + 1) % keys.count } ?? 0
        BrocolisKeyStore.selectKey(keys[i].id)
        BrocolisKeyStore.setRecipientKeyIds([])
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
        hideAccents()
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
        // Le menu ⚙️ garde sa ligne d'aide.
        guard page != .menu else { return }
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
        statusLabel.text = loc("🔑 Pour \(recipientName) (⚙️ pour changer). Reçu : copie-le, puis « Lire ».", "🔑 For \(recipientName) (⚙️ to change). Got one: copy it, then « Read ».", "🔑 Para \(recipientName) (⚙️ para cambiar). Recibido: cópialo y luego « Leer ».")
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

/// La bulle d'aperçu d'Apple : la touche s'élargit vers le haut et montre la
/// lettre en grand, au-dessus du doigt.
final class KeyPreview: UIView {
    private let shape = CAShapeLayer()
    private let label = UILabel()

    override init(frame: CGRect) {
        super.init(frame: frame)
        isUserInteractionEnabled = false
        isHidden = true
        layer.addSublayer(shape)
        shape.shadowColor = UIColor.black.cgColor
        shape.shadowOpacity = 0.3
        shape.shadowRadius = 2
        shape.shadowOffset = CGSize(width: 0, height: 1)
        label.textAlignment = .center
        label.textColor = .label
        addSubview(label)
    }

    required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

    func show(text: String, keyFrame key: CGRect, in area: CGRect, color: UIColor, emoji: Bool) {
        let bubbleW = max(key.width + 20, 46)
        let bubbleH = max(key.height * 1.15, 48)
        let neck: CGFloat = 10
        let total = CGRect(x: key.midX - bubbleW / 2, y: key.minY - bubbleH - neck + 4,
                           width: bubbleW, height: bubbleH + neck - 4 + key.height)
        // Reste dans le clavier (iOS ne laisse pas dessiner au-dessus).
        var f = total
        f.origin.x = min(max(f.minX, area.minX + 1), area.maxX - f.width - 1)
        f.origin.y = max(f.minY, area.minY)
        frame = f

        let bubble = CGRect(x: 0, y: 0, width: f.width, height: bubbleH)
        let stem = CGRect(x: key.minX - f.minX, y: f.height - key.height, width: key.width, height: key.height)
        let path = UIBezierPath(roundedRect: bubble, cornerRadius: 8)
        path.append(UIBezierPath(roundedRect: stem, cornerRadius: 5))
        // Le cou qui relie la bulle à la touche.
        let neckPath = UIBezierPath()
        neckPath.move(to: CGPoint(x: bubble.minX, y: bubble.maxY - 8))
        neckPath.addLine(to: CGPoint(x: bubble.maxX, y: bubble.maxY - 8))
        neckPath.addLine(to: CGPoint(x: stem.maxX, y: stem.minY + 6))
        neckPath.addLine(to: CGPoint(x: stem.minX, y: stem.minY + 6))
        neckPath.close()
        path.append(neckPath)

        CATransaction.begin()
        CATransaction.setDisableActions(true)
        shape.frame = CGRect(origin: .zero, size: f.size)
        shape.path = path.cgPath
        shape.shadowPath = path.cgPath
        shape.fillColor = color.resolvedColor(with: traitCollection).cgColor
        CATransaction.commit()

        label.text = text
        label.font = .systemFont(ofSize: emoji ? 40 : 34, weight: .regular)
        label.frame = bubble.insetBy(dx: 2, dy: 4)
        isHidden = false
        superview?.bringSubviewToFront(self)
    }

}
