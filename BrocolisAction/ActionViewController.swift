//
//  ActionViewController.swift
//  Brocolis 🥦 — Action Extension
//
//  Apparaît dans le menu Partager dès qu'une app partage du texte ou un lien
//  (NSExtensionActivationSupportsText / WebURL ; TRUEPREDICATE est refusé par
//  l'App Store). Sans ((…)), chiffre tout le texte ; avec, seulement ces
//  passages.
//  Chiffre les ((secrets))
//  ou déchiffre les jetons [[BROCOLIS:v1:...]] avec la clé partagée (App Group),
//  puis affiche le résultat avec un bouton « Copier ».
//
//  LECTURE D'UNE CONVERSATION ENTIÈRE, SANS COPIER-COLLER : dans WhatsApp (et la
//  plupart des messageries), sélectionne PLUSIEURS messages (appui long → coche
//  plusieurs) puis Partager → Brocolis 🥦. L'extension agrège tous les messages
//  partagés et affiche toute la conversation en clair, d'un coup.
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
            title: loc("Copier", "Copy", "Copiar"), style: .done, target: self, action: #selector(copyResult)
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
        let textType = UTType.plainText.identifier

        // On agrège le texte de TOUS les éléments partagés (et de toutes leurs
        // pièces jointes), pour gérer la sélection de plusieurs messages d'un
        // coup. Le résultat est assemblé dans l'ordre, en attendant les
        // chargements asynchrones avec un DispatchGroup.
        var pieces: [String?] = []          // ordre préservé, indexé
        let group = DispatchGroup()
        let lock = NSLock()

        func store(_ text: String, at index: Int) {
            guard !text.isEmpty else { return }
            lock.lock(); pieces[index] = text; lock.unlock()
        }

        for item in items {
            // 1) Texte sélectionné directement porté par l'élément.
            if let text = item.attributedContentText?.string, !text.isEmpty {
                pieces.append(text)
                continue
            }
            // 2) Sinon, chaque pièce jointe texte de l'élément.
            for provider in item.attachments ?? []
            where provider.hasItemConformingToTypeIdentifier(textType) {
                let index = pieces.count
                pieces.append(nil)
                group.enter()
                provider.loadItem(forTypeIdentifier: textType, options: nil) { data, _ in
                    var text = ""
                    if let s = data as? String {
                        text = s
                    } else if let url = data as? URL,
                              let s = try? String(contentsOf: url, encoding: .utf8) {
                        text = s
                    } else if let d = data as? Data, let s = String(data: d, encoding: .utf8) {
                        text = s
                    }
                    store(text, at: index)
                    group.leave()
                }
            }
        }

        group.notify(queue: .main) {
            let joined = pieces.compactMap { $0 }.joined(separator: "\n")
            completion(joined)
        }
    }

    // MARK: Transformation

    private func process(_ input: String) {
        guard !input.isEmpty else {
            statusLabel.text = loc("Aucun texte ici.", "No text here.", "Ningún texto aquí.")
            textView.text = loc("Brocolis 🥦 travaille sur du texte. Sélectionne un ou plusieurs messages (ou du texte), puis Partager → Brocolis.", "Brocolis 🥦 works on text. Select one or more messages (or some text), then Share → Brocolis.", "Brocolis 🥦 trabaja con texto. Selecciona uno o varios mensajes (o texto), luego Compartir → Brocolis.")
            resultText = ""
            return
        }
        guard BrocolisKeyStore.isActive else {
            statusLabel.text = loc("⏸ Brocolis est désactivé.", "⏸ Brocolis is disabled.", "⏸ Brocolis está desactivado.")
            textView.text = loc("Ouvre l’app Brocolis 🥦 et active-le pour chiffrer/déchiffrer.", "Open the Brocolis 🥦 app and enable it to encrypt/decrypt.", "Abre la app Brocolis 🥦 y actívalo para cifrar/descifrar.")
            resultText = ""
            return
        }
        // Déchiffrement : un message reçu peut être chiffré avec N'IMPORTE
        // laquelle de tes clés → on les essaie toutes.
        if BrocolisCrypto.containsToken(input) {
            let keys = BrocolisKeyStore.keys
            guard !keys.isEmpty else {
                statusLabel.text = loc("🔑 Aucune clé configurée.", "🔑 No key configured.", "🔑 Ninguna clave configurada.")
                textView.text = loc("Ouvre l’app Brocolis 🥦 pour ajouter une clé, puis réessaie.", "Open the Brocolis 🥦 app to add a key, then try again.", "Abre la app Brocolis 🥦 para añadir una clave, luego inténtalo de nuevo.")
                resultText = ""
                return
            }
            // v3 (double cliquet) compris : `BrocolisV3` garde le clair d'un
            // message déjà ouvert (il ne se déchiffre qu'une fois).
            let (text, n) = BrocolisV3.openTokens(input, keys: keys)
            resultText = text
            textView.text = text
            UIPasteboard.general.string = text
            statusLabel.text = n > 0
                ? loc("🔓 \(n) message(s) en clair — lis ci-dessous. Aucune copie nécessaire.", "🔓 \(n) message(s) in cleartext — read below. No copy needed.", "🔓 \(n) mensaje(s) en claro — lee abajo. No hace falta copiar.")
                : loc("Aucun message lisible avec tes clés (clé d’un autre ?).", "No readable message with your keys (someone else’s key?).", "Ningún mensaje legible con tus claves (¿clave de otra persona?).")
            return
        }

        // Chiffrement : pour la (ou les) clé(s) destinataire(s) choisie(s) —
        // en v3 pour un contact appairé (ou une clé « à deux » en PSK), sinon
        // v1/v2 (docs/SECURITE.md §8.5).
        let encKeys = BrocolisKeyStore.encryptionNamedKeys()
        guard !encKeys.isEmpty else {
            if BrocolisKeyStore.hasKey {
                statusLabel.text = loc("⌛️ Clé(s) destinataire(s) expirée(s).", "⌛️ Recipient key(s) expired.", "⌛️ Clave(s) de destinatario expirada(s).")
                textView.text = loc("Prolonge une clé dans l’app Brocolis 🥦, puis réessaie.", "Extend a key in the Brocolis 🥦 app, then try again.", "Prolonga una clave en la app Brocolis 🥦, luego inténtalo de nuevo.")
            } else {
                statusLabel.text = loc("🔑 Aucune clé configurée.", "🔑 No key configured.", "🔑 Ninguna clave configurada.")
                textView.text = loc("Ouvre l’app Brocolis 🥦 pour ajouter une clé, puis réessaie.", "Open the Brocolis 🥦 app to add a key, then try again.", "Abre la app Brocolis 🥦 para añadir una clave, luego inténtalo de nuevo.")
            }
            resultText = ""
            return
        }

        let result = BrocolisTransform.auto(
            input, codec: BrocolisV3.codec(recipients: encKeys, all: BrocolisKeyStore.keys),
            encryptWholeAlways: BrocolisKeyStore.encryptWholeAlways)

        // Garde-fou : si rien n'a été chiffré, on NE copie PAS de clair et on
        // l'indique clairement — pour ne jamais faire croire que c'est protégé.
        guard result.isEncrypted else {
            statusLabel.text = loc("⚠️ Rien n'a été chiffré — texte NON copié (vérifie ta clé).", "⚠️ Nothing was encrypted — text NOT copied (check your key).", "⚠️ No se cifró nada — texto NO copiado (verifica tu clave).")
            textView.text = result.text
            resultText = ""
            return
        }

        resultText = result.text
        textView.text = result.text

        // Brocolis étant actif, on copie directement le résultat : il n'y a plus
        // qu'à coller EN REMPLAÇANT le texte d'origine.
        UIPasteboard.general.string = result.text
        let recipients = encKeys.count > 1
            ? loc(" · \(encKeys.count) destinataires", " · \(encKeys.count) recipients", " · \(encKeys.count) destinatarios")
            : " · " + BrocolisV3.protectionUsed(result.text, recipients: encKeys).label
        statusLabel.text = result.label + recipients
            + loc(" — ✅ Copié. Colle en remplaçant ton texte (n'envoie pas le clair).", " — ✅ Copied. Paste over your text (don’t send the cleartext).", " — ✅ Copiado. Pega reemplazando tu texto (no envíes el texto claro).")
    }

    // MARK: Actions

    @objc private func copyResult() {
        guard !resultText.isEmpty else { return }
        UIPasteboard.general.string = resultText
        statusLabel.text = loc("✅ Copié. Colle en remplaçant ton texte d'origine (n'envoie pas le clair).", "✅ Copied. Paste over your original text (don’t send the cleartext).", "✅ Copiado. Pega reemplazando tu texto original (no envíes el texto claro).")
    }

    @objc private func done() {
        extensionContext?.completeRequest(returningItems: [], completionHandler: nil)
    }
}
