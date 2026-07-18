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
//  L'extension ne gère QUE le texte. Les médias chiffrés (photo, vocal) se
//  créent et se lisent dans l'app Brocolis 🥦 elle-même : ici, une bulle média
//  reçue renvoie simplement vers l'app. Le réseau ne transporte que du chiffré.
//

import UIKit
import Messages
import SwiftUI
import WidgetKit

// MARK: - Médias chiffrés : détection seule (l'affichage se fait dans l'app)

/// Enveloppe des médias DANS le texte chiffré, identique à l'app (`MediaPayload`).
/// L'extension ne fait plus qu'en DÉTECTER la présence (pour renvoyer vers
/// l'app) : elle ne les affiche plus. Voir l'app Brocolis 🥦 pour voir/écouter.
enum BrocolisMedia {
    static let imagePrefix = "BRCM1:img:"
    static let audioPrefix = "BRCM1:aud:"

    enum Kind {
        case text(String)
        case media   // photo ou vocal : à ouvrir dans l'app
    }

    /// Décode un clair déchiffré : texte affichable, ou média (renvoi vers l'app).
    static func decode(_ clear: String) -> Kind {
        if clear.hasPrefix(imagePrefix) || clear.hasPrefix(audioPrefix) {
            return .media
        }
        return .text(clear)
    }
}

// MARK: - Limite de taille du jeton (URL d'une bulle iMessage)

/// L'URL d'un `MSMessage` ne peut pas porter un jeton illimité : on borne le
/// texte chiffré qui part dans une bulle.
enum BrocolisMediaLimits {
    /// Budget du jeton chiffré (texte base64) qui tient dans l'URL d'une bulle.
    static let maxTokenChars = 90_000
}

// MARK: - Modèle observé par la vue SwiftUI

@MainActor
final class BrocolisiMessageModel: ObservableObject {
    /// Texte en clair du message sélectionné (bulle touchée), si une de nos
    /// clés l'ouvre.
    @Published var selectedClear: String?
    /// Vrai si la bulle touchée est un média chiffré (photo/vocal) : l'extension
    /// ne l'affiche pas, elle renvoie vers l'app.
    @Published var selectedIsMedia = false
    /// Vrai si la bulle touchée est chiffrée avec une clé qu'on n'a PAS.
    @Published var selectedLocked = false
    /// Message d'erreur d'envoi (ex. texte trop long pour une bulle iMessage).
    @Published var sendError: String?
    @Published var isExpanded = false
    @Published var keys: [NamedKey] = []
    @Published var selectedKeyId: String?
    /// Interrupteur global Brocolis (partagé avec l'app, le clavier, les
    /// widgets via l'App Group). En pause → RIEN ne se déchiffre ici.
    @Published var isActive = BrocolisKeyStore.isActive
    /// Résultat du bouton « Lire un message copié ».
    @Published var clipboardClear: String?
    @Published var clipboardLocked = false

    /// Le dernier jeton de bulle touché, gardé pour re-déchiffrer quand on
    /// réactive Brocolis.
    private var selectedToken: String?

    func refreshKeys() {
        keys = BrocolisKeyStore.keys
        selectedKeyId = BrocolisKeyStore.selectedKeyId ?? keys.first?.id
        isActive = BrocolisKeyStore.isActive
    }

    /// Active / met en pause Brocolis (même état que l'app et les widgets).
    func setActive(_ value: Bool) {
        BrocolisKeyStore.setActive(value)
        isActive = BrocolisKeyStore.isActive
        WidgetCenter.shared.reloadAllTimelines()
        if isActive {
            // Réactivé : rouvre la bulle sélectionnée s'il y en avait une.
            decryptSelectedToken()
        } else {
            // En pause : on efface tout clair affiché.
            selectedClear = nil
            selectedIsMedia = false
            selectedLocked = false
            clipboardClear = nil
            clipboardLocked = false
        }
    }

    /// Décode la bulle sélectionnée : URL `?t=<jeton>` → déchiffre avec toutes
    /// nos clés (seulement si Brocolis est actif).
    func update(selected: MSMessage?) {
        guard let url = selected?.url,
              let comps = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let token = comps.queryItems?.first(where: { $0.name == "t" })?.value,
              !token.isEmpty else {
            selectedToken = nil
            selectedClear = nil
            selectedIsMedia = false
            selectedLocked = false
            return
        }
        selectedToken = token
        decryptSelectedToken()
    }

    private func decryptSelectedToken() {
        guard let token = selectedToken else { return }
        guard isActive else {
            selectedClear = nil
            selectedIsMedia = false
            selectedLocked = false
            return
        }
        let (text, opened) = BrocolisCrypto.decryptTokens(token, keys: BrocolisKeyStore.allSymmetricKeys())
        if opened > 0 {
            selectedLocked = false
            switch BrocolisMedia.decode(text) {
            case .text(let t):
                selectedClear = t; selectedIsMedia = false
            case .media:
                // Photo/vocal : plus affichés ici, on renvoie vers l'app.
                selectedClear = nil; selectedIsMedia = true
            }
        } else {
            selectedClear = nil
            selectedIsMedia = false
            selectedLocked = true
        }
    }

    /// Déchiffre le presse-papiers : pour lire facilement un message chiffré
    /// reçu en TEXTE (clavier, ancien format, correspondant sans bulle riche).
    /// Appui long sur le message → Copier → ce bouton.
    func readClipboard() {
        guard isActive else { return }
        clipboardClear = nil
        clipboardLocked = false
        guard let raw = UIPasteboard.general.string,
              BrocolisCrypto.containsToken(raw) else {
            clipboardLocked = true
            return
        }
        let (text, opened) = BrocolisCrypto.decryptTokens(raw, keys: BrocolisKeyStore.allSymmetricKeys())
        if opened > 0, case .text(let t) = BrocolisMedia.decode(text) {
            clipboardClear = t
        } else {
            clipboardLocked = true
        }
    }

    /// Auto-lecture à l'OUVERTURE du panneau : si un jeton Brocolis TEXTE est
    /// déjà dans le presse-papiers, on l'affiche déchiffré tout de suite — pas
    /// besoin d'appuyer sur « Lire un message copié ». Silencieux si rien à lire.
    /// `hasStrings` (métadonnée, sans demander « Coller ») évite de solliciter
    /// iOS quand le presse-papiers ne contient pas de texte.
    func autoReadClipboard() {
        guard isActive, UIPasteboard.general.hasStrings else { return }
        guard let raw = UIPasteboard.general.string,
              BrocolisCrypto.containsToken(raw) else { return }
        let (text, opened) = BrocolisCrypto.decryptTokens(raw, keys: BrocolisKeyStore.allSymmetricKeys())
        if opened > 0, case .text(let t) = BrocolisMedia.decode(text) { clipboardClear = t }
    }

    var selectedKey: NamedKey? {
        keys.first(where: { $0.id == selectedKeyId }) ?? keys.first
    }
}

// MARK: - Contrôleur iMessage

final class MessagesViewController: MSMessagesAppViewController {

    private let model = BrocolisiMessageModel()
    /// Contrôleur SwiftUI hôte, gardé pour pouvoir le (ré)installer si iOS
    /// relance l'extension — cause fréquente d'un panneau qui s'ouvre vide.
    private var host: UIHostingController<BrocolisiMessageRootView>?

    override func viewDidLoad() {
        super.viewDidLoad()
        // Fond OPAQUE aux couleurs de Brocolis. Les extensions iMessage sont
        // relancées très agressivement par iOS (budget mémoire minuscule) : si
        // une frame arrive avant que SwiftUI ait fini de se dessiner, on voit
        // alors le vert Brocolis — jamais l'écran noir « planté » signalé.
        view.backgroundColor = UIColor(red: 232.0 / 255, green: 245.0 / 255,
                                       blue: 219.0 / 255, alpha: 1)
        installHostIfNeeded()
    }

    /// Installe la vue SwiftUI une seule fois. Rappelée à l'activation comme
    /// filet de sécurité : si le panneau s'était ouvert vide (hôte perdu après
    /// une relance de l'extension), il se reconstruit tout seul.
    private func installHostIfNeeded() {
        guard host == nil else { return }
        let root = BrocolisiMessageRootView(
            model: model,
            onSend: { [weak self] text in self?.sendEncrypted(text) },
            onInsertPlainToken: { [weak self] text in self?.insertPlainToken(text) },
            onRequestExpand: { [weak self] in self?.requestPresentationStyle(.expanded) }
        )
        let host = UIHostingController(rootView: root)
        // Transparent : c'est le fond vert du conteneur qui montre à travers.
        host.view.backgroundColor = .clear
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
        self.host = host
    }

    override func willBecomeActive(with conversation: MSConversation) {
        super.willBecomeActive(with: conversation)
        installHostIfNeeded()          // filet : reconstruit le panneau s'il était vide
        model.refreshKeys()
        model.update(selected: conversation.selectedMessage)
        model.isExpanded = presentationStyle == .expanded
        // Force une passe de layout : évite qu'une frame vide reste figée après
        // une relance de l'extension.
        view.setNeedsLayout()
        autoReadIfNoBubble()
    }

    override func didBecomeActive(with conversation: MSConversation) {
        super.didBecomeActive(with: conversation)
        autoReadIfNoBubble()
    }

    /// À l'ouverture, si aucune bulle 🥦 n'est déjà déchiffrée, on tente de lire
    /// un jeton texte déjà copié pour l'afficher directement (sans bouton).
    private func autoReadIfNoBubble() {
        guard model.selectedClear == nil, !model.selectedIsMedia else { return }
        model.autoReadClipboard()
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
        insertEncrypted(clear: text, summary: "🥦 Message chiffré")
    }

    /// Cœur commun : scelle `clear` avec la clé choisie et insère la bulle verte
    /// dont l'URL porte le jeton chiffré. L'URL d'un `MSMessage` ne peut pas
    /// porter un jeton illimité → garde-fou de taille avec message clair.
    private func insertEncrypted(clear: String, summary: String) {
        model.sendError = nil
        guard let conversation = activeConversation,
              let key = model.selectedKey,
              let sym = try? BrocolisCrypto.symmetricKey(fromBase64: key.base64),
              let token = try? BrocolisCrypto.encryptToken(Data(clear.utf8), key: sym)
        else { return }

        // Limite prudente pour l'URL d'une bulle iMessage.
        guard token.utf8.count <= BrocolisMediaLimits.maxTokenChars else {
            model.sendError = loc(
                "Ce message est trop long pour une bulle iMessage. Envoie-le depuis l'app Brocolis 🥦 (Messagerie).",
                "This message is too long for an iMessage bubble. Send it from the Brocolis 🥦 app (Messagerie).",
                "Este mensaje es demasiado largo para una burbuja de iMessage. Envíalo desde la app Brocolis 🥦 (Messagerie)."
            )
            return
        }

        var comps = URLComponents()
        comps.scheme = "https"
        comps.host = "brocolis.invalid" // jamais résolu : simple support du jeton
        comps.queryItems = [URLQueryItem(name: "t", value: token)]

        // Tout le visuel est DANS l'image (fond vert logo + textes) : la bulle
        // entière est verte au lieu du fond sombre système. L'image voyage avec
        // le message, le destinataire la voit aussi.
        let layout = MSMessageTemplateLayout()
        layout.image = BrocolisBubbleImage.make()

        let message = MSMessage(session: MSSession())
        message.url = comps.url
        message.layout = layout
        // Pas de `summaryText` : c'est lui qu'iMessage affiche dans une zone
        // SOMBRE sous l'image. En l'omettant, la bulle reste TOUTE VERTE.
        // (Contrepartie : la notification/l'aperçu de liste ne portent plus
        // « 🥦 Message chiffré ».) `summary` conservé pour un usage éventuel.
        _ = summary

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

// MARK: - Image de bulle (fond vert du logo, plus de fond sombre)

/// Libellé de la bulle, ADAPTÉ à la langue du téléphone, avec repli anglais.
/// (Le texte est dessiné dans une image → pas de Localizable.strings, on choisit
/// la chaîne selon le code langue de l'appareil.)
enum BrocolisBubbleText {
    static var label: String {
        let code = (Locale.preferredLanguages.first ?? "en").prefix(2).lowercased()
        switch code {
        case "fr": return "Message chiffré"
        case "es": return "Mensaje cifrado"
        case "de": return "Verschlüsselte Nachricht"
        case "it": return "Messaggio cifrato"
        case "pt": return "Mensagem cifrada"
        default: return "Encrypted message" // repli anglais
        }
    }
}

/// Bulle iMessage TOUTE VERTE : fond vert du logo qui remplit toute la bulle,
/// avec le libellé (localisé) écrit en NOIR. Combiné à l'absence de
/// `summaryText` (voir `insertEncrypted`), la bulle n'a aucune zone sombre.
/// Le jeton chiffré voyage dans l'URL du message.
enum BrocolisBubbleImage {
    static func make() -> UIImage {
        let size = CGSize(width: 360, height: 88)
        let renderer = UIGraphicsImageRenderer(size: size)
        return renderer.image { ctx in
            let cg = ctx.cgContext
            // Fond vert clair du logo, léger dégradé pour un rendu doux.
            let bgTop = UIColor(red: 238.0 / 255, green: 248.0 / 255, blue: 226.0 / 255, alpha: 1)
            let bgBottom = UIColor(red: 224.0 / 255, green: 241.0 / 255, blue: 208.0 / 255, alpha: 1)
            if let gradient = CGGradient(colorsSpace: CGColorSpaceCreateDeviceRGB(),
                                         colors: [bgTop.cgColor, bgBottom.cgColor] as CFArray,
                                         locations: [0, 1]) {
                cg.drawLinearGradient(gradient,
                                      start: CGPoint(x: 0, y: 0),
                                      end: CGPoint(x: 0, y: size.height),
                                      options: [])
            } else {
                bgTop.setFill()
                cg.fill(CGRect(origin: .zero, size: size))
            }

            // 🥦 + libellé localisé sur une même ligne (même ligne de base),
            // centrée. Écriture en NOIR.
            let line = NSMutableAttributedString(string: "🥦 ", attributes: [
                .font: UIFont.systemFont(ofSize: 22),
            ])
            line.append(NSAttributedString(string: BrocolisBubbleText.label, attributes: [
                .font: UIFont.systemFont(ofSize: 22, weight: .semibold),
                .foregroundColor: UIColor.black,
            ]))
            let lineSize = line.size()
            line.draw(at: CGPoint(x: (size.width - lineSize.width) / 2,
                                  y: (size.height - lineSize.height) / 2))
        }
    }
}

// MARK: - Vue SwiftUI

struct BrocolisiMessageRootView: View {
    @ObservedObject var model: BrocolisiMessageModel
    var onSend: (String) -> Void
    var onInsertPlainToken: (String) -> Void
    var onRequestExpand: () -> Void

    @State private var draft = ""
    /// Suivi du focus du champ de saisie : quand on écrit, on passe en plein
    /// écran ET on remonte le champ au-dessus du clavier (sinon il est masqué).
    @FocusState private var composerFocused: Bool

    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
    private let brocoliBg = Color(red: 232.0 / 255, green: 245.0 / 255, blue: 219.0 / 255)

    var body: some View {
        ScrollViewReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    activeToggleRow
                    if model.isActive {
                        if model.selectedIsMedia {
                            mediaInAppCard
                        } else if let clear = model.selectedClear {
                            readCard(clear)
                        } else if model.selectedLocked {
                            lockedCard
                        }
                        clipboardSection
                        composer
                    } else {
                        pausedCard
                    }
                }
                .padding(14)
            }
            .background(brocoliBg.opacity(0.35))
            // Dès qu'on prend le focus du champ : plein écran + on remonte le
            // champ au-dessus du clavier pour toujours voir ce qu'on écrit.
            .onChange(of: composerFocused) { focused in
                guard focused else { return }
                if !model.isExpanded { onRequestExpand() }
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                    withAnimation { proxy.scrollTo("composerField", anchor: .center) }
                }
            }
            // En tapant, on garde le champ visible (il grandit jusqu'à 4 lignes).
            .onChange(of: draft) { _ in
                guard composerFocused else { return }
                withAnimation { proxy.scrollTo("composerField", anchor: .center) }
            }
        }
    }

    // Interrupteur Actif / Pause — même état que l'app et les widgets.
    private var activeToggleRow: some View {
        Toggle(isOn: Binding(get: { model.isActive },
                             set: { model.setActive($0) })) {
            HStack(spacing: 6) {
                Text("🥦")
                Text(model.isActive ? loc("Brocolis actif", "Brocolis active", "Brocolis activo")
                                    : loc("Brocolis en pause", "Brocolis paused", "Brocolis en pausa"))
                    .font(.subheadline).bold()
                    .foregroundStyle(model.isActive ? brocoliGreen : .secondary)
            }
        }
        .tint(brocoliGreen)
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
    }

    private var pausedCard: some View {
        Label(loc("En pause : rien ne se déchiffre et rien ne s'envoie. Active l'interrupteur pour lire et écrire.",
                  "Paused: nothing is decrypted and nothing is sent. Turn on the switch to read and write.",
                  "En pausa: no se descifra ni se envía nada. Activa el interruptor para leer y escribir."),
              systemImage: "pause.circle.fill")
            .font(.footnote).foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
    }

    // « Lire un message copié » : déchiffre le presse-papiers (messages reçus
    // en texte [[BROCOLIS:…]] — clavier, anciens messages…).
    @ViewBuilder private var clipboardSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                model.readClipboard()
            } label: {
                Label(loc("Lire un message copié", "Read a copied message", "Leer un mensaje copiado"), systemImage: "doc.on.clipboard")
                    .font(.subheadline).bold()
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(brocoliGreen)

            if let clear = model.clipboardClear {
                VStack(alignment: .leading, spacing: 6) {
                    Label(loc("Déchiffré", "Decrypted", "Descifrado"), systemImage: "lock.open.fill")
                        .font(.caption).bold().foregroundStyle(brocoliGreen)
                    Text(clear)
                        .font(.body)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 12).fill(brocoliBg))
            } else if model.clipboardLocked {
                Text(loc("Rien à déchiffrer dans le presse-papiers (copie d'abord un message 🥦, appui long → Copier).",
                         "Nothing to decrypt in the clipboard (copy a 🥦 message first, long-press → Copy).",
                         "No hay nada que descifrar en el portapapeles (copia antes un mensaje 🥦, mantén pulsado → Copiar)."))
                    .font(.caption2).foregroundStyle(.secondary)
            }

            Text(loc("Bulle verte « 🥦 » : touche-la, elle s'ouvre déchiffrée ici — sans copier. Message reçu en texte : copie-le, il s'affiche tout seul à l'ouverture (ou touche le bouton).",
                     "Green bubble « 🥦 »: tap it, it opens decrypted here — without copying. Message received as text: copy it, it shows up on its own when opening (or tap the button).",
                     "Burbuja verde « 🥦 »: tócala, se abre descifrada aquí — sin copiar. Mensaje recibido como texto: cópialo, aparece solo al abrir (o toca el botón)."))
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
    }

    // Bulle touchée → clair, bien visible.
    private func readCard(_ text: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(loc("Message déchiffré", "Decrypted message", "Mensaje descifrado"), systemImage: "lock.open.fill")
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

    // Bulle touchée = média (photo/vocal) : plus affiché ici, on renvoie vers
    // l'app Brocolis 🥦 qui, elle, sait le voir/écouter.
    private var mediaInAppCard: some View {
        Label(loc("Ce message contient une photo ou un vocal chiffré. Ouvre-le dans l'app Brocolis 🥦 pour le voir ou l'écouter.",
                  "This message contains an encrypted photo or voice message. Open it in the Brocolis 🥦 app to view or listen.",
                  "Este mensaje contiene una foto o un mensaje de voz cifrado. Ábrelo en la app Brocolis 🥦 para verlo o escucharlo."),
              systemImage: "photo.on.rectangle.angled")
            .font(.footnote).foregroundStyle(.secondary)
            .padding(14)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 16).fill(Color(.systemBackground)))
            .overlay(RoundedRectangle(cornerRadius: 16).stroke(brocoliGreen.opacity(0.35)))
    }

    private var lockedCard: some View {
        Label(loc("Ce message est chiffré avec une clé que tu n'as pas.",
                  "This message is encrypted with a key you don’t have.",
                  "Este mensaje está cifrado con una clave que no tienes."),
              systemImage: "lock.fill")
            .font(.footnote).foregroundStyle(.secondary)
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
    }

    @ViewBuilder private var composer: some View {
        if model.keys.isEmpty {
            Label(loc("Ouvre Brocolis 🥦 pour créer une clé ou t'appairer.",
                      "Open Brocolis 🥦 to create a key or pair up.",
                      "Abre Brocolis 🥦 para crear una clave o emparejarte."),
                  systemImage: "key.slash")
                .font(.footnote).foregroundStyle(.secondary)
                .padding(12)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
        } else {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Label(loc("Chiffrer pour", "Encrypt for", "Cifrar para"), systemImage: "key.fill")
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

                // Champ à CONTRASTE GARANTI : `.roundedBorder` s'adapte mal au
                // thème sombre du panneau iMessage (on voyait mal ce qu'on tapait).
                // Ici : texte `.primary` + fond adaptatif + police `.body` lisible.
                TextField(loc("Message secret…", "Secret message…", "Mensaje secreto…"), text: $draft, axis: .vertical)
                    .font(.body)
                    .foregroundStyle(.primary)
                    .tint(brocoliGreen) // curseur vert bien visible
                    .lineLimit(1...4)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 10)
                    .background(RoundedRectangle(cornerRadius: 12).fill(Color(.secondarySystemBackground)))
                    .overlay(RoundedRectangle(cornerRadius: 12).stroke(brocoliGreen.opacity(0.4), lineWidth: 1))
                    .id("composerField") // cible du défilement : on centre CE champ
                    .focused($composerFocused)
                    .onTapGesture {
                        // En présentation compacte, le clavier n'est pas
                        // autorisé : on demande le plein écran d'abord, puis on
                        // prend le focus (ce qui déclenche le scroll ci-dessus).
                        if !model.isExpanded {
                            onRequestExpand()
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
                                composerFocused = true
                            }
                        } else {
                            composerFocused = true
                        }
                    }

                if let err = model.sendError {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }

                HStack(spacing: 10) {
                    Button {
                        send(via: onSend)
                    } label: {
                        Label(loc("Envoyer chiffré", "Send encrypted", "Enviar cifrado"), systemImage: "paperplane.fill")
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
                    .accessibilityLabel(loc("Insérer en texte brut", "Insert as plain text", "Insertar como texto sin formato"))
                }

                Text(loc("Ton texte part chiffré : la bulle « 🥦 » se lit d'un tap avec Brocolis. Sans la clé et sans l'app, rien n'est lisible. Le bouton « Abc » insère le jeton en texte (compatible clavier/app). Pour envoyer une photo 📷 ou un vocal 🎙️, utilise l'app Brocolis 🥦.",
                         "Your text goes out encrypted: the « 🥦 » bubble reads with one tap using Brocolis. Without the key and without the app, nothing is readable. The « Abc » button inserts the token as text (compatible with keyboard/app). To send a photo 📷 or voice message 🎙️, use the Brocolis 🥦 app.",
                         "Tu texto sale cifrado: la burbuja « 🥦 » se lee con un toque usando Brocolis. Sin la clave y sin la app, nada es legible. El botón « Abc » inserta el token como texto (compatible con teclado/app). Para enviar una foto 📷 o un mensaje de voz 🎙️, usa la app Brocolis 🥦."))
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
