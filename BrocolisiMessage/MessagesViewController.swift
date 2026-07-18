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
import WidgetKit
import AVFoundation
import PhotosUI

// MARK: - Médias chiffrés (photo / vocal) dans le jeton

/// Enveloppe des médias DANS le texte chiffré, identique à l'app (`MediaPayload`)
/// pour que photo et vocal soient interopérables entre l'app et iMessage. Le
/// réseau (et iMessage) ne voit qu'un jeton chiffré : ni image, ni son en clair.
enum BrocolisMedia {
    static let imagePrefix = "BRCM1:img:"
    static let audioPrefix = "BRCM1:aud:"

    enum Kind {
        case text(String)
        case image(Data)
        case audio(Data)
    }

    /// Décode un clair déchiffré en contenu affichable.
    static func decode(_ clear: String) -> Kind {
        if clear.hasPrefix(imagePrefix),
           let data = Data(base64Encoded: String(clear.dropFirst(imagePrefix.count))) {
            return .image(data)
        }
        if clear.hasPrefix(audioPrefix),
           let data = Data(base64Encoded: String(clear.dropFirst(audioPrefix.count))) {
            return .audio(data)
        }
        return .text(clear)
    }

    static func imageClear(_ jpeg: Data) -> String { imagePrefix + jpeg.base64EncodedString() }
    static func audioClear(_ m4a: Data) -> String { audioPrefix + m4a.base64EncodedString() }
}

// MARK: - Limites de taille des médias (URL d'une bulle iMessage)

/// L'URL d'un `MSMessage` ne peut pas porter un média lourd : on borne tout ce
/// qui part dans une bulle. Un seul endroit pour régler ces limites.
enum BrocolisMediaLimits {
    /// Budget du jeton chiffré (texte base64) qui tient dans l'URL d'une bulle.
    static let maxTokenChars = 90_000
    /// Budget des OCTETS bruts du média : base64 gonfle de ~4/3, plus le
    /// sur-emballage AES/jeton ⇒ on garde une marge sous maxTokenChars.
    static let maxMediaBytes = 62_000            // ≈ 60 Ko
    /// Durée maximale d'un vocal.
    static let maxVoiceSeconds: TimeInterval = 20
    /// Débit AAC mono utilisé (24 kbit/s ≈ 3 Ko/s) : sert à estimer le poids en
    /// direct pendant l'enregistrement.
    static let voiceBytesPerSecond = 3_000

    /// Poids d'un vocal « plein » (durée max) — pour l'afficher à l'utilisateur.
    static var maxVoiceBytesEstimate: Int { Int(maxVoiceSeconds) * voiceBytesPerSecond }
}

/// Formate un nombre d'octets en « 42 Ko » / « 1,2 Mo » pour l'affichage.
func brocolisFormatBytes(_ bytes: Int) -> String {
    let formatter = ByteCountFormatter()
    formatter.countStyle = .file
    formatter.allowedUnits = [.useKB, .useMB]
    return formatter.string(fromByteCount: Int64(bytes))
}

/// Formate une durée en « 0:07 ».
func brocolisFormatDuration(_ seconds: TimeInterval) -> String {
    let s = Int(seconds.rounded())
    return String(format: "%d:%02d", s / 60, s % 60)
}

/// Réduit une photo pour l'envoi chiffré DANS une bulle iMessage. On resize et
/// on baisse la qualité par paliers JUSQU'À passer sous `maxMediaBytes` : plus
/// d'erreur « trop lourd », l'image s'adapte toute seule. Pour une vraie photo
/// pleine résolution, l'app Brocolis 🥦 (Messagerie) reste le bon canal.
func brocolisPanelJPEG(from image: UIImage, targetBytes: Int = BrocolisMediaLimits.maxMediaBytes) -> Data? {
    func jpeg(maxDimension: CGFloat, quality: CGFloat) -> Data? {
        let largest = max(image.size.width, image.size.height)
        guard largest > 0 else { return nil }
        let scale = min(1, maxDimension / largest)
        let target = CGSize(width: image.size.width * scale, height: image.size.height * scale)
        let renderer = UIGraphicsImageRenderer(size: target)
        let resized = renderer.image { _ in image.draw(in: CGRect(origin: .zero, size: target)) }
        return resized.jpegData(compressionQuality: quality)
    }

    // Du plus grand/net au plus petit/compressé : on renvoie le PREMIER résultat
    // qui tient dans le budget.
    let dimensions: [CGFloat] = [720, 600, 480, 360, 280]
    let qualities: [CGFloat] = [0.5, 0.4, 0.3, 0.2]
    for dim in dimensions {
        for q in qualities {
            if let data = jpeg(maxDimension: dim, quality: q), data.count <= targetBytes {
                return data
            }
        }
    }
    // Dernier recours : le plus léger possible (peut rester sous le budget).
    return jpeg(maxDimension: 220, quality: 0.15)
}

// MARK: - Voix : enregistrement et lecture (AVFoundation)

/// Enregistre un vocal court en M4A (AAC mono, léger). Demande la permission
/// micro au premier usage. Coupe tout seul à `maxVoiceSeconds` et publie la
/// durée + le poids estimé en direct pour les afficher à l'utilisateur.
final class PanelVoiceRecorder: ObservableObject {
    @Published var isRecording = false
    /// Temps écoulé pendant l'enregistrement (mis à jour ~10×/s).
    @Published var elapsed: TimeInterval = 0

    private var recorder: AVAudioRecorder?
    private var fileURL: URL?
    private var timer: Timer?
    /// Appelé quand l'enregistrement s'arrête tout seul (durée max atteinte).
    private var onAutoStop: ((Data?) -> Void)?

    /// Poids estimé du vocal en cours (octets), d'après la durée et le débit.
    var estimatedBytes: Int { Int(elapsed) * BrocolisMediaLimits.voiceBytesPerSecond }

    func start(onAutoStop: @escaping (Data?) -> Void) {
        let session = AVAudioSession.sharedInstance()
        session.requestRecordPermission { [weak self] granted in
            DispatchQueue.main.async {
                guard granted, let self else { return }
                self.onAutoStop = onAutoStop
                try? session.setCategory(.playAndRecord, mode: .default,
                                         options: [.defaultToSpeaker])
                try? session.setActive(true)
                let url = FileManager.default.temporaryDirectory
                    .appendingPathComponent("brocolis-voix-\(UUID().uuidString).m4a")
                let settings: [String: Any] = [
                    AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
                    AVSampleRateKey: 16_000.0,
                    AVNumberOfChannelsKey: 1,
                    AVEncoderBitRateKey: 24_000,
                ]
                self.recorder = try? AVAudioRecorder(url: url, settings: settings)
                self.fileURL = url
                self.elapsed = 0
                self.recorder?.record()
                self.isRecording = self.recorder?.isRecording ?? false
                guard self.isRecording else { return }
                self.timer = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { [weak self] _ in
                    guard let self, let rec = self.recorder else { return }
                    self.elapsed = rec.currentTime
                    if self.elapsed >= BrocolisMediaLimits.maxVoiceSeconds {
                        let data = self.finish()
                        self.onAutoStop?(data)
                    }
                }
            }
        }
    }

    /// Arrêt manuel : renvoie l'audio enregistré (nil si vide/refusé).
    func stop() -> Data? { finish() }

    deinit { timer?.invalidate() }

    private func finish() -> Data? {
        timer?.invalidate()
        timer = nil
        recorder?.stop()
        recorder = nil
        isRecording = false
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        defer { if let url = fileURL { try? FileManager.default.removeItem(at: url) }; fileURL = nil }
        guard let url = fileURL, let data = try? Data(contentsOf: url), !data.isEmpty else { return nil }
        return data
    }
}

/// Joue les vocaux déchiffrés reçus dans le panneau (un seul à la fois).
final class PanelVoicePlayer: NSObject, ObservableObject, AVAudioPlayerDelegate {
    @Published var isPlaying = false
    private var player: AVAudioPlayer?

    func toggle(data: Data) {
        if isPlaying {
            player?.stop()
            isPlaying = false
            return
        }
        try? AVAudioSession.sharedInstance().setCategory(.playback)
        try? AVAudioSession.sharedInstance().setActive(true)
        player = try? AVAudioPlayer(data: data)
        player?.delegate = self
        player?.play()
        isPlaying = player != nil
    }

    func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        DispatchQueue.main.async { self.isPlaying = false }
    }
}

// MARK: - Modèle observé par la vue SwiftUI

@MainActor
final class BrocolisiMessageModel: ObservableObject {
    /// Texte en clair du message sélectionné (bulle touchée), si une de nos
    /// clés l'ouvre.
    @Published var selectedClear: String?
    /// Photo déchiffrée de la bulle touchée (si c'était une photo chiffrée).
    @Published var selectedImage: Data?
    /// Vocal déchiffré de la bulle touchée (si c'était un vocal chiffré).
    @Published var selectedAudio: Data?
    /// Vrai si la bulle touchée est chiffrée avec une clé qu'on n'a PAS.
    @Published var selectedLocked = false
    /// Message d'erreur d'envoi (ex. média trop lourd pour une bulle iMessage).
    @Published var sendError: String?
    /// Info du dernier média envoyé (ex. « Vocal envoyé · 0:14 · 42 Ko »).
    @Published var lastMediaInfo: String?
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
            selectedImage = nil
            selectedAudio = nil
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
            selectedImage = nil
            selectedAudio = nil
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
            selectedImage = nil
            selectedAudio = nil
            selectedLocked = false
            return
        }
        let (text, opened) = BrocolisCrypto.decryptTokens(token, keys: BrocolisKeyStore.allSymmetricKeys())
        if opened > 0 {
            selectedLocked = false
            switch BrocolisMedia.decode(text) {
            case .text(let t):
                selectedClear = t; selectedImage = nil; selectedAudio = nil
            case .image(let d):
                selectedImage = d; selectedClear = nil; selectedAudio = nil
            case .audio(let d):
                selectedAudio = d; selectedClear = nil; selectedImage = nil
            }
        } else {
            selectedClear = nil
            selectedImage = nil
            selectedAudio = nil
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
        if opened > 0 {
            clipboardClear = text
        } else {
            clipboardLocked = true
        }
    }

    /// Auto-lecture à l'OUVERTURE du panneau : si un jeton Brocolis est déjà
    /// dans le presse-papiers, on l'affiche déchiffré tout de suite — pas besoin
    /// d'appuyer sur « Lire un message copié ». Silencieux si rien à lire.
    /// `hasStrings` (métadonnée, sans demander « Coller ») évite de solliciter
    /// iOS quand le presse-papiers ne contient pas de texte.
    func autoReadClipboard() {
        guard isActive, UIPasteboard.general.hasStrings else { return }
        guard let raw = UIPasteboard.general.string,
              BrocolisCrypto.containsToken(raw) else { return }
        let (text, opened) = BrocolisCrypto.decryptTokens(raw, keys: BrocolisKeyStore.allSymmetricKeys())
        if opened > 0 { clipboardClear = text }
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
            onSendImage: { [weak self] data in self?.sendEncryptedImage(data) },
            onSendVoice: { [weak self] data, duration in self?.sendEncryptedVoice(data, duration: duration) },
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
        autoReadIfNoBubble()
    }

    override func didBecomeActive(with conversation: MSConversation) {
        super.didBecomeActive(with: conversation)
        autoReadIfNoBubble()
    }

    /// À l'ouverture, si aucune bulle 🥦 n'est déjà déchiffrée, on tente de lire
    /// un jeton déjà copié pour l'afficher directement (sans bouton).
    private func autoReadIfNoBubble() {
        guard model.selectedClear == nil,
              model.selectedImage == nil,
              model.selectedAudio == nil else { return }
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

    /// Envoie une photo CHIFFRÉE : compressée, encodée `BRCM1:img:`, scellée
    /// dans le jeton de l'URL. Sans la bonne clé (et sans l'app), la bulle reste
    /// la placeholder verte : ni image, ni aperçu ne fuient.
    private func sendEncryptedImage(_ jpeg: Data) {
        let info = "Photo envoyée · \(brocolisFormatBytes(jpeg.count))"
        insertEncrypted(clear: BrocolisMedia.imageClear(jpeg), summary: "🥦 Photo chiffrée", info: info)
    }

    /// Envoie un vocal CHIFFRÉ : encodé `BRCM1:aud:`, scellé dans le jeton.
    /// Inaudible sans la bonne clé et sans l'app. `duration` sert à afficher le
    /// temps du vocal à l'utilisateur.
    private func sendEncryptedVoice(_ m4a: Data, duration: TimeInterval) {
        let info = "Vocal envoyé · \(brocolisFormatDuration(duration)) · \(brocolisFormatBytes(m4a.count))"
        insertEncrypted(clear: BrocolisMedia.audioClear(m4a), summary: "🥦 Vocal chiffré", info: info)
    }

    /// Cœur commun : scelle `clear` avec la clé choisie et insère la bulle verte
    /// dont l'URL porte le jeton chiffré. L'URL d'un `MSMessage` ne peut pas
    /// porter un média lourd → garde-fou de taille avec message clair. `info`
    /// (facultatif) s'affiche après l'envoi (poids/durée du média).
    private func insertEncrypted(clear: String, summary: String, info: String? = nil) {
        model.sendError = nil
        guard let conversation = activeConversation,
              let key = model.selectedKey,
              let sym = try? BrocolisCrypto.symmetricKey(fromBase64: key.base64),
              let token = try? BrocolisCrypto.encryptToken(Data(clear.utf8), key: sym)
        else { return }

        // Limite prudente pour l'URL d'une bulle iMessage.
        guard token.utf8.count <= BrocolisMediaLimits.maxTokenChars else {
            model.sendError = "Ce média est trop lourd pour une bulle iMessage. Envoie-le depuis l'app Brocolis 🥦 (Messagerie)."
            return
        }
        model.lastMediaInfo = info

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
        message.summaryText = summary

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

/// Dessine le contenu de la bulle iMessage en MINIATURE : le brocoli 🥦 SEUL,
/// centré, sur fond vert du logo — aucun texte. iMessage étire l'image à la
/// largeur de la bulle en gardant son ratio : une image basse et large = une
/// bulle courte, une vraie miniature.
enum BrocolisBubbleImage {
    static func make() -> UIImage {
        let size = CGSize(width: 360, height: 72)
        let renderer = UIGraphicsImageRenderer(size: size)
        return renderer.image { ctx in
            let cg = ctx.cgContext

            // Fond vert clair du logo, en léger dégradé pour un rendu plus doux.
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

            // Le brocoli 🥦 SEUL, centré. Aucun texte.
            let broc = NSAttributedString(string: "🥦", attributes: [
                .font: UIFont.systemFont(ofSize: 46),
            ])
            let brocSize = broc.size()
            broc.draw(at: CGPoint(x: (size.width - brocSize.width) / 2,
                                  y: (size.height - brocSize.height) / 2))
        }
    }
}

// MARK: - Vue SwiftUI

struct BrocolisiMessageRootView: View {
    @ObservedObject var model: BrocolisiMessageModel
    var onSend: (String) -> Void
    var onSendImage: (Data) -> Void
    var onSendVoice: (Data, TimeInterval) -> Void
    var onInsertPlainToken: (String) -> Void
    var onRequestExpand: () -> Void

    @State private var draft = ""
    @State private var photoItem: PhotosPickerItem?
    /// Photo choisie et compressée, EN ATTENTE d'envoi (aperçu avant d'envoyer).
    @State private var pendingPhoto: Data?
    @StateObject private var recorder = PanelVoiceRecorder()
    @StateObject private var player = PanelVoicePlayer()

    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
    private let brocoliBg = Color(red: 232.0 / 255, green: 245.0 / 255, blue: 219.0 / 255)

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 12) {
                activeToggleRow
                if model.isActive {
                    if model.selectedImage != nil || model.selectedAudio != nil {
                        mediaReadCard
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
    }

    // Interrupteur Actif / Pause — même état que l'app et les widgets.
    private var activeToggleRow: some View {
        Toggle(isOn: Binding(get: { model.isActive },
                             set: { model.setActive($0) })) {
            HStack(spacing: 6) {
                Text("🥦")
                Text(model.isActive ? "Brocolis actif" : "Brocolis en pause")
                    .font(.subheadline).bold()
                    .foregroundStyle(model.isActive ? brocoliGreen : .secondary)
            }
        }
        .tint(brocoliGreen)
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
    }

    private var pausedCard: some View {
        Label("En pause : rien ne se déchiffre et rien ne s'envoie. Active l'interrupteur pour lire et écrire.",
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
                Label("Lire un message copié", systemImage: "doc.on.clipboard")
                    .font(.subheadline).bold()
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(brocoliGreen)

            if let clear = model.clipboardClear {
                VStack(alignment: .leading, spacing: 6) {
                    Label("Déchiffré", systemImage: "lock.open.fill")
                        .font(.caption).bold().foregroundStyle(brocoliGreen)
                    Text(clear)
                        .font(.body)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 12).fill(brocoliBg))
            } else if model.clipboardLocked {
                Text("Rien à déchiffrer dans le presse-papiers (copie d'abord un message 🥦, appui long → Copier).")
                    .font(.caption2).foregroundStyle(.secondary)
            }

            Text("Bulle verte « 🥦 » : touche-la, elle s'ouvre déchiffrée ici — sans copier. Message reçu en texte : copie-le, il s'affiche tout seul à l'ouverture (ou touche le bouton).")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
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

    // Bulle touchée → photo/vocal déchiffré.
    @ViewBuilder private var mediaReadCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let data = model.selectedImage, let ui = UIImage(data: data) {
                Label("Photo déchiffrée", systemImage: "lock.open.fill")
                    .font(.caption).bold().foregroundStyle(brocoliGreen)
                Image(uiImage: ui)
                    .resizable()
                    .scaledToFit()
                    .frame(maxWidth: .infinity)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
            } else if let data = model.selectedAudio {
                Label("Vocal déchiffré", systemImage: "lock.open.fill")
                    .font(.caption).bold().foregroundStyle(brocoliGreen)
                Button {
                    player.toggle(data: data)
                } label: {
                    Label(player.isPlaying ? "Arrêter" : "Écouter le vocal",
                          systemImage: player.isPlaying ? "stop.fill" : "play.fill")
                        .font(.subheadline).bold()
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(brocoliGreen)
            }
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

                mediaRow

                if let err = model.sendError {
                    Label(err, systemImage: "exclamationmark.triangle.fill")
                        .font(.caption2).foregroundStyle(.orange)
                        .frame(maxWidth: .infinity, alignment: .leading)
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

                Text("Texte, photo 📷 et vocal 🎙️ partent chiffrés : la bulle « 🥦 » se lit d'un tap avec Brocolis. Sans la clé et sans l'app, rien n'est lisible ni audible. Le bouton « Abc » insère le jeton en texte (compatible clavier/app).")
                    .font(.caption2).foregroundStyle(.secondary)
            }
            .padding(12)
            .background(RoundedRectangle(cornerRadius: 16).fill(Color(.systemBackground)))
        }
    }

    // Photo 📷 + micro 🎙️ : deux médias chiffrés dans la bulle, comme le texte.
    @ViewBuilder private var mediaRow: some View {
        HStack(spacing: 10) {
            PhotosPicker(selection: $photoItem, matching: .images, photoLibrary: .shared()) {
                Label("Photo", systemImage: "photo.fill")
                    .font(.subheadline).bold()
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(brocoliGreen)
            .onChange(of: photoItem) { newItem in
                guard let newItem else { return }
                model.sendError = nil
                model.lastMediaInfo = nil
                Task {
                    if let data = try? await newItem.loadTransferable(type: Data.self),
                       let image = UIImage(data: data),
                       let jpeg = brocolisPanelJPEG(from: image) {
                        // Aperçu avant envoi : on garde la photo compressée.
                        await MainActor.run { pendingPhoto = jpeg }
                    }
                    await MainActor.run { photoItem = nil }
                }
            }

            Button {
                if recorder.isRecording {
                    let duration = recorder.elapsed
                    if let m4a = recorder.stop() { onSendVoice(m4a, duration) }
                } else {
                    model.sendError = nil
                    model.lastMediaInfo = nil
                    recorder.start(onAutoStop: { data in
                        if let m4a = data { onSendVoice(m4a, BrocolisMediaLimits.maxVoiceSeconds) }
                    })
                }
            } label: {
                Label(recorder.isRecording ? "Arrêter et envoyer" : "Vocal",
                      systemImage: recorder.isRecording ? "stop.circle.fill" : "mic.fill")
                    .font(.subheadline).bold()
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.bordered)
            .tint(recorder.isRecording ? .red : brocoliGreen)
        }

        // Aperçu de la photo choisie AVANT de l'envoyer (avec son poids).
        if let photo = pendingPhoto, let ui = UIImage(data: photo) {
            photoPreview(photo, ui)
        }

        if recorder.isRecording {
            // En direct : minuterie + poids estimé + barre de progression.
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Label("\(brocolisFormatDuration(recorder.elapsed)) / \(brocolisFormatDuration(BrocolisMediaLimits.maxVoiceSeconds))",
                          systemImage: "record.circle")
                        .font(.caption).bold().foregroundStyle(.red)
                    Spacer()
                    Text("~ \(brocolisFormatBytes(recorder.estimatedBytes))")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
                ProgressView(value: min(recorder.elapsed / BrocolisMediaLimits.maxVoiceSeconds, 1))
                    .tint(.red)
            }
        } else if let info = model.lastMediaInfo {
            // Après envoi : ce que pesait le média.
            Label(info, systemImage: "checkmark.seal.fill")
                .font(.caption).foregroundStyle(brocoliGreen)
                .frame(maxWidth: .infinity, alignment: .leading)
        }

        // Rappel des limites d'une bulle iMessage.
        Text("Vocal max : \(brocolisFormatDuration(BrocolisMediaLimits.maxVoiceSeconds)) · ~\(brocolisFormatBytes(BrocolisMediaLimits.maxVoiceBytesEstimate)). Photo compressée automatiquement (~\(brocolisFormatBytes(BrocolisMediaLimits.maxMediaBytes)) max).")
            .font(.caption2).foregroundStyle(.secondary)
    }

    // Aperçu de la photo choisie : image + poids, puis Envoyer / Annuler.
    private func photoPreview(_ data: Data, _ ui: UIImage) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Label("Aperçu avant envoi", systemImage: "photo")
                    .font(.caption).bold().foregroundStyle(brocoliGreen)
                Spacer()
                Text(brocolisFormatBytes(data.count))
                    .font(.caption).foregroundStyle(.secondary).monospacedDigit()
            }

            Image(uiImage: ui)
                .resizable()
                .scaledToFit()
                .frame(maxWidth: .infinity, maxHeight: 200)
                .clipShape(RoundedRectangle(cornerRadius: 12))

            HStack(spacing: 10) {
                Button {
                    onSendImage(data)
                    pendingPhoto = nil
                } label: {
                    Label("Envoyer chiffré", systemImage: "paperplane.fill")
                        .font(.subheadline).bold()
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(brocoliGreen)

                Button(role: .cancel) {
                    pendingPhoto = nil
                } label: {
                    Label("Annuler", systemImage: "xmark")
                        .font(.subheadline)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .tint(.secondary)
            }
        }
        .padding(12)
        .background(RoundedRectangle(cornerRadius: 14).fill(Color(.systemBackground)))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(brocoliGreen.opacity(0.35)))
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
