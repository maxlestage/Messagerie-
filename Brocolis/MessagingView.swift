//
//  MessagingView.swift
//  Brocolis 🥦
//
//  Messagerie LIVE, adossée à tes clés existantes. Ici, pas de copier-coller :
//  tu choisis un correspondant PARMI TES CLÉS 🔑 (une clé = une personne), et tu
//  discutes en clair dans l'app. Chaque message part chiffré (AES-256-GCM avec
//  la clé de ce correspondant) vers l'API `messagerie-api` ; le serveur ne voit
//  que du charabia. « En clair ici, illisible partout ailleurs. »
//
//  L'identifiant de conversation est DÉRIVÉ de la clé partagée (empreinte SHA-256) :
//  les deux correspondants, qui possèdent la même clé, calculent le même
//  identifiant sans que le serveur connaisse la clé. Pas besoin de « créer » une
//  conversation : partager une clé suffit à partager un fil.
//

import SwiftUI
import CryptoKit
import UIKit
import AudioToolbox
import AVFoundation
import PhotosUI
import LocalAuthentication

/// Comme `loc`, mais renvoie un `Text` qui REND le Markdown (**gras**, `code`).
/// Indispensable car `Text(uneString)` (chaîne dynamique) afficherait le Markdown
/// verbatim, contrairement à `Text("littéral")`. Repli verbatim si parsing échoue.
func locText(_ fr: String, _ en: String, _ es: String) -> Text {
    let s = loc(fr, en, es)
    if let attr = try? AttributedString(
        markdown: s,
        options: .init(interpretedSyntax: .inlineOnlyPreservingWhitespace)
    ) {
        return Text(attr)
    }
    return Text(s)
}

// NOTE : `MessagingPrefs`, `ChatBody`/`ChatLine`, `MediaPayload` et
// `BrocolisMessagingClient` vivent désormais dans
// `Shared/BrocolisMessagingCore.swift`, partagé avec l'app montre.

// MARK: - Style (avatars dégradés, vert Brocolis)

/// Dégradé d'avatar stable par nom : chaque correspondant a « sa » couleur.
func brocolisAvatarGradient(for name: String) -> LinearGradient {
    let palette: [(Color, Color)] = [
        (Color(red: 0.18, green: 0.62, blue: 0.29), Color(red: 0.45, green: 0.78, blue: 0.35)),
        (Color(red: 0.10, green: 0.45, blue: 0.65), Color(red: 0.30, green: 0.70, blue: 0.80)),
        (Color(red: 0.55, green: 0.30, blue: 0.75), Color(red: 0.80, green: 0.45, blue: 0.85)),
        (Color(red: 0.85, green: 0.45, blue: 0.20), Color(red: 0.95, green: 0.65, blue: 0.30)),
        (Color(red: 0.75, green: 0.25, blue: 0.40), Color(red: 0.95, green: 0.45, blue: 0.55)),
        (Color(red: 0.15, green: 0.55, blue: 0.50), Color(red: 0.35, green: 0.75, blue: 0.65)),
    ]
    let index = abs(name.unicodeScalars.reduce(0) { $0 &* 31 &+ Int($1.value) }) % palette.count
    let (a, b) = palette[index]
    return LinearGradient(colors: [a, b], startPoint: .topLeading, endPoint: .bottomTrailing)
}

/// Dégradé des bulles envoyées (vert Brocolis).
let brocolisBubbleGradient = LinearGradient(
    colors: [Color(red: 0.24, green: 0.68, blue: 0.33), Color(red: 0.14, green: 0.55, blue: 0.27)],
    startPoint: .top, endPoint: .bottom
)

/// Bulle de discussion avec « queue » : trois coins bien ronds, le coin côté
/// expéditeur resserré. (Équivalent d'UnevenRoundedRectangle, qui exige
/// iOS 16.4 — la cible est 16.0, d'où cette forme maison.)
struct ChatBubbleShape: Shape {
    var isMine: Bool

    func path(in rect: CGRect) -> Path {
        let r: CGFloat = 18
        let tail: CGFloat = 5
        let bl = isMine ? r : tail   // bas-gauche
        let br = isMine ? tail : r   // bas-droite
        var p = Path()
        p.move(to: CGPoint(x: rect.minX + r, y: rect.minY))
        p.addLine(to: CGPoint(x: rect.maxX - r, y: rect.minY))
        p.addArc(center: CGPoint(x: rect.maxX - r, y: rect.minY + r), radius: r,
                 startAngle: .degrees(-90), endAngle: .degrees(0), clockwise: false)
        p.addLine(to: CGPoint(x: rect.maxX, y: rect.maxY - br))
        p.addArc(center: CGPoint(x: rect.maxX - br, y: rect.maxY - br), radius: br,
                 startAngle: .degrees(0), endAngle: .degrees(90), clockwise: false)
        p.addLine(to: CGPoint(x: rect.minX + bl, y: rect.maxY))
        p.addArc(center: CGPoint(x: rect.minX + bl, y: rect.maxY - bl), radius: bl,
                 startAngle: .degrees(90), endAngle: .degrees(180), clockwise: false)
        p.addLine(to: CGPoint(x: rect.minX, y: rect.minY + r))
        p.addArc(center: CGPoint(x: rect.minX + r, y: rect.minY + r), radius: r,
                 startAngle: .degrees(180), endAngle: .degrees(270), clockwise: false)
        p.closeSubpath()
        return p
    }
}

// MARK: - Store d'une conversation (déchiffre pour l'affichage)

@MainActor
final class BrocolisChatStore: ObservableObject {
    @Published private(set) var lines: [ChatLine] = []
    @Published private(set) var status: String?
    /// Jusqu'où le correspondant a LU (seq) — pour l'accusé « Lu ».
    @Published private(set) var otherReadUpTo: UInt64 = 0
    @Published var draft: String = ""

    let correspondent: NamedKey
    private let key: SymmetricKey
    private let conversationId: String
    private let client: BrocolisMessagingClient

    /// Messages bruts accumulés (par id), pour re-rendre à l'arrivée.
    private var raw: [BrocolisMessagingClient.RawMessage] = []
    private var seenIds = Set<String>()
    private var cursor: UInt64 = 0
    private var task: Task<Void, Never>?
    /// Vrai après le 1er chargement : on ne sonne QUE pour les messages qui
    /// arrivent ensuite (pas pour tout l'historique à l'ouverture).
    private var didInitialLoad = false
    private var lastReadPosted: UInt64 = 0

    /// Échoue si la clé est illisible ou le serveur non configuré.
    init?(correspondent: NamedKey) {
        guard let key = try? BrocolisCrypto.symmetricKey(fromBase64: correspondent.base64),
              let cid = BrocolisMessagingClient.conversationId(forKeyBase64: correspondent.base64),
              let base = URL(string: MessagingPrefs.serverURL), MessagingPrefs.isConfigured
        else { return nil }
        self.correspondent = correspondent
        self.key = key
        self.conversationId = cid
        self.client = BrocolisMessagingClient(baseURL: base, deviceId: MessagingPrefs.deviceId)
    }

    func start() {
        guard task == nil else { return }
        // Conversation ouverte : le compteur « non lus » de la Live Activity
        // repart à zéro.
        BrocolisLiveActivity.clearUnread()
        // Plancher de confidentialité : on ne recharge JAMAIS ce qui a été effacé
        // à la fermeture — seulement les messages plus récents que le plancher.
        cursor = max(cursor, MessagingPrefs.floor(for: conversationId))
        let floor = cursor
        task = Task { @MainActor [weak self] in
            guard let self else { return }
            // 1) Rattrapage de l'historique (au-dessus du plancher uniquement).
            if let (msgs, cur, readers) = try? await self.client.fetch(conversationId: self.conversationId, after: floor) {
                self.applyReaders(readers)
                self.ingest(msgs, cursor: cur)
            }
            self.didInitialLoad = true
            // 2) Temps réel, avec reconnexion + rattrapage à chaque reprise.
            while !Task.isCancelled {
                do {
                    try await self.client.stream(
                        conversationId: self.conversationId,
                        onMessage: { msg in Task { @MainActor [weak self] in self?.ingest([msg], cursor: nil) } },
                        onRead: { reader, upTo in Task { @MainActor [weak self] in self?.handleRead(reader: reader, upTo: upTo) } }
                    )
                } catch {
                    if Task.isCancelled { break }
                    self.status = loc("Reconnexion…", "Reconnecting…", "Reconectando…")
                    if let (msgs, cur, readers) = try? await self.client.fetch(conversationId: self.conversationId, after: self.cursor) {
                        self.applyReaders(readers)
                        self.ingest(msgs, cursor: cur)
                    }
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    /// Efface les messages affichés et remonte le plancher au dernier message vu :
    /// à la réouverture, l'historique effacé ne réapparaît pas, seuls les
    /// nouveaux messages (seq plus grand) s'afficheront. Appelé à la fermeture.
    func eraseNow() {
        stop()
        MessagingPrefs.setFloor(cursor, for: conversationId)
        raw.removeAll()
        seenIds.removeAll()
        lines = []
        otherReadUpTo = 0
        didInitialLoad = false
        status = nil
        // `cursor` reste au plancher : le prochain start() ne récupère que du neuf.
    }

    private func ingest(_ msgs: [BrocolisMessagingClient.RawMessage], cursor cur: UInt64?) {
        status = nil
        let me = MessagingPrefs.deviceId
        var newIncoming = 0
        for m in msgs where !seenIds.contains(m.id) {
            seenIds.insert(m.id)
            raw.append(m)
            if m.senderId != me { newIncoming += 1 }
        }
        if let cur { cursor = max(cursor, cur) } else {
            cursor = max(cursor, raw.map(\.seq).max() ?? cursor)
        }
        render()
        // Son + vibration UNIQUEMENT pour un nouveau message reçu après l'ouverture.
        if didInitialLoad && newIncoming > 0 {
            notifyNewMessage()
            // La conversation est OUVERTE : le message est vu immédiatement,
            // donc pas de compteur — juste « dernier message de X » sur le 🥦.
            BrocolisLiveActivity.noteIncoming(from: correspondent.name,
                                              count: newIncoming, isReading: true)
        }
        // Accusé de lecture : on a lu jusqu'au dernier seq connu.
        postReadIfNeeded()
    }

    private func handleRead(reader: String, upTo: UInt64) {
        guard reader != MessagingPrefs.deviceId else { return }
        if upTo > otherReadUpTo { otherReadUpTo = upTo }
    }

    private func applyReaders(_ readers: [String: UInt64]) {
        let me = MessagingPrefs.deviceId
        let maxOther = readers.filter { $0.key != me }.values.max() ?? 0
        if maxOther > otherReadUpTo { otherReadUpTo = maxOther }
    }

    private func postReadIfNeeded() {
        let top = raw.map(\.seq).max() ?? 0
        guard top > lastReadPosted else { return }
        lastReadPosted = top
        Task { [weak self] in
            guard let self else { return }
            await self.client.markRead(conversationId: self.conversationId, upTo: top)
        }
    }

    // Tonalité système « message reçu » + vibration légère.
    private func notifyNewMessage() {
        AudioServicesPlaySystemSound(1003) // son court de réception
        UIImpactFeedbackGenerator(style: .medium).impactOccurred()
    }

    private func render() {
        lines = raw
            .sorted { $0.seq < $1.seq }
            .map { m in
                let (text, opened) = BrocolisCrypto.decryptTokens(m.ciphertext, keys: [key])
                return ChatLine(
                    id: m.id,
                    body: opened > 0 ? MediaPayload.body(from: text) : .locked,
                    isMine: m.senderId == MessagingPrefs.deviceId,
                    seq: m.seq
                )
            }
    }

    func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        draft = ""
        sendPlain(text, restoreDraftOnFailure: text)
    }

    /// Envoie une photo (JPEG déjà compressé) — chiffrée comme le texte.
    func sendImage(_ jpeg: Data) {
        sendPlain(MediaPayload.imagePrefix + jpeg.base64EncodedString())
    }

    /// Envoie un message vocal (M4A) — chiffré comme le texte.
    func sendVoice(_ m4a: Data) {
        sendPlain(MediaPayload.audioPrefix + m4a.base64EncodedString())
    }

    /// Chiffre `plain` (texte OU média encodé) et l'envoie. Le serveur ne voit
    /// qu'un jeton — il ignore même si c'est une image ou un vocal.
    private func sendPlain(_ plain: String, restoreDraftOnFailure: String? = nil) {
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.client.send(text: plain, conversationId: self.conversationId, key: self.key)
            } catch {
                await MainActor.run {
                    if let draft = restoreDraftOnFailure { self.draft = draft }
                    self.status = loc("Envoi impossible", "Couldn’t send", "No se pudo enviar")
                }
            }
        }
    }
}

// MARK: - Voix : enregistrement et lecture (AVFoundation)

/// Enregistre un vocal en M4A (AAC mono 32 kbit/s : léger, suffisant pour la
/// voix). Demande la permission micro au premier usage.
final class VoiceRecorder: ObservableObject {
    @Published var isRecording = false
    private var recorder: AVAudioRecorder?
    private var fileURL: URL?

    func start() {
        let session = AVAudioSession.sharedInstance()
        session.requestRecordPermission { [weak self] granted in
            DispatchQueue.main.async {
                guard granted, let self else { return }
                try? session.setCategory(.playAndRecord, mode: .default,
                                         options: [.defaultToSpeaker])
                try? session.setActive(true)
                let url = FileManager.default.temporaryDirectory
                    .appendingPathComponent("brocolis-voix-\(UUID().uuidString).m4a")
                let settings: [String: Any] = [
                    AVFormatIDKey: Int(kAudioFormatMPEG4AAC),
                    AVSampleRateKey: 22_050.0,
                    AVNumberOfChannelsKey: 1,
                    AVEncoderBitRateKey: 32_000,
                ]
                self.recorder = try? AVAudioRecorder(url: url, settings: settings)
                self.fileURL = url
                self.recorder?.record()
                self.isRecording = self.recorder?.isRecording ?? false
            }
        }
    }

    /// Arrête et renvoie l'audio enregistré (nil si vide/refusé).
    func stop() -> Data? {
        recorder?.stop()
        recorder = nil
        isRecording = false
        try? AVAudioSession.sharedInstance().setActive(false, options: .notifyOthersOnDeactivation)
        defer { if let url = fileURL { try? FileManager.default.removeItem(at: url) } }
        guard let url = fileURL, let data = try? Data(contentsOf: url), !data.isEmpty else { return nil }
        return data
    }
}

/// Joue les vocaux déchiffrés (un seul à la fois, icône synchronisée).
final class VoicePlayer: NSObject, ObservableObject, AVAudioPlayerDelegate {
    @Published var playingId: String?
    private var player: AVAudioPlayer?

    func toggle(id: String, data: Data) {
        if playingId == id {
            player?.stop()
            playingId = nil
            return
        }
        try? AVAudioSession.sharedInstance().setCategory(.playback)
        player = try? AVAudioPlayer(data: data)
        player?.delegate = self
        player?.play()
        playingId = player != nil ? id : nil
    }

    func audioPlayerDidFinishPlaying(_ player: AVAudioPlayer, successfully flag: Bool) {
        DispatchQueue.main.async { self.playingId = nil }
    }
}

/// Réduit une photo pour l'envoi chiffré : max 1280 px, JPEG qualité 0,6.
/// (~100-500 Ko : rapide à chiffrer, envoyer et déchiffrer.)
func brocolisJPEG(from image: UIImage, maxDimension: CGFloat = 1280, quality: CGFloat = 0.6) -> Data? {
    let largest = max(image.size.width, image.size.height)
    guard largest > 0 else { return nil }
    let scale = min(1, maxDimension / largest)
    let target = CGSize(width: image.size.width * scale, height: image.size.height * scale)
    let renderer = UIGraphicsImageRenderer(size: target)
    let resized = renderer.image { _ in image.draw(in: CGRect(origin: .zero, size: target)) }
    return resized.jpegData(compressionQuality: quality)
}

// MARK: - Écran : choix du correspondant (parmi les clés)

struct MessagingHomeView: View {
    @State private var keys: [NamedKey] = BrocolisKeyStore.keys
    @State private var serverURL: String = MessagingPrefs.serverURL
    @State private var showServerEdit = false

    var body: some View {
        List {
            if !MessagingPrefs.isConfigured {
                Section {
                    Button {
                        serverURL = MessagingPrefs.serverURL
                        showServerEdit = true
                    } label: {
                        Label(loc("Configurer le serveur", "Configure the server", "Configurar el servidor"), systemImage: "network")
                    }
                } footer: {
                    locText("Renseigne l'URL de ton API `messagerie-api` (ex. `https://…`). Sans elle, impossible d'échanger des messages en direct.", "Enter the URL of your `messagerie-api` API (e.g. `https://…`). Without it, exchanging live messages is impossible.", "Introduce la URL de tu API `messagerie-api` (p. ej. `https://…`). Sin ella, es imposible intercambiar mensajes en directo.")
                }
                .listRowBackground(Color.brocoliCard)
            }

            Section {
                if keys.isEmpty {
                    Text(loc("Aucune clé. Crée-en une ou appaire-toi : chaque clé devient un correspondant ici.", "No key. Create one or pair up: each key becomes a contact here.", "Ninguna clave. Crea una o vincúlate: cada clave se convierte en un contacto aquí."))
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(keys) { key in
                        NavigationLink {
                            BrocolisChatView(correspondent: key)
                        } label: {
                            correspondentRow(key)
                        }
                        .disabled(!MessagingPrefs.isConfigured)
                    }
                }
            } header: {
                Text(loc("Correspondants", "Contacts", "Contactos"))
            } footer: {
                locText("Une **clé = une personne**. Choisis qui : les messages sont chiffrés avec sa clé, lisibles en clair ici et illisibles partout ailleurs.", "One **key = one person**. Choose who: messages are encrypted with their key, readable in the clear here and unreadable everywhere else.", "Una **clave = una persona**. Elige a quién: los mensajes se cifran con su clave, legibles en claro aquí e ilegibles en cualquier otro lugar.")
            }
            .listRowBackground(Color.brocoliCard)
        }
        .brocolisBackground()
        .navigationTitle(loc("Messagerie", "Messaging", "Mensajería"))
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    serverURL = MessagingPrefs.serverURL
                    showServerEdit = true
                } label: { Image(systemName: "gearshape") }
            }
        }
        .onAppear { keys = BrocolisKeyStore.keys }
        .alert(loc("Serveur de messagerie", "Messaging server", "Servidor de mensajería"), isPresented: $showServerEdit) {
            TextField("https://…", text: $serverURL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button(loc("Enregistrer", "Save", "Guardar")) { MessagingPrefs.serverURL = serverURL }
            Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) {}
        } message: {
            Text(loc("URL de l'API messagerie-api (Rust/Actix).", "URL of the messagerie-api API (Rust/Actix).", "URL de la API messagerie-api (Rust/Actix)."))
        }
    }

    private func correspondentRow(_ key: NamedKey) -> some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(brocolisAvatarGradient(for: key.name))
                Text(initials(key.name)).font(.headline).bold().foregroundStyle(.white)
            }
            .frame(width: 46, height: 46)
            .shadow(color: .black.opacity(0.12), radius: 3, y: 1)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name).font(.headline)
                if let phone = BrocolisKeyStore.keyPhone(key.id) {
                    Text(phone).font(.caption).foregroundStyle(.secondary)
                } else {
                    Label(loc("Chiffré avec sa clé", "Encrypted with their key", "Cifrado con su clave"), systemImage: "lock.fill")
                        .font(.caption).foregroundStyle(.secondary).labelStyle(.titleAndIcon)
                }
            }
        }
        .padding(.vertical, 2)
    }

    private func initials(_ name: String) -> String {
        let parts = name.split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }.map(String.init).joined()
        return letters.isEmpty ? "🔑" : letters.uppercased()
    }
}

// MARK: - Écran : conversation

struct BrocolisChatView: View {
    @StateObject private var store: StoreBox

    init(correspondent: NamedKey) {
        _store = StateObject(wrappedValue: StoreBox(correspondent: correspondent))
    }

    var body: some View {
        Group {
            if let store = store.store {
                chat(store)
            } else {
                ContentUnavailableCompat(
                    systemImage: "network.slash",
                    title: loc("Serveur non configuré", "Server not configured", "Servidor no configurado"),
                    message: loc("Renseigne l'URL du serveur de messagerie pour discuter en direct.", "Enter the messaging server URL to chat live.", "Introduce la URL del servidor de mensajería para chatear en directo.")
                )
                .navigationTitle(store.name)
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }

    private func chat(_ store: BrocolisChatStore) -> some View {
        // Verrou partagé : une conversation ouverte se re-verrouille aussi au
        // retour d'arrière-plan (sans redemander Face ID si déjà déverrouillé).
        LockGate { ChatScreen(store: store) }
    }
}

/// Boîte qui tente de créer le store (échoue proprement si non configuré).
@MainActor
final class StoreBox: ObservableObject {
    let store: BrocolisChatStore?
    let name: String
    init(correspondent: NamedKey) {
        self.name = correspondent.name
        self.store = BrocolisChatStore(correspondent: correspondent)
    }
}

private struct ChatScreen: View {
    @ObservedObject var store: BrocolisChatStore
    @Environment(\.scenePhase) private var scenePhase
    @State private var invite: InvitePayload?
    @StateObject private var recorder = VoiceRecorder()
    @StateObject private var player = VoicePlayer()
    @State private var photoItem: PhotosPickerItem?

    /// État de la liaison avec le correspondant, déduit des messages reçus.
    private enum LinkState { case waiting, keyMismatch, connected }
    private var linkState: LinkState {
        let incoming = store.lines.filter { !$0.isMine }
        if incoming.isEmpty { return .waiting }
        if incoming.contains(where: { !$0.locked }) { return .connected }
        return .keyMismatch // il écrit, mais rien ne s'ouvre avec ta clé
    }

    var body: some View {
        VStack(spacing: 0) {
            banner
            messages
            Divider()
            composer
        }
        .brocolisBackground()
        .navigationTitle(store.correspondent.name)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { store.start() }
        .onDisappear { store.stop() }
        .onChange(of: scenePhase) { phase in
            // Fermeture / passage en arrière-plan : on efface les messages
            // affichés (si l'option est active), sinon on coupe juste le flux.
            // `.inactive` (centre de notifications, aperçu multitâche) est
            // transitoire : on n'efface PAS, seul `.background` compte.
            switch phase {
            case .background:
                if MessagingPrefs.eraseOnClose { store.eraseNow() } else { store.stop() }
            case .active:
                store.start()
            default:
                break
            }
        }
        .sheet(item: $invite) { payload in
            MessageComposeView(recipients: payload.recipients, body: payload.body) {
                invite = nil
            }
            .ignoresSafeArea()
        }
    }

    // Bandeau d'état : dit CLAIREMENT pourquoi ça n'avance pas, et propose l'action.
    @ViewBuilder private var banner: some View {
        switch linkState {
        case .connected:
            EmptyView()
        case .waiting:
            bannerBox(color: .orange, icon: "hourglass") {
                Text(loc("En attente de \(store.correspondent.name)", "Waiting for \(store.correspondent.name)", "Esperando a \(store.correspondent.name)")).font(.subheadline).bold()
                locText("Pour qu'il reçoive tes messages, il doit avoir Brocolis 🥦 **et TA clé**. Envoie-la-lui :", "For them to receive your messages, they must have Brocolis 🥦 **and YOUR key**. Send it to them:", "Para que reciba tus mensajes, debe tener Brocolis 🥦 **y TU clave**. Envíasela:")
                    .font(.caption).foregroundStyle(.secondary)
                inviteButton
            }
        case .keyMismatch:
            bannerBox(color: .red, icon: "key.slash") {
                Text(loc("\(store.correspondent.name) écrit, mais vos clés ne correspondent pas", "\(store.correspondent.name) is writing, but your keys don’t match", "\(store.correspondent.name) escribe, pero vuestras claves no coinciden"))
                    .font(.subheadline).bold()
                locText("Ses messages restent 🔒 car sa clé n'est pas exactement la tienne. La solution sûre : refaites l'**appairage** (le même code à deux), ou renvoie-lui ta clé.", "Their messages stay 🔒 because their key isn’t exactly yours. The safe fix: redo the **pairing** (the same code together), or send them your key again.", "Sus mensajes siguen 🔒 porque su clave no es exactamente la tuya. La solución segura: rehaced el **emparejamiento** (el mismo código entre los dos), o vuélvele a enviar tu clave.")
                    .font(.caption).foregroundStyle(.secondary)
                inviteButton
            }
        }
    }

    @ViewBuilder private var inviteButton: some View {
        if let phone = BrocolisKeyStore.keyPhone(store.correspondent.id), canSendMessages() {
            Button {
                invite = InvitePayload(
                    recipients: [phone],
                    body: brocolisInviteBody(contactName: store.correspondent.name,
                                             keyBase64: store.correspondent.base64)
                )
            } label: {
                Label(loc("Inviter par iMessage", "Invite via iMessage", "Invitar por iMessage"), systemImage: "paperplane.fill")
                    .font(.caption).bold()
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .padding(.top, 2)
        }
    }

    private func bannerBox<Content: View>(color: Color, icon: String,
                                          @ViewBuilder _ content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon).foregroundStyle(color)
            VStack(alignment: .leading, spacing: 4) { content() }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(color.opacity(0.10))
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // « Distribué » (arrivé sur le serveur) ou « Lu » (le correspondant a ouvert),
    // sous ton dernier message envoyé — comme iMessage.
    @ViewBuilder private var deliveryStatus: some View {
        if let last = store.lines.last, last.isMine {
            Text(store.otherReadUpTo >= last.seq ? loc("Lu", "Read", "Leído") : loc("Distribué", "Delivered", "Entregado"))
                .font(.caption2).foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .trailing)
                .padding(.trailing, 6)
        }
    }

    private var messages: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 6) {
                    if store.lines.isEmpty {
                        emptyChat
                    }
                    ForEach(store.lines) { bubble($0) }
                    deliveryStatus
                }
                .padding()
                .animation(.spring(response: 0.35, dampingFraction: 0.8), value: store.lines)
            }
            .background(
                LinearGradient(colors: [Color(red: 238.0 / 255, green: 248.0 / 255, blue: 226.0 / 255),
                                        Color(red: 224.0 / 255, green: 241.0 / 255, blue: 208.0 / 255)],
                               startPoint: .top, endPoint: .bottom)
            )
            .overlay(alignment: .top) {
                if let status = store.status {
                    Text(status).font(.caption).foregroundStyle(.secondary)
                        .padding(6).background(.ultraThinMaterial, in: Capsule()).padding(.top, 6)
                }
            }
            .onChange(of: store.lines.count) { _ in
                if let last = store.lines.last {
                    withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                }
            }
        }
    }

    private var emptyChat: some View {
        VStack(spacing: 10) {
            ZStack {
                Circle().fill(brocolisAvatarGradient(for: store.correspondent.name))
                Text(String(store.correspondent.name.prefix(1)).uppercased())
                    .font(.largeTitle).bold().foregroundStyle(.white)
            }
            .frame(width: 76, height: 76)
            .shadow(color: .black.opacity(0.15), radius: 6, y: 3)
            Text(store.correspondent.name).font(.title3).bold()
            Label(loc("Chiffré de bout en bout", "End-to-end encrypted", "Cifrado de extremo a extremo"), systemImage: "lock.fill")
                .font(.caption).foregroundStyle(.secondary)
            Text(loc("Dis bonjour 👋", "Say hello 👋", "Di hola 👋"))
                .font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 40)
    }

    // Bulles avec « queue » : le coin côté expéditeur est resserré.
    // Texte, photo ou vocal — et « 🔒 » uniforme quand la clé manque.
    private func bubble(_ m: ChatLine) -> some View {
        let shape = ChatBubbleShape(isMine: m.isMine)
        return Group {
            switch m.body {
            case .text(let text):
                Text(text)
                    .padding(.horizontal, 13).padding(.vertical, 9)
                    .background { bubbleFill(shape, isMine: m.isMine) }
                    .foregroundStyle(m.isMine ? .white : .primary)
                    .contextMenu {
                        Button {
                            UIPasteboard.general.string = text
                        } label: { Label(loc("Copier", "Copy", "Copiar"), systemImage: "doc.on.doc") }
                    }

            case .locked:
                Label(loc("Message chiffré", "Encrypted message", "Mensaje cifrado"), systemImage: "lock.fill")
                    .font(.subheadline)
                    .padding(.horizontal, 13).padding(.vertical, 9)
                    .background { shape.fill(Color(.secondarySystemBackground)) }
                    .foregroundStyle(.secondary)

            case .image(let data):
                if let ui = UIImage(data: data) {
                    Image(uiImage: ui)
                        .resizable()
                        .scaledToFit()
                        .frame(maxWidth: 230, maxHeight: 300)
                        .clipShape(shape)
                        .overlay(shape.stroke(Color.black.opacity(0.08)))
                } else {
                    Label(loc("Photo illisible", "Unreadable photo", "Foto ilegible"), systemImage: "photo")
                        .font(.subheadline).foregroundStyle(.secondary)
                        .padding(10)
                        .background { shape.fill(Color(.secondarySystemBackground)) }
                }

            case .audio(let data):
                Button {
                    player.toggle(id: m.id, data: data)
                } label: {
                    HStack(spacing: 8) {
                        Image(systemName: player.playingId == m.id ? "stop.circle.fill" : "play.circle.fill")
                            .font(.title2)
                        Image(systemName: "waveform")
                        Text(loc("Vocal", "Voice message", "Mensaje de voz")).font(.subheadline).bold()
                    }
                    .padding(.horizontal, 13).padding(.vertical, 9)
                    .background { bubbleFill(shape, isMine: m.isMine) }
                    .foregroundStyle(m.isMine ? .white : .primary)
                }
                .buttonStyle(.plain)
            }
        }
        .frame(maxWidth: .infinity, alignment: m.isMine ? .trailing : .leading)
        .padding(m.isMine ? .leading : .trailing, 48)
        .transition(.scale(scale: 0.85, anchor: m.isMine ? .bottomTrailing : .bottomLeading)
            .combined(with: .opacity))
        .id(m.id)
    }

    @ViewBuilder private func bubbleFill(_ shape: ChatBubbleShape, isMine: Bool) -> some View {
        if isMine {
            shape.fill(brocolisBubbleGradient)
                .shadow(color: .green.opacity(0.25), radius: 3, y: 1)
        } else {
            shape.fill(Color(.secondarySystemBackground))
        }
    }

    private var canSend: Bool {
        !store.draft.trimmingCharacters(in: .whitespaces).isEmpty
    }

    private var composer: some View {
        HStack(spacing: 10) {
            if recorder.isRecording {
                // Enregistrement en cours : point rouge + stop = envoi chiffré.
                HStack(spacing: 8) {
                    Circle().fill(.red).frame(width: 10, height: 10)
                    Text(loc("Enregistrement…", "Recording…", "Grabando…")).font(.subheadline).foregroundStyle(.secondary)
                    Spacer()
                    Button {
                        if let data = recorder.stop() { store.sendVoice(data) }
                        UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    } label: {
                        Image(systemName: "arrow.up")
                            .font(.system(size: 17, weight: .bold))
                            .foregroundStyle(.white)
                            .frame(width: 36, height: 36)
                            .background(Circle().fill(brocolisBubbleGradient))
                    }
                }
                .padding(.horizontal, 6)
            } else {
                // Photo (chiffrée) — le sélecteur système, sans permission.
                PhotosPicker(selection: $photoItem, matching: .images) {
                    Image(systemName: "photo")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Color(red: 0.18, green: 0.62, blue: 0.29))
                        .frame(width: 32, height: 32)
                }
                // Vocal (chiffré).
                Button {
                    recorder.start()
                } label: {
                    Image(systemName: "mic")
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Color(red: 0.18, green: 0.62, blue: 0.29))
                        .frame(width: 32, height: 32)
                }
                TextField(loc("Message chiffré…", "Encrypted message…", "Mensaje cifrado…"), text: $store.draft, axis: .vertical)
                    .padding(.horizontal, 14).padding(.vertical, 9)
                    .background(Capsule().fill(Color(.secondarySystemBackground)))
                    .lineLimit(1...4)
                Button {
                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    store.send()
                } label: {
                    Image(systemName: "arrow.up")
                        .font(.system(size: 17, weight: .bold))
                        .foregroundStyle(.white)
                        .frame(width: 36, height: 36)
                        .background(Circle().fill(canSend ? AnyShapeStyle(brocolisBubbleGradient)
                                                          : AnyShapeStyle(Color.gray.opacity(0.4))))
                }
                .disabled(!canSend)
                .scaleEffect(canSend ? 1.0 : 0.9)
                .animation(.spring(response: 0.3, dampingFraction: 0.6), value: canSend)
            }
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
        .background(.bar)
        .onChange(of: photoItem) { item in
            guard let item else { return }
            Task {
                if let data = try? await item.loadTransferable(type: Data.self),
                   let image = UIImage(data: data),
                   let jpeg = brocolisJPEG(from: image) {
                    store.sendImage(jpeg)
                }
                photoItem = nil
            }
        }
    }
}

// ContentUnavailableView n'existe qu'en iOS 17 : petit repli.
private struct ContentUnavailableCompat: View {
    let systemImage: String
    let title: String
    let message: String
    var body: some View {
        if #available(iOS 17.0, *) {
            ContentUnavailableView(title, systemImage: systemImage, description: Text(message))
        } else {
            VStack(spacing: 10) {
                Image(systemName: systemImage).font(.largeTitle).foregroundStyle(.secondary)
                Text(title).font(.headline)
                Text(message).font(.subheadline).foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }
            .padding()
        }
    }
}

#Preview {
    NavigationStack { MessagingHomeView() }
}

// MARK: - Verrouillage des messages (Face ID / code, « comme Apple »)

enum BrocolisAppLock {
    /// Authentifie via Face ID / Touch ID, avec repli automatique sur le code de
    /// l'appareil (mécanisme standard Apple). `true` si déverrouillé.
    static func authenticate(reason: String) async -> Bool {
        let ctx = LAContext()
        ctx.localizedCancelTitle = loc("Annuler", "Cancel", "Cancelar")
        var err: NSError?
        // .deviceOwnerAuthentication : biométrie si disponible, sinon code appareil.
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            // Aucun code d'appareil configuré : impossible de verrouiller, on laisse passer.
            return true
        }
        return await withCheckedContinuation { cont in
            ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
                cont.resume(returning: ok)
            }
        }
    }
}

/// État de verrou PARTAGÉ par toute la messagerie : déverrouiller une fois
/// déverrouille l'ensemble (accueil + conversation ouverte), et un seul passage
/// en arrière-plan re-verrouille tout. Évite les doubles demandes de Face ID.
final class BrocolisLockManager: ObservableObject {
    static let shared = BrocolisLockManager()
    @Published var unlocked = false
    @Published var failed = false
    private var authenticating = false
    private init() {}

    func lock() {
        unlocked = false
        failed = false
    }

    /// Déclenche une authentification si nécessaire (idempotent : pas de double
    /// prompt si une demande est déjà en cours ou si c'est déjà déverrouillé).
    /// Appelé depuis le fil principal (SwiftUI).
    func ensureUnlocked() {
        guard MessagingPrefs.lockEnabled else { unlocked = true; return }
        guard !unlocked, !authenticating else { return }
        authenticating = true
        failed = false
        Task {
            let ok = await BrocolisAppLock.authenticate(reason: loc("Voir vos messages Brocolis 🥦", "See your Brocolis 🥦 messages", "Ver tus mensajes de Brocolis 🥦"))
            await MainActor.run {
                self.authenticating = false
                self.unlocked = ok
                self.failed = !ok
            }
        }
    }
}

/// Enveloppe une vue derrière le verrou partagé (si activé dans les réglages).
struct LockGate<Content: View>: View {
    @ViewBuilder var content: () -> Content
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject private var lock = BrocolisLockManager.shared

    var body: some View {
        Group {
            if !MessagingPrefs.lockEnabled || lock.unlocked {
                content()
            } else {
                lockScreen
            }
        }
        .onAppear { lock.ensureUnlocked() }
        .onChange(of: scenePhase) { phase in
            switch phase {
            case .background: lock.lock() // re-verrouille à la fermeture
            case .active: lock.ensureUnlocked()
            default: break
            }
        }
    }

    private var lockScreen: some View {
        VStack(spacing: 18) {
            Text("🥦").font(.system(size: 64))
            Image(systemName: "lock.fill").font(.largeTitle).foregroundStyle(.green)
            Text(loc("Messages verrouillés", "Messages locked", "Mensajes bloqueados")).font(.title3).bold()
            Text(loc("Déverrouille avec Face ID ou ton code pour voir tes messages.", "Unlock with Face ID or your passcode to see your messages.", "Desbloquea con Face ID o tu código para ver tus mensajes."))
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button {
                lock.ensureUnlocked()
            } label: {
                Label(loc("Déverrouiller", "Unlock", "Desbloquear"), systemImage: "faceid")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.green)
            if lock.failed {
                Text(loc("Déverrouillage annulé ou échoué. Réessaie.", "Unlock canceled or failed. Try again.", "Desbloqueo cancelado o fallido. Inténtalo de nuevo."))
                    .font(.footnote)
                    .foregroundStyle(.red)
            }
        }
        .padding(32)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color(.systemBackground))
    }
}
