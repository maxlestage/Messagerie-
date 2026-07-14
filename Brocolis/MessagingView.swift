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

// MARK: - Préférences messagerie (App Group)

/// Petits réglages persistés dans l'App Group : identité d'appareil (pour
/// distinguer « mes » messages) et URL du serveur de messagerie.
enum MessagingPrefs {
    private static var defaults: UserDefaults? {
        UserDefaults(suiteName: BrocolisKeyStore.appGroup)
    }
    private static let deviceIdName = "messaging_device_id"
    private static let serverURLName = "messaging_server_url"

    /// Identité stable de CET appareil (attribuée une fois). Sert de `senderId`
    /// et d'en-tête `X-User-Id`. Ne révèle rien : c'est un UUID opaque.
    static var deviceId: String {
        if let id = defaults?.string(forKey: deviceIdName), !id.isEmpty { return id }
        let id = UUID().uuidString
        defaults?.set(id, forKey: deviceIdName)
        return id
    }

    /// URL de l'API de messagerie. Par défaut : le même serveur que
    /// l'appairage (ton instance Heroku), qui héberge aussi la messagerie.
    /// Modifiable si tu déploies ailleurs.
    static var serverURL: String {
        get {
            let saved = defaults?.string(forKey: serverURLName) ?? ""
            return saved.isEmpty ? BrocolisKeyStore.serverURL : saved
        }
        set { defaults?.set(newValue.trimmingCharacters(in: .whitespacesAndNewlines),
                            forKey: serverURLName) }
    }

    static var isConfigured: Bool { URL(string: serverURL) != nil && !serverURL.isEmpty }
}

// MARK: - Modèle affiché

/// Un message prêt à afficher : déchiffré localement.
struct ChatLine: Identifiable, Equatable {
    let id: String
    let text: String
    let isMine: Bool
    let locked: Bool   // vrai si on n'a pas pu déchiffrer (clé différente)
}

// MARK: - Client réseau (ne transporte que du chiffré)

/// Parle à `messagerie-api`. Chiffre/déchiffre avec une clé Brocolis ; le
/// serveur ne voit que des jetons `[[BROCOLIS:v1:…]]`.
struct BrocolisMessagingClient {
    let baseURL: URL
    let deviceId: String

    /// Identifiant de conversation dérivé de la clé partagée (empreinte SHA-256,
    /// base64url). Déterministe et à sens unique : le serveur ne peut pas
    /// remonter à la clé, mais les deux correspondants tombent sur le même id.
    static func conversationId(forKeyBase64 b64: String) -> String? {
        guard let key = try? BrocolisCrypto.symmetricKey(fromBase64: b64) else { return nil }
        let raw = key.withUnsafeBytes { Data(Array($0)) }
        var hasher = SHA256()
        hasher.update(data: Data("brocolis-conv-v1".utf8))
        hasher.update(data: raw)
        return Data(Array(hasher.finalize())).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func request(_ path: String, method: String = "GET") -> URLRequest {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.setValue(deviceId, forHTTPHeaderField: "X-User-Id")
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        return req
    }

    /// Chiffre `text` avec `key` et l'envoie. Le corps chiffré est un jeton
    /// Brocolis (interopérable avec le reste de l'app).
    func send(text: String, conversationId: String, key: SymmetricKey) async throws {
        let token = try BrocolisCrypto.encryptToken(Data(text.utf8), key: key)
        var req = request("v1/messages", method: "POST")
        let body: [String: Any] = [
            "id": UUID().uuidString,
            "conversationId": conversationId,
            "senderId": deviceId,
            "ciphertext": token,
        ]
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (_, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw URLError(.badServerResponse)
        }
    }

    /// Message brut renvoyé par le serveur (on ignore les champs superflus).
    struct RawMessage: Decodable {
        let id: String
        let senderId: String
        let ciphertext: String
        let seq: UInt64
    }
    private struct Page: Decodable { let messages: [RawMessage]; let cursor: UInt64 }

    /// Récupère l'historique (au-delà du curseur `after`).
    func fetch(conversationId: String, after: UInt64) async throws -> ([RawMessage], UInt64) {
        var comps = URLComponents(url: baseURL.appendingPathComponent("v1/messages"),
                                  resolvingAgainstBaseURL: false)!
        comps.queryItems = [
            URLQueryItem(name: "conversationId", value: conversationId),
            URLQueryItem(name: "after", value: String(after)),
        ]
        var req = URLRequest(url: comps.url!)
        req.setValue(deviceId, forHTTPHeaderField: "X-User-Id")
        let (data, _) = try await URLSession.shared.data(for: req)
        let page = try JSONDecoder().decode(Page.self, from: data)
        return (page.messages, page.cursor)
    }

    /// Flux temps réel (SSE). Appelle `onMessage` pour chaque nouveau message ;
    /// se termine (throw) si la connexion tombe.
    func stream(conversationId: String, onMessage: @escaping (RawMessage) -> Void) async throws {
        var comps = URLComponents(url: baseURL.appendingPathComponent("v1/stream"),
                                  resolvingAgainstBaseURL: false)!
        comps.queryItems = [URLQueryItem(name: "conversationId", value: conversationId)]
        var req = URLRequest(url: comps.url!)
        req.timeoutInterval = 3600
        req.setValue(deviceId, forHTTPHeaderField: "X-User-Id")
        req.setValue("text/event-stream", forHTTPHeaderField: "Accept")

        let (bytes, resp) = try await URLSession.shared.bytes(for: req)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw URLError(.badServerResponse)
        }
        for try await line in bytes.lines {
            guard line.hasPrefix("data:") else { continue }
            let json = line.dropFirst("data:".count).trimmingCharacters(in: .whitespaces)
            if let d = json.data(using: .utf8),
               let msg = try? JSONDecoder().decode(RawMessage.self, from: d) {
                onMessage(msg)
            }
        }
    }
}

// MARK: - Store d'une conversation (déchiffre pour l'affichage)

@MainActor
final class BrocolisChatStore: ObservableObject {
    @Published private(set) var lines: [ChatLine] = []
    @Published private(set) var status: String?
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
        task = Task { @MainActor [weak self] in
            guard let self else { return }
            // 1) Rattrapage de l'historique.
            if let (msgs, cur) = try? await self.client.fetch(conversationId: self.conversationId, after: 0) {
                self.ingest(msgs, cursor: cur)
            }
            // 2) Temps réel, avec reconnexion + rattrapage à chaque reprise.
            while !Task.isCancelled {
                do {
                    try await self.client.stream(conversationId: self.conversationId) { msg in
                        Task { @MainActor [weak self] in self?.ingest([msg], cursor: nil) }
                    }
                } catch {
                    if Task.isCancelled { break }
                    self.status = "Reconnexion…"
                    if let (msgs, cur) = try? await self.client.fetch(conversationId: self.conversationId, after: self.cursor) {
                        self.ingest(msgs, cursor: cur)
                    }
                    try? await Task.sleep(nanoseconds: 2_000_000_000)
                }
            }
        }
    }

    func stop() { task?.cancel(); task = nil }

    private func ingest(_ msgs: [BrocolisMessagingClient.RawMessage], cursor cur: UInt64?) {
        status = nil
        for m in msgs where !seenIds.contains(m.id) {
            seenIds.insert(m.id)
            raw.append(m)
        }
        if let cur { cursor = max(cursor, cur) } else {
            cursor = max(cursor, raw.map(\.seq).max() ?? cursor)
        }
        render()
    }

    private func render() {
        lines = raw
            .sorted { $0.seq < $1.seq }
            .map { m in
                let (text, opened) = BrocolisCrypto.decryptTokens(m.ciphertext, keys: [key])
                return ChatLine(
                    id: m.id,
                    text: opened > 0 ? text : "🔒 message chiffré",
                    isMine: m.senderId == MessagingPrefs.deviceId,
                    locked: opened == 0
                )
            }
    }

    func send() {
        let text = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        draft = ""
        Task { [weak self] in
            guard let self else { return }
            do {
                try await self.client.send(text: text, conversationId: self.conversationId, key: self.key)
            } catch {
                await MainActor.run { self.draft = text; self.status = "Envoi impossible" }
            }
        }
    }
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
                        Label("Configurer le serveur", systemImage: "network")
                    }
                } footer: {
                    Text("Renseigne l'URL de ton API `messagerie-api` (ex. `https://…`). Sans elle, impossible d'échanger des messages en direct.")
                }
            }

            Section {
                if keys.isEmpty {
                    Text("Aucune clé. Crée-en une ou appaire-toi : chaque clé devient un correspondant ici.")
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
                Text("Correspondants")
            } footer: {
                Text("Une **clé = une personne**. Choisis qui : les messages sont chiffrés avec sa clé, lisibles en clair ici et illisibles partout ailleurs.")
            }
        }
        .navigationTitle("Messagerie")
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
        .alert("Serveur de messagerie", isPresented: $showServerEdit) {
            TextField("https://…", text: $serverURL)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
            Button("Enregistrer") { MessagingPrefs.serverURL = serverURL }
            Button("Annuler", role: .cancel) {}
        } message: {
            Text("URL de l'API messagerie-api (Rust/Actix).")
        }
    }

    private func correspondentRow(_ key: NamedKey) -> some View {
        HStack(spacing: 12) {
            ZStack {
                Circle().fill(Color.green.opacity(0.2))
                Text(initials(key.name)).font(.headline).foregroundStyle(.green)
            }
            .frame(width: 42, height: 42)
            VStack(alignment: .leading, spacing: 2) {
                Text(key.name).font(.headline)
                Label("Chiffré avec sa clé", systemImage: "lock.fill")
                    .font(.caption).foregroundStyle(.secondary).labelStyle(.titleAndIcon)
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
                    title: "Serveur non configuré",
                    message: "Renseigne l'URL du serveur de messagerie pour discuter en direct."
                )
                .navigationTitle(store.name)
                .navigationBarTitleDisplayMode(.inline)
            }
        }
    }

    private func chat(_ store: BrocolisChatStore) -> some View {
        ChatScreen(store: store)
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

    var body: some View {
        VStack(spacing: 0) {
            messages
            Divider()
            composer
        }
        .navigationTitle(store.correspondent.name)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { store.start() }
        .onDisappear { store.stop() }
    }

    private var messages: some View {
        ScrollViewReader { proxy in
            ScrollView {
                LazyVStack(spacing: 8) {
                    ForEach(store.lines) { bubble($0) }
                }
                .padding()
            }
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

    private func bubble(_ m: ChatLine) -> some View {
        Text(m.text)
            .padding(.horizontal, 12).padding(.vertical, 8)
            .background(m.isMine ? Color.green : Color(.secondarySystemBackground))
            .foregroundStyle(m.isMine ? .white : (m.locked ? .secondary : .primary))
            .clipShape(RoundedRectangle(cornerRadius: 18))
            .frame(maxWidth: .infinity, alignment: m.isMine ? .trailing : .leading)
            .padding(m.isMine ? .leading : .trailing, 40)
            .id(m.id)
    }

    private var composer: some View {
        HStack(spacing: 8) {
            TextField("Message chiffré…", text: $store.draft, axis: .vertical)
                .textFieldStyle(.roundedBorder)
                .lineLimit(1...4)
            Button { store.send() } label: {
                Image(systemName: "arrow.up.circle.fill").font(.title)
            }
            .disabled(store.draft.trimmingCharacters(in: .whitespaces).isEmpty)
        }
        .padding(8)
        .background(.bar)
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
