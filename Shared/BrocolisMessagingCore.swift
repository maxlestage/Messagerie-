//
//  BrocolisMessagingCore.swift
//  Brocolis 🥦 (partagé app iPhone + app montre)
//
//  Cœur RÉUTILISABLE de la messagerie live : préférences (identité d'appareil,
//  URL du serveur, plancher de confidentialité), modèle d'un message affiché,
//  enveloppe des médias et client réseau. AUCUNE UI ici : le fichier compile
//  tel quel sur iOS ET sur watchOS (l'app montre parle au même serveur, avec
//  les mêmes clés, synchronisées depuis l'iPhone).
//

import Foundation
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

    /// Adopte l'identité d'un autre appareil (synchronisation montre ← iPhone) :
    /// la montre envoie et lit comme « toi », pas comme un correspondant.
    static func adoptDeviceId(_ id: String) {
        guard !id.isEmpty else { return }
        defaults?.set(id, forKey: deviceIdName)
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

    // MARK: Confidentialité

    private static let eraseOnCloseName = "messaging_erase_on_close"
    private static let lockEnabledName = "messaging_lock_enabled"
    private static let floorPrefix = "messaging_floor_" // + conversationId

    /// Efface les messages affichés à la fermeture de l'app : on ne recharge
    /// plus l'historique déjà vu, seuls les NOUVEAUX messages réapparaissent.
    /// Activé par défaut (confidentialité). Voir `floor(for:)`.
    static var eraseOnClose: Bool {
        get { defaults?.object(forKey: eraseOnCloseName) as? Bool ?? true }
        set { defaults?.set(newValue, forKey: eraseOnCloseName) }
    }

    /// Exige Face ID / Touch ID / code de l'appareil pour VOIR les messages
    /// (comme le verrouillage proposé par Apple). Activé par défaut.
    static var lockEnabled: Bool {
        get { defaults?.object(forKey: lockEnabledName) as? Bool ?? true }
        set { defaults?.set(newValue, forKey: lockEnabledName) }
    }

    /// « Plancher » d'une conversation : le plus grand `seq` déjà effacé. Le
    /// store ne recharge que les messages STRICTEMENT au-dessus. Effacer à la
    /// fermeture = remonter ce plancher au dernier message vu.
    static func floor(for conversationId: String) -> UInt64 {
        UInt64(defaults?.integer(forKey: floorPrefix + conversationId) ?? 0)
    }

    static func setFloor(_ seq: UInt64, for conversationId: String) {
        defaults?.set(Int(seq), forKey: floorPrefix + conversationId)
    }
}

// MARK: - Modèle affiché

/// Un message prêt à afficher : déchiffré localement.
/// Contenu d'un message affiché. Sans la bonne clé, TOUT est `.locked` :
/// texte illisible, image invisible, vocal inécoutable.
enum ChatBody: Equatable {
    case text(String)
    case image(Data)   // JPEG déchiffré
    case audio(Data)   // M4A déchiffré
    case locked        // clé absente/différente → rien n'est montré
}

struct ChatLine: Identifiable, Equatable {
    let id: String
    let body: ChatBody
    let isMine: Bool
    let seq: UInt64

    var locked: Bool { body == .locked }
}

/// Enveloppe des médias DANS le texte chiffré : le serveur ne voit même pas
/// qu'il s'agit d'une image ou d'un vocal — juste un jeton plus long.
enum MediaPayload {
    static let imagePrefix = "BRCM1:img:"
    static let audioPrefix = "BRCM1:aud:"

    /// Décode un texte déchiffré en contenu affichable.
    static func body(from clear: String) -> ChatBody {
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
    private struct Page: Decodable {
        let messages: [RawMessage]
        let cursor: UInt64
        let readers: [String: UInt64]?
    }
    // Évènement SSE : soit un message, soit un accusé de lecture {type:"read"}.
    private struct ReadEvent: Decodable { let type: String; let reader: String; let upTo: UInt64 }

    /// Récupère l'historique + les curseurs de lecture (`readers`).
    func fetch(conversationId: String, after: UInt64) async throws
        -> ([RawMessage], UInt64, [String: UInt64]) {
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
        return (page.messages, page.cursor, page.readers ?? [:])
    }

    /// Accusé de lecture : signale qu'on a lu jusqu'à `upTo`.
    func markRead(conversationId: String, upTo: UInt64) async {
        var req = request("v1/read", method: "POST")
        req.httpBody = try? JSONSerialization.data(withJSONObject: [
            "conversationId": conversationId, "upTo": upTo,
        ])
        _ = try? await URLSession.shared.data(for: req)
    }

    /// Flux temps réel (SSE). `onMessage` pour un message, `onRead` pour un
    /// accusé de lecture. Se termine (throw) si la connexion tombe.
    func stream(conversationId: String,
                onMessage: @escaping (RawMessage) -> Void,
                onRead: @escaping (String, UInt64) -> Void) async throws {
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
            guard let d = json.data(using: .utf8) else { continue }
            if let ev = try? JSONDecoder().decode(ReadEvent.self, from: d), ev.type == "read" {
                onRead(ev.reader, ev.upTo)
            } else if let msg = try? JSONDecoder().decode(RawMessage.self, from: d) {
                onMessage(msg)
            }
        }
    }
}
