//
//  PairingClient.swift
//  Brocolis 🥦 (app uniquement)
//
//  Client du serveur de rendez-vous : échange des clés publiques (appairage à
//  deux) et distribue les clés de groupe emballées (X25519). Le serveur ne voit
//  que des clés publiques et des blobs chiffrés.
//
//  v3 (docs/SECURITE.md §8.4) : chaque publication porte aussi le paquet de
//  clés v3 de l'appareil (`bundle`, public et signé), et la liste des
//  participants rend celui des autres. Champ optionnel : un ancien client
//  n'en envoie pas, un ancien serveur l'ignore.
//

import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct PairingPeer: Decodable {
    let peerId: String
    let pub: String
    /// Son paquet de clés v3 (base64), s'il en a publié un.
    let bundle: String?
}

struct WrapItem {
    let toPeerId: String
    let blob: String
}

struct WrapInbox: Decodable {
    let from: String
    let fromPub: String
    let blob: String
}

/// Ce que l'appairage dit du correspondant v3 (docs/SECURITE.md §8.4).
struct BrocolisV3Contact {
    /// Son paquet, s'il en a publié un ET que j'ai publié le mien.
    let bundle: String?
    /// À deux (sinon : clé de groupe, jamais de v3).
    let duo: Bool

    /// L'empreinte à comparer : celle qui couvre les identités v3 si l'on est
    /// à deux avec un appareil v3, sinon celle d'avant.
    func fingerprint(key: String, legacy: String) -> String {
        guard duo, let fp = BrocolisV3.pairingFingerprint(keyBase64: key, peerBundle: bundle) else { return legacy }
        return fp
    }

    /// Celui qui rejoint : l'invitant est `wrap.from` / `wrap.fromPub` ; à
    /// deux si le salon ne compte qu'un autre participant (moi exclu).
    static func joining(room: [PairingPeer], wrap: WrapInbox, myBundle: String?) -> BrocolisV3Contact {
        let inviter = room.first { $0.peerId == wrap.from && $0.pub == wrap.fromPub }
        return BrocolisV3Contact(bundle: myBundle == nil ? nil : inviter?.bundle, duo: room.count <= 1)
    }
}

private struct PairingResponse: Decodable { let peers: [PairingPeer] }
private struct WrapResponse: Decodable { let wrap: WrapInbox? }

enum PairingError: LocalizedError {
    case badURL
    case server(Int)
    case network(String)

    var errorDescription: String? {
        switch self {
        case .badURL: return loc("URL de serveur invalide.", "Invalid server URL.", "URL de servidor no válida.")
        case .server(let code): return loc("Le serveur a répondu \(code).", "The server responded \(code).", "El servidor respondió \(code).")
        case .network(let m): return loc("Erreur réseau : \(m)", "Network error: \(m)", "Error de red: \(m)")
        }
    }
}

struct PairingClient {
    let baseURL: String

    /// Publie sa clé publique ; renvoie les clés publiques des autres participants.
    /// `host` : c'est l'invitant — le serveur ne laisse que lui remettre la clé.
    /// `bundle` : mon paquet de clés v3 (`BrocolisV3.myBundle()`), s'il y en a.
    func publish(code: String, peerId: String, pub: String, host: Bool = false,
                 bundle: String? = nil) async throws -> [PairingPeer] {
        var body: [String: Any] = ["code": code, "peerId": peerId, "pub": pub, "host": host]
        if let bundle { body["bundle"] = bundle }
        let data = try await raw(method: "POST", path: "/pair", body: body)
        return try JSONDecoder().decode(PairingResponse.self, from: data).peers
    }

    /// Récupère les clés publiques des autres participants du code.
    func fetch(code: String, peerId: String) async throws -> [PairingPeer] {
        let data = try await raw(method: "GET", path: pairQuery(code: code, peerId: peerId), body: nil)
        return try JSONDecoder().decode(PairingResponse.self, from: data).peers
    }

    /// (Fondateur) Dépose les clés de groupe emballées pour chaque membre.
    func postWraps(code: String, fromPeerId: String, fromPub: String, items: [WrapItem]) async throws {
        let itemsJSON = items.map { ["toPeerId": $0.toPeerId, "blob": $0.blob] }
        _ = try await raw(method: "POST", path: "/wrap",
                          body: ["code": code, "fromPeerId": fromPeerId, "fromPub": fromPub, "items": itemsJSON])
    }

    /// (Membre) Récupère la clé de groupe emballée qui lui est destinée, si dispo.
    func fetchWrap(code: String, peerId: String) async throws -> WrapInbox? {
        let data = try await raw(method: "GET", path: "/wrap?" + query(code: code, peerId: peerId), body: nil)
        return try JSONDecoder().decode(WrapResponse.self, from: data).wrap
    }

    /// Enregistre le push token de la Live Activity sous (code, peerId) : un
    /// correspondant pourra ensuite déclencher une mise à jour à distance.
    func registerLiveActivityToken(code: String, peerId: String, token: String) async throws {
        _ = try await raw(method: "POST", path: "/push/live-activity/token",
                          body: ["code": code, "peerId": peerId, "token": token])
    }

    /// Déclenche une mise à jour (ou fin) de la Live Activity d'un correspondant,
    /// via son token enregistré sous (code, peerId).
    func updateLiveActivity(
        code: String, peerId: String, event: String, contentState: [String: Any]
    ) async throws {
        _ = try await raw(method: "POST", path: "/push/live-activity/update",
                          body: ["code": code, "peerId": peerId, "event": event,
                                 "contentState": contentState])
    }

    // MARK: Bas niveau

    private func pairQuery(code: String, peerId: String) -> String {
        "/pair?" + query(code: code, peerId: peerId)
    }

    private func query(code: String, peerId: String) -> String {
        let c = code.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? code
        let p = peerId.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? peerId
        return "code=\(c)&peerId=\(p)"
    }

    private func raw(method: String, path: String, body: Any?) async throws -> Data {
        let base = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL
        guard let url = URL(string: base + path) else { throw PairingError.badURL }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.timeoutInterval = 15
        if let body {
            req.setValue("application/json", forHTTPHeaderField: "content-type")
            req.httpBody = try JSONSerialization.data(withJSONObject: body)
        }

        do {
            let (data, resp) = try await URLSession.shared.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw PairingError.network(loc("réponse inattendue", "unexpected response", "respuesta inesperada"))
            }
            guard (200..<300).contains(http.statusCode) else {
                throw PairingError.server(http.statusCode)
            }
            return data
        } catch let e as PairingError {
            throw e
        } catch {
            throw PairingError.network(error.localizedDescription)
        }
    }
}
