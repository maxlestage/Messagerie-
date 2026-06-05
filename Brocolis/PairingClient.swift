//
//  PairingClient.swift
//  Brocolis 🥦 (app uniquement)
//
//  Client du serveur de rendez-vous : publie sa clé publique sous un code et
//  récupère celle du correspondant. Le serveur ne voit que des clés publiques.
//

import Foundation

struct PairingPeer: Decodable {
    let peerId: String
    let pub: String
}

private struct PairingResponse: Decodable {
    let peers: [PairingPeer]
}

enum PairingError: LocalizedError {
    case badURL
    case server(Int)
    case network(String)

    var errorDescription: String? {
        switch self {
        case .badURL: return "URL de serveur invalide."
        case .server(let code): return "Le serveur a répondu \(code)."
        case .network(let m): return "Erreur réseau : \(m)"
        }
    }
}

struct PairingClient {
    let baseURL: String

    /// Publie sa clé publique ; renvoie les clés publiques des autres participants.
    func publish(code: String, peerId: String, pub: String) async throws -> [PairingPeer] {
        try await request(
            method: "POST",
            path: "/pair",
            body: ["code": code, "peerId": peerId, "pub": pub]
        )
    }

    /// Récupère les clés publiques des autres participants du code.
    func fetch(code: String, peerId: String) async throws -> [PairingPeer] {
        let c = code.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? code
        let p = peerId.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? peerId
        return try await request(method: "GET", path: "/pair?code=\(c)&peerId=\(p)", body: nil)
    }

    private func request(method: String, path: String, body: [String: String]?) async throws -> [PairingPeer] {
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
                throw PairingError.network("réponse inattendue")
            }
            guard (200..<300).contains(http.statusCode) else {
                throw PairingError.server(http.statusCode)
            }
            return try JSONDecoder().decode(PairingResponse.self, from: data).peers
        } catch let e as PairingError {
            throw e
        } catch {
            throw PairingError.network(error.localizedDescription)
        }
    }
}
