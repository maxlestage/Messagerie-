//
//  PairingView.swift
//  Brocolis 🥦 (app uniquement)
//
//  Appairage automatique : les deux personnes saisissent le MÊME code court ;
//  l'app échange les clés publiques via le serveur de rendez-vous et dérive
//  seule la clé AES partagée (X25519). On affiche une empreinte à comparer.
//

import SwiftUI
import CryptoKit

struct PairingView: View {
    @Environment(\.dismiss) private var dismiss

    @State private var serverURL = BrocolisKeyStore.serverURL
    @State private var code = ""
    @State private var status = ""
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var isPairing = false
    @State private var pairingTask: Task<Void, Never>?

    private let codeAlphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    var body: some View {
        Form {
            Section {
                Text("Saisissez **le même code** sur les deux téléphones, sur le même serveur. L’app récupère la clé de l’autre et dérive la clé partagée automatiquement.")
                    .font(.subheadline)
            }

            Section("Serveur de rendez-vous") {
                TextField("https://relais.example.com", text: $serverURL)
                    .keyboardType(.URL)
                    .autocorrectionDisabled()
                    .textInputAutocapitalization(.never)
            }

            Section("Code de jumelage") {
                HStack {
                    TextField("ex. ABC123", text: $code)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.characters)
                        .font(.system(.title3, design: .monospaced))
                    Button("Générer") { code = randomCode() }
                        .buttonStyle(.bordered)
                }
            }

            Section {
                Button {
                    startPairing()
                } label: {
                    if isPairing {
                        HStack { ProgressView(); Text("Appairage…") }
                    } else {
                        Label("Appairer", systemImage: "link")
                    }
                }
                .disabled(isPairing || serverURL.trimmingCharacters(in: .whitespaces).isEmpty || code.trimmingCharacters(in: .whitespaces).isEmpty)

                if isPairing {
                    Button("Annuler", role: .cancel) { cancelPairing() }
                }
            } footer: {
                if !status.isEmpty { Text(status) }
            }

            if let fp = fingerprint {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("Appairé", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                        Text("Empreinte de sécurité")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text(fp)
                            .font(.system(.title3, design: .monospaced))
                            .textSelection(.enabled)
                    }
                } footer: {
                    Text("Comparez cette empreinte de vive voix avec votre correspondant. Si elle est identique des deux côtés, la connexion n’a pas été interceptée.")
                }
            }
        }
        .navigationTitle("Appairage")
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { cancelPairing() }
    }

    // MARK: Logique

    private func randomCode(length: Int = 6) -> String {
        String((0..<length).map { _ in codeAlphabet.randomElement()! })
    }

    private func startPairing() {
        BrocolisKeyStore.setServerURL(serverURL)
        let normalizedCode = code.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        code = normalizedCode

        isPairing = true
        status = "Publication de ta clé publique…"
        fingerprint = nil

        let client = PairingClient(baseURL: serverURL.trimmingCharacters(in: .whitespaces))
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        pairingTask = Task {
            do {
                _ = try await client.publish(code: normalizedCode, peerId: peerId, pub: myPub)
                await update("En attente du correspondant…")

                // Sondage jusqu'à 60 s.
                for _ in 0..<40 {
                    if Task.isCancelled { return }
                    let peers = try await client.fetch(code: normalizedCode, peerId: peerId)
                    if let peer = peers.first(where: { $0.pub != myPub }) {
                        try finishPairing(priv: priv, peerPub: peer.pub)
                        return
                    }
                    try await Task.sleep(nanoseconds: 1_500_000_000)
                }
                await finish(error: "Délai dépassé : le correspondant n’a pas rejoint le code.")
            } catch is CancellationError {
                // annulé par l'utilisateur
            } catch {
                let message = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                await finish(error: message)
            }
        }
    }

    private func finishPairing(priv: Curve25519.KeyAgreement.PrivateKey, peerPub: String) throws {
        let derived = try BrocolisKeyAgreement.derive(myPrivate: priv, peerPublicBase64: peerPub)
        BrocolisKeyStore.setKey(derived.symmetricKeyBase64)
        BrocolisKeyStore.setPairingFingerprint(derived.fingerprint)
        BrocolisKeyStore.setActive(true)
        Task { @MainActor in
            fingerprint = derived.fingerprint
            status = "✅ Appairage réussi. Brocolis est actif."
            isPairing = false
        }
    }

    @MainActor private func update(_ s: String) { status = s }

    @MainActor private func finish(error: String) {
        status = "⚠️ " + error
        isPairing = false
    }

    private func cancelPairing() {
        pairingTask?.cancel()
        pairingTask = nil
        if isPairing { isPairing = false }
    }
}

#Preview {
    NavigationStack { PairingView() }
}
