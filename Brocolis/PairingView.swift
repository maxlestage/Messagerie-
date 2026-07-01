//
//  PairingView.swift
//  Brocolis 🥦 (app uniquement)
//
//  Appairage automatique via le serveur de rendez-vous (X25519) :
//   - À deux : échange des clés publiques, dérivation directe de la clé AES.
//   - Groupe : un fondateur génère une clé de groupe et la distribue, emballée
//     (chiffrée) pour chaque membre. Tout le monde obtient la même clé,
//     automatiquement, sans copier-coller.
//

import SwiftUI
import CryptoKit

struct PairingView: View {
    @State private var code = ""
    @State private var status = ""
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var isWorking = false
    @State private var task: Task<Void, Never>?

    private let codeAlphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    var body: some View {
        Form {
            Section {
                Text("Saisissez **le même code** sur tous les téléphones.")
                    .font(.subheadline)
            }

            // LED d'état : vert = tout bon (appairés), orange = en cours,
            // rouge = échec, gris = en attente.
            Section {
                HStack(spacing: 14) {
                    ZStack {
                        Circle()
                            .fill(ledColor)
                            .frame(width: 24, height: 24)
                            .shadow(color: ledColor.opacity(0.9),
                                    radius: pairState == .success ? 9 : 3)
                        if pairState == .working {
                            Circle()
                                .stroke(ledColor.opacity(0.5), lineWidth: 3)
                                .frame(width: 24, height: 24)
                        }
                    }
                    Text(ledLabel)
                        .font(.subheadline)
                        .foregroundStyle(pairState == .success ? .green : .primary)
                    Spacer()
                }
                .animation(.easeInOut, value: pairState)
            }

            Section("Code de jumelage") {
                HStack {
                    TextField("ex. ABC123", text: $code)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.characters)
                        .font(.system(.title3, design: .monospaced))
                    Button("Générer") { code = randomCode() }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                }
            }

            Section {
                actionButton(title: "Appairer à deux", systemImage: "person.2.fill") {
                    run { try await pairTwo() }
                }
            } footer: {
                Text("Pour 2 personnes : chacune dérive la clé directement.")
            }

            Section {
                actionButton(title: "Créer le groupe (je distribue la clé)", systemImage: "person.3.fill") {
                    run { try await createGroup() }
                }
                actionButton(title: "Rejoindre le groupe", systemImage: "person.fill.badge.plus") {
                    run { try await joinGroup() }
                }
            } header: {
                Text("Groupe (3+)")
            } footer: {
                Text("Ordre : les membres touchent d’abord « Rejoindre le groupe », puis le fondateur touche « Créer le groupe ». Le fondateur génère la clé et la distribue chiffrée à chacun.")
            }

            if isWorking {
                Section {
                    Button("Annuler", role: .cancel) { cancel() }
                }
            }

            if !status.isEmpty {
                Section { Text(status).font(.subheadline) }
            }

            if let fp = fingerprint {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Label("Clé en place", systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                        Text("Empreinte de sécurité")
                            .font(.caption).foregroundStyle(.secondary)
                        Text(fp)
                            .font(.system(.title3, design: .monospaced))
                            .textSelection(.enabled)
                    }
                } footer: {
                    Text("Comparez cette empreinte de vive voix avec les autres. Si elle est identique pour tous, la clé n’a pas été interceptée.")
                }
            }
        }
        .navigationTitle("Appairage")
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { cancel() }
    }

    // MARK: État visuel (LED)

    private enum PairState: Equatable { case idle, working, success, error }

    private var pairState: PairState {
        if isWorking { return .working }
        if fingerprint != nil { return .success }
        if status.hasPrefix("⚠️") { return .error }
        return .idle
    }

    private var ledColor: Color {
        switch pairState {
        case .idle:    return .gray
        case .working: return .orange
        case .success: return .green
        case .error:   return .red
        }
    }

    private var ledLabel: String {
        switch pairState {
        case .idle:    return "En attente — saisis un code, puis lance l’appairage."
        case .working: return "Appairage en cours…"
        case .success: return "✅ Tout bon — clé en place, vous êtes appairés."
        case .error:   return "Échec — vérifie le code et réessaie."
        }
    }

    // MARK: UI helpers

    private func actionButton(title: String, systemImage: String, action: @escaping () -> Void) -> some View {
        // On ne désactive PLUS le bouton quand le code est vide : sinon il ne se
        // passe rien quand on touche, sans explication. À la place, `run` détecte
        // le code manquant et le signale clairement.
        Button(action: action) {
            Label(title, systemImage: systemImage)
        }
        .disabled(isWorking)
    }

    private func randomCode(length: Int = 6) -> String {
        String((0..<length).map { _ in codeAlphabet.randomElement()! })
    }

    // MARK: Orchestration

    private func run(_ body: @escaping () async throws -> Void) {
        code = code.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        // Garde-fou : sans code, on explique au lieu de rester inerte.
        guard !code.isEmpty else {
            status = "⚠️ Entre d’abord un code de jumelage (le MÊME que ton correspondant), ou touche « Générer » et partage-le-lui."
            return
        }
        isWorking = true
        fingerprint = nil
        task = Task {
            do {
                try await body()
            } catch is CancellationError {
                // annulé
            } catch {
                await finish(error: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
            }
        }
    }

    private func cancel() {
        task?.cancel()
        task = nil
        if isWorking { isWorking = false }
    }

    private var client: PairingClient { PairingClient(baseURL: BrocolisKeyStore.serverURL) }

    // MARK: Flux — à deux

    private func pairTwo() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        await update("Publication de ta clé publique…")
        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)
        await update("En attente du correspondant…")

        for _ in 0..<40 {
            if Task.isCancelled { return }
            let peers = try await client.fetch(code: code, peerId: peerId)
            if let peer = peers.first(where: { $0.pub != myPub }) {
                let derived = try BrocolisKeyAgreement.derive(myPrivate: priv, peerPublicBase64: peer.pub)
                BrocolisKeyStore.setPairingPeerIds([peer.peerId])
                applyKey(derived.symmetricKeyBase64, fingerprint: derived.fingerprint,
                         message: "✅ Appairé. Brocolis est actif.", peerId: peerId)
                return
            }
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
        await finish(error: "Délai dépassé : le correspondant n’a pas rejoint.")
    }

    // MARK: Flux — fondateur du groupe

    private func createGroup() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        // Le fondateur a la clé tout de suite.
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()
        applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                 message: "Clé de groupe créée. Distribution en cours…", peerId: peerId, keepWorking: true)

        // Publie sa clé publique pour que les membres puissent déballer.
        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)

        var wrappedTo = Set<String>()
        for _ in 0..<30 {
            if Task.isCancelled { return }
            let peers = try await client.fetch(code: code, peerId: peerId)
            let newPeers = peers.filter { !wrappedTo.contains($0.peerId) && $0.pub != myPub }
            if !newPeers.isEmpty {
                var items: [WrapItem] = []
                for p in newPeers {
                    let blob = try BrocolisKeyAgreement.wrapGroupKey(
                        groupKeyBase64: groupKey, forPeerPublicBase64: p.pub, myPrivate: priv)
                    items.append(WrapItem(toPeerId: p.peerId, blob: blob))
                }
                try await client.postWraps(code: code, fromPeerId: peerId, fromPub: myPub, items: items)
                newPeers.forEach { wrappedTo.insert($0.peerId) }
                BrocolisKeyStore.setPairingPeerIds(Array(wrappedTo))
                await update("Clé distribuée à \(wrappedTo.count) membre(s). Touche « Annuler » quand tout le monde a reçu.")
            }
            try await Task.sleep(nanoseconds: 2_000_000_000)
        }
        await finish(message: "Distribution terminée (\(wrappedTo.count) membre(s)).")
    }

    // MARK: Flux — membre du groupe

    private func joinGroup() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        await update("Publication de ta clé publique…")
        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)
        await update("En attente de la clé du groupe…")

        for _ in 0..<60 {
            if Task.isCancelled { return }
            if let wrap = try await client.fetchWrap(code: code, peerId: peerId) {
                let groupKey = try BrocolisKeyAgreement.unwrapGroupKey(
                    blobBase64: wrap.blob, fromPeerPublicBase64: wrap.fromPub, myPrivate: priv)
                BrocolisKeyStore.setPairingPeerIds([wrap.from])
                applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                         message: "✅ Clé de groupe reçue. Brocolis est actif.", peerId: peerId)
                return
            }
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
        await finish(error: "Délai dépassé : aucune clé de groupe reçue. Le fondateur a-t-il lancé la distribution ?")
    }

    // MARK: Application du résultat

    private func applyKey(_ keyB64: String, fingerprint fp: String, message: String, peerId: String, keepWorking: Bool = false) {
        let name = code.trimmingCharacters(in: .whitespacesAndNewlines)
        BrocolisKeyStore.addKey(name: name.isEmpty ? "Appairage" : name, base64: keyB64)
        BrocolisKeyStore.setPairingFingerprint(fp)
        BrocolisKeyStore.setPairingIdentity(code: name, peerId: peerId)
        BrocolisKeyStore.setActive(true)
        BrocolisLiveActivity.sync(active: true)
        // Enregistre le push token de la Live Activity (dès qu'il est disponible)
        // pour autoriser les mises à jour à distance.
        Task { await BrocolisPush.registerLiveActivityToken() }
        Task { @MainActor in
            fingerprint = fp
            status = message
            if !keepWorking { isWorking = false }
        }
    }

    @MainActor private func update(_ s: String) { status = s }

    @MainActor private func finish(message: String) {
        status = message
        isWorking = false
    }

    @MainActor private func finish(error: String) {
        status = "⚠️ " + error
        isWorking = false
    }
}

#Preview {
    NavigationStack { PairingView() }
}
