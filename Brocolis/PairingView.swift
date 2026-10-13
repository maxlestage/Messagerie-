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
import CoreImage.CIFilterBuiltins

struct PairingView: View {
    @State private var code = ""
    @State private var status = ""
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var isWorking = false
    @State private var task: Task<Void, Never>?
    /// Les participants vus dans le salon (clés publiques seulement), en direct.
    @State private var roomPeers: [PairingPeer] = []
    /// Offre à montrer si l'appairage ajouterait une clé au-delà du gratuit.
    @State private var paywallReason: BrocolisPaidFeature?

    private let codeAlphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    var body: some View {
        Form {
            Section {
                locText("Saisissez **le même code** sur tous les téléphones.", "Enter **the same code** on every phone.", "Escribe **el mismo código** en todos los teléfonos.")
                    .font(.subheadline)
            }
            .listRowBackground(Color.brocoliCard)

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
            .listRowBackground(Color.brocoliCard)

            Section(loc("Code de jumelage", "Pairing code", "Código de emparejamiento")) {
                HStack {
                    TextField(loc("ex. ABC123", "e.g. ABC123", "ej. ABC123"), text: $code)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.characters)
                        .font(.system(.title3, design: .monospaced))
                    Button(loc("Générer", "Generate", "Generar")) { code = randomCode() }
                        .buttonStyle(.bordered)
                        .disabled(isWorking)
                }
            }
            .listRowBackground(Color.brocoliCard)

            // Le code en QR : l'appareil photo de l'autre téléphone ouvre le
            // salon en direct sur le site, avec le code déjà rempli.
            if !trimmedCode.isEmpty, let qr = qrImage(for: salonURL) {
                Section {
                    VStack(spacing: 10) {
                        Image(uiImage: qr)
                            .interpolation(.none)
                            .resizable()
                            .scaledToFit()
                            .frame(width: 180, height: 180)
                            .padding(10)
                            .background(Color.white, in: RoundedRectangle(cornerRadius: 14))
                        Text(trimmedCode.uppercased())
                            .font(.system(.title2, design: .monospaced).weight(.bold))
                        ShareLink(item: salonURL,
                                  message: Text(loc("Mon code Brocolis 🥦 : \(trimmedCode.uppercased())",
                                                    "My Brocolis 🥦 code: \(trimmedCode.uppercased())",
                                                    "Mi código Brocolis 🥦: \(trimmedCode.uppercased())"))) {
                            Label(loc("Partager le code", "Share the code", "Compartir el código"),
                                  systemImage: "square.and.arrow.up")
                        }
                        .buttonStyle(.bordered)
                    }
                    .frame(maxWidth: .infinity)
                } footer: {
                    Text(loc("Fais scanner ce QR ou partage le code : ton correspondant saisit le même code dans son app.",
                             "Have them scan this QR or share the code: your contact enters the same code in their app.",
                             "Haz escanear este QR o comparte el código: tu contacto introduce el mismo código en su app."))
                }
                .listRowBackground(Color.brocoliCard)
            }

            // Le salon en direct : qui a déjà publié sa clé publique sous ce code.
            if isWorking || !roomPeers.isEmpty {
                Section(loc("Dans le salon", "In the room", "En la sala")) {
                    if roomPeers.isEmpty {
                        HStack(spacing: 10) {
                            ProgressView()
                            Text(loc("On guette les arrivées…", "Watching for arrivals…", "Vigilando las llegadas…"))
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        ForEach(roomPeers, id: \.peerId) { peer in
                            HStack(spacing: 10) {
                                Text("🥦")
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(loc("Participant", "Participant", "Participante") + " · " + String(peer.peerId.prefix(6)))
                                        .font(.subheadline.weight(.semibold))
                                    Text(loc("clé publique", "public key", "clave pública") + " : " + String(peer.pub.prefix(14)) + "…")
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .transition(.move(edge: .leading).combined(with: .opacity))
                        }
                    }
                }
                .animation(.spring(response: 0.4, dampingFraction: 0.8), value: roomPeers.map(\.peerId))
                .listRowBackground(Color.brocoliCard)
            }

            Section {
                actionButton(title: loc("Appairer à deux", "Pair one-to-one", "Emparejar entre dos"), systemImage: "person.2.fill") {
                    run { try await pairTwo() }
                }
            } footer: {
                Text(loc("Pour 2 personnes : chacune dérive la clé directement.", "For 2 people: each one derives the key directly.", "Para 2 personas: cada una deriva la clave directamente."))
            }
            .listRowBackground(Color.brocoliCard)

            Section {
                actionButton(title: loc("Créer le groupe (je distribue la clé)", "Create the group (I distribute the key)", "Crear el grupo (yo distribuyo la clave)"), systemImage: "person.3.fill") {
                    run { try await createGroup() }
                }
                actionButton(title: loc("Rejoindre le groupe", "Join the group", "Unirse al grupo"), systemImage: "person.fill.badge.plus") {
                    run { try await joinGroup() }
                }
            } header: {
                Text(loc("Groupe (3+)", "Group (3+)", "Grupo (3+)"))
            } footer: {
                Text(loc("Ordre : les membres touchent d’abord « Rejoindre le groupe », puis le fondateur touche « Créer le groupe ». Le fondateur génère la clé et la distribue chiffrée à chacun.", "Order: members first tap “Join the group”, then the founder taps “Create the group”. The founder generates the key and distributes it encrypted to each member.", "Orden: los miembros tocan primero «Unirse al grupo», luego el fundador toca «Crear el grupo». El fundador genera la clave y la distribuye cifrada a cada uno."))
            }
            .listRowBackground(Color.brocoliCard)

            if isWorking {
                Section {
                    Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) { cancel() }
                }
                .listRowBackground(Color.brocoliCard)
            }

            if !status.isEmpty {
                Section { Text(status).font(.subheadline) }
                    .listRowBackground(Color.brocoliCard)
            }

            if let fp = fingerprint {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Label(loc("Clé en place", "Key in place", "Clave en su lugar"), systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                        Text(loc("Empreinte de sécurité", "Security fingerprint", "Huella de seguridad"))
                            .font(.caption).foregroundStyle(.secondary)
                        Text(fp)
                            .font(.system(.title3, design: .monospaced))
                            .textSelection(.enabled)
                    }
                } footer: {
                    Text(loc("Comparez cette empreinte de vive voix avec les autres. Si elle est identique pour tous, la clé n’a pas été interceptée.", "Compare this fingerprint out loud with the others. If it is identical for everyone, the key has not been intercepted.", "Compara esta huella en voz alta con los demás. Si es idéntica para todos, la clave no ha sido interceptada."))
                }
                .listRowBackground(Color.brocoliCard)
            }
        }
        .brocolisBackground()
        .navigationTitle(loc("Appairage", "Pairing", "Emparejamiento"))
        .navigationBarTitleDisplayMode(.inline)
        .onDisappear { cancel() }
        .sheet(item: $paywallReason) { reason in PaywallView(reason: reason) }
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
        case .idle:    return loc("En attente — saisis un code, puis lance l’appairage.", "Waiting — enter a code, then start pairing.", "Esperando — escribe un código, luego inicia el emparejamiento.")
        case .working: return loc("Appairage en cours…", "Pairing in progress…", "Emparejamiento en curso…")
        case .success: return loc("✅ Tout bon — clé en place, vous êtes appairés.", "✅ All good — key in place, you’re paired.", "✅ Todo bien — clave en su lugar, estáis emparejados.")
        case .error:   return loc("Échec — vérifie le code et réessaie.", "Failed — check the code and retry.", "Error — comprueba el código y reinténtalo.")
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

    // MARK: QR et salon

    private var trimmedCode: String {
        code.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// La page « Salon » du site, servie par le serveur, avec le code rempli.
    private var salonURL: URL {
        let lang = Locale.current.language.languageCode?.identifier ?? "fr"
        let site = ["fr", "en", "es"].contains(lang) ? lang : "fr"
        let encoded = trimmedCode.uppercased()
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        return URL(string: "\(BrocolisKeyStore.serverURL)/\(site)/salon/?code=\(encoded)")
            ?? URL(string: BrocolisKeyStore.serverURL)!
    }

    private func qrImage(for url: URL) -> UIImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(url.absoluteString.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage?.transformed(by: CGAffineTransform(scaleX: 8, y: 8)),
              let cg = CIContext().createCGImage(output, from: output.extent) else { return nil }
        return UIImage(cgImage: cg)
    }

    @MainActor private func showPeers(_ peers: [PairingPeer], excluding myPub: String) {
        roomPeers = peers.filter { $0.pub != myPub }
    }

    // MARK: Orchestration

    private func run(_ body: @escaping () async throws -> Void) {
        code = code.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
        // Garde-fou : sans code, on explique au lieu de rester inerte.
        guard !code.isEmpty else {
            status = loc("⚠️ Entre d’abord un code de jumelage (le MÊME que ton correspondant), ou touche « Générer » et partage-le-lui.", "⚠️ Enter a pairing code first (the SAME as your contact’s), or tap “Generate” and share it with them.", "⚠️ Escribe primero un código de emparejamiento (el MISMO que tu contacto), o toca «Generar» y compártelo con él.")
            return
        }
        // Un appairage ajoute une clé : même limite que créer ou importer
        // (3 clés en gratuit), vérifiée AVANT de rejoindre le salon.
        if case .needs(_, let feature) = BrocolisPlan.gateForAddingKey(
            currentKeyCount: BrocolisKeyStore.keys.count, tier: BrocolisPlan.tier) {
            paywallReason = feature
            return
        }
        isWorking = true
        fingerprint = nil
        roomPeers = []
        task = Task {
            do {
                try await body()
            } catch is CancellationError {
                // annulé
            } catch {
                finish(error: (error as? LocalizedError)?.errorDescription ?? error.localizedDescription)
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

        update(loc("Publication de ta clé publique…", "Publishing your public key…", "Publicando tu clave pública…"))
        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)
        update(loc("En attente du correspondant…", "Waiting for the contact…", "Esperando al contacto…"))

        for _ in 0..<40 {
            if Task.isCancelled { return }
            let peers = try await client.fetch(code: code, peerId: peerId)
            await showPeers(peers, excluding: myPub)
            if let peer = peers.first(where: { $0.pub != myPub }) {
                let derived = try BrocolisKeyAgreement.derive(myPrivate: priv, peerPublicBase64: peer.pub)
                BrocolisKeyStore.setPairingPeerIds([peer.peerId])
                applyKey(derived.symmetricKeyBase64, fingerprint: derived.fingerprint,
                         message: loc("✅ Appairé. Brocolis est actif.", "✅ Paired. Brocolis is active.", "✅ Emparejado. Brocolis está activo."), peerId: peerId)
                return
            }
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
        finish(error: loc("Délai dépassé : le correspondant n’a pas rejoint.", "Timed out: the contact didn’t join.", "Tiempo agotado: el contacto no se ha unido."))
    }

    // MARK: Flux — fondateur du groupe

    private func createGroup() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        // Le fondateur a la clé tout de suite.
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()
        applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                 message: loc("Clé de groupe créée. Distribution en cours…", "Group key created. Distribution in progress…", "Clave de grupo creada. Distribución en curso…"), peerId: peerId, keepWorking: true)

        // Publie sa clé publique pour que les membres puissent déballer.
        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)

        var wrappedTo = Set<String>()
        for _ in 0..<30 {
            if Task.isCancelled { return }
            let peers = try await client.fetch(code: code, peerId: peerId)
            await showPeers(peers, excluding: myPub)
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
                update(loc("Clé distribuée à \(wrappedTo.count) membre(s). Touche « Annuler » quand tout le monde a reçu.", "Key distributed to \(wrappedTo.count) member(s). Tap “Cancel” when everyone has received it.", "Clave distribuida a \(wrappedTo.count) miembro(s). Toca «Cancelar» cuando todos la hayan recibido."))
            }
            try await Task.sleep(nanoseconds: 2_000_000_000)
        }
        finish(message: loc("Distribution terminée (\(wrappedTo.count) membre(s)).", "Distribution complete (\(wrappedTo.count) member(s)).", "Distribución completada (\(wrappedTo.count) miembro(s))."))
    }

    // MARK: Flux — membre du groupe

    private func joinGroup() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        update(loc("Publication de ta clé publique…", "Publishing your public key…", "Publicando tu clave pública…"))
        let others = try await client.publish(code: code, peerId: peerId, pub: myPub)
        await showPeers(others, excluding: myPub)
        update(loc("En attente de la clé du groupe…", "Waiting for the group key…", "Esperando la clave del grupo…"))

        for _ in 0..<60 {
            if Task.isCancelled { return }
            if let wrap = try await client.fetchWrap(code: code, peerId: peerId) {
                let groupKey = try BrocolisKeyAgreement.unwrapGroupKey(
                    blobBase64: wrap.blob, fromPeerPublicBase64: wrap.fromPub, myPrivate: priv)
                BrocolisKeyStore.setPairingPeerIds([wrap.from])
                applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                         message: loc("✅ Clé de groupe reçue. Brocolis est actif.", "✅ Group key received. Brocolis is active.", "✅ Clave de grupo recibida. Brocolis está activo."), peerId: peerId)
                return
            }
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
        finish(error: loc("Délai dépassé : aucune clé de groupe reçue. Le fondateur a-t-il lancé la distribution ?", "Timed out: no group key received. Did the founder start the distribution?", "Tiempo agotado: no se ha recibido ninguna clave de grupo. ¿El fundador ha iniciado la distribución?"))
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
