//
//  PairingView.swift
//  Brocolis 🥦 (app uniquement)
//
//  Appairage automatique via le serveur de rendez-vous (X25519), en deux
//  gestes : « J'invite » (affiche un QR code) ou « Je rejoins » (le scanne, ou
//  tape le code). L'invitant génère la clé et la remet, chiffrée pour chacun,
//  à toute personne qui rejoint : à 2 comme en groupe, dans n'importe quel
//  ordre. Le « Mode compatible » garde l'ancien appairage à deux (dérivation
//  directe) pour les versions qui n'ont que lui.
//

import SwiftUI
import CryptoKit
import CoreImage.CIFilterBuiltins
import VisionKit

struct PairingView: View {
    /// Deux gestes seulement : j'invite (je montre un code) ou je rejoins
    /// (je scanne / tape le code). Ça marche à 2 comme à 10.
    private enum Mode: Hashable { case invite, join }

    @State private var mode: Mode
    @State private var contactName = ""
    @State private var code: String
    /// Code reçu par lien (brocolis://pair?code=…) : on rejoint tout seul.
    private let initialCode: String?
    /// Fin de validité de l'invitation affichée (le salon garde 10 min).
    @State private var inviteDeadline: Date?
    @State private var status = ""
    @State private var fingerprint: String? = nil
    @State private var isWorking = false
    @State private var task: Task<Void, Never>?
    /// Les participants vus dans le salon (clés publiques seulement), en direct.
    @State private var roomPeers: [PairingPeer] = []
    /// Combien de personnes ont reçu la clé (côté invitant).
    @State private var delivered = 0
    @State private var showScanner = false
    /// Offre à montrer si l'appairage ajouterait une clé au-delà du gratuit.
    @State private var paywallReason: BrocolisPaidFeature?
    @Environment(\.dismiss) private var dismiss

    private let codeAlphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")

    init(initialCode: String? = nil) {
        self.initialCode = initialCode
        _mode = State(initialValue: initialCode == nil ? .invite : .join)
        _code = State(initialValue: initialCode ?? "")
    }

    var body: some View {
        Form {
            Section {
                TextField(loc("Avec qui ? (ex. Clément) — facultatif", "With whom? (e.g. Sam) — optional", "¿Con quién? (ej. Clara) — opcional"), text: $contactName)
                    .textInputAutocapitalization(.words)
                    .disabled(isWorking)
                Picker("", selection: $mode) {
                    Text(loc("J’invite", "I invite", "Invito")).tag(Mode.invite)
                    Text(loc("Je rejoins", "I join", "Me uno")).tag(Mode.join)
                }
                .pickerStyle(.segmented)
                .disabled(isWorking)
            } footer: {
                Text(mode == .invite
                     ? loc("À côté : fais scanner ton QR. Loin : envoie le lien par message — il le touche, son app s’ouvre et vous êtes appairés. Marche à 2 comme en groupe.", "Nearby: have them scan your QR. Far away: send the link by message — they tap it, their app opens and you’re paired. Works for 2 or a group.", "Cerca: que escaneen tu QR. Lejos: envía el enlace por mensaje — lo tocan, su app se abre y quedáis emparejados. Funciona entre 2 o en grupo.")
                     : loc("Tu as reçu un lien ? Touche-le, tout se fait seul. Sinon scanne le QR ou tape le code.", "Got a link? Just tap it, everything happens on its own. Otherwise scan the QR or type the code.", "¿Recibiste un enlace? Tócalo y todo se hace solo. Si no, escanea el QR o escribe el código."))
            }
            .listRowBackground(Color.brocoliCard)

            if mode == .invite {
                inviteSection
            } else {
                joinSection
            }

            if !status.isEmpty {
                Section {
                    HStack(spacing: 10) {
                        if isWorking { ProgressView() }
                        Text(status).font(.subheadline)
                    }
                }
                .listRowBackground(Color.brocoliCard)
            }

            if let fp = fingerprint {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        Label(loc("Appairés ✅", "Paired ✅", "Emparejados ✅"), systemImage: "checkmark.seal.fill")
                            .foregroundStyle(.green)
                        Text(loc("Empreinte de sécurité", "Security fingerprint", "Huella de seguridad"))
                            .font(.caption).foregroundStyle(.secondary)
                        Text(fp)
                            .font(.system(.title3, design: .monospaced))
                            .textSelection(.enabled)
                    }
                } footer: {
                    Text(loc("Facultatif : comparez cette empreinte de vive voix — par un appel si vous êtes loin. Identique pour tous = la clé n’a pas été interceptée.", "Optional: compare this fingerprint out loud — on a call if you’re far apart. Identical for everyone = the key wasn’t intercepted.", "Opcional: comparad esta huella en voz alta — por llamada si estáis lejos. Idéntica para todos = la clave no ha sido interceptada."))
                }
                .listRowBackground(Color.brocoliCard)
            }

            Section {
                DisclosureGroup(loc("Mode compatible (anciennes versions)", "Compatibility mode (older versions)", "Modo compatible (versiones antiguas)")) {
                    Text(loc("Si l’autre téléphone n’a que « Appairer à deux » : saisissez le même code de part et d’autre, puis touchez ce bouton.", "If the other phone only has “Pair one-to-one”: enter the same code on both, then tap this button.", "Si el otro teléfono solo tiene «Emparejar entre dos»: escribid el mismo código en ambos y tocad este botón."))
                        .font(.footnote).foregroundStyle(.secondary)
                    codeField
                    Button {
                        run { try await pairTwo() }
                    } label: {
                        Label(loc("Appairer à deux", "Pair one-to-one", "Emparejar entre dos"), systemImage: "person.2.fill")
                    }
                    .disabled(isWorking)
                }
            }
            .listRowBackground(Color.brocoliCard)
        }
        .brocolisBackground()
        .navigationTitle(loc("Appairage", "Pairing", "Emparejamiento"))
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: mode) { _ in
            cancel()
            status = ""
            fingerprint = nil
            roomPeers = []
            code = ""
        }
        .onAppear {
            // Arrivé par un lien : on rejoint directement.
            if let c = initialCode, !c.isEmpty, !isWorking, fingerprint == nil {
                run { try await joinGroup() }
            }
        }
        .onDisappear { cancel() }
        // Pendant l'attente, l'écran ne se met pas en veille.
        .onChange(of: isWorking) { working in
            UIApplication.shared.isIdleTimerDisabled = working
        }
        .sheet(item: $paywallReason) { reason in PaywallView(reason: reason) }
        .sheet(isPresented: $showScanner) {
            QRScannerSheet { scanned in
                showScanner = false
                if let c = Self.scannedCode(from: scanned) {
                    code = c
                    run { try await joinGroup() }
                } else {
                    status = loc("⚠️ Ce QR n’est pas un code Brocolis.", "⚠️ This QR isn’t a Brocolis code.", "⚠️ Este QR no es un código Brocolis.")
                }
            }
        }
    }

    // MARK: J'invite

    @ViewBuilder private var inviteSection: some View {
        if isWorking, !trimmedCode.isEmpty, let qr = qrImage(for: salonURL) {
            Section {
                VStack(spacing: 10) {
                    Image(uiImage: qr)
                        .interpolation(.none)
                        .resizable()
                        .scaledToFit()
                        .frame(width: 210, height: 210)
                        .padding(10)
                        .background(Color.white, in: RoundedRectangle(cornerRadius: 14))
                    Text(trimmedCode)
                        .font(.system(.largeTitle, design: .monospaced).weight(.bold))
                        .kerning(4)
                    ShareLink(item: salonURL,
                              message: Text(loc("Appairons-nous sur Brocolis 🥦 (dans les 10 min) : touche ce lien puis « Ouvrir dans l’app ». Ou dans l’app : Appairage → Je rejoins → code \(trimmedCode).",
                                                "Let’s pair on Brocolis 🥦 (within 10 min): tap this link, then “Open in the app”. Or in the app: Pairing → I join → code \(trimmedCode).",
                                                "Emparejémonos en Brocolis 🥦 (en 10 min): toca este enlace y luego «Abrir en la app». O en la app: Emparejamiento → Me uno → código \(trimmedCode)."))) {
                        Label(loc("Envoyer le lien (à distance)", "Send the link (remote)", "Enviar el enlace (a distancia)"), systemImage: "paperplane.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.brocoliGreen)
                    if isWorking, let deadline = inviteDeadline, deadline > Date() {
                        HStack(spacing: 4) {
                            Text(loc("Valable encore", "Still valid for", "Válido aún"))
                            Text(timerInterval: Date()...deadline, countsDown: true)
                                .monospacedDigit()
                        }
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    }
                    Text(delivered == 0
                         ? loc("En attente des autres…", "Waiting for the others…", "Esperando a los demás…")
                         : loc("\(delivered) personne(s) appairée(s)", "\(delivered) person(s) paired", "\(delivered) persona(s) emparejada(s)"))
                        .font(.headline)
                        .foregroundStyle(delivered == 0 ? Color.secondary : Color.green)
                    if isWorking {
                        Button(loc("Terminé", "Done", "Listo")) {
                            let paired = delivered > 0
                            cancel()
                            if paired { dismiss() }
                        }
                            .buttonStyle(.borderedProminent)
                            .tint(.brocoliGreen)
                    }
                }
                .frame(maxWidth: .infinity)
                .animation(.spring(response: 0.4, dampingFraction: 0.8), value: delivered)
            }
            .listRowBackground(Color.brocoliCard)
        } else {
            Section {
                Button {
                    code = randomCode()
                    run { try await createGroup() }
                } label: {
                    Label(loc("Afficher mon QR code", "Show my QR code", "Mostrar mi código QR"), systemImage: "qrcode")
                        .font(.headline)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 6)
                }
                .buttonStyle(.borderedProminent)
                .tint(.brocoliGreen)
            }
            .listRowBackground(Color.brocoliCard)
        }
    }

    // MARK: Je rejoins

    @ViewBuilder private var joinSection: some View {
        Section {
            Button {
                showScanner = true
            } label: {
                Label(loc("Scanner le QR code", "Scan the QR code", "Escanear el código QR"), systemImage: "qrcode.viewfinder")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
            }
            .buttonStyle(.borderedProminent)
            .tint(.brocoliGreen)
            .disabled(isWorking)
        }
        .listRowBackground(Color.brocoliCard)

        Section(loc("Ou tape le code", "Or type the code", "O escribe el código")) {
            codeField
            Button {
                run { try await joinGroup() }
            } label: {
                Label(loc("Rejoindre", "Join", "Unirme"), systemImage: "person.fill.badge.plus")
            }
            .disabled(isWorking || trimmedCode.count < 4)
        }
        .listRowBackground(Color.brocoliCard)

        if isWorking && !roomPeers.isEmpty {
            Section(loc("Dans le salon", "In the room", "En la sala")) {
                Text(loc("\(roomPeers.count) autre(s) personne(s) connectée(s)", "\(roomPeers.count) other person(s) connected", "\(roomPeers.count) otra(s) persona(s) conectada(s)"))
            }
            .listRowBackground(Color.brocoliCard)
        }

        if isWorking {
            Section {
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) { cancel() }
            }
            .listRowBackground(Color.brocoliCard)
        }
    }

    private var codeField: some View {
        TextField(loc("ex. K7P2QX", "e.g. K7P2QX", "ej. K7P2QX"), text: $code)
            .autocorrectionDisabled()
            .textInputAutocapitalization(.characters)
            .font(.system(.title2, design: .monospaced))
            .disabled(isWorking)
            .onChange(of: code) { v in
                let clean = String(v.uppercased().filter { $0.isLetter || $0.isNumber }.prefix(12))
                if clean != v { code = clean }
            }
    }

    /// Le code d'un QR Brocolis (lien du salon `…?code=K7P2QX`) ou d'un code nu.
    static func scannedCode(from raw: String) -> String? {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let comps = URLComponents(string: text),
           let c = comps.queryItems?.first(where: { $0.name == "code" })?.value, !c.isEmpty {
            return c.uppercased()
        }
        let bare = text.uppercased()
        if (4...12).contains(bare.count), bare.allSatisfy({ $0.isLetter || $0.isNumber }) { return bare }
        return nil
    }

    // MARK: UI helpers

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
            status = loc("⚠️ Entre d’abord le code (ou scanne le QR).", "⚠️ Enter the code first (or scan the QR).", "⚠️ Escribe primero el código (o escanea el QR).")
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
        delivered = 0
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
        UIApplication.shared.isIdleTimerDisabled = false
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

    /// L'invitant génère la clé et la remet, chiffrée (X25519), à chaque
    /// personne qui rejoint avec son code — à 2 comme à 10, dans n'importe quel
    /// ordre, pendant 5 minutes. La clé n'est enregistrée qu'à la première
    /// remise : une invitation restée sans réponse ne laisse rien derrière elle.
    private func createGroup() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString
        let groupKey = BrocolisKeyAgreement.generateGroupKeyBase64()
        // Le salon garde l'invitation 10 min : de quoi laisser à quelqu'un de
        // loin le temps de voir le message et de toucher le lien.
        let deadline = Date().addingTimeInterval(10 * 60 - 15)
        await MainActor.run { delivered = 0; inviteDeadline = deadline }

        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)
        update(loc("Fais scanner ce QR, ou envoie le lien. Garde cet écran ouvert.", "Have them scan this QR, or send the link. Keep this screen open.", "Haz que escaneen este QR o envía el enlace. Mantén esta pantalla abierta."))

        var wrappedTo = Set<String>()
        while Date() < deadline {
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
                let first = wrappedTo.isEmpty
                newPeers.forEach { wrappedTo.insert($0.peerId) }
                BrocolisKeyStore.setPairingPeerIds(Array(wrappedTo))
                if first {
                    applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                             message: loc("✅ Appairé ! D’autres peuvent encore scanner ; touche « Terminé » quand c’est bon.", "✅ Paired! Others can still scan; tap “Done” when everyone’s in.", "✅ ¡Emparejado! Otros aún pueden escanear; toca «Listo» cuando estén todos."),
                             peerId: peerId, keepWorking: true)
                }
                let n = wrappedTo.count
                await MainActor.run { delivered = n }
            }
            try await Task.sleep(nanoseconds: 2_000_000_000)
        }
        if wrappedTo.isEmpty {
            finish(error: loc("Personne n’a rejoint en 10 min. Réessaie quand l’autre est disponible.", "Nobody joined within 10 min. Try again when the other person is available.", "Nadie se ha unido en 10 min. Reinténtalo cuando la otra persona esté disponible."))
        } else {
            finish(message: loc("✅ Terminé : \(wrappedTo.count) personne(s) appairée(s).", "✅ Done: \(wrappedTo.count) person(s) paired.", "✅ Listo: \(wrappedTo.count) persona(s) emparejada(s)."))
        }
    }

    // MARK: Flux — membre du groupe

    private func joinGroup() async throws {
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        let peerId = UUID().uuidString

        update(loc("Publication de ta clé publique…", "Publishing your public key…", "Publicando tu clave pública…"))
        let others = try await client.publish(code: code, peerId: peerId, pub: myPub)
        await showPeers(others, excluding: myPub)
        update(loc("Connexion… (l’invitant doit avoir son QR affiché)", "Connecting… (the inviter must have their QR showing)", "Conectando… (quien invita debe tener su QR visible)"))

        // Jusqu'à 10 min : l'invitant, s'il est loin, a pu quitter l'app un
        // instant ; il remet la clé dès qu'il revient sur l'écran.
        for _ in 0..<400 {
            if Task.isCancelled { return }
            if let wrap = try await client.fetchWrap(code: code, peerId: peerId) {
                let groupKey = try BrocolisKeyAgreement.unwrapGroupKey(
                    blobBase64: wrap.blob, fromPeerPublicBase64: wrap.fromPub, myPrivate: priv)
                BrocolisKeyStore.setPairingPeerIds([wrap.from])
                applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                         message: loc("✅ Appairé ! Brocolis est actif.", "✅ Paired! Brocolis is active.", "✅ ¡Emparejado! Brocolis está activo."), peerId: peerId)
                return
            }
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
        finish(error: loc("Pas de réponse : vérifie le code, et que l’autre a bien son QR affiché.", "No answer: check the code, and that the other person has their QR showing.", "Sin respuesta: comprueba el código y que la otra persona tenga su QR visible."))
    }

    // MARK: Application du résultat

    private func applyKey(_ keyB64: String, fingerprint fp: String, message: String, peerId: String, keepWorking: Bool = false) {
        let name = code.trimmingCharacters(in: .whitespacesAndNewlines)
        let who = contactName.trimmingCharacters(in: .whitespacesAndNewlines)
        BrocolisKeyStore.addKey(name: who.isEmpty ? (name.isEmpty ? "Appairage" : name) : who, base64: keyB64)
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

// MARK: - Scanner de QR (appareil photo)

/// Scanne un QR code avec l'appareil photo (VisionKit) et rend son texte.
struct QRScannerSheet: View {
    let onScan: (String) -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Group {
                if DataScannerViewController.isSupported && DataScannerViewController.isAvailable {
                    QRScannerView(onScan: onScan)
                        .ignoresSafeArea()
                } else {
                    VStack(spacing: 12) {
                        Image(systemName: "camera.fill").font(.largeTitle)
                        Text(loc("Le scan n’est pas disponible (appareil photo refusé ou non pris en charge). Tape le code à la place.", "Scanning isn’t available (camera denied or unsupported). Type the code instead.", "El escaneo no está disponible (cámara denegada o no compatible). Escribe el código."))
                            .multilineTextAlignment(.center)
                    }
                    .padding()
                }
            }
            .navigationTitle(loc("Scanner le QR", "Scan the QR", "Escanear el QR"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc("Annuler", "Cancel", "Cancelar")) { dismiss() }
                }
            }
        }
    }
}

private struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

    func makeUIViewController(context: Context) -> DataScannerViewController {
        let scanner = DataScannerViewController(
            recognizedDataTypes: [.barcode(symbologies: [.qr])],
            qualityLevel: .fast,
            isHighlightingEnabled: true)
        scanner.delegate = context.coordinator
        try? scanner.startScanning()
        return scanner
    }

    func updateUIViewController(_ scanner: DataScannerViewController, context: Context) {}

    static func dismantleUIViewController(_ scanner: DataScannerViewController, coordinator: Coordinator) {
        scanner.stopScanning()
    }

    final class Coordinator: NSObject, DataScannerViewControllerDelegate {
        private let onScan: (String) -> Void
        private var done = false

        init(onScan: @escaping (String) -> Void) { self.onScan = onScan }

        func dataScanner(_ scanner: DataScannerViewController, didAdd items: [RecognizedItem], allItems: [RecognizedItem]) {
            guard !done else { return }
            for item in items {
                if case .barcode(let code) = item, let text = code.payloadStringValue {
                    done = true
                    UINotificationFeedbackGenerator().notificationOccurred(.success)
                    onScan(text)
                    return
                }
            }
        }
    }
}
