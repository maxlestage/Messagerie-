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
    /// Fin du suivi en direct sur cet écran (l'invitation, elle, tient 7 jours).
    @State private var inviteDeadline: Date?
    /// Invitations / réponses en attente (à distance, en différé).
    @State private var pendingInvites = BrocolisPendingPairing.invites
    @State private var pendingJoins = BrocolisPendingPairing.joins
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
                     ? loc("À côté : fais scanner ton QR. Loin : envoie le lien par message. Pas besoin d’être en ligne en même temps : l’invitation tient 7 jours et se termine toute seule. Marche à 2 comme en groupe.", "Nearby: have them scan your QR. Far away: send the link by message. No need to be online at the same time: the invitation lasts 7 days and completes on its own. Works for 2 or a group.", "Cerca: que escaneen tu QR. Lejos: envía el enlace por mensaje. No hace falta estar conectados a la vez: la invitación dura 7 días y se completa sola. Funciona entre 2 o en grupo.")
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

            if !isWorking && (!pendingInvites.isEmpty || !pendingJoins.isEmpty) {
                Section {
                    ForEach(pendingInvites) { inv in
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(inv.name).font(.subheadline.weight(.semibold))
                                Text(inv.keyAdded
                                     ? loc("Invitation · \(inv.wrapped.count) personne(s) l’ont rejointe · code \(inv.code)", "Invitation · \(inv.wrapped.count) person(s) joined · code \(inv.code)", "Invitación · \(inv.wrapped.count) persona(s) se unieron · código \(inv.code)")
                                     : loc("Invitation envoyée · personne encore · code \(inv.code)", "Invitation sent · nobody yet · code \(inv.code)", "Invitación enviada · nadie aún · código \(inv.code)"))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        } icon: { Image(systemName: "paperplane") }
                    }
                    .onDelete { idx in
                        idx.map { pendingInvites[$0].code }.forEach { BrocolisPendingPairing.cancel(code: $0) }
                        reloadPending()
                    }
                    ForEach(pendingJoins) { join in
                        Label {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(join.name).font(.subheadline.weight(.semibold))
                                Text(loc("Acceptée · la clé arrive dès que l’autre ouvre Brocolis · code \(join.code)", "Accepted · the key arrives once they open Brocolis · code \(join.code)", "Aceptada · la clave llega cuando la otra persona abra Brocolis · código \(join.code)"))
                                    .font(.caption).foregroundStyle(.secondary)
                            }
                        } icon: { Image(systemName: "hourglass") }
                    }
                    .onDelete { idx in
                        idx.map { pendingJoins[$0].code }.forEach { BrocolisPendingPairing.cancel(code: $0) }
                        reloadPending()
                    }
                    Button {
                        Task {
                            let done = await BrocolisPendingPairing.resume()
                            await MainActor.run {
                                reloadPending()
                                status = done.isEmpty
                                    ? loc("Rien de nouveau pour l’instant.", "Nothing new yet.", "Nada nuevo por ahora.")
                                    : done.joined(separator: "\n")
                            }
                        }
                    } label: {
                        Label(loc("Vérifier maintenant", "Check now", "Comprobar ahora"), systemImage: "arrow.clockwise")
                    }
                } header: {
                    Text(loc("En attente (à distance)", "Pending (remote)", "Pendientes (a distancia)"))
                } footer: {
                    Text(loc("Tout se termine tout seul à l’ouverture de l’app, pendant 7 jours. Glisse pour annuler.", "Everything completes on its own when the app opens, for 7 days. Swipe to cancel.", "Todo se completa solo al abrir la app, durante 7 días. Desliza para cancelar."))
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
            reloadPending()
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
                              message: Text(loc("Appairons-nous sur Brocolis 🥦 (valable 7 jours) : touche ce lien puis « Ouvrir dans l’app ». Ou dans l’app : Appairage → Je rejoins → code \(trimmedCode).",
                                                "Let’s pair on Brocolis 🥦 (valid 7 days): tap this link, then “Open in the app”. Or in the app: Pairing → I join → code \(trimmedCode).",
                                                "Emparejémonos en Brocolis 🥦 (válido 7 días): toca este enlace y luego «Abrir en la app». O en la app: Emparejamiento → Me uno → código \(trimmedCode)."))) {
                        Label(loc("Envoyer le lien (à distance)", "Send the link (remote)", "Enviar el enlace (a distancia)"), systemImage: "paperplane.fill")
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.brocoliGreen)
                    Text(loc("Valable 7 jours · tu peux fermer l’app", "Valid 7 days · you can close the app", "Válido 7 días · puedes cerrar la app"))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                    Text(delivered == 0
                         ? loc("En attente des autres…", "Waiting for the others…", "Esperando a los demás…")
                         : loc("\(delivered) personne(s) appairée(s)", "\(delivered) person(s) paired", "\(delivered) persona(s) emparejada(s)"))
                        .font(.headline)
                        .foregroundStyle(delivered == 0 ? Color.secondary : Color.green)
                    if isWorking {
                        Button(delivered > 0 ? loc("Terminé", "Done", "Listo") : loc("Fermer (l’invitation reste active)", "Close (the invitation stays active)", "Cerrar (la invitación sigue activa)")) {
                            cancel()
                            dismiss()
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
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) {
                    BrocolisPendingPairing.cancel(code: code)
                    cancel()
                    status = ""
                    reloadPending()
                }
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
        reloadPending()
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
        // Sur cet écran, on suit les arrivées en direct pendant 10 min ; ensuite
        // l'invitation reste en attente (7 jours) et se termine à l'ouverture.
        let deadline = Date().addingTimeInterval(10 * 60)
        var invite = BrocolisPendingPairing.Invite(code: code, name: keyName, groupKey: groupKey,
                                                   peerId: peerId, created: Date())
        BrocolisPendingPairing.upsert(invite)
        await MainActor.run { delivered = 0; inviteDeadline = deadline }

        _ = try await client.publish(code: code, peerId: peerId, pub: myPub)
        update(loc("Fais scanner ce QR, ou envoie le lien. Tu peux fermer l’app : l’invitation reste valable 7 jours et se termine toute seule.", "Have them scan this QR, or send the link. You can close the app: the invitation stays valid 7 days and completes on its own.", "Haz que escaneen este QR o envía el enlace. Puedes cerrar la app: la invitación es válida 7 días y se completa sola."))

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
                invite.wrapped = Array(wrappedTo)
                invite.keyAdded = true
                BrocolisPendingPairing.upsert(invite)
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
            finish(message: loc("⏳ Invitation en attente (7 jours) : dès que l’autre rejoint, la clé s’installe à ta prochaine ouverture de Brocolis.", "⏳ Invitation pending (7 days): as soon as they join, the key installs the next time you open Brocolis.", "⏳ Invitación pendiente (7 días): en cuanto se una, la clave se instala la próxima vez que abras Brocolis."))
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
        BrocolisPendingPairing.upsert(BrocolisPendingPairing.Join(code: code, name: keyName, peerId: peerId, created: Date()))
        let others = try await client.publish(code: code, peerId: peerId, pub: myPub)
        await showPeers(others, excluding: myPub)
        update(loc("Connexion… (l’invitant doit avoir son QR affiché)", "Connecting… (the inviter must have their QR showing)", "Conectando… (quien invita debe tener su QR visible)"))

        // Une minute et demie sur place ; ensuite la réponse reste en attente et
        // se termine toute seule à une prochaine ouverture de l'app.
        for _ in 0..<60 {
            if Task.isCancelled { return }
            if let wrap = try await client.fetchWrap(code: code, peerId: peerId) {
                let groupKey = try BrocolisKeyAgreement.unwrapGroupKey(
                    blobBase64: wrap.blob, fromPeerPublicBase64: wrap.fromPub, myPrivate: priv)
                BrocolisKeyStore.setPairingPeerIds([wrap.from])
                BrocolisPendingPairing.cancel(code: code)
                applyKey(groupKey, fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: groupKey),
                         message: loc("✅ Appairé ! Brocolis est actif.", "✅ Paired! Brocolis is active.", "✅ ¡Emparejado! Brocolis está activo."), peerId: peerId)
                return
            }
            try await Task.sleep(nanoseconds: 1_500_000_000)
        }
        finish(message: loc("⏳ Invitation acceptée. La personne qui t’invite n’est pas en ligne : la clé arrivera toute seule, à ta prochaine ouverture de Brocolis après la sienne. Tu n’as rien d’autre à faire.", "⏳ Invitation accepted. The inviter isn’t online: the key will arrive on its own, the next time you open Brocolis after they do. Nothing else to do.", "⏳ Invitación aceptada. Quien te invita no está conectado: la clave llegará sola la próxima vez que abras Brocolis después de esa persona. No tienes que hacer nada más."))
    }

    // MARK: Application du résultat

    /// Le nom de la clé : la personne si on l'a saisie, sinon le code.
    private var keyName: String {
        let who = contactName.trimmingCharacters(in: .whitespacesAndNewlines)
        return who.isEmpty ? loc("Appairage \(code)", "Pairing \(code)", "Emparejamiento \(code)") : who
    }

    private func applyKey(_ keyB64: String, fingerprint fp: String, message: String, peerId: String, keepWorking: Bool = false) {
        BrocolisPendingPairing.install(key: keyB64, name: keyName, fingerprint: fp, code: code, peerId: peerId)
        Task { @MainActor in
            fingerprint = fp
            status = message
            if !keepWorking { isWorking = false }
        }
    }

    private func reloadPending() {
        pendingInvites = BrocolisPendingPairing.invites
        pendingJoins = BrocolisPendingPairing.joins
    }

    @MainActor private func update(_ s: String) { status = s }

    @MainActor private func finish(message: String) {
        status = message
        isWorking = false
        reloadPending()
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

// MARK: - Appairage à distance, en différé

/// Quand les deux sont loin, ils ne sont pas en ligne en même temps. Une
/// invitation (ou une réponse) reste donc EN ATTENTE sur le téléphone, 7 jours,
/// et se termine toute seule à chaque ouverture de l'app :
///  - l'invitant republie sa clé publique, remet la clé (chiffrée) à quiconque
///    a rejoint entre-temps, et l'installe chez lui à la première arrivée ;
///  - celui qui rejoint republie la sienne et récupère la clé dès qu'elle l'attend.
/// Republier à chaque ouverture rend le tout insensible aux redémarrages du
/// serveur (qui garde tout en mémoire).
enum BrocolisPendingPairing {
    struct Invite: Codable, Identifiable {
        var id: String { code }
        let code: String
        let name: String
        let groupKey: String
        let peerId: String
        let created: Date
        var keyAdded = false
        var wrapped: [String] = []
    }

    struct Join: Codable, Identifiable {
        var id: String { code }
        let code: String
        let name: String
        let peerId: String
        let created: Date
    }

    static let lifetime: TimeInterval = 7 * 24 * 3600
    private static let invitesKey = "pending_invites"
    private static let joinsKey = "pending_joins"
    private static var defaults: UserDefaults { .standard }

    static var invites: [Invite] {
        get { load(invitesKey) }
        set { save(newValue, invitesKey) }
    }

    static var joins: [Join] {
        get { load(joinsKey) }
        set { save(newValue, joinsKey) }
    }

    static func upsert(_ invite: Invite) {
        invites = invites.filter { $0.code != invite.code } + [invite]
    }

    static func upsert(_ join: Join) {
        joins = joins.filter { $0.code != join.code } + [join]
    }

    static func cancel(code: String) {
        invites = invites.filter { $0.code != code }
        joins = joins.filter { $0.code != code }
    }

    private static func load<T: Decodable>(_ key: String) -> [T] {
        guard let data = defaults.data(forKey: key),
              let list = try? JSONDecoder().decode([T].self, from: data) else { return [] }
        return list
    }

    private static func save<T: Encodable>(_ list: [T], _ key: String) {
        defaults.set(try? JSONEncoder().encode(list), forKey: key)
    }

    /// Installe une clé obtenue par appairage (mêmes effets partout).
    static func install(key: String, name: String, fingerprint: String, code: String, peerId: String) {
        BrocolisKeyStore.addKey(name: name, base64: key)
        BrocolisKeyStore.setPairingFingerprint(fingerprint)
        BrocolisKeyStore.setPairingIdentity(code: code, peerId: peerId)
        BrocolisKeyStore.setActive(true)
        BrocolisLiveActivity.sync(active: true)
        Task { await BrocolisPush.registerLiveActivityToken() }
    }

    /// Fait avancer toutes les invitations et réponses en attente. Renvoie ce
    /// qui vient d'aboutir, à annoncer.
    @discardableResult
    static func resume() async -> [String] {
        let now = Date()
        invites = invites.filter { now.timeIntervalSince($0.created) < lifetime }
        joins = joins.filter { now.timeIntervalSince($0.created) < lifetime }
        guard !invites.isEmpty || !joins.isEmpty else { return [] }

        let client = PairingClient(baseURL: BrocolisKeyStore.serverURL)
        let priv = BrocolisKeyAgreement.loadOrCreatePrivateKey()
        let myPub = BrocolisKeyAgreement.publicKeyBase64(of: priv)
        var done: [String] = []

        for var invite in invites {
            guard let peers = try? await client.publish(code: invite.code, peerId: invite.peerId, pub: myPub) else { continue }
            let others = peers.filter { $0.pub != myPub }
            guard !others.isEmpty else { continue }
            // On remet la clé à TOUS (pas seulement aux nouveaux) : après un
            // redémarrage du serveur, les anciennes remises ont pu disparaître.
            let items = others.compactMap { p in
                (try? BrocolisKeyAgreement.wrapGroupKey(groupKeyBase64: invite.groupKey,
                                                        forPeerPublicBase64: p.pub, myPrivate: priv))
                    .map { WrapItem(toPeerId: p.peerId, blob: $0) }
            }
            guard (try? await client.postWraps(code: invite.code, fromPeerId: invite.peerId,
                                               fromPub: myPub, items: items)) != nil else { continue }
            let fresh = others.filter { !invite.wrapped.contains($0.peerId) }
            if !invite.keyAdded {
                install(key: invite.groupKey, name: invite.name,
                        fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: invite.groupKey),
                        code: invite.code, peerId: invite.peerId)
                invite.keyAdded = true
            }
            if !fresh.isEmpty {
                invite.wrapped += fresh.map(\.peerId)
                BrocolisKeyStore.setPairingPeerIds(invite.wrapped)
                done.append(loc("✅ « \(invite.name) » : \(fresh.count) personne(s) ont rejoint ton invitation.",
                                "✅ “\(invite.name)”: \(fresh.count) person(s) joined your invitation.",
                                "✅ «\(invite.name)»: \(fresh.count) persona(s) se unieron a tu invitación."))
            }
            upsert(invite)
        }

        for join in joins {
            _ = try? await client.publish(code: join.code, peerId: join.peerId, pub: myPub)
            guard let wrap = try? await client.fetchWrap(code: join.code, peerId: join.peerId),
                  let key = try? BrocolisKeyAgreement.unwrapGroupKey(
                    blobBase64: wrap.blob, fromPeerPublicBase64: wrap.fromPub, myPrivate: priv) else { continue }
            BrocolisKeyStore.setPairingPeerIds([wrap.from])
            install(key: key, name: join.name,
                    fingerprint: BrocolisKeyAgreement.groupFingerprint(groupKeyBase64: key),
                    code: join.code, peerId: join.peerId)
            joins = joins.filter { $0.code != join.code }
            done.append(loc("✅ Appairage « \(join.name) » terminé : la clé est arrivée.",
                            "✅ Pairing “\(join.name)” complete: the key has arrived.",
                            "✅ Emparejamiento «\(join.name)» completado: la clave ha llegado."))
        }
        return done
    }
}
