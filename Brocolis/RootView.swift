//
//  RootView.swift
//  Brocolis 🥦
//
//  État « Actif » + appairage automatique (X25519) + gestion manuelle de la clé.
//

import SwiftUI
import UIKit

struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject private var router = AppRouter.shared

    @State private var keyBase64: String? = BrocolisKeyStore.keyBase64
    @State private var isActive = BrocolisKeyStore.isActive
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var keyTTL = BrocolisKeyStore.keyTTLSeconds
    @State private var importText = ""
    @State private var alertMessage: String?
    @State private var showPairing = false

    private let ttlOptions: [(label: String, seconds: Int)] = [
        ("Jamais", 0),
        ("1 heure", 3600),
        ("24 heures", 86_400),
        ("7 jours", 604_800),
    ]

    private var hasKey: Bool { keyBase64 != nil }

    var body: some View {
        NavigationStack {
            Form {
                statusSection
                pairingSection
                if hasKey { expirySection }
                howToSection
                keySection
                generateSection
                importSection
                if hasKey { deleteSection }
            }
            .navigationTitle("Brocolis 🥦")
            .onAppear {
                purgeIfNeeded()
                if router.openPairing { showPairing = true; router.openPairing = false }
            }
            .onChange(of: scenePhase) { phase in
                if phase == .active { purgeIfNeeded() }
            }
            .onChange(of: router.openPairing) { open in
                if open { showPairing = true; router.openPairing = false }
            }
            .sheet(isPresented: $showPairing, onDismiss: reload) {
                NavigationStack { PairingView() }
            }
            .alert(
                "Brocolis",
                isPresented: Binding(
                    get: { alertMessage != nil },
                    set: { if !$0 { alertMessage = nil } }
                )
            ) {
                Button("OK", role: .cancel) { alertMessage = nil }
            } message: {
                Text(alertMessage ?? "")
            }
        }
    }

    // MARK: État actif

    private var statusSection: some View {
        Section {
            Toggle(isOn: activeBinding) {
                Label(isActive ? "Actif" : "Inactif", systemImage: isActive ? "lock.shield.fill" : "lock.shield")
                    .foregroundStyle(isActive ? .green : .secondary)
            }
            .disabled(!hasKey)
        } header: {
            Text("État")
        } footer: {
            if !hasKey {
                Text("Appaire-toi à un correspondant ou crée une clé pour pouvoir activer Brocolis.")
            } else if isActive {
                Text("Brocolis reste actif tant que tu ne le désactives pas (ou que tu ne fermes pas l’app). L’extension Partager chiffre/déchiffre dans tes autres apps.")
            } else {
                Text("Active Brocolis pour que l’extension Partager chiffre/déchiffre dans tes autres apps.")
            }
        }
    }

    private var activeBinding: Binding<Bool> {
        Binding(
            get: { isActive },
            set: { newValue in
                BrocolisKeyStore.setActive(newValue)
                isActive = BrocolisKeyStore.isActive
            }
        )
    }

    // MARK: Appairage automatique

    private var pairingSection: some View {
        Section {
            Button {
                showPairing = true
            } label: {
                Label("Appairer automatiquement", systemImage: "person.2.badge.key.fill")
            }
            if let fp = fingerprint {
                LabeledContent("Empreinte", value: fp)
                    .font(.system(.footnote, design: .monospaced))
            }
        } header: {
            Text("Correspondant")
        } footer: {
            Text("Échange la clé automatiquement avec un correspondant via un code court (X25519) — sans copier la clé. Compare l’empreinte de vive voix pour vérifier qu’il n’y a pas d’interception.")
        }
    }

    // MARK: Expiration / rotation

    private var expirySection: some View {
        Section {
            Picker("Validité de la clé", selection: ttlBinding) {
                ForEach(ttlOptions, id: \.seconds) { opt in
                    Text(opt.label).tag(opt.seconds)
                }
            }
            expiryStatus
        } header: {
            Text("Expiration")
        } footer: {
            Text("Au-delà de la validité, l’extension refuse de chiffrer/déchiffrer tant que la clé n’est pas renouvelée. Pour un groupe, le fondateur relance « Créer le groupe » pour distribuer une nouvelle clé.")
        }
    }

    private var ttlBinding: Binding<Int> {
        Binding(
            get: { keyTTL },
            set: { newValue in
                BrocolisKeyStore.setKeyTTL(newValue)
                keyTTL = BrocolisKeyStore.keyTTLSeconds
            }
        )
    }

    @ViewBuilder private var expiryStatus: some View {
        if let expires = BrocolisKeyStore.keyExpiresAt {
            if BrocolisKeyStore.isExpired {
                Label("Clé expirée — renouvelle-la", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else {
                let lead = BrocolisKeyStore.notificationLead(ttlSeconds: keyTTL) ?? 0
                let soon = expires.timeIntervalSinceNow <= lead
                Label {
                    Text("Expire \(expires.formatted(.relative(presentation: .named)))")
                } icon: {
                    Image(systemName: soon ? "exclamationmark.triangle.fill" : "clock")
                }
                .foregroundStyle(soon ? .orange : .secondary)
            }
        } else {
            Text("Pas d’expiration").foregroundStyle(.secondary)
        }
    }

    // MARK: Mode d'emploi

    private var howToSection: some View {
        Section("Comment ça marche") {
            Text("Sélectionne du texte dans n’importe quelle app de messagerie, ouvre le menu **Partager**, puis choisis **Brocolis 🥦** pour chiffrer tes ((secrets)) ou déchiffrer les jetons reçus.")
                .font(.subheadline)
            Text("⚠️ Le résultat chiffré est copié : **colle‑le en remplaçant ton texte d’origine**. Ne laisse pas la version en clair dans le message, sinon elle reste visible.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Clé (manuel)

    private var keySection: some View {
        Section("Clé partagée") {
            if let key = keyBase64 {
                Text(key)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                Button {
                    UIPasteboard.general.string = key
                    alertMessage = "Clé copiée dans le presse-papiers."
                } label: {
                    Label("Copier la clé", systemImage: "doc.on.doc")
                }
                ShareLink(item: key) {
                    Label("Partager la clé", systemImage: "square.and.arrow.up")
                }
            } else {
                Label("Aucune clé configurée", systemImage: "exclamationmark.lock")
                    .foregroundStyle(.orange)
            }
        }
    }

    private var generateSection: some View {
        Section {
            Button {
                let b64 = BrocolisCrypto.generateKeyBase64()
                BrocolisKeyStore.setKey(b64)
                BrocolisKeyStore.setPairingFingerprint(nil)
                reload()
            } label: {
                Label("Générer une nouvelle clé", systemImage: "key.fill")
            }
        } header: {
            Text("Générer (manuel)")
        } footer: {
            Text("Crée une clé AES-256 aléatoire à partager manuellement (équivalent de `brocolis keygen`).")
        }
    }

    private var importSection: some View {
        Section("Importer (manuel)") {
            TextField("Clé base64 (32 octets)", text: $importText, axis: .vertical)
                .font(.system(.footnote, design: .monospaced))
                .autocorrectionDisabled()
                .textInputAutocapitalization(.never)
            Button {
                importKey()
            } label: {
                Label("Importer cette clé", systemImage: "square.and.arrow.down")
            }
            .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        }
    }

    private var deleteSection: some View {
        Section {
            Button(role: .destructive) {
                BrocolisKeyStore.clearKey()
                reload()
            } label: {
                Label("Supprimer la clé", systemImage: "trash")
            }
        }
    }

    // MARK: Logique

    /// Purge la clé si elle est périmée, prévient l'utilisateur, puis rafraîchit.
    private func purgeIfNeeded() {
        if BrocolisKeyStore.purgeExpiredKey() {
            alertMessage = "La clé avait expiré : elle a été supprimée automatiquement. Renouvelle-la ou ré-appaire-toi."
        }
        reload()
    }

    private func reload() {
        keyBase64 = BrocolisKeyStore.keyBase64
        isActive = BrocolisKeyStore.isActive
        fingerprint = BrocolisKeyStore.pairingFingerprint
        keyTTL = BrocolisKeyStore.keyTTLSeconds
        BrocolisNotifications.refresh()
    }

    private func importKey() {
        do {
            _ = try BrocolisCrypto.symmetricKey(fromBase64: importText)
            BrocolisKeyStore.setKey(importText)
            BrocolisKeyStore.setPairingFingerprint(nil)
            importText = ""
            reload()
            alertMessage = "Clé importée."
        } catch {
            alertMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}

#Preview {
    RootView()
}
