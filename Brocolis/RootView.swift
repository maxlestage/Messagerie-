//
//  RootView.swift
//  Brocolis 🥦
//
//  État « Actif » + appairage + gestion de PLUSIEURS clés nommées.
//  La clé sélectionnée chiffre ; au déchiffrement, toutes les clés sont essayées.
//

import SwiftUI
import UIKit

struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject private var router = AppRouter.shared

    @State private var keys: [NamedKey] = BrocolisKeyStore.keys
    @State private var selectedId: String? = BrocolisKeyStore.selectedKeyId
    @State private var isActive = BrocolisKeyStore.isActive
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var keyTTL = BrocolisKeyStore.selectedKey?.ttlSeconds ?? 0

    @State private var alertMessage: String?
    @State private var showPairing = false
    @State private var showGenerate = false
    @State private var newKeyName = ""
    @State private var showImport = false
    @State private var importName = ""
    @State private var importText = ""
    @State private var renameTarget: NamedKey?
    @State private var renameText = ""

    private let ttlOptions: [(label: String, seconds: Int)] = [
        ("Jamais", 0),
        ("1 heure", 3600),
        ("24 heures", 86_400),
        ("7 jours", 604_800),
    ]

    private var hasKey: Bool { !keys.isEmpty }
    private var selected: NamedKey? {
        keys.first(where: { $0.id == selectedId }) ?? keys.first
    }

    var body: some View {
        NavigationStack {
            Form {
                statusSection
                pairingSection
                keysSection
                selectedKeySection
                howToSection
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
            .alert("Nouvelle clé", isPresented: $showGenerate) {
                TextField("Nom (ex. Maman)", text: $newKeyName)
                Button("Générer") {
                    BrocolisKeyStore.addKey(name: newKeyName, base64: BrocolisCrypto.generateKeyBase64())
                    reload()
                }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("Crée une clé AES-256 aléatoire, nommée, et la sélectionne.")
            }
            .alert("Importer une clé", isPresented: $showImport) {
                TextField("Nom", text: $importName)
                TextField("Clé base64 (32 octets)", text: $importText)
                Button("Importer") { importKey() }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("Colle la clé reçue d’un correspondant.")
            }
            .alert("Renommer la clé", isPresented: renameBinding) {
                TextField("Nom", text: $renameText)
                Button("OK") {
                    if let t = renameTarget { BrocolisKeyStore.renameKey(id: t.id, name: renameText) }
                    renameTarget = nil
                    reload()
                }
                Button("Annuler", role: .cancel) { renameTarget = nil }
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
                Text("Ajoute au moins une clé pour pouvoir activer Brocolis.")
            } else if isActive {
                Text("Brocolis reste actif tant que tu ne le désactives pas. L’extension Partager chiffre/déchiffre dans tes autres apps.")
            } else {
                Text("Active Brocolis pour que l’extension Partager fonctionne.")
            }
        }
    }

    private var activeBinding: Binding<Bool> {
        Binding(
            get: { isActive },
            set: { newValue in
                BrocolisKeyStore.setActive(newValue)
                isActive = BrocolisKeyStore.isActive
                BrocolisLiveActivity.sync(active: isActive)
            }
        )
    }

    private var renameBinding: Binding<Bool> {
        Binding(get: { renameTarget != nil }, set: { if !$0 { renameTarget = nil } })
    }

    // MARK: Appairage

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
            Text("Échange la clé via un code court (X25519). La clé reçue est ajoutée à ta liste.")
        }
    }

    // MARK: Clés

    private var keysSection: some View {
        Section {
            ForEach(keys) { key in
                HStack {
                    Image(systemName: key.id == selectedId ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(key.id == selectedId ? .green : .secondary)
                    Text(key.name)
                    Spacer()
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    BrocolisKeyStore.selectKey(key.id)
                    reload()
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) {
                        BrocolisKeyStore.deleteKey(id: key.id)
                        reload()
                    } label: {
                        Label("Supprimer", systemImage: "trash")
                    }
                    Button {
                        renameTarget = key
                        renameText = key.name
                    } label: {
                        Label("Renommer", systemImage: "pencil")
                    }
                    .tint(.blue)
                }
            }

            Button {
                newKeyName = ""
                showGenerate = true
            } label: {
                Label("Générer une nouvelle clé", systemImage: "key.fill")
            }
            Button {
                importName = ""
                importText = ""
                showImport = true
            } label: {
                Label("Importer une clé", systemImage: "square.and.arrow.down")
            }
        } header: {
            Text("Clés")
        } footer: {
            if hasKey {
                Text("La clé cochée sert à chiffrer. Au déchiffrement, toutes tes clés sont essayées. Glisse une clé pour la renommer ou la supprimer.")
            } else {
                Text("Aucune clé. Génère-en une, importe-en une, ou appaire-toi.")
            }
        }
    }

    @ViewBuilder private var selectedKeySection: some View {
        if let sel = selected {
            Section("Clé sélectionnée") {
                Text(sel.name).font(.headline)
                Text(sel.base64)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                Button {
                    UIPasteboard.general.string = sel.base64
                    alertMessage = "Clé copiée dans le presse-papiers."
                } label: {
                    Label("Copier la clé", systemImage: "doc.on.doc")
                }
                ShareLink(item: sel.base64) {
                    Label("Partager la clé", systemImage: "square.and.arrow.up")
                }
            }

            Section {
                Picker("Validité", selection: ttlBinding(for: sel.id)) {
                    ForEach(ttlOptions, id: \.seconds) { opt in
                        Text(opt.label).tag(opt.seconds)
                    }
                }
                expiryStatus(for: sel)
            } header: {
                Text("Expiration de « \(sel.name) »")
            } footer: {
                Text("Au-delà de la validité, l’extension refuse de chiffrer avec cette clé. Le déchiffrement reste possible jusqu’à ce qu’elle soit purgée à l’ouverture de l’app.")
            }
        }
    }

    private func ttlBinding(for id: String) -> Binding<Int> {
        Binding(
            get: { keyTTL },
            set: { newValue in
                BrocolisKeyStore.setKeyTTL(newValue, forKeyId: id)
                reload()
            }
        )
    }

    @ViewBuilder private func expiryStatus(for key: NamedKey) -> some View {
        if let expires = key.expiresAt {
            if BrocolisKeyStore.isExpired(expiresAt: expires, now: Date()) {
                Label("Expirée — renouvelle-la", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else {
                let lead = BrocolisKeyStore.notificationLead(ttlSeconds: key.ttlSeconds) ?? 0
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

    // MARK: Logique

    private func reload() {
        keys = BrocolisKeyStore.keys
        selectedId = BrocolisKeyStore.selectedKeyId ?? keys.first?.id
        isActive = BrocolisKeyStore.isActive
        fingerprint = BrocolisKeyStore.pairingFingerprint
        keyTTL = BrocolisKeyStore.selectedKey?.ttlSeconds ?? 0
        BrocolisNotifications.refresh()
        BrocolisLiveActivity.sync(active: isActive)
    }

    private func purgeIfNeeded() {
        if BrocolisKeyStore.purgeExpiredKey() {
            alertMessage = "Une clé avait expiré : elle a été supprimée automatiquement."
        }
        reload()
    }

    private func importKey() {
        let trimmed = importText.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try BrocolisCrypto.symmetricKey(fromBase64: trimmed)
            BrocolisKeyStore.addKey(name: importName, base64: trimmed)
            importText = ""
            importName = ""
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
