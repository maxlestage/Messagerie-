//
//  RootView.swift
//  Brocolis 🥦
//
//  État « Actif » + gestion de la clé partagée + mode d'emploi de l'extension.
//

import SwiftUI
import UIKit

struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase

    @State private var keyBase64: String? = BrocolisKeyStore.keyBase64
    @State private var isActive = BrocolisKeyStore.isActive
    @State private var importText = ""
    @State private var alertMessage: String?

    private var hasKey: Bool { keyBase64 != nil }

    var body: some View {
        NavigationStack {
            Form {
                statusSection
                howToSection
                keySection
                generateSection
                importSection
                if hasKey { deleteSection }
            }
            .navigationTitle("Brocolis 🥦")
            .onChange(of: scenePhase) { phase in
                if phase == .active {
                    // Resynchronise l'UI avec l'état partagé au retour dans l'app.
                    keyBase64 = BrocolisKeyStore.keyBase64
                    isActive = BrocolisKeyStore.isActive
                }
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
                Text("Génère ou importe une clé pour pouvoir activer Brocolis.")
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

    // MARK: Mode d'emploi

    private var howToSection: some View {
        Section("Comment ça marche") {
            Text("Sélectionne du texte dans n’importe quelle app de messagerie, ouvre le menu **Partager**, puis choisis **Brocolis 🥦** pour chiffrer tes ((secrets)) ou déchiffrer les jetons reçus.")
                .font(.subheadline)
        }
    }

    // MARK: Clé

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
                keyBase64 = b64
            } label: {
                Label("Générer une nouvelle clé", systemImage: "key.fill")
            }
        } header: {
            Text("Générer")
        } footer: {
            Text("Crée une clé AES-256 aléatoire (équivalent de `brocolis keygen`). Transmets-la par un canal sûr.")
        }
    }

    private var importSection: some View {
        Section("Importer") {
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
                keyBase64 = nil
                isActive = BrocolisKeyStore.isActive
            } label: {
                Label("Supprimer la clé", systemImage: "trash")
            }
        }
    }

    private func importKey() {
        do {
            _ = try BrocolisCrypto.symmetricKey(fromBase64: importText)
            BrocolisKeyStore.setKey(importText)
            keyBase64 = BrocolisKeyStore.keyBase64
            importText = ""
            alertMessage = "Clé importée."
        } catch {
            alertMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}

#Preview {
    RootView()
}
