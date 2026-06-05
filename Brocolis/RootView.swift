//
//  RootView.swift
//  Brocolis 🥦
//
//  Gestion de la clé partagée + mode d'emploi de l'extension.
//

import SwiftUI
import UIKit

struct RootView: View {
    @State private var keyBase64: String? = BrocolisKeyStore.keyBase64
    @State private var importText = ""
    @State private var alertMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text("Sélectionne du texte dans n’importe quelle app de messagerie, ouvre le menu **Partager**, puis choisis **Brocolis 🥦** pour chiffrer tes ((secrets)) ou déchiffrer les jetons reçus.")
                        .font(.subheadline)
                } header: {
                    Text("Comment ça marche")
                }

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
                } footer: {
                    Text("Transmets cette clé par un canal sûr à tes correspondants. Quiconque la possède peut lire les messages chiffrés.")
                }

                Section("Générer") {
                    Button {
                        let b64 = BrocolisCrypto.generateKeyBase64()
                        BrocolisKeyStore.setKey(b64)
                        keyBase64 = b64
                    } label: {
                        Label("Générer une nouvelle clé", systemImage: "key.fill")
                    }
                } footer: {
                    Text("Crée une clé AES-256 aléatoire (équivalent de `brocolis keygen`).")
                }

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

                if keyBase64 != nil {
                    Section {
                        Button(role: .destructive) {
                            BrocolisKeyStore.clearKey()
                            keyBase64 = nil
                        } label: {
                            Label("Supprimer la clé", systemImage: "trash")
                        }
                    }
                }
            }
            .navigationTitle("Brocolis 🥦")
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
