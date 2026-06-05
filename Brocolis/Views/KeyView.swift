//
//  KeyView.swift
//  Messagerie 🥦
//
//  Réglages de la clé symétrique partagée : génération, import, partage,
//  suppression. C'est l'équivalent de `brocolis keygen`.
//

import SwiftUI
import UIKit

struct KeyView: View {
    @EnvironmentObject private var keyStore: KeyStore
    @Environment(\.dismiss) private var dismiss

    @State private var importText = ""
    @State private var showImportError = false
    @State private var importError = ""
    @State private var confirmClear = false

    var body: some View {
        NavigationStack {
            Form {
                if let key = keyStore.keyBase64 {
                    Section("Clé partagée actuelle") {
                        Text(key)
                            .font(.system(.footnote, design: .monospaced))
                            .textSelection(.enabled)
                        Button {
                            UIPasteboard.general.string = key
                        } label: {
                            Label("Copier la clé", systemImage: "doc.on.doc")
                        }
                        ShareLink(item: key) {
                            Label("Partager la clé", systemImage: "square.and.arrow.up")
                        }
                    } footer: {
                        Text("Transmets cette clé par un canal sûr aux personnes avec qui tu veux échanger. Quiconque possède la clé peut lire les messages chiffrés.")
                    }
                } else {
                    Section {
                        Label("Aucune clé configurée", systemImage: "exclamationmark.lock")
                            .foregroundStyle(.orange)
                    }
                }

                Section("Générer") {
                    Button {
                        keyStore.generate()
                    } label: {
                        Label("Générer une nouvelle clé", systemImage: "key.fill")
                    }
                } footer: {
                    Text("Crée une clé AES-256 aléatoire. Les messages chiffrés avec une ancienne clé deviendront illisibles.")
                }

                Section("Importer") {
                    TextField("Clé base64 (32 octets)", text: $importText, axis: .vertical)
                        .font(.system(.footnote, design: .monospaced))
                        .lineLimit(1...4)
                        .autocorrectionDisabled()
                        .textInputAutocapitalization(.never)
                    Button {
                        importKey()
                    } label: {
                        Label("Importer cette clé", systemImage: "square.and.arrow.down")
                    }
                    .disabled(importText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                } footer: {
                    Text("Colle la clé reçue d'un correspondant pour pouvoir lire ses messages.")
                }

                if keyStore.hasKey {
                    Section {
                        Button(role: .destructive) {
                            confirmClear = true
                        } label: {
                            Label("Supprimer la clé", systemImage: "trash")
                        }
                    }
                }
            }
            .navigationTitle("Clé de chiffrement")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button("OK") { dismiss() }
                }
            }
            .alert("Clé invalide", isPresented: $showImportError) {
                Button("OK", role: .cancel) {}
            } message: {
                Text(importError)
            }
            .alert("Supprimer la clé ?", isPresented: $confirmClear) {
                Button("Supprimer", role: .destructive) { keyStore.clear() }
                Button("Annuler", role: .cancel) {}
            } message: {
                Text("Sans clé, les messages chiffrés deviennent illisibles. Cette action est irréversible.")
            }
        }
    }

    private func importKey() {
        do {
            try keyStore.importKey(importText)
            importText = ""
        } catch {
            importError = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            showImportError = true
        }
    }
}

#Preview {
    KeyView()
        .environmentObject(KeyStore())
}
