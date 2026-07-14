//
//  BrocolisContacts.swift
//  Brocolis 🥦
//
//  Import du CARNET D'ADRESSES (avec permission) pour choisir un correspondant
//  par son NOM et son NUMÉRO — au lieu de tout taper à la main.
//
//  ⚠️ iOS interdit de lire les SMS / iMessage. On lit donc les Contacts (là où
//  sont les gens que tu textes), jamais les messages. Le numéro sert d'identité
//  et d'étiquette ; il n'est PAS la clé de chiffrement (un numéro est public).
//  Le chiffrement reste assuré par la clé partagée (appairage).
//

import Foundation
import Contacts
import SwiftUI
import UIKit
import MessageUI

/// Un contact retenu : nom + un numéro (normalisé pour l'affichage/identité).
struct PhoneContact: Identifiable, Equatable {
    let id: String          // identifiant stable (contact + numéro)
    let name: String
    let phoneNumber: String // normalisé : « + » éventuel puis chiffres
    let rawNumber: String   // tel qu'affiché dans les Contacts

    var initials: String {
        let parts = name.split(separator: " ")
        let letters = parts.prefix(2).compactMap { $0.first }.map(String.init).joined()
        return letters.isEmpty ? "?" : letters.uppercased()
    }
}

enum BrocolisContacts {

    enum AccessState { case granted, denied, notDetermined }

    static func authorization() -> AccessState {
        switch CNContactStore.authorizationStatus(for: .contacts) {
        case .authorized: return .granted
        case .notDetermined: return .notDetermined
        default: return .denied // .denied, .restricted, .limited traités comme non accordés
        }
    }

    /// Demande l'accès (affiche l'alerte système au 1er appel).
    static func requestAccess() async -> Bool {
        await withCheckedContinuation { cont in
            CNContactStore().requestAccess(for: .contacts) { granted, _ in
                cont.resume(returning: granted)
            }
        }
    }

    /// Récupère TOUS les contacts ayant au moins un numéro. Une entrée par
    /// numéro (un contact avec mobile + fixe apparaît deux fois, étiqueté).
    static func fetchAll() async -> [PhoneContact] {
        await withCheckedContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                let store = CNContactStore()
                let keys = [
                    CNContactGivenNameKey, CNContactFamilyNameKey,
                    CNContactOrganizationNameKey, CNContactPhoneNumbersKey,
                ] as [CNKeyDescriptor]
                let request = CNContactFetchRequest(keysToFetch: keys)
                var out: [PhoneContact] = []
                do {
                    try store.enumerateContacts(with: request) { contact, _ in
                        let name = displayName(for: contact)
                        for phone in contact.phoneNumbers {
                            let raw = phone.value.stringValue
                            let normalized = normalize(raw)
                            guard !normalized.isEmpty else { continue }
                            out.append(PhoneContact(
                                id: "\(contact.identifier)#\(normalized)",
                                name: name,
                                phoneNumber: normalized,
                                rawNumber: raw
                            ))
                        }
                    }
                } catch {
                    // En cas d'échec (permission retirée en cours), on renvoie vide.
                }
                // Tri alphabétique, doublons de numéro fusionnés.
                var seen = Set<String>()
                let deduped = out
                    .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
                    .filter { seen.insert($0.phoneNumber).inserted }
                cont.resume(returning: deduped)
            }
        }
    }

    private static func displayName(for c: CNContact) -> String {
        let full = "\(c.givenName) \(c.familyName)".trimmingCharacters(in: .whitespaces)
        if !full.isEmpty { return full }
        if !c.organizationName.isEmpty { return c.organizationName }
        return c.phoneNumbers.first?.value.stringValue ?? "Sans nom"
    }

    /// Normalise un numéro : conserve un « + » de tête puis les chiffres.
    /// (Normalisation légère, suffisante comme identité/affichage ; une mise au
    /// format E.164 complet nécessiterait la région du contact.)
    static func normalize(_ raw: String) -> String {
        var result = ""
        for (i, ch) in raw.enumerated() {
            if ch == "+" && i == 0 { result.append("+") }
            else if ch.isNumber { result.append(ch) }
        }
        return result
    }
}

// MARK: - Sélecteur de contact (feuille)

/// Liste TOUS tes contacts (avec numéro), cherchable. Tape un contact pour le
/// choisir : on renvoie son nom + son numéro à l'appelant.
struct ContactPickerView: View {
    var onPick: (PhoneContact) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var contacts: [PhoneContact] = []
    @State private var query = ""
    @State private var state: LoadState = .loading

    private enum LoadState { case loading, ready, denied }

    private var filtered: [PhoneContact] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty else { return contacts }
        return contacts.filter {
            $0.name.localizedCaseInsensitiveContains(q) || $0.phoneNumber.contains(q)
        }
    }

    var body: some View {
        NavigationStack {
            Group {
                switch state {
                case .loading:
                    ProgressView("Lecture de tes contacts…")
                case .denied:
                    deniedView
                case .ready:
                    listView
                }
            }
            .navigationTitle("Mes contacts")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Fermer") { dismiss() }
                }
            }
            .task { await load() }
        }
    }

    private var listView: some View {
        List {
            if contacts.isEmpty {
                Text("Aucun contact avec un numéro de téléphone.")
                    .foregroundStyle(.secondary)
            }
            ForEach(filtered) { c in
                Button {
                    onPick(c)
                    dismiss()
                } label: {
                    HStack(spacing: 12) {
                        ZStack {
                            Circle().fill(Color.green.opacity(0.2))
                            Text(c.initials).font(.headline).foregroundStyle(.green)
                        }
                        .frame(width: 40, height: 40)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(c.name).font(.body).foregroundStyle(.primary)
                            Text(c.rawNumber).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                }
            }
        }
        .listStyle(.plain)
        .searchable(text: $query, prompt: "Nom ou numéro")
    }

    private var deniedView: some View {
        VStack(spacing: 12) {
            Image(systemName: "person.crop.circle.badge.exclamationmark")
                .font(.system(size: 44)).foregroundStyle(.secondary)
            Text("Accès aux contacts refusé").font(.headline)
            Text("Autorise Brocolis à lire tes contacts dans Réglages → Brocolis → Contacts.")
                .font(.subheadline).foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button("Ouvrir les Réglages") {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            }
            .buttonStyle(.borderedProminent)
        }
        .padding(40)
    }

    private func load() async {
        switch BrocolisContacts.authorization() {
        case .denied:
            state = .denied
        case .granted:
            contacts = await BrocolisContacts.fetchAll()
            state = .ready
        case .notDetermined:
            let ok = await BrocolisContacts.requestAccess()
            if ok {
                contacts = await BrocolisContacts.fetchAll()
                state = .ready
            } else {
                state = .denied
            }
        }
    }
}

// MARK: - Composer iMessage (inviter un contact par son numéro)

/// L'appareil peut-il envoyer des SMS/iMessages ? (faux sur simulateur / sans SIM)
func canSendMessages() -> Bool { MFMessageComposeViewController.canSendText() }

/// Ouvre Messages **déjà adressé** au numéro, avec un corps pré-rempli
/// (invitation + clé). L'utilisateur n'a plus qu'à envoyer.
struct MessageComposeView: UIViewControllerRepresentable {
    let recipients: [String]
    let body: String
    var onFinish: () -> Void = {}

    func makeCoordinator() -> Coordinator { Coordinator(onFinish: onFinish) }

    func makeUIViewController(context: Context) -> MFMessageComposeViewController {
        let vc = MFMessageComposeViewController()
        vc.recipients = recipients
        vc.body = body
        vc.messageComposeDelegate = context.coordinator
        return vc
    }

    func updateUIViewController(_ vc: MFMessageComposeViewController, context: Context) {}

    final class Coordinator: NSObject, MFMessageComposeViewControllerDelegate {
        let onFinish: () -> Void
        init(onFinish: @escaping () -> Void) { self.onFinish = onFinish }
        func messageComposeViewController(_ controller: MFMessageComposeViewController,
                                          didFinishWith result: MessageComposeResult) {
            controller.dismiss(animated: true) { self.onFinish() }
        }
    }
}

/// Texte d'invitation envoyé par iMessage : explique quoi faire + contient la clé.
func brocolisInviteBody(contactName: String, keyBase64: String) -> String {
    """
    Rejoins-moi sur Brocolis 🥦 pour qu'on discute chiffré (illisible pour tout le monde d'autre).

    1) Installe l'app Brocolis
    2) Ouvre-la → « Importer une clé »
    3) Colle CETTE clé :

    \(keyBase64)

    (C'est notre clé commune : garde-la pour toi.)
    """
}
