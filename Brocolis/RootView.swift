//
//  RootView.swift
//  Brocolis 🥦
//
//  État « Actif » + appairage + gestion de PLUSIEURS clés nommées.
//  La clé sélectionnée chiffre ; au déchiffrement, toutes les clés sont essayées.
//

import SwiftUI
import UIKit
import StoreKit
import AuthenticationServices

// Fond de la marque + application « plein écran » (contenu + barre de navigation).
// Défini une fois ici, réutilisé par tous les écrans de l'app.
extension Color {
    static let brocoliBg = Color(red: 232.0 / 255, green: 245.0 / 255, blue: 219.0 / 255)
    /// Fond des cartes : un cran PLUS FONCÉ que le fond (vert doux, plus de blanc pur).
    static let brocoliCard = Color(red: 220.0 / 255, green: 239.0 / 255, blue: 208.0 / 255)
    /// Vert de la marque — le même que l'écran d'offres et la montre.
    static let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
}

extension View {
    /// Pose le fond vert Brocolis derrière l'écran ET la barre de navigation.
    /// `scrollContentBackground(.hidden)` masque le fond gris des Form/List pour
    /// que le vert apparaisse ; sans effet sur les vues non défilantes.
    func brocolisBackground() -> some View {
        self
            .scrollContentBackground(.hidden)
            .background(Color.brocoliBg.ignoresSafeArea())
            .toolbarBackground(Color.brocoliBg, for: .navigationBar)
            .toolbarBackground(.visible, for: .navigationBar)
    }
}

struct RootView: View {
    @Environment(\.scenePhase) private var scenePhase
    @ObservedObject private var router = AppRouter.shared
    /// Palier courant, observé : la section Forfait se met à jour dès qu'un
    /// achat aboutit ou que le serveur ouvre un accès offert.
    @ObservedObject private var store = BrocolisStore.shared
    @State private var showOffers = false
    @State private var showManageSubscription = false
    /// Résultat de « Se connecter avec Apple » à afficher sous le bouton.
    @State private var appleMessage: String?
    @Environment(\.colorScheme) private var colorScheme

    @State private var keys: [NamedKey] = BrocolisKeyStore.keys
    /// La protection de chaque clé (docs/SECURITE.md §8.8).
    @State private var protections: [String: BrocolisProtection] = [:]
    @State private var selectedId: String? = BrocolisKeyStore.selectedKeyId
    @State private var recipientIds: [String] = BrocolisKeyStore.recipientKeyIds
    @State private var isActive = BrocolisKeyStore.isActive
    @State private var encryptWhole = BrocolisKeyStore.encryptWholeAlways
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var keyTTL = BrocolisKeyStore.selectedKey?.ttlSeconds ?? 0
    @State private var pairedPeerCount = BrocolisKeyStore.pairingPeerIds.count
    /// Pourquoi l'écran d'offres s'ouvre, s'il s'ouvre.
    @State private var paywallReason: BrocolisPaidFeature?

    @State private var alertMessage: String?
    @State private var showPairing = false
    @State private var showGenerate = false
    @State private var newKeyName = ""
    @State private var showImport = false
    @State private var importName = ""
    @State private var importText = ""
    /// Clé collée PROTÉGÉE (`[[BROCOLIS-CLE:v1:…]]`) : on demande sa phrase.
    @State private var showImportPassphrase = false
    @State private var importPassphrase = ""
    /// Clé à partager protégée par une phrase secrète (feuille dédiée).
    @State private var protectedShareKey: NamedKey?
    @State private var showContacts = false
    @State private var invite: InvitePayload?
    @State private var renameTarget: NamedKey?
    @State private var renameText = ""
    @State private var deleteTarget: NamedKey?

    @State private var lockEnabled = MessagingPrefs.lockEnabled
    @State private var eraseOnClose = MessagingPrefs.eraseOnClose

    private let ttlOptions: [(label: String, seconds: Int)] = [
        (loc("Jamais", "Never", "Nunca"), 0),
        (loc("1 heure", "1 hour", "1 hora"), 3600),
        (loc("24 heures", "24 hours", "24 horas"), 86_400),
        (loc("7 jours", "7 days", "7 días"), 604_800),
    ]

    private var hasKey: Bool { !keys.isEmpty }
    private var selected: NamedKey? {
        keys.first(where: { $0.id == selectedId }) ?? keys.first
    }

    var body: some View {
        NavigationStack {
            Form {
                // `.listRowBackground` par SECTION (fiable) : sur le Form global
                // il n'a aucun effet — d'où les cartes restées blanches.
                quickStartSection.listRowBackground(Color.brocoliCard)
                messagingSection.listRowBackground(Color.brocoliCard)
                planSection.listRowBackground(Color.brocoliCard)
                privacySection.listRowBackground(Color.brocoliCard)
                conversationSection.listRowBackground(Color.brocoliCard)
                keyboardSection.listRowBackground(Color.brocoliCard)
                encryptionSection.listRowBackground(Color.brocoliCard)
                pairingSection.listRowBackground(Color.brocoliCard)
                keysSection.listRowBackground(Color.brocoliCard)
                recipientsSection.listRowBackground(Color.brocoliCard)
                selectedKeySection.listRowBackground(Color.brocoliCard)
                howToSection.listRowBackground(Color.brocoliCard)
                deviceIdSection.listRowBackground(Color.brocoliCard)
                creditsSection.listRowBackground(Color.brocoliCard)
            }
            .brocolisBackground()
            .sheet(isPresented: $showOffers) { PaywallView(reason: nil) }
            // Feuille Apple native : changer de formule, résilier, voir la date
            // de renouvellement — sans quitter l'app.
            .manageSubscriptionsSheet(isPresented: $showManageSubscription)
            .navigationTitle("Brocolis 🥦")
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    NavigationLink {
                        KeyboardHubView()
                    } label: {
                        Image(systemName: "keyboard")
                    }
                    .accessibilityLabel(loc("Clavier", "Keyboard", "Teclado"))
                }
            }
            .onAppear {
                purgeIfNeeded()
                Task { await BrocolisPush.subscribeLiveActivity() }
                resumePendingPairing()
                if router.openPairing { showPairing = true; router.openPairing = false }
            }
            .onChange(of: scenePhase) { phase in
                if phase == .active {
                    purgeIfNeeded()
                    Task { await BrocolisPush.subscribeLiveActivity() }
                    resumePendingPairing()
                }
            }
            .onChange(of: router.openPairing) { open in
                if open { showPairing = true; router.openPairing = false }
            }
            .sheet(isPresented: $showPairing, onDismiss: reload) {
                NavigationStack { PairingView(initialCode: router.pairingCode) }
                    .onDisappear { router.pairingCode = nil }
            }
            .sheet(isPresented: $showContacts) {
                ContactPickerView { contact in
                    createKeyFromContact(contact)
                }
            }
            .sheet(item: $paywallReason) { reason in
                PaywallView(reason: reason)
            }
            .sheet(item: $invite) { payload in
                MessageComposeView(recipients: payload.recipients, body: payload.body) {
                    invite = nil
                }
                .ignoresSafeArea()
            }
            .sheet(item: $protectedShareKey) { key in
                ProtectedKeyShareView(key: key)
            }
            .alert(loc("Nouvelle clé", "New key", "Nueva clave"), isPresented: $showGenerate) {
                TextField(loc("Nom (ex. Maman)", "Name (e.g. Mom)", "Nombre (ej. Mamá)"), text: $newKeyName)
                Button(loc("Générer", "Generate", "Generar")) {
                    guard canAddKey() else { return }
                    BrocolisKeyStore.addKey(name: newKeyName, base64: BrocolisCrypto.generateKeyBase64())
                    BrocolisKeyStore.setActive(true) // activation auto : plus besoin de l'interrupteur
                    reload()
                }
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) {}
            } message: {
                Text(loc("Crée une clé AES-256 aléatoire, nommée, et la sélectionne.", "Creates a random named AES-256 key and selects it.", "Crea una clave AES-256 aleatoria con nombre y la selecciona."))
            }
            .alert(loc("Importer une clé", "Import a key", "Importar una clave"), isPresented: $showImport) {
                TextField(loc("Nom", "Name", "Nombre"), text: $importName)
                TextField(loc("Clé reçue (protégée ou base64)", "Received key (protected or base64)", "Clave recibida (protegida o base64)"), text: $importText)
                Button(loc("Importer", "Import", "Importar")) { importKey() }
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) {}
            } message: {
                Text(loc("Colle la clé reçue d’un correspondant. Si elle est protégée ([[BROCOLIS-CLE:…]]), Brocolis te demandera sa phrase secrète.", "Paste the key received from a contact. If it is protected ([[BROCOLIS-CLE:…]]), Brocolis will ask for its passphrase.", "Pega la clave recibida de un contacto. Si está protegida ([[BROCOLIS-CLE:…]]), Brocolis te pedirá su frase secreta."))
            }
            .alert(loc("Clé protégée", "Protected key", "Clave protegida"), isPresented: $showImportPassphrase) {
                SecureField(loc("Phrase secrète", "Passphrase", "Frase secreta"), text: $importPassphrase)
                Button(loc("Déverrouiller", "Unlock", "Desbloquear")) { importProtectedKey() }
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) { importPassphrase = "" }
            } message: {
                Text(loc("Tape la phrase secrète que ton correspondant t’a donnée (de vive voix).", "Type the passphrase your contact gave you (in person).", "Escribe la frase secreta que te dio tu contacto (de viva voz)."))
            }
            .alert(loc("Renommer la clé", "Rename key", "Renombrar clave"), isPresented: renameBinding) {
                TextField(loc("Nom", "Name", "Nombre"), text: $renameText)
                Button("OK") {
                    if let t = renameTarget { BrocolisKeyStore.renameKey(id: t.id, name: renameText) }
                    renameTarget = nil
                    reload()
                }
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) { renameTarget = nil }
            }
            .alert(
                loc("Supprimer la clé ?", "Delete key?", "¿Eliminar la clave?"),
                isPresented: Binding(get: { deleteTarget != nil },
                                     set: { if !$0 { deleteTarget = nil } })
            ) {
                Button(loc("Supprimer", "Delete", "Eliminar"), role: .destructive) {
                    if let t = deleteTarget {
                        BrocolisKeyStore.deleteKey(id: t.id)
                        BrocolisV3.forget(keyId: t.id)
                    }
                    deleteTarget = nil
                    reload()
                }
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) { deleteTarget = nil }
            } message: {
                Text(loc(
                    "Cette clé sera supprimée. Tu ne pourras plus déchiffrer les messages qui l'utilisent.",
                    "This key will be deleted. You will no longer be able to decrypt messages that use it.",
                    "Esta clave se eliminará. Ya no podrás descifrar los mensajes que la usan."))
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

    // MARK: Démarrage / état en un coup d'œil

    // La toute première chose qu'on voit : soit « commence ici » (aucune clé),
    // soit un état clair « Prêt / En pause » avec l'action évidente.
    @ViewBuilder private var quickStartSection: some View {
        if !hasKey {
            Section {
                Button {
                    newKeyName = ""
                    showGenerate = true
                } label: {
                    Label(loc("Créer ma première clé", "Create my first key", "Crear mi primera clave"), systemImage: "key.fill")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .listRowInsets(EdgeInsets(top: 10, leading: 14, bottom: 6, trailing: 14))

                Button {
                    showPairing = true
                } label: {
                    Label(loc("M’appairer avec quelqu’un", "Pair with someone", "Emparejar con alguien"), systemImage: "person.2.fill")
                }
            } header: {
                Text(loc("Bienvenue 🥦", "Welcome 🥦", "Bienvenido 🥦"))
            } footer: {
                locText("Une **clé** = une discussion privée avec une personne. Crée-en une et partage-la (ou appaire-toi en direct), et tu pourras chiffrer tes messages dans n’importe quelle app.", "A **key** = a private conversation with one person. Create one and share it (or pair live), and you can encrypt your messages in any app.", "Una **clave** = una conversación privada con una persona. Crea una y compártela (o empareja en directo), y podrás cifrar tus mensajes en cualquier app.")
            }
        } else {
            // Contrôle d'état TOUJOURS présent, en tête de liste : un seul
            // interrupteur clair pour activer / mettre en pause.
            Section {
                Toggle(isOn: activeBinding) {
                    HStack(spacing: 12) {
                        Image(systemName: isActive ? "checkmark.seal.fill" : "pause.circle.fill")
                            .font(.title2)
                            .foregroundStyle(isActive ? .green : .orange)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(isActive ? loc("Prêt à chiffrer", "Ready to encrypt", "Listo para cifrar") : loc("En pause", "Paused", "En pausa"))
                                .font(.headline)
                            Text(isActive
                                 ? loc("Utilise le clavier 🥦 ou « Partager » dans tes apps.", "Use the 🥦 keyboard or “Share” in your apps.", "Usa el teclado 🥦 o «Compartir» en tus apps.")
                                 : loc("Active pour chiffrer dans tes apps.", "Turn on to encrypt in your apps.", "Actívalo para cifrar en tus apps."))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                .padding(.vertical, 2)
            } header: {
                Text(loc("État", "Status", "Estado"))
            }
        }
    }

    // MARK: Messagerie live (un correspondant = une clé)

    @ViewBuilder private var messagingSection: some View {
        if hasKey {
            Section {
                NavigationLink {
                    LockGate { MessagingHomeView() }
                } label: {
                    Label(loc("Ouvrir la messagerie", "Open messaging", "Abrir mensajería"), systemImage: "bubble.left.and.bubble.right.fill")
                }
            } header: {
                Text(loc("Discuter en direct", "Chat live", "Chatear en directo"))
            } footer: {
                locText("Choisis un correspondant **parmi tes clés** et discute en clair dans l’app. Chaque message part chiffré avec sa clé : lisible ici, illisible partout ailleurs (serveur, iMessage…).", "Pick a contact **from your keys** and chat in the clear inside the app. Each message leaves encrypted with its key: readable here, unreadable everywhere else (server, iMessage…).", "Elige un contacto **entre tus claves** y chatea en claro dentro de la app. Cada mensaje sale cifrado con su clave: legible aquí, ilegible en cualquier otro lugar (servidor, iMessage…).")
            }
        }
    }

    // MARK: Confidentialité (verrou + effacement à la fermeture)

    @ViewBuilder private var privacySection: some View {
        if hasKey {
            Section {
                Toggle(isOn: lockBinding) {
                    Label(loc("Verrouiller par Face ID / code", "Lock with Face ID / passcode", "Bloquear con Face ID / código"), systemImage: "faceid")
                }
                Toggle(isOn: eraseBinding) {
                    Label(loc("Effacer à la fermeture", "Erase on close", "Borrar al cerrar"), systemImage: "eraser")
                }
            } header: {
                Text(loc("Confidentialité", "Privacy", "Privacidad"))
            } footer: {
                locText("**Verrouiller** : il faut Face ID (ou le code de l’appareil) pour voir tes messages, comme le propose Apple.\n\n**Effacer à la fermeture** (facultatif) : en quittant l’app, les messages affichés disparaissent ; à la réouverture, seuls les **nouveaux** réapparaissent. Désactivé, tout l’historique encore sur le serveur (7 jours) reste visible.", "**Lock** : Face ID (or the device passcode) is required to see your messages, just as Apple offers.\n\n**Erase on close** (optional): when you leave the app, the displayed messages disappear; on reopening, only the **new** ones reappear. Turned off, the whole history still on the server (7 days) stays visible.", "**Bloquear** : hace falta Face ID (o el código del dispositivo) para ver tus mensajes, como propone Apple.\n\n**Borrar al cerrar** (opcional): al salir de la app, los mensajes mostrados desaparecen; al reabrir, solo reaparecen los **nuevos**. Desactivado, todo el historial aún en el servidor (7 días) sigue visible.")
            }
        }
    }

    private var lockBinding: Binding<Bool> {
        Binding(
            get: { lockEnabled },
            set: { MessagingPrefs.lockEnabled = $0; lockEnabled = $0 }
        )
    }

    private var eraseBinding: Binding<Bool> {
        Binding(
            get: { eraseOnClose },
            set: {
                MessagingPrefs.eraseOnClose = $0
                eraseOnClose = $0
                // La montre suit le réglage sans attendre le passage en arrière-plan.
                #if canImport(WatchConnectivity)
                BrocolisWatchSync.shared.pushNow()
                #endif
            }
        )
    }

    // MARK: Conversation (lecture/écriture à la volée)

    private var conversationSection: some View {
        Section {
            NavigationLink {
                ConversationView()
            } label: {
                Label(loc("Ouvrir la conversation", "Open conversation", "Abrir conversación"), systemImage: "text.bubble.fill")
            }
        } header: {
            Text(loc("Lire à la volée", "Read on the fly", "Leer al vuelo"))
        } footer: {
            Text(loc("Colle toute une discussion : Brocolis déchiffre automatiquement les messages protégés par tes clés et laisse 🔒 ceux des autres. Plus besoin de « traduire » message par message.", "Paste a whole conversation: Brocolis automatically decrypts the messages protected by your keys and leaves 🔒 on the others. No more “translating” message by message.", "Pega una conversación entera: Brocolis descifra automáticamente los mensajes protegidos por tus claves y deja 🔒 en los demás. Ya no hay que «traducir» mensaje por mensaje."))
        }
    }

    // MARK: Clavier (chiffrer sans copier)

    private var keyboardSection: some View {
        Section {
            NavigationLink {
                KeyboardHubView()
            } label: {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(loc("Clavier Brocolis 🥦", "Brocolis 🥦 keyboard", "Teclado Brocolis 🥦"))
                            .font(.headline)
                        Text(KeyboardHubView.isInstalled()
                             ? loc("Ajouté · vibrations, thème, disposition…", "Added · haptics, theme, layout…", "Añadido · vibración, tema, distribución…")
                             : loc("À ajouter · installation et réglages", "To add · setup and settings", "Por añadir · instalación y ajustes"))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                } icon: {
                    Image(systemName: "keyboard")
                }
            }
        } header: {
            Text(loc("Envoyer sans copier", "Send without copying", "Enviar sin copiar"))
        } footer: {
            Text(loc("Écris et chiffre dans n’importe quelle app, sans copier-coller. Tout se règle ici, ou avec ⚙️ sur le clavier.", "Type and encrypt in any app, no copy-paste. Set everything here, or with ⚙️ on the keyboard.", "Escribe y cifra en cualquier app, sin copiar y pegar. Todo se ajusta aquí o con ⚙️ en el teclado."))
        }
    }

    // MARK: Chiffrement

    private var encryptionSection: some View {
        Section {
            Label(loc("Sans ((…)) : tout le message est chiffré d’un bloc.", "Without ((…)): the whole message is encrypted as one block.", "Sin ((…)): todo el mensaje se cifra en un bloque."), systemImage: "lock.rectangle.on.rectangle.fill")
            Label(loc("Avec ((…)) : seuls ces passages sont chiffrés, le reste reste lisible.", "With ((…)): only those parts are encrypted, the rest stays readable.", "Con ((…)): solo esos fragmentos se cifran, el resto queda legible."), systemImage: "parentheses")
        } header: {
            Text(loc("Chiffrement", "Encryption", "Cifrado"))
        } footer: {
            Text(loc("Même règle dans le partage, le clavier et iMessage. Exemple : « RDV ((au 12 rue X)) demain » → seule l’adresse part chiffrée.", "Same rule in Share, the keyboard and iMessage. Example: « Meet ((at 12 X street)) tomorrow » → only the address is encrypted.", "Misma regla al compartir, en el teclado y en iMessage. Ejemplo: « Cita ((en calle X 12)) mañana » → solo la dirección se cifra."))
        }
    }

    private var encryptWholeBinding: Binding<Bool> {
        Binding(
            get: { encryptWhole },
            set: { newValue in
                BrocolisKeyStore.setEncryptWholeAlways(newValue)
                encryptWhole = BrocolisKeyStore.encryptWholeAlways
            }
        )
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
                Label(loc("Appairer automatiquement", "Pair automatically", "Emparejar automáticamente"), systemImage: "person.2.badge.key.fill")
            }
            if let fp = fingerprint {
                LabeledContent(loc("Empreinte", "Fingerprint", "Huella"), value: fp)
                    .font(.system(.footnote, design: .monospaced))
            }
            if pairedPeerCount > 0 {
                Button {
                    Task {
                        let n = await BrocolisPush.notifyPeers()
                        await MainActor.run {
                            alertMessage = n > 0
                                ? loc("Mise à jour envoyée à \(n) correspondant(s).", "Update sent to \(n) contact(s).", "Actualización enviada a \(n) contacto(s).")
                                : loc("Aucune notification envoyée (correspondant hors ligne, ou push non configuré côté serveur).", "No notification sent (contact offline, or push not configured on the server).", "No se envió ninguna notificación (contacto sin conexión, o push no configurado en el servidor).")
                        }
                    }
                } label: {
                    Label(loc("Notifier mes correspondants", "Notify my contacts", "Notificar a mis contactos"), systemImage: "bell.badge")
                }
            }
        } header: {
            Text(loc("Correspondant", "Contact", "Contacto"))
        } footer: {
            Text(loc("Échange la clé via un code court (X25519). La clé reçue est ajoutée à ta liste.\n\n« Notifier mes correspondants » met à jour leur Live Activity 🥦 à distance (push).", "Exchange the key via a short code (X25519). The received key is added to your list.\n\n“Notify my contacts” updates their Live Activity 🥦 remotely (push).", "Intercambia la clave mediante un código corto (X25519). La clave recibida se añade a tu lista.\n\n«Notificar a mis contactos» actualiza su Live Activity 🥦 de forma remota (push)."))
        }
    }

    // MARK: Clés

    private var keysSection: some View {
        Section {
            ForEach(keys) { key in
                HStack {
                    Image(systemName: key.id == selectedId ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(key.id == selectedId ? .green : .secondary)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(key.name)
                        if let phone = BrocolisKeyStore.keyPhone(key.id) {
                            Text(phone).font(.caption).foregroundStyle(.secondary)
                        }
                        Text((protections[key.id] ?? .legacy).label)
                            .font(.caption2).foregroundStyle(.secondary)
                    }
                    Spacer()
                    // Menu VISIBLE (⋯) : renommer / supprimer, en plus du balayage.
                    Menu {
                        Button {
                            renameTarget = key
                            renameText = key.name
                        } label: {
                            Label(loc("Renommer", "Rename", "Renombrar"), systemImage: "pencil")
                        }
                        Button(role: .destructive) {
                            deleteTarget = key
                        } label: {
                            Label(loc("Supprimer", "Delete", "Eliminar"), systemImage: "trash")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                            .foregroundStyle(.secondary)
                            .imageScale(.large)
                    }
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    BrocolisKeyStore.selectKey(key.id)
                    reload()
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) {
                        deleteTarget = key
                    } label: {
                        Label(loc("Supprimer", "Delete", "Eliminar"), systemImage: "trash")
                    }
                    Button {
                        renameTarget = key
                        renameText = key.name
                    } label: {
                        Label(loc("Renommer", "Rename", "Renombrar"), systemImage: "pencil")
                    }
                    .tint(.blue)
                }
            }

            Button {
                showContacts = true
            } label: {
                Label(loc("Ajouter depuis mes contacts", "Add from my contacts", "Añadir desde mis contactos"), systemImage: "person.crop.circle.badge.plus")
            }
            Button {
                newKeyName = ""
                showGenerate = true
            } label: {
                Label(loc("Générer une nouvelle clé", "Generate a new key", "Generar una nueva clave"), systemImage: "key.fill")
            }
            Button {
                importName = ""
                importText = ""
                showImport = true
            } label: {
                Label(loc("Importer une clé", "Import a key", "Importar una clave"), systemImage: "square.and.arrow.down")
            }
        } header: {
            Text(loc("Clés", "Keys", "Claves"))
        } footer: {
            if hasKey {
                Text(loc("La clé cochée sert à chiffrer. Au déchiffrement, toutes tes clés sont essayées. Glisse une clé pour la renommer ou la supprimer.", "The checked key is used to encrypt. When decrypting, all your keys are tried. Swipe a key to rename or delete it.", "La clave marcada se usa para cifrar. Al descifrar, se prueban todas tus claves. Desliza una clave para renombrarla o eliminarla."))
            } else {
                Text(loc("Aucune clé. Génère-en une, importe-en une, ou appaire-toi.", "No key. Generate one, import one, or pair up.", "Ninguna clave. Genera una, importa una, o empareja."))
            }
        }
    }

    // MARK: Destinataires (chiffrer pour plusieurs clés)

    @ViewBuilder private var recipientsSection: some View {
        if keys.count >= 2 {
            Section {
                ForEach(keys) { key in
                    let on = recipientIds.contains(key.id)
                    HStack {
                        Image(systemName: on ? "checkmark.square.fill" : "square")
                            .foregroundStyle(on ? .green : .secondary)
                        Text(key.name)
                        Spacer()
                    }
                    .contentShape(Rectangle())
                    .onTapGesture { toggleRecipient(key.id) }
                }
                if !recipientIds.isEmpty {
                    Button(loc("Tout décocher (revenir à la clé sélectionnée)", "Uncheck all (back to the selected key)", "Desmarcar todo (volver a la clave seleccionada)")) {
                        recipientIds = []
                        BrocolisKeyStore.setRecipientKeyIds([])
                    }
                    .font(.footnote)
                }
            } header: {
                Text(loc("Chiffrer pour", "Encrypt for", "Cifrar para"))
            } footer: {
                if recipientIds.count >= 2 {
                    locText("Le message sera lisible par **\(recipientIds.count) clés** à la fois (un seul jeton `v2`). Pratique pour écrire à plusieurs correspondants d’un coup.\n\n⚠️ Le format `v2` n’est lisible que par une app Brocolis à jour (pas par l’ancien proxy brocolis).", "The message will be readable by **\(recipientIds.count) keys** at once (a single `v2` token). Handy for writing to several contacts at a time.\n\n⚠️ The `v2` format is only readable by an up-to-date Brocolis app (not by the old brocolis proxy).", "El mensaje será legible por **\(recipientIds.count) claves** a la vez (un solo token `v2`). Práctico para escribir a varios contactos de una vez.\n\n⚠️ El formato `v2` solo lo puede leer una app Brocolis actualizada (no el antiguo proxy brocolis).")
                } else if recipientIds.count == 1 {
                    locText("Une seule clé cochée : message classique `v1`, lisible par les détenteurs de cette clé.", "A single key checked: classic `v1` message, readable by the holders of that key.", "Una sola clave marcada: mensaje clásico `v1`, legible por los poseedores de esa clave.")
                } else {
                    locText("Coche plusieurs clés pour qu’**un même message soit lisible par plusieurs correspondants à la fois**. Si tu ne coches rien, Brocolis chiffre pour la clé sélectionnée (point vert ci-dessus).", "Check several keys so that **the same message is readable by several contacts at once**. If you check nothing, Brocolis encrypts for the selected key (green dot above).", "Marca varias claves para que **un mismo mensaje sea legible por varios contactos a la vez**. Si no marcas nada, Brocolis cifra para la clave seleccionada (punto verde arriba).")
                }
            }
        }
    }

    private func toggleRecipient(_ id: String) {
        if let i = recipientIds.firstIndex(of: id) {
            recipientIds.remove(at: i)
        } else {
            recipientIds.append(id)
        }
        BrocolisKeyStore.setRecipientKeyIds(recipientIds)
    }

    @ViewBuilder private var selectedKeySection: some View {
        if let sel = selected {
            Section {
                Text(sel.name).font(.headline)
                Text((protections[sel.id] ?? .legacy).label)
                    .font(.footnote).foregroundStyle(.secondary)
                // L'identité de ce contact a changé (§9.8) : rien ne part vers
                // lui tant que l'empreinte n'a pas été comparée.
                if BrocolisV3.isBlocked(sel) {
                    Button {
                        BrocolisKeyStore.confirmIdentity(keyId: sel.id)
                        reload()
                    } label: {
                        Label(loc("J’ai comparé l’empreinte", "I compared the fingerprint", "He comparado la huella"),
                              systemImage: "checkmark.shield")
                    }
                }
                // Une clé sans appairage v3, partagée avec UNE personne à jour :
                // le double cliquet à partir de la clé (PSK, §8.5). Jamais
                // automatique : un ancien correspondant ne lirait plus rien.
                if sel.v3Bundle == nil && sel.duo != false {
                    Toggle(isOn: Binding(
                        get: { sel.psk == true },
                        set: { on in
                            BrocolisKeyStore.setPsk(on, forKeyId: sel.id)
                            reload()
                        })) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(loc("Double cliquet avec cette clé (PSK)", "Double ratchet with this key (PSK)", "Doble trinquete con esta clave (PSK)"))
                            Text(loc("Seulement si cette clé est partagée avec UNE personne dont l’app Brocolis est à jour. Ses réponses suivront toutes seules.",
                                     "Only if this key is shared with ONE person whose Brocolis app is up to date. Their replies will follow on their own.",
                                     "Solo si esta clave se comparte con UNA persona cuya app Brocolis está actualizada. Sus respuestas seguirán solas."))
                                .font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
                // Partage RECOMMANDÉ : la clé part chiffrée par une phrase
                // secrète, donnée à part (de vive voix).
                Button {
                    protectedShareKey = sel
                } label: {
                    Label(loc("Partager protégée par une phrase secrète", "Share protected by a passphrase", "Compartir protegida con una frase secreta"), systemImage: "lock.shield.fill")
                        .fontWeight(.semibold)
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.borderedProminent)
                .tint(.green)
                .listRowInsets(EdgeInsets(top: 10, leading: 14, bottom: 6, trailing: 14))

                // Ancien partage EN CLAIR : toujours possible, mais replié et
                // signalé — quiconque voit ce texte peut lire vos messages.
                DisclosureGroup {
                    Label(loc("En clair, la clé est lisible par quiconque voit le message, le presse-papiers ou une sauvegarde. Préfère le partage protégé.", "In the clear, the key is readable by anyone who sees the message, the clipboard or a backup. Prefer protected sharing.", "En claro, la clave es legible por cualquiera que vea el mensaje, el portapapeles o una copia de seguridad. Prefiere el envío protegido."), systemImage: "exclamationmark.triangle.fill")
                        .font(.footnote)
                        .foregroundStyle(.orange)
                    Text(sel.base64)
                        .font(.system(.footnote, design: .monospaced))
                        .textSelection(.enabled)
                    Button {
                        UIPasteboard.general.string = sel.base64
                        alertMessage = loc("Clé copiée EN CLAIR dans le presse-papiers.", "Key copied IN THE CLEAR to the clipboard.", "Clave copiada EN CLARO en el portapapeles.")
                    } label: {
                        Label(loc("Copier la clé en clair", "Copy key in the clear", "Copiar clave en claro"), systemImage: "doc.on.doc")
                    }
                    ShareLink(item: sel.base64) {
                        Label(loc("Partager la clé en clair", "Share key in the clear", "Compartir clave en claro"), systemImage: "square.and.arrow.up")
                    }
                    if let phone = BrocolisKeyStore.keyPhone(sel.id), canSendMessages() {
                        Button {
                            invite = InvitePayload(
                                recipients: [phone],
                                body: brocolisInviteBody(contactName: sel.name, keyBase64: sel.base64)
                            )
                        } label: {
                            Label(loc("Inviter \(sel.name) par iMessage (clé en clair)", "Invite \(sel.name) by iMessage (key in the clear)", "Invitar a \(sel.name) por iMessage (clave en claro)"), systemImage: "paperplane")
                        }
                    }
                } label: {
                    Label(loc("Partage en clair (déconseillé)", "Share in the clear (not recommended)", "Compartir en claro (desaconsejado)"), systemImage: "lock.open")
                        .foregroundStyle(.secondary)
                }
            } header: {
                Text(loc("Clé sélectionnée", "Selected key", "Clave seleccionada"))
            }

            Section {
                Picker(loc("Validité", "Validity", "Validez"), selection: ttlBinding(for: sel.id)) {
                    ForEach(ttlOptions, id: \.seconds) { opt in
                        Text(opt.label).tag(opt.seconds)
                    }
                }
                expiryStatus(for: sel)
            } header: {
                Text(loc("Expiration de « \(sel.name) »", "Expiration of “\(sel.name)”", "Caducidad de «\(sel.name)»"))
            } footer: {
                Text(loc("Au-delà de la validité, l’extension refuse de chiffrer avec cette clé. Le déchiffrement reste possible jusqu’à ce qu’elle soit purgée à l’ouverture de l’app.", "Beyond the validity period, the extension refuses to encrypt with this key. Decryption stays possible until it is purged when the app opens.", "Pasado el periodo de validez, la extensión se niega a cifrar con esta clave. El descifrado sigue siendo posible hasta que se purgue al abrir la app."))
            }
        }
    }

    private func ttlBinding(for id: String) -> Binding<Int> {
        Binding(
            get: { keyTTL },
            set: { newValue in
                // L'expiration automatique était annoncée dans l'écran
                // d'offres sans être appliquée nulle part : porte posée ici.
                let gate = BrocolisPlan.gateForKeyExpiry(ttlSeconds: newValue,
                                                         tier: BrocolisPlan.tier)
                if case .needs(_, let feature) = gate {
                    paywallReason = feature
                    return
                }
                BrocolisKeyStore.setKeyTTL(newValue, forKeyId: id)
                reload()
            }
        )
    }

    @ViewBuilder private func expiryStatus(for key: NamedKey) -> some View {
        if let expires = key.expiresAt {
            if BrocolisKeyStore.isExpired(expiresAt: expires, now: Date()) {
                Label(loc("Expirée — renouvelle-la", "Expired — renew it", "Caducada — renuévala"), systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else {
                let lead = BrocolisKeyStore.notificationLead(ttlSeconds: key.ttlSeconds) ?? 0
                let soon = expires.timeIntervalSinceNow <= lead
                Label {
                    Text(loc("Expire \(expires.formatted(.relative(presentation: .named)))", "Expires \(expires.formatted(.relative(presentation: .named)))", "Caduca \(expires.formatted(.relative(presentation: .named)))"))
                } icon: {
                    Image(systemName: soon ? "exclamationmark.triangle.fill" : "clock")
                }
                .foregroundStyle(soon ? .orange : .secondary)
            }
        } else {
            Text(loc("Pas d’expiration", "No expiration", "Sin caducidad")).foregroundStyle(.secondary)
        }
    }

    // MARK: Mode d'emploi

    private var howToSection: some View {
        Section(loc("Comment ça marche", "How it works", "Cómo funciona")) {
            locText("Sélectionne du texte dans n’importe quelle app de messagerie, ouvre le menu **Partager**, puis choisis **Brocolis 🥦** pour chiffrer tes ((secrets)) ou déchiffrer les jetons reçus.", "Select text in any messaging app, open the **Share** menu, then choose **Brocolis 🥦** to encrypt your ((secrets)) or decrypt the tokens you receive.", "Selecciona texto en cualquier app de mensajería, abre el menú **Compartir**, luego elige **Brocolis 🥦** para cifrar tus ((secretos)) o descifrar los tokens recibidos.")
                .font(.subheadline)
            locText("⚠️ Le résultat chiffré est copié : **colle‑le en remplaçant ton texte d’origine**. Ne laisse pas la version en clair dans le message, sinon elle reste visible.", "⚠️ The encrypted result is copied: **paste it over your original text**. Do not leave the clear version in the message, or it stays visible.", "⚠️ El resultado cifrado se copia: **pégalo reemplazando tu texto original**. No dejes la versión en claro en el mensaje, o seguirá visible.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
    }

    // MARK: Forfait

    /// Toujours visible : jusqu'ici l'écran d'offres n'apparaissait qu'en
    /// butant sur une limite, et rien ne permettait de voir son forfait ni
    /// d'en changer.
    private var planSection: some View {
        Section {
            HStack(spacing: 12) {
                Image(systemName: store.tier == .free ? "leaf.fill" : "crown.fill")
                    .font(.title2)
                    .foregroundStyle(store.tier == .free ? Color.secondary : Color.brocoliGreen)
                    .frame(width: 32)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(planName).font(.headline)
                        if isOffered {
                            Text(loc("offert", "complimentary", "de cortesía"))
                                .font(.caption2.bold())
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(Capsule().fill(Color.brocoliGreen.opacity(0.2)))
                        }
                    }
                    Text(planDetail).font(.footnote).foregroundStyle(.secondary)
                }
            }
            .padding(.vertical, 2)

            Button { showOffers = true } label: {
                Label(store.tier == .free
                      ? loc("Voir les formules", "See plans", "Ver los planes")
                      : loc("Changer de formule", "Change plan", "Cambiar de plan"),
                      systemImage: "arrow.up.arrow.down.circle")
            }
            // Gérer / résilier n'a de sens que pour un abonnement App Store :
            // un accès offert ne se gère pas chez Apple.
            if BrocolisPlan.purchasedTier > .free {
                Button { showManageSubscription = true } label: {
                    Label(loc("Gérer mon abonnement", "Manage my subscription",
                              "Gestionar mi suscripción"),
                          systemImage: "creditcard")
                }
            }
            appleAccessRow
        } header: {
            Text(loc("Forfait", "Plan", "Plan"))
        } footer: {
            Text(loc("Mensuel, sans engagement. Le chiffrement reste gratuit et illimité.",
                     "Monthly, no commitment. Encryption stays free and unlimited.",
                     "Mensual, sin compromiso. El cifrado sigue siendo gratuito e ilimitado."))
        }
        // Rafraîchit l'accès offert à l'affichage : utile juste après avoir
        // ajouté son identifiant à BROCOLIS_PRO_IDS, sans relancer l'app.
        .task { await store.refreshGrantedAccess() }
    }

    /// Accès offert par e-mail : « Se connecter avec Apple » prouve l'e-mail au
    /// serveur, qui ouvre Pro s'il figure dans `BROCOLIS_PRO_EMAILS`.
    @ViewBuilder
    private var appleAccessRow: some View {
        if let email = store.linkedEmail {
            HStack {
                Label(email, systemImage: "apple.logo")
                    .font(.footnote)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                Button(loc("Déconnecter", "Sign out", "Cerrar sesión"), role: .destructive) {
                    Task { await store.unlinkApple() }
                }
                .font(.footnote)
                .buttonStyle(.borderless)
            }
        } else {
            VStack(alignment: .leading, spacing: 6) {
                SignInWithAppleButton(.signIn) { request in
                    request.requestedScopes = [.email]
                } onCompletion: { result in
                    handleAppleSignIn(result)
                }
                .signInWithAppleButtonStyle(colorScheme == .dark ? .white : .black)
                .frame(height: 44)
                .disabled(store.isWorking)
                Text(appleMessage ?? loc(
                    "Accès offert ? Connecte-toi avec Apple et choisis « Partager mon e-mail ».",
                    "Complimentary access? Sign in with Apple and choose “Share My Email”.",
                    "¿Acceso de cortesía? Inicia sesión con Apple y elige «Compartir mi correo»."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.vertical, 4)
        }
    }

    private func handleAppleSignIn(_ result: Result<ASAuthorization, Error>) {
        switch result {
        case .success(let authorization):
            guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential,
                  let data = credential.identityToken,
                  let token = String(data: data, encoding: .utf8) else {
                appleMessage = loc("Apple n'a pas renvoyé de jeton.", "Apple returned no token.",
                                   "Apple no devolvió ningún token.")
                return
            }
            Task { appleMessage = await store.linkApple(identityToken: token) }
        case .failure(let error):
            // Annulation par l'utilisateur : rien à signaler.
            if (error as? ASAuthorizationError)?.code == .canceled { return }
            appleMessage = error.localizedDescription
        }
    }

    private var planName: String {
        switch store.tier {
        case .free: return loc("Gratuit", "Free", "Gratis")
        case .plus: return "Brocolis+"
        case .pro:  return "Brocolis Pro"
        }
    }

    private var planDetail: String {
        switch store.tier {
        case .free:
            return loc("\(BrocolisPlan.freeKeyLimit) clés · chiffrement illimité",
                       "\(BrocolisPlan.freeKeyLimit) keys · unlimited encryption",
                       "\(BrocolisPlan.freeKeyLimit) claves · cifrado ilimitado")
        case .plus:
            return loc("Clés illimitées · expiration automatique",
                       "Unlimited keys · automatic expiry",
                       "Claves ilimitadas · caducidad automática")
        case .pro:
            return loc("Tout Brocolis+ · photos et vocaux chiffrés",
                       "All of Brocolis+ · encrypted photos and voice notes",
                       "Todo Brocolis+ · fotos y notas de voz cifradas")
        }
    }

    /// Le palier vient du serveur (accès offert), pas d'un abonnement payé.
    private var isOffered: Bool {
        BrocolisPlan.grantedTier > BrocolisPlan.purchasedTier
    }

    // MARK: Identifiant d'appareil

    /// L'identifiant opaque de CET appareil. Sert à ouvrir un accès offert
    /// depuis le serveur (liste `BROCOLIS_PRO_IDS`) : sans un moyen de le
    /// lire, impossible de remplir cette liste. Ne révèle rien — c'est un
    /// UUID, pas une identité.
    private var deviceIdSection: some View {
        Section(loc("Cet appareil", "This device", "Este dispositivo")) {
            VStack(alignment: .leading, spacing: 6) {
                Text(MessagingPrefs.deviceId)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .lineLimit(2)
                Button {
                    UIPasteboard.general.string = MessagingPrefs.deviceId
                    alertMessage = loc("Identifiant copié.", "Identifier copied.",
                                       "Identificador copiado.")
                } label: {
                    Label(loc("Copier l'identifiant", "Copy identifier", "Copiar identificador"),
                          systemImage: "doc.on.doc")
                }
                .font(.footnote)
                Text(loc("Identifiant opaque de cet appareil. Il ne révèle rien de toi : il sert au serveur à reconnaître tes messages, et à t'ouvrir un accès offert.",
                         "Opaque identifier for this device. It reveals nothing about you: the server uses it to recognise your messages, and to open a complimentary access.",
                         "Identificador opaco de este dispositivo. No revela nada de ti: el servidor lo usa para reconocer tus mensajes y para abrirte un acceso de cortesía."))
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Crédits

    private var creditsSection: some View {
        Section {
            VStack(spacing: 4) {
                Text("Brocolis 🥦")
                    .font(.subheadline).bold()
                Text(loc("Conçu et développé par Maxime Nathan Lestage", "Designed and developed by Maxime Nathan Lestage", "Diseñado y desarrollado por Maxime Nathan Lestage"))
                    .font(.footnote).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .center)
            .padding(.vertical, 4)
        }
    }

    // MARK: Logique

    private func reload() {
        keys = BrocolisKeyStore.keys
        protections = BrocolisV3.protections(keys)
        selectedId = BrocolisKeyStore.selectedKeyId ?? keys.first?.id
        recipientIds = BrocolisKeyStore.recipientKeyIds
        isActive = BrocolisKeyStore.isActive
        encryptWhole = BrocolisKeyStore.encryptWholeAlways
        fingerprint = BrocolisKeyStore.pairingFingerprint
        keyTTL = BrocolisKeyStore.selectedKey?.ttlSeconds ?? 0
        pairedPeerCount = BrocolisKeyStore.pairingPeerIds.count
        BrocolisNotifications.refresh()
        BrocolisLiveActivity.sync(active: isActive)
    }

    private func purgeIfNeeded() {
        if BrocolisKeyStore.purgeExpiredKey() {
            alertMessage = loc("Une clé avait expiré : elle a été supprimée automatiquement.", "A key had expired: it was deleted automatically.", "Una clave había caducado: se eliminó automáticamente.")
        }
        reload()
    }

    /// Appairages à distance en attente : ils se terminent à chaque ouverture.
    private func resumePendingPairing() {
        Task {
            let done = await BrocolisPendingPairing.resume()
            guard !done.isEmpty else { return }
            await MainActor.run {
                reload()
                alertMessage = done.joined(separator: "\n")
            }
        }
    }

    /// Peut-on ajouter une clé de plus ? Sinon, on ouvre l'écran d'offres.
    /// La limite porte sur l'AJOUT : aucune clé existante n'est jamais retirée,
    /// même si le trousseau dépasse déjà ce que le gratuit permet.
    private func canAddKey() -> Bool {
        let gate = BrocolisPlan.gateForAddingKey(currentKeyCount: BrocolisKeyStore.keys.count,
                                                 tier: BrocolisPlan.tier)
        if case .needs(_, let feature) = gate {
            paywallReason = feature
            return false
        }
        return true
    }

    // Crée une clé pour un contact choisi : nommée d'après lui, avec son numéro
    // rattaché. La clé est neuve → il faut la PARTAGER avec ce contact (ou
    // s'appairer) pour qu'il puisse déchiffrer. Le numéro sert d'identité, pas
    // de clé.
    private func createKeyFromContact(_ contact: PhoneContact) {
        guard canAddKey() else { return }
        let id = BrocolisKeyStore.addKey(name: contact.name,
                                         base64: BrocolisCrypto.generateKeyBase64())
        BrocolisKeyStore.setKeyPhone(contact.phoneNumber, forKeyId: id)
        BrocolisKeyStore.setActive(true)
        reload()
        alertMessage = loc("Clé créée pour « \(contact.name) » (\(contact.phoneNumber)). Partage-la avec ce contact (ou appaire-toi) pour qu’il puisse lire tes messages.", "Key created for “\(contact.name)” (\(contact.phoneNumber)). Share it with this contact (or pair up) so they can read your messages.", "Clave creada para «\(contact.name)» (\(contact.phoneNumber)). Compártela con este contacto (o empareja) para que pueda leer tus mensajes.")
    }

    private func importKey() {
        let trimmed = importText.trimmingCharacters(in: .whitespacesAndNewlines)
        // Clé PROTÉGÉE par une phrase secrète : on demande la phrase. Petit
        // délai : l'alerte d'import doit avoir fini de se fermer.
        if BrocolisKeyToken.containsToken(trimmed) {
            guard canAddKey() else { return }
            importPassphrase = ""
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) {
                showImportPassphrase = true
            }
            return
        }
        do {
            _ = try BrocolisCrypto.symmetricKey(fromBase64: trimmed)
            guard canAddKey() else { return }
            finishImport(base64: trimmed)
        } catch {
            alertMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }

    /// Déchiffre la clé protégée collée avec la phrase saisie (v2 Argon2id ou
    /// v1 PBKDF2 : hors du fil principal). Phrase fausse ou jeton abîmé :
    /// message d'erreur, rien n'est importé.
    private func importProtectedKey() {
        let token = importText
        let passphrase = importPassphrase
        importPassphrase = ""
        Task {
            let result = await BrocolisKeyToken.openInBackground(token: token, passphrase: passphrase)
            await MainActor.run {
                switch result {
                case .success(let keyBase64):
                    finishImport(base64: keyBase64)
                case .failure(let error):
                    alertMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                }
            }
        }
    }

    private func finishImport(base64: String) {
        BrocolisKeyStore.addKey(name: importName, base64: base64)
        BrocolisKeyStore.setActive(true) // activation auto
        importText = ""
        importName = ""
        reload()
        alertMessage = loc("Clé importée — Brocolis est prêt.", "Key imported — Brocolis is ready.", "Clave importada — Brocolis está listo.")
    }
}

/// Charge utile pour présenter le composer iMessage (destinataire + corps).
struct InvitePayload: Identifiable {
    let id = UUID()
    let recipients: [String]
    let body: String
}

// MARK: - Partage d'une clé protégée par une phrase secrète

/// « Partager protégée par une phrase secrète » : on choisit une phrase (deux
/// fois), Brocolis chiffre la clé en un jeton `[[BROCOLIS-CLE:v1:…]]` (format
/// commun avec Talka et l'Android) qui peut voyager par n'importe quel canal.
/// La phrase, elle, se donne À PART — de vive voix.
struct ProtectedKeyShareView: View {
    let key: NamedKey
    @Environment(\.dismiss) private var dismiss
    @State private var passphrase = ""
    @State private var confirmation = ""
    @State private var token: String?
    @State private var working = false
    @State private var errorMessage: String?
    @State private var copied = false
    @State private var invite: InvitePayload?

    var body: some View {
        NavigationStack {
            Form {
                if let token {
                    readySection(token).listRowBackground(Color.brocoliCard)
                } else {
                    passphraseSection.listRowBackground(Color.brocoliCard)
                }
            }
            .brocolisBackground()
            .navigationTitle(loc("Clé protégée", "Protected key", "Clave protegida"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc("Fermer", "Close", "Cerrar")) { dismiss() }
                }
            }
            .sheet(item: $invite) { payload in
                MessageComposeView(recipients: payload.recipients, body: payload.body) {
                    invite = nil
                }
                .ignoresSafeArea()
            }
        }
    }

    private var passphraseSection: some View {
        Section {
            SecureField(loc("Phrase secrète", "Passphrase", "Frase secreta"), text: $passphrase)
            SecureField(loc("Confirme la phrase", "Confirm the passphrase", "Confirma la frase"), text: $confirmation)
            Button {
                protect()
            } label: {
                HStack {
                    Label(loc("Protéger la clé", "Protect the key", "Proteger la clave"), systemImage: "lock.shield.fill")
                    if working {
                        Spacer()
                        ProgressView()
                    }
                }
            }
            .disabled(working || passphrase.isEmpty || confirmation.isEmpty)
            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .font(.footnote)
                    .foregroundStyle(.orange)
            }
        } header: {
            Text(loc("Phrase secrète pour « \(key.name) »", "Passphrase for “\(key.name)”", "Frase secreta para «\(key.name)»"))
        } footer: {
            Text(loc("\(BrocolisKeyToken.minPassphraseLength) caractères au moins. Choisis plusieurs mots, faciles à dire et difficiles à deviner : sans la phrase, la clé protégée est inutilisable.",
                     "At least \(BrocolisKeyToken.minPassphraseLength) characters. Pick several words, easy to say and hard to guess: without the passphrase, the protected key is useless.",
                     "Al menos \(BrocolisKeyToken.minPassphraseLength) caracteres. Elige varias palabras, fáciles de decir y difíciles de adivinar: sin la frase, la clave protegida no sirve."))
        }
    }

    private func readySection(_ token: String) -> some View {
        Section {
            Text(token)
                .font(.system(.footnote, design: .monospaced))
                .textSelection(.enabled)
            ShareLink(item: brocolisProtectedInviteBody(contactName: key.name, token: token)) {
                Label(loc("Partager la clé protégée", "Share the protected key", "Compartir la clave protegida"), systemImage: "square.and.arrow.up")
            }
            Button {
                UIPasteboard.general.string = token
                copied = true
            } label: {
                Label(copied ? loc("Copiée", "Copied", "Copiada") : loc("Copier la clé protégée", "Copy the protected key", "Copiar la clave protegida"),
                      systemImage: copied ? "checkmark" : "doc.on.doc")
            }
            if let phone = BrocolisKeyStore.keyPhone(key.id), canSendMessages() {
                Button {
                    invite = InvitePayload(
                        recipients: [phone],
                        body: brocolisProtectedInviteBody(contactName: key.name, token: token)
                    )
                } label: {
                    Label(loc("Inviter \(key.name) par iMessage", "Invite \(key.name) by iMessage", "Invitar a \(key.name) por iMessage"), systemImage: "paperplane.fill")
                }
            }
        } header: {
            Text(loc("Clé protégée prête", "Protected key ready", "Clave protegida lista"))
        } footer: {
            locText("**Donne la phrase secrète à part**, de vive voix — jamais dans le même message. Ton correspondant colle ce texte dans Brocolis → « Importer », puis tape la phrase.",
                    "**Give the passphrase separately**, in person — never in the same message. Your contact pastes this text into Brocolis → “Import”, then types the passphrase.",
                    "**Da la frase secreta aparte**, de viva voz — nunca en el mismo mensaje. Tu contacto pega este texto en Brocolis → «Importar» y luego escribe la frase.")
        }
    }

    private func protect() {
        errorMessage = nil
        guard passphrase.count >= BrocolisKeyToken.minPassphraseLength else {
            errorMessage = BrocolisKeyToken.KeyTokenError.passphraseTooShort.errorDescription
            return
        }
        guard passphrase == confirmation else {
            errorMessage = BrocolisKeyToken.KeyTokenError.passphraseMismatch.errorDescription
            return
        }
        working = true
        let keyBase64 = key.base64
        let phrase = passphrase
        // Argon2id (64 Mio, clé protégée v2) : hors du fil principal.
        Task {
            let result = await BrocolisKeyToken.sealInBackground(keyBase64: keyBase64, passphrase: phrase)
            await MainActor.run {
                working = false
                switch result {
                case .success(let sealed):
                    token = sealed
                    passphrase = ""
                    confirmation = ""
                case .failure(let error):
                    errorMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
                }
            }
        }
    }
}

#Preview {
    RootView()
}

// MARK: - Menu du clavier Brocolis

/// Tout ce qui concerne le clavier, au même endroit : installation, essai,
/// retour des touches, disposition, apparence, saisie, mode d'emploi.
/// Enregistré dans l'App Group : le clavier relit tout à chaque ouverture (et
/// son menu ⚙️ modifie les mêmes réglages).
struct KeyboardHubView: View {
    @Environment(\.scenePhase) private var scenePhase
    @State private var installed = KeyboardHubView.isInstalled()
    @State private var trial = ""
    @State private var haptics = BrocolisKeyboardPrefs.haptics
    @State private var sound = BrocolisKeyboardPrefs.sound
    @State private var layout = BrocolisKeyboardPrefs.layout
    @State private var keySize = BrocolisKeyboardPrefs.keySize
    @State private var theme = BrocolisKeyboardPrefs.theme
    @State private var autoCapitalize = BrocolisKeyboardPrefs.autoCapitalize
    @State private var doubleSpace = BrocolisKeyboardPrefs.doubleSpacePeriod
    @State private var accents = BrocolisKeyboardPrefs.accentKeys
    @State private var longAccents = BrocolisKeyboardPrefs.longPressAccents
    @State private var spaceCursor = BrocolisKeyboardPrefs.spaceCursor
    @State private var emojiKey = BrocolisKeyboardPrefs.emojiKey

    /// Le clavier figure-t-il parmi les claviers ajoutés dans Réglages ?
    static func isInstalled() -> Bool {
        UITextInputMode.activeInputModes.contains { mode in
            (mode.value(forKey: "identifier") as? String)?.hasPrefix("rs.brocolis.messagerie.keyboard") == true
        }
    }

    var body: some View {
        Form {
            Section {
                HStack(spacing: 12) {
                    Image(systemName: installed ? "checkmark.seal.fill" : "keyboard.badge.ellipsis")
                        .font(.title2)
                        .foregroundStyle(installed ? Color.brocoliGreen : Color.orange)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(installed
                             ? loc("Clavier ajouté", "Keyboard added", "Teclado añadido")
                             : loc("Clavier pas encore ajouté", "Keyboard not added yet", "Teclado aún no añadido"))
                            .font(.headline)
                        Text(loc("Réglages → Général → Clavier → Claviers → Ajouter → Brocolis 🥦, puis « Accès complet ».", "Settings → General → Keyboard → Keyboards → Add → Brocolis 🥦, then « Full Access ».", "Ajustes → General → Teclado → Teclados → Añadir → Brocolis 🥦, luego « Acceso completo »."))
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                Button {
                    if let url = URL(string: UIApplication.openSettingsURLString) {
                        UIApplication.shared.open(url)
                    }
                } label: {
                    Label(loc("Ouvrir les Réglages", "Open Settings", "Abrir Ajustes"), systemImage: "gear")
                }
            } header: {
                Text(loc("Installation", "Setup", "Instalación"))
            }

            Section {
                TextField(loc("Touche ici, puis 🌐 pour choisir Brocolis", "Tap here, then 🌐 to pick Brocolis", "Toca aquí y luego 🌐 para elegir Brocolis"), text: $trial, axis: .vertical)
                    .lineLimit(2...5)
                if !trial.isEmpty {
                    Button(role: .destructive) { trial = "" } label: {
                        Label(loc("Effacer l’essai", "Clear", "Borrar"), systemImage: "xmark.circle")
                    }
                }
            } header: {
                Text(loc("Essayer", "Try it", "Probar"))
            } footer: {
                Text(loc("Les réglages ci-dessous s’appliquent dès que le clavier se rouvre.", "Settings below apply as soon as the keyboard reopens.", "Los ajustes de abajo se aplican al reabrir el teclado."))
            }

            Section {
                Picker(selection: $haptics) {
                    ForEach(BrocolisKeyboardPrefs.Haptics.allCases) { Text($0.title).tag($0) }
                } label: {
                    Label(loc("Vibrations", "Haptics", "Vibraciones"), systemImage: "iphone.radiowaves.left.and.right")
                }
                .onChange(of: haptics) { v in
                    BrocolisKeyboardPrefs.haptics = v
                    switch v {
                    case .off: break
                    case .light: UIImpactFeedbackGenerator(style: .light).impactOccurred()
                    case .medium: UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                    case .strong: UIImpactFeedbackGenerator(style: .heavy).impactOccurred()
                    }
                }
                Toggle(isOn: $sound) {
                    Label(loc("Son des touches", "Key sounds", "Sonido de teclas"), systemImage: "speaker.wave.2")
                }
                .onChange(of: sound) { v in BrocolisKeyboardPrefs.sound = v }
            } header: {
                Text(loc("Retour des touches", "Key feedback", "Respuesta de las teclas"))
            } footer: {
                Text(loc("iOS ne laisse vibrer un clavier que s’il a l’« Accès complet ». Le son suit aussi Réglages → Sons et vibrations → Retour clavier.", "iOS only lets a keyboard vibrate with « Full Access ». Sound also follows Settings → Sounds & Haptics → Keyboard Feedback.", "iOS solo deja vibrar un teclado con « Acceso completo ». El sonido también sigue Ajustes → Sonidos y vibraciones → Respuesta del teclado."))
            }

            Section(loc("Apparence", "Appearance", "Apariencia")) {
                Picker(selection: $theme) {
                    ForEach(BrocolisKeyboardPrefs.Theme.allCases) { Text($0.title).tag($0) }
                } label: {
                    Label(loc("Thème", "Theme", "Tema"), systemImage: "paintpalette")
                }
                .onChange(of: theme) { v in BrocolisKeyboardPrefs.theme = v }
                Picker(selection: $layout) {
                    ForEach(BrocolisKeyboardPrefs.Layout.allCases) { Text($0.title).tag($0) }
                } label: {
                    Label(loc("Disposition", "Layout", "Distribución"), systemImage: "keyboard")
                }
                .onChange(of: layout) { v in BrocolisKeyboardPrefs.layout = v }
                Picker(selection: $keySize) {
                    ForEach(BrocolisKeyboardPrefs.KeySize.allCases) { Text($0.title).tag($0) }
                } label: {
                    Label(loc("Taille des touches", "Key size", "Tamaño de teclas"), systemImage: "textformat.size")
                }
                .onChange(of: keySize) { v in BrocolisKeyboardPrefs.keySize = v }
                Toggle(isOn: $accents) {
                    Label(loc("Accents à côté de l’espace", "Accents next to space", "Acentos junto al espacio"), systemImage: "character")
                }
                .onChange(of: accents) { v in BrocolisKeyboardPrefs.accentKeys = v }
                Toggle(isOn: $emojiKey) {
                    Label(loc("Touche emojis 😀", "Emoji key 😀", "Tecla emojis 😀"), systemImage: "face.smiling")
                }
                .onChange(of: emojiKey) { v in BrocolisKeyboardPrefs.emojiKey = v }
            }

            Section(loc("Saisie", "Typing", "Escritura")) {
                Toggle(isOn: $longAccents) {
                    Label(loc("Appui long → accents (e → é è ê ë)", "Long press → accents (e → é è ê ë)", "Pulsación larga → acentos (e → é è ê ë)"), systemImage: "hand.tap")
                }
                .onChange(of: longAccents) { v in BrocolisKeyboardPrefs.longPressAccents = v }
                Toggle(isOn: $spaceCursor) {
                    Label(loc("Glisser sur l’espace → curseur", "Slide on space → cursor", "Deslizar en espacio → cursor"), systemImage: "arrow.left.and.right")
                }
                .onChange(of: spaceCursor) { v in BrocolisKeyboardPrefs.spaceCursor = v }
                Toggle(isOn: $autoCapitalize) {
                    Label(loc("Majuscule automatique", "Auto-capitalization", "Mayúscula automática"), systemImage: "textformat")
                }
                .onChange(of: autoCapitalize) { v in BrocolisKeyboardPrefs.autoCapitalize = v }
                Toggle(isOn: $doubleSpace) {
                    Label(loc("Double espace → point", "Double space → period", "Doble espacio → punto"), systemImage: "space")
                }
                .onChange(of: doubleSpace) { v in BrocolisKeyboardPrefs.doubleSpacePeriod = v }
            }

            Section(loc("Mode d’emploi", "How to use", "Cómo se usa")) {
                Label(loc("Envoyer : écris, puis 🔒 Chiffrer — le texte est remplacé chiffré sur place.", "Send: type, then 🔒 Encrypt — the text is replaced encrypted in place.", "Enviar: escribe y luego 🔒 Cifrar — el texto se reemplaza cifrado."), systemImage: "lock.fill")
                Label(loc("Ne chiffrer qu’un passage : touche ((…)) et écris le secret entre les parenthèses — même avec « Tout chiffrer ».", "Encrypt only part: tap ((…)) and type the secret inside — even with « Encrypt everything ».", "Cifrar solo una parte: toca ((…)) y escribe el secreto dentro — incluso con « Cifrar todo »."), systemImage: "parentheses")
                Label(loc("Lire : copie le message reçu, puis 📋 Lire — il s’affiche en clair sur le clavier.", "Read: copy the message you got, then 📋 Read — it shows in clear on the keyboard.", "Leer: copia el mensaje recibido y luego 📋 Leer — se muestra en claro en el teclado."), systemImage: "doc.on.clipboard")
                Label(loc("⚙️ sur le clavier : vibrations, son, disposition, taille, thème… sans quitter ton app.", "⚙️ on the keyboard: haptics, sound, layout, size, theme… without leaving your app.", "⚙️ en el teclado: vibración, sonido, distribución, tamaño, tema… sin salir de tu app."), systemImage: "gearshape")
                Label(loc("Photos et vocaux chiffrés : seulement dans la messagerie Brocolis 🥦 (l’app ou le site), jamais dans une autre messagerie.", "Encrypted photos and voice notes: only in Brocolis 🥦 messaging (the app or the site), never in another messaging app.", "Fotos y audios cifrados: solo en la mensajería Brocolis 🥦 (la app o el sitio), nunca en otra mensajería."), systemImage: "photo.on.rectangle")
            }
        }
        .navigationTitle(loc("Clavier", "Keyboard", "Teclado"))
        .navigationBarTitleDisplayMode(.inline)
        .onChange(of: scenePhase) { phase in
            // Retour des Réglages : le clavier vient peut-être d'être ajouté,
            // et le menu ⚙️ du clavier a pu changer des réglages.
            if phase == .active { reload() }
        }
        .onAppear(perform: reload)
    }

    private func reload() {
        installed = Self.isInstalled()
        haptics = BrocolisKeyboardPrefs.haptics
        sound = BrocolisKeyboardPrefs.sound
        layout = BrocolisKeyboardPrefs.layout
        keySize = BrocolisKeyboardPrefs.keySize
        theme = BrocolisKeyboardPrefs.theme
        autoCapitalize = BrocolisKeyboardPrefs.autoCapitalize
        doubleSpace = BrocolisKeyboardPrefs.doubleSpacePeriod
        accents = BrocolisKeyboardPrefs.accentKeys
        longAccents = BrocolisKeyboardPrefs.longPressAccents
        spaceCursor = BrocolisKeyboardPrefs.spaceCursor
        emojiKey = BrocolisKeyboardPrefs.emojiKey
    }
}
