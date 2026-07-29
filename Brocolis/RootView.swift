//
//  RootView.swift
//  Brocolis 🥦
//
//  État « Actif » + appairage + gestion de PLUSIEURS clés nommées.
//  La clé sélectionnée chiffre ; au déchiffrement, toutes les clés sont essayées.
//

import SwiftUI
import UIKit

// Fond de la marque + application « plein écran » (contenu + barre de navigation).
// Défini une fois ici, réutilisé par tous les écrans de l'app.
extension Color {
    static let brocoliBg = Color(red: 232.0 / 255, green: 245.0 / 255, blue: 219.0 / 255)
    /// Fond des cartes : un cran PLUS FONCÉ que le fond (vert doux, plus de blanc pur).
    static let brocoliCard = Color(red: 220.0 / 255, green: 239.0 / 255, blue: 208.0 / 255)
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

    @State private var keys: [NamedKey] = BrocolisKeyStore.keys
    @State private var selectedId: String? = BrocolisKeyStore.selectedKeyId
    @State private var recipientIds: [String] = BrocolisKeyStore.recipientKeyIds
    @State private var isActive = BrocolisKeyStore.isActive
    @State private var encryptWhole = BrocolisKeyStore.encryptWholeAlways
    @State private var fingerprint: String? = BrocolisKeyStore.pairingFingerprint
    @State private var keyTTL = BrocolisKeyStore.selectedKey?.ttlSeconds ?? 0
    @State private var pairedPeerCount = BrocolisKeyStore.pairingPeerIds.count

    @State private var alertMessage: String?
    @State private var showPairing = false
    @State private var showGenerate = false
    @State private var newKeyName = ""
    @State private var showImport = false
    @State private var importName = ""
    @State private var importText = ""
    @State private var showContacts = false
    @State private var invite: InvitePayload?
    @State private var renameTarget: NamedKey?
    @State private var renameText = ""

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
                privacySection.listRowBackground(Color.brocoliCard)
                conversationSection.listRowBackground(Color.brocoliCard)
                keyboardSection.listRowBackground(Color.brocoliCard)
                encryptionSection.listRowBackground(Color.brocoliCard)
                pairingSection.listRowBackground(Color.brocoliCard)
                keysSection.listRowBackground(Color.brocoliCard)
                recipientsSection.listRowBackground(Color.brocoliCard)
                selectedKeySection.listRowBackground(Color.brocoliCard)
                howToSection.listRowBackground(Color.brocoliCard)
            }
            .listRowBackground(Color.brocoliCard)
            .brocolisBackground()
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
            .sheet(isPresented: $showContacts) {
                ContactPickerView { contact in
                    createKeyFromContact(contact)
                }
            }
            .sheet(item: $invite) { payload in
                MessageComposeView(recipients: payload.recipients, body: payload.body) {
                    invite = nil
                }
                .ignoresSafeArea()
            }
            .alert(loc("Nouvelle clé", "New key", "Nueva clave"), isPresented: $showGenerate) {
                TextField(loc("Nom (ex. Maman)", "Name (e.g. Mom)", "Nombre (ej. Mamá)"), text: $newKeyName)
                Button(loc("Générer", "Generate", "Generar")) {
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
                TextField(loc("Clé base64 (32 octets)", "Base64 key (32 bytes)", "Clave base64 (32 bytes)"), text: $importText)
                Button(loc("Importer", "Import", "Importar")) { importKey() }
                Button(loc("Annuler", "Cancel", "Cancelar"), role: .cancel) {}
            } message: {
                Text(loc("Colle la clé reçue d’un correspondant.", "Paste the key received from a contact.", "Pega la clave recibida de un contacto."))
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
                locText("**Verrouiller** : il faut Face ID (ou le code de l’appareil) pour voir tes messages, comme le propose Apple.\n\n**Effacer à la fermeture** : en quittant l’app, les messages affichés disparaissent ; à la réouverture, seuls les **nouveaux** messages réapparaissent.", "**Lock** : Face ID (or the device passcode) is required to see your messages, just as Apple offers.\n\n**Erase on close** : when you leave the app, the displayed messages disappear; on reopening, only the **new** messages reappear.", "**Bloquear** : hace falta Face ID (o el código del dispositivo) para ver tus mensajes, como propone Apple.\n\n**Borrar al cerrar** : al salir de la app, los mensajes mostrados desaparecen; al reabrir, solo reaparecen los mensajes **nuevos**.")
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
            set: { MessagingPrefs.eraseOnClose = $0; eraseOnClose = $0 }
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
            Button {
                if let url = URL(string: UIApplication.openSettingsURLString) {
                    UIApplication.shared.open(url)
                }
            } label: {
                Label(loc("Activer le clavier Brocolis 🥦", "Enable the Brocolis 🥦 keyboard", "Activar el teclado Brocolis 🥦"), systemImage: "keyboard")
            }
        } header: {
            Text(loc("Envoyer sans copier", "Send without copying", "Enviar sin copiar"))
        } footer: {
            locText("Active le **Clavier Brocolis 🥦** (Réglages → Général → Clavier → Claviers → Ajouter), puis autorise l’**Accès complet** (nécessaire pour lire tes clés et le presse-papiers). Ensuite, dans n’importe quelle app :\n\n• **Envoyer** : tape ton message, bascule sur Brocolis avec 🌐, touche **Chiffrer** — le texte est remplacé chiffré sur place, sans copier-coller.\n\n• **Lire un reçu** : appui long sur le message → Copier, bascule sur Brocolis avec 🌐, touche **📋 Lire** — il s’affiche en clair sur le clavier, sans quitter l’app.", "Enable the **Brocolis 🥦 Keyboard** (Settings → General → Keyboard → Keyboards → Add New Keyboard), then allow **Full Access** (needed to read your keys and the clipboard). Then, in any app:\n\n• **Send** : type your message, switch to Brocolis with 🌐, tap **Encrypt** — the text is replaced encrypted in place, no copy-paste.\n\n• **Read a received one** : long-press the message → Copy, switch to Brocolis with 🌐, tap **📋 Read** — it appears in the clear on the keyboard, without leaving the app.", "Activa el **Teclado Brocolis 🥦** (Ajustes → General → Teclado → Teclados → Añadir nuevo teclado), luego permite el **Acceso completo** (necesario para leer tus claves y el portapapeles). Después, en cualquier app:\n\n• **Enviar** : escribe tu mensaje, cambia a Brocolis con 🌐, toca **Cifrar** — el texto se reemplaza cifrado en el sitio, sin copiar y pegar.\n\n• **Leer uno recibido** : mantén pulsado el mensaje → Copiar, cambia a Brocolis con 🌐, toca **📋 Leer** — se muestra en claro en el teclado, sin salir de la app.")
        }
    }

    // MARK: Chiffrement

    private var encryptionSection: some View {
        Section {
            Toggle(isOn: encryptWholeBinding) {
                Label(loc("Tout chiffrer", "Encrypt everything", "Cifrar todo"), systemImage: "lock.rectangle.on.rectangle.fill")
            }
        } header: {
            Text(loc("Chiffrement", "Encryption", "Cifrado"))
        } footer: {
            Text(encryptWhole
                 ? loc("Toute ta sélection est chiffrée d'un bloc, même quand tu es seul — pas besoin d'entourer le texte de ((…)).", "Your whole selection is encrypted as one block, even on your own — no need to wrap the text in ((…)).", "Toda tu selección se cifra en un bloque, incluso a solas — no hace falta rodear el texto con ((…)).")
                 : loc("Seuls les passages entre ((…)) sont chiffrés ; le reste du texte reste en clair.", "Only the parts between ((…)) are encrypted; the rest of the text stays in the clear.", "Solo se cifran los fragmentos entre ((…)); el resto del texto queda en claro."))
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
                    }
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
            Section(loc("Clé sélectionnée", "Selected key", "Clave seleccionada")) {
                Text(sel.name).font(.headline)
                Text(sel.base64)
                    .font(.system(.footnote, design: .monospaced))
                    .textSelection(.enabled)
                Button {
                    UIPasteboard.general.string = sel.base64
                    alertMessage = loc("Clé copiée dans le presse-papiers.", "Key copied to the clipboard.", "Clave copiada en el portapapeles.")
                } label: {
                    Label(loc("Copier la clé", "Copy key", "Copiar clave"), systemImage: "doc.on.doc")
                }
                ShareLink(item: sel.base64) {
                    Label(loc("Partager la clé", "Share key", "Compartir clave"), systemImage: "square.and.arrow.up")
                }
                if let phone = BrocolisKeyStore.keyPhone(sel.id), canSendMessages() {
                    Button {
                        invite = InvitePayload(
                            recipients: [phone],
                            body: brocolisInviteBody(contactName: sel.name, keyBase64: sel.base64)
                        )
                    } label: {
                        Label(loc("Inviter \(sel.name) par iMessage", "Invite \(sel.name) by iMessage", "Invitar a \(sel.name) por iMessage"), systemImage: "paperplane.fill")
                    }
                }
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

    // MARK: Logique

    private func reload() {
        keys = BrocolisKeyStore.keys
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

    // Crée une clé pour un contact choisi : nommée d'après lui, avec son numéro
    // rattaché. La clé est neuve → il faut la PARTAGER avec ce contact (ou
    // s'appairer) pour qu'il puisse déchiffrer. Le numéro sert d'identité, pas
    // de clé.
    private func createKeyFromContact(_ contact: PhoneContact) {
        let id = BrocolisKeyStore.addKey(name: contact.name,
                                         base64: BrocolisCrypto.generateKeyBase64())
        BrocolisKeyStore.setKeyPhone(contact.phoneNumber, forKeyId: id)
        BrocolisKeyStore.setActive(true)
        reload()
        alertMessage = loc("Clé créée pour « \(contact.name) » (\(contact.phoneNumber)). Partage-la avec ce contact (ou appaire-toi) pour qu’il puisse lire tes messages.", "Key created for “\(contact.name)” (\(contact.phoneNumber)). Share it with this contact (or pair up) so they can read your messages.", "Clave creada para «\(contact.name)» (\(contact.phoneNumber)). Compártela con este contacto (o empareja) para que pueda leer tus mensajes.")
    }

    private func importKey() {
        let trimmed = importText.trimmingCharacters(in: .whitespacesAndNewlines)
        do {
            _ = try BrocolisCrypto.symmetricKey(fromBase64: trimmed)
            BrocolisKeyStore.addKey(name: importName, base64: trimmed)
            BrocolisKeyStore.setActive(true) // activation auto
            importText = ""
            importName = ""
            reload()
            alertMessage = loc("Clé importée — Brocolis est prêt.", "Key imported — Brocolis is ready.", "Clave importada — Brocolis está listo.")
        } catch {
            alertMessage = (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
        }
    }
}

/// Charge utile pour présenter le composer iMessage (destinataire + corps).
struct InvitePayload: Identifiable {
    let id = UUID()
    let recipients: [String]
    let body: String
}

#Preview {
    RootView()
}
