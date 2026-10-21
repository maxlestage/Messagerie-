//
//  BrocolisV3Store.swift
//  Brocolis 🥦 (partagé app + clavier + Partager + iMessage)
//
//  Où vit le v3 sur l'iPhone, et comment plusieurs processus s'en servent
//  sans jamais réutiliser une clé de message (docs/SECURITE.md §8.1, §8.3) :
//
//  - l'appareil v3 (`Device`, JSON de la référence) au TROUSSEAU, compte
//    `v3_device`, groupe d'accès de l'App Group, `AfterFirstUnlockThisDeviceOnly`
//    — sans repli vers les `UserDefaults` : Trousseau fermé = v3 indisponible
//    pour cette opération (l'envoi se fait alors en v1/v2) ;
//  - les sessions et les messages ouverts dans `BrocolisV3/etat.bin` du
//    conteneur de l'App Group : nonce ‖ AES-256-GCM(JSON) ‖ tag, sous une clé
//    de 32 octets du Trousseau (`v3_state_key`), données associées
//    `brocolis-v3-etat-v1`, écrit d'un bloc (fichier temporaire renommé),
//    dossier exclu des sauvegardes ;
//  - chaque opération est une TRANSACTION sous `flock(LOCK_EX)` de
//    `BrocolisV3/verrou` : lire → chiffrer/déchiffrer → écrire l'appareil,
//    puis l'état → lâcher le verrou → rendre le jeton. Un descripteur par
//    transaction : deux fils d'un même processus s'excluent aussi. Rien
//    d'asynchrone dedans (le verrou dure quelques millisecondes).
//
//  `BrocolisV3` (en bas) est la façade dont se servent l'app et les
//  extensions : chiffrer pour une clé nommée, lire un texte collé, la
//  protection affichée, l'appairage.
//

import Foundation
import BrocolisProto
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

enum BrocolisV3StoreError: Error, Equatable {
    /// Le Trousseau ne répond pas (appareil jamais déverrouillé, clavier
    /// sans accès complet…).
    case unavailable
    /// Le dossier, le verrou ou le fichier d'état ne s'écrivent pas.
    case io
}

/// L'appareil et l'état v3, sous verrou entre processus.
final class BrocolisV3Store {
    static let deviceAccount = "v3_device"
    static let stateKeyAccount = "v3_state_key"
    static let stateAAD = Data("brocolis-v3-etat-v1".utf8)

    let directory: URL
    let vault: BrocolisSecretVault

    init(directory: URL, vault: BrocolisSecretVault) {
        self.directory = directory
        self.vault = vault
    }

    /// Celui de l'app et de ses extensions (conteneur de l'App Group,
    /// Trousseau partagé). `nil` hors iOS (et sur la montre, qui n'a pas de
    /// sessions : §8.7).
    static let shared: BrocolisV3Store? = {
        #if canImport(Security) && !os(watchOS)
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: BrocolisKeyStore.appGroup) else { return nil }
        return BrocolisV3Store(
            directory: container.appendingPathComponent("BrocolisV3", isDirectory: true),
            vault: BrocolisKeychainVault(service: BrocolisKeyStore.keychainService,
                                         accessGroup: BrocolisKeyStore.appGroup))
        #else
        return nil
        #endif
    }()

    var stateURL: URL { directory.appendingPathComponent("etat.bin") }
    var lockURL: URL { directory.appendingPathComponent("verrou") }

    /// Une transaction (§8.3). Si `body` lève, rien n'est écrit.
    func transaction<T>(now: UInt64 = BrocolisV3.now(), _ body: (BrocolisV3Engine) throws -> T) throws -> T {
        try prepareDirectory()
        let fd = open(lockURL.path, O_RDWR | O_CREAT, 0o600)
        guard fd >= 0 else { throw BrocolisV3StoreError.io }
        defer { close(fd) }
        while flock(fd, LOCK_EX) != 0 {
            guard errno == EINTR else { throw BrocolisV3StoreError.io }
        }
        defer { _ = flock(fd, LOCK_UN) }

        let key = try stateKey()
        let deviceJson: String?
        switch vault.read(Self.deviceAccount) {
        case .found(let data): deviceJson = String(decoding: data, as: UTF8.self)
        case .notFound: deviceJson = nil
        case .failed: throw BrocolisV3StoreError.unavailable
        }
        let engine = BrocolisV3Engine(deviceJson: deviceJson, stored: readState(key: key), now: now)
        let out = try body(engine)
        // L'appareil d'abord : sa mémoire des premiers messages n'est jamais
        // en retard sur les sessions (§8.3).
        if engine.deviceDirty {
            guard vault.write(Data(engine.device.toJson().utf8), account: Self.deviceAccount) else {
                throw BrocolisV3StoreError.unavailable
            }
        }
        if engine.stateDirty { try writeState(engine.stored, key: key) }
        return out
    }

    private func prepareDirectory() throws {
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            throw BrocolisV3StoreError.io
        }
        // Jamais dans une sauvegarde : un état de cliquet restauré en retard
        // réutiliserait des clés de message déjà servies.
        var url = directory
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? url.setResourceValues(values)
    }

    /// La clé de l'état : lue au Trousseau, ou créée (sous le verrou : deux
    /// processus n'en créent jamais deux).
    private func stateKey() throws -> SymmetricKey {
        switch vault.read(Self.stateKeyAccount) {
        case .found(let data) where data.count == 32:
            return SymmetricKey(data: data)
        case .found, .notFound:
            let key = SymmetricKey(size: .bits256)
            let raw = key.withUnsafeBytes { Data($0) }
            guard vault.write(raw, account: Self.stateKeyAccount) else { throw BrocolisV3StoreError.unavailable }
            // Une clé neuve n'ouvre pas l'ancien fichier : il repart de zéro.
            try? FileManager.default.removeItem(at: stateURL)
            return key
        case .failed:
            throw BrocolisV3StoreError.unavailable
        }
    }

    private func readState(key: SymmetricKey) -> BrocolisV3Stored? {
        guard let sealed = try? Data(contentsOf: stateURL), sealed.count >= 12 + 16,
              let box = try? AES.GCM.SealedBox(combined: sealed),
              let json = try? AES.GCM.open(box, using: key, authenticating: Self.stateAAD)
        else { return nil }
        return try? JSONDecoder().decode(BrocolisV3Stored.self, from: json)
    }

    private func writeState(_ stored: BrocolisV3Stored, key: SymmetricKey) throws {
        guard let json = try? JSONEncoder().encode(stored),
              let sealed = try? AES.GCM.seal(json, using: key, authenticating: Self.stateAAD).combined
        else { throw BrocolisV3StoreError.io }
        #if os(iOS)
        let options: Data.WritingOptions = [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
        #else
        let options: Data.WritingOptions = [.atomic]
        #endif
        do { try sealed.write(to: stateURL, options: options) } catch { throw BrocolisV3StoreError.io }
    }
}

// MARK: - La façade : ce dont l'app et les extensions se servent

/// Le v3 pour l'app et ses extensions. Tout passe par une transaction du
/// magasin partagé ; v3 indisponible = l'ancien format (§8.5).
enum BrocolisV3 {
    /// Le magasin (remplaçable dans les tests).
    static var store: BrocolisV3Store? = BrocolisV3Store.shared

    static func now() -> UInt64 { UInt64(max(0, Date().timeIntervalSince1970)) }

    // MARK: Clés nommées → clés du moteur

    private static let bundleCache = NSCache<NSString, BundleBox>()
    private final class BundleBox { let bundle: KeyBundle; init(_ b: KeyBundle) { bundle = b } }

    /// Le paquet d'un contact, vérifié une fois puis gardé en mémoire.
    static func bundle(_ base64: String?) -> KeyBundle? {
        guard let base64, !base64.isEmpty else { return nil }
        if let hit = bundleCache.object(forKey: base64 as NSString) { return hit.bundle }
        guard let b = try? KeyBundle.fromBase64(base64) else { return nil }
        bundleCache.setObject(BundleBox(b), forKey: base64 as NSString)
        return b
    }

    static func key(_ k: NamedKey) -> BrocolisV3Key? {
        guard let raw = Data(base64Encoded: k.base64.trimmingCharacters(in: .whitespacesAndNewlines)),
              raw.count == 32 else { return nil }
        return BrocolisV3Key(
            id: k.id, raw: Array(raw), bundle: bundle(k.v3Bundle),
            bundleAt: UInt64(max(0, k.v3Since?.timeIntervalSince1970 ?? 0)),
            group: k.duo == false, psk: k.psk == true, caps: caps(k.v3Caps))
    }

    /// La capacité v4 d'un contact (64 octets), si elle est bien formée ; le
    /// moteur la vérifie contre le paquet (§9.6).
    static func caps(_ base64: String?) -> [UInt8]? {
        guard let base64, let raw = Base64.decode(base64), raw.count == 64 else { return nil }
        return raw
    }

    static func keys(_ ks: [NamedKey]) -> [BrocolisV3Key] { ks.compactMap(key) }

    /// Une transaction sur le magasin partagé ; `nil` si le v3 est
    /// indisponible.
    static func run<T>(_ body: (BrocolisV3Engine, UInt64) throws -> T) -> T? {
        guard let store else { return nil }
        let t = now()
        return try? store.transaction(now: t) { try body($0, t) }
    }

    // MARK: Envoyer, lire

    /// Le jeton v3 de `text` pour la clé `k`, ou `nil` (→ v1/v2).
    static func seal(_ text: String, for k: NamedKey) -> String? {
        guard let key = key(k) else { return nil }
        return run { e, t in e.seal(text, for: key, now: t) } ?? nil
    }

    /// Ce qui chiffre et ce qui lit pour les extensions et l'écran
    /// Conversation : v3 pour UNE clé destinataire qui le permet (§8.5),
    /// sinon v1 (une clé) ou v2 (plusieurs) ; lecture v3, v2, v1.
    static func codec(recipients: [NamedKey], all: [NamedKey]) -> BrocolisCodec {
        let sym = recipients.compactMap { try? BrocolisCrypto.symmetricKey(fromBase64: $0.base64) }
        return BrocolisCodec(
            seal: { text in
                if recipients.count == 1, let token = seal(text, for: recipients[0]) { return token }
                return BrocolisCrypto.sealToken(Data(text.utf8), keys: sym)
            },
            open: { openTokens($0, keys: all) })
    }

    /// Remplace chaque jeton d'un texte collé par son clair : les v3 en une
    /// seule transaction, puis v2 et v1 avec toutes les clés.
    static func openTokens(_ input: String, keys: [NamedKey]) -> (text: String, count: Int) {
        let sym = keys.compactMap { try? BrocolisCrypto.symmetricKey(fromBase64: $0.base64) }
        let found = BrocolisV3Format.findTokens(input).map { String(input[$0]) }
        var clear = memo.lookup(found)
        let missing = found.filter { clear[$0] == nil }
        if !missing.isEmpty {
            let v3keys = self.keys(keys)
            let opened: [String: String] = run { (e, t) -> [String: String] in
                var out: [String: String] = [:]
                for token in missing where out[token] == nil {
                    switch e.open(token, keys: v3keys, now: t) {
                    case .text(let s): out[token] = s
                    case .replay: out[token] = alreadyRead
                    case .failed: break
                    }
                }
                return out
            } ?? [:]
            memo.store(opened.filter { $0.value != alreadyRead })
            clear.merge(opened) { a, _ in a }
        }
        return BrocolisCrypto.decryptTokens(input, keys: sym, other: { clear[$0] })
    }

    /// Les clairs v3 ouverts récemment par ce processus : un écran qui se
    /// redessine (Conversation) ne refait pas une transaction par ligne.
    private static let memo = Memo()

    private final class Memo {
        private let lock = NSLock()
        private var map: [String: String] = [:]
        private var order: [String] = []

        func lookup(_ tokens: [String]) -> [String: String] {
            lock.lock(); defer { lock.unlock() }
            var out: [String: String] = [:]
            for t in tokens { if let c = map[t] { out[t] = c } }
            return out
        }

        func store(_ entries: [String: String]) {
            lock.lock(); defer { lock.unlock() }
            for (t, c) in entries where map[t] == nil {
                map[t] = c
                order.append(t)
            }
            while order.count > 256 { map.removeValue(forKey: order.removeFirst()) }
        }
    }

    static var alreadyRead: String {
        loc("🔐 (déjà lu sur cet appareil)", "🔐 (already read on this device)", "🔐 (ya leído en este dispositivo)")
    }

    // MARK: Protection affichée (§8.8)

    /// La protection de chaque clé, en une transaction (`.legacy` partout si
    /// le v3 est indisponible).
    static func protections(_ ks: [NamedKey]) -> [String: BrocolisProtection] {
        let pairs = ks.compactMap { k in key(k).map { (k.id, $0) } }
        let result = run { e, t in
            Dictionary(pairs.map { ($0.0, e.protection($0.1, now: t)) }, uniquingKeysWith: { a, _ in a })
        }
        return result ?? Dictionary(ks.map { ($0.id, BrocolisProtection.legacy) }, uniquingKeysWith: { a, _ in a })
    }

    static func protection(_ k: NamedKey) -> BrocolisProtection { protections([k])[k.id] ?? .legacy }

    /// La protection qu'a reçue un texte qu'on vient de chiffrer : celle de
    /// la clé s'il porte un jeton v3, sinon l'ancien format.
    static func protectionUsed(_ sealed: String, recipients: [NamedKey]) -> BrocolisProtection {
        guard recipients.count == 1, sealed.contains(JetonV3.head) || sealed.contains(JetonV4.head) else {
            return .legacy
        }
        return protection(recipients[0])
    }

    // MARK: Appairage (§8.4)

    /// Mon paquet de clés, à publier dans le salon.
    static func myBundle() -> String? { run { e, _ in e.bundleBase64 } ?? nil }

    /// Ce que je publie dans le salon, en une transaction : le paquet (§8.4)
    /// et, si j'ai ML-KEM, la capacité v4 signée (§9.6).
    static func myPublication() -> (bundle: String?, caps: String?) {
        run { e, _ in (e.bundleBase64, e.capsBase64) } ?? (nil, nil)
    }

    /// L'empreinte d'appairage à deux, si le correspondant a publié un paquet
    /// valide (sinon `nil` : l'empreinte d'avant). Sous le contexte v4 si sa
    /// capacité v4 est valide et que j'ai ML-KEM (§9.7) : un serveur qui la
    /// retire d'un seul côté fait afficher deux empreintes différentes.
    static func pairingFingerprint(keyBase64: String, peerBundle: String?, peerCaps: String? = nil) -> String? {
        guard let peer = bundle(peerBundle),
              let raw = Data(base64Encoded: keyBase64), raw.count == 32,
              let mine = run({ e, _ in (e.identity, e.device.supportsPq) }) else { return nil }
        if mine.1 && BrocolisV3Format.capsValid(peer, caps(peerCaps)) {
            return BrocolisV3Format.pairingFingerprint4(key: Array(raw), mine.0, BrocolisV3Format.identity(of: peer))
        }
        return BrocolisV3Format.pairingFingerprint(key: Array(raw), mine.0, BrocolisV3Format.identity(of: peer))
    }

    /// L'invitant ouvre la session dès l'appairage (§8.4).
    static func openSession(for k: NamedKey) {
        guard let key = key(k) else { return }
        _ = run { e, t in e.openSession(key, now: t) }
    }

    /// Une clé supprimée : ses sessions PSK partent avec elle.
    static func forget(keyId: String) {
        _ = run { e, _ in e.forget(keyId: keyId) }
    }

    // MARK: Messagerie (§8.7)

    /// Le `ciphertext` d'un message, en v3 si la clé le permet, sinon `nil`.
    static func sealMessage(_ clear: String, for k: NamedKey) -> String? {
        guard let key = key(k) else { return nil }
        return run { e, t in e.sealMessage(clear, for: key, now: t) } ?? nil
    }

    /// Ouvre des messages de la messagerie en une transaction : pour chacun,
    /// `nil` s'il ne porte pas de jeton v3 (→ v1), sinon le résultat.
    static func openMessages(_ messages: [(ciphertext: String, mine: Bool)],
                             conversation k: NamedKey, all: [NamedKey]) -> [BrocolisV3Opened?] {
        guard messages.contains(where: { !BrocolisV3Format.findTokens($0.ciphertext).isEmpty }),
              let conv = key(k) else { return messages.map { _ in nil } }
        let v3keys = keys(all)
        return run { e, t in
            messages.map { e.openMessage($0.ciphertext, keys: v3keys, conversation: conv, mine: $0.mine, now: t) }
        } ?? messages.map { BrocolisV3Format.findTokens($0.ciphertext).isEmpty ? nil : .failed(.etat) }
    }
}
