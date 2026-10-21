//
//  BrocolisV3.swift
//  Brocolis 🥦 (partagé app + clavier + Partager + iMessage)
//
//  Le protocole v3 dans Brocolis (docs/SECURITE.md §8) : sessions à double
//  cliquet, établies en hybride X25519 + ML-KEM-768 (iOS 26 ; avant : X25519
//  seul, affiché « classique »), avec le paquet `BrocolisProto`.
//
//  Ce fichier est la logique PURE (ni Trousseau, ni fichier, ni UI), testée
//  sous Linux ; c'est la même que le site (`site/src/v3.rs`) et qu'Android :
//
//  - un appareil v3 (`Device`) par installation, entretenu à chaque
//    transaction (§8.1) ;
//  - deux sessions au plus par contact (la dernière qui a servi envoie), et
//    des sessions PSK par clé (§8.2) ;
//  - les messages ouverts : un message v3 ne se déchiffre qu'une fois, son
//    clair est gardé sous l'empreinte du jeton (§8.2) ;
//  - le choix du format d'un envoi (§8.5), la réception et la réparation
//    (seulement d'une session perdue, §8.6) ;
//  - l'empreinte d'appairage (§8.4) et l'enveloppe des médias (§8.7).
//
//  Le v4 (§9) passe par le même moteur, comme sur le site : un contact dont
//  la capacité v4 signée est valide (ou dont un message v4 est déjà arrivé)
//  reçoit des jetons `[[BROCOLIS:v4:…]]` à triple cliquet et en-têtes
//  chiffrés, et ne redescend plus jamais en v3 ; la PSK v4 suit les mêmes
//  règles (§9.6). Son empreinte d'appairage prend le contexte v4 (§9.7).
//
//  La persistance et le verrou entre processus sont dans
//  `BrocolisV3Store.swift`.
//

import Foundation
import BrocolisProto
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif

// MARK: - Protection affichée (§8.8)

/// La protection d'une clé, telle que le prochain envoi la donnera.
enum BrocolisProtection: String, Equatable {
    case triple, triplePsk, postQuantum, classic, psk, legacy

    /// Libellé affiché partout où s'affiche une clé ou un contact.
    var label: String {
        switch self {
        case .triple:
            return loc("🔐 triple cliquet (post-quantique à chaque message)", "🔐 triple ratchet (post-quantum on every message)", "🔐 triple trinquete (poscuántico en cada mensaje)")
        case .triplePsk:
            return loc("🔐 triple cliquet, clé partagée (PSK)", "🔐 triple ratchet, shared key (PSK)", "🔐 triple trinquete, clave compartida (PSK)")
        case .postQuantum:
            return loc("🔐 double cliquet (post-quantique)", "🔐 double ratchet (post-quantum)", "🔐 doble trinquete (poscuántico)")
        case .classic:
            return loc("🔐 double cliquet (classique)", "🔐 double ratchet (classic)", "🔐 doble trinquete (clásico)")
        case .psk:
            return loc("🔐 double cliquet, clé partagée (PSK)", "🔐 double ratchet, shared key (PSK)", "🔐 doble trinquete, clave compartida (PSK)")
        case .legacy:
            return loc("ancien format", "old format", "formato antiguo")
        }
    }

    var isRatchet: Bool { self != .legacy }
}

// MARK: - Une clé vue par le moteur

/// Une clé nommée, telle que le moteur v3 la voit (§8.5).
struct BrocolisV3Key {
    /// L'identifiant de la clé nommée (où ranger ses sessions PSK).
    let id: String
    /// La clé partagée (32 octets).
    let raw: [UInt8]
    /// Le paquet du correspondant reçu à l'appairage, vérifié.
    let bundle: KeyBundle?
    /// Quand ce paquet est arrivé (secondes Unix).
    let bundleAt: UInt64
    /// Une clé de groupe (3 personnes ou plus) : jamais de v3.
    let group: Bool
    /// Marquée « à deux, double cliquet » par l'utilisateur (PSK).
    let psk: Bool
    /// Sa capacité v4 signée (64 octets), reçue avec le paquet (§9.6) ;
    /// vérifiée par le moteur.
    var caps: [UInt8]? = nil
}

/// Le résultat d'une réception.
enum BrocolisV3Opened: Equatable {
    /// Le clair (déchiffré à l'instant, ou gardé).
    case text(String)
    /// Déjà lu, et le clair n'est plus gardé.
    case replay
    /// Illisible (pas pour nous, session perdue, altéré…).
    case failed(Erreur)
}

// MARK: - Constantes et outils (§8)

enum BrocolisV3Format {
    /// Le début du clair v3 qui porte une clé de média (§8.7).
    static let mediaPrefix = "BRCM3:"
    /// Au-delà (ou pour un média `BRCM1:`), l'enveloppe des médias.
    static let mediaThreshold = 16 * 1024
    /// Un paquet d'appairage ouvre une session pendant 30 jours (§8.5).
    static let bundleMaxAge: UInt64 = 30 * Protocole.jour
    /// Celui qui rejoint relit le salon pendant 8 jours (§8.4).
    static let groupWatch: TimeInterval = 8 * 24 * 3600
    /// Ce qui précède les identités dans l'empreinte d'appairage (§8.4).
    static let fingerprintContext = Array("Brocolis_v3_Appairage".utf8)
    /// …quand les deux côtés ont une capacité v4 valide (§9.7).
    static let fingerprintContext4 = Array("Brocolis_v4_Appairage".utf8)
    /// Messages ouverts gardés : 2 000 au plus et 1 Mio de clair (§8.2).
    static let openedMax = 2_000
    static let openedMaxBytes = 1 << 20
    /// Deux sessions au plus par contact.
    static let sessionsPerPeer = 2

    /// Faut-il réparer ? Seulement une session PERDUE (§8.6).
    static func needsRepair(_ e: Erreur) -> Bool {
        e == .sessionInconnue || e == .cleInconnue
    }

    /// L'empreinte d'appairage à deux (§8.4) :
    /// SHA-256("Brocolis_v3_Appairage" ‖ K ‖ min(P_A, P_B) ‖ max(P_A, P_B))[0..8],
    /// P = IK X25519 ‖ IK Ed25519, en XXXX-XXXX-XXXX-XXXX.
    static func pairingFingerprint(key: [UInt8], _ a: [UInt8], _ b: [UInt8]) -> String {
        fingerprint(context: fingerprintContext, key: key, a, b)
    }

    /// L'empreinte d'appairage v4 (§9.7) : la même, sous
    /// `"Brocolis_v4_Appairage"`. Un serveur qui retire la capacité d'un seul
    /// côté fait afficher deux empreintes différentes.
    static func pairingFingerprint4(key: [UInt8], _ a: [UInt8], _ b: [UInt8]) -> String {
        fingerprint(context: fingerprintContext4, key: key, a, b)
    }

    private static func fingerprint(context: [UInt8], key: [UInt8], _ a: [UInt8], _ b: [UInt8]) -> String {
        let (lo, hi) = a.lexicographicallyPrecedes(b) || a == b ? (a, b) : (b, a)
        let digest = Kdf.sha256(context + key + lo + hi)
        let hex = digest.prefix(8).map { String(format: "%02X", $0) }.joined()
        var out = ""
        for (i, ch) in hex.enumerated() {
            if i != 0 && i % 4 == 0 { out += "-" }
            out.append(ch)
        }
        return out
    }

    /// L'identité d'un paquet : IK X25519 ‖ IK Ed25519 (64 octets).
    static func identity(of bundle: KeyBundle) -> [UInt8] {
        bundle.identity.dh + bundle.identity.sign
    }

    /// La capacité v4 du paquet est-elle valide (§9.6) : 64 octets signés
    /// (Ed25519 strict) par son identité, et un paquet qui propose ML-KEM.
    static func capsValid(_ bundle: KeyBundle, _ caps: [UInt8]?) -> Bool {
        guard bundle.pq != nil, let caps, caps.count == 64 else { return false }
        return (try? Paquet.verifyCaps4(identity: bundle.identity, signature: caps)) != nil
    }

    /// Un jeton v4 (`[[BROCOLIS:v4:…]]`) ?
    static func isV4(_ token: String) -> Bool {
        normalize(token).hasPrefix(JetonV4.head)
    }

    /// Le jeton sans aucun blanc (une messagerie peut couper une ligne).
    static func normalize(_ token: String) -> String {
        String(token.unicodeScalars.filter { !CharacterSet.whitespacesAndNewlines.contains($0) }.map(Character.init))
    }

    /// L'empreinte d'un jeton, sous laquelle son clair est gardé (§8.2).
    static func tokenHash(_ token: String) -> String {
        hex(Kdf.sha256(Array(normalize(token).utf8)))
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Les jetons v3 et v4 d'un texte, dans l'ordre (les jetons v1 de
    /// l'enveloppe des médias n'en sont pas).
    static func findTokens(_ text: String) -> [Range<String.Index>] {
        var out: [Range<String.Index>] = []
        var from = text.startIndex
        while let start = text.range(of: "[[BROCOLIS:v", range: from..<text.endIndex) {
            let rest = text[start.lowerBound...]
            guard rest.hasPrefix(JetonV3.head) || rest.hasPrefix(JetonV4.head) else {
                from = start.upperBound
                continue
            }
            guard let end = text.range(of: "]]", range: start.upperBound..<text.endIndex) else { break }
            out.append(start.lowerBound..<end.upperBound)
            from = end.upperBound
        }
        return out
    }
}

// MARK: - L'état gardé (§8.2)

/// Les sessions d'un contact (ou d'une clé PSK).
final class BrocolisV3Peer {
    var sessions: [Session] = []
    var current: [UInt8]?

    init() {}

    init(stored: StoredPeer) {
        sessions = stored.sessions.compactMap { try? Session.fromJson($0) }
            .prefix(BrocolisV3Format.sessionsPerPeer).map { $0 }
        current = sessions.map(\.sessionId).first { BrocolisV3Format.hex($0) == stored.current }
    }

    var stored: StoredPeer {
        StoredPeer(current: current.map(BrocolisV3Format.hex) ?? "", sessions: sessions.map { $0.toJson() })
    }

    func get(_ id: [UInt8]) -> Session? { sessions.first { $0.sessionId == id } }

    var sendingId: [UInt8]? {
        if let current, sessions.contains(where: { $0.sessionId == current }) { return current }
        return sessions.last?.sessionId
    }

    var sending: Session? { sendingId.flatMap(get) }

    /// Range une session (remplace celle de même identifiant, la plus
    /// ancienne part au-delà de deux) et en fait la session d'envoi.
    func put(_ s: Session) {
        let id = s.sessionId
        sessions.removeAll { $0.sessionId == id }
        sessions.append(s)
        while sessions.count > BrocolisV3Format.sessionsPerPeer { sessions.removeFirst() }
        current = id
    }

    struct StoredPeer: Codable {
        var current: String
        /// Chaque session, dans le JSON de la référence.
        var sessions: [String]
    }
}

/// Les sessions v4 d'un contact (ou d'une clé PSK), rangées comme les v3.
final class BrocolisV4Peer {
    var sessions: [Session4] = []
    var current: [UInt8]?

    init() {}

    init(stored: BrocolisV3Peer.StoredPeer) {
        sessions = stored.sessions.compactMap { try? Session4.fromJson($0) }
            .prefix(BrocolisV3Format.sessionsPerPeer).map { $0 }
        current = sessions.map(\.sessionId).first { BrocolisV3Format.hex($0) == stored.current }
    }

    var stored: BrocolisV3Peer.StoredPeer {
        BrocolisV3Peer.StoredPeer(current: current.map(BrocolisV3Format.hex) ?? "", sessions: sessions.map { $0.toJson() })
    }

    func get(_ id: [UInt8]) -> Session4? { sessions.first { $0.sessionId == id } }

    var sendingId: [UInt8]? {
        if let current, sessions.contains(where: { $0.sessionId == current }) { return current }
        return sessions.last?.sessionId
    }

    var sending: Session4? { sendingId.flatMap(get) }

    /// Range une session (remplace celle de même identifiant, la plus
    /// ancienne part au-delà de deux) et en fait la session d'envoi.
    func put(_ s: Session4) {
        let id = s.sessionId
        sessions.removeAll { $0.sessionId == id }
        sessions.append(s)
        while sessions.count > BrocolisV3Format.sessionsPerPeer { sessions.removeFirst() }
        current = id
    }
}

/// L'état chiffré au repos : sessions et messages ouverts.
struct BrocolisV3Stored: Codable {
    struct Opened: Codable {
        var h: String
        var text: String
        var at: UInt64
        var mine: Bool
    }

    var v: Int = 1
    var peers: [String: BrocolisV3Peer.StoredPeer] = [:]
    var psk: [String: BrocolisV3Peer.StoredPeer] = [:]
    var pskSeen: [String] = []
    var pskReplay: String?
    var opened: [Opened] = []
    /// Les sessions v4 (§9), rangées comme les v3.
    var peers4: [String: BrocolisV3Peer.StoredPeer] = [:]
    var psk4: [String: BrocolisV3Peer.StoredPeer] = [:]
    /// Les contacts (IK X25519, hex) dont un message v4 est arrivé : on ne
    /// leur écrit plus qu'en v4 (§9.6).
    var v4Seen: [String] = []
    /// Les clés sur lesquelles une PSK v4 est arrivée.
    var psk4Seen: [String] = []
}

// Décodage tolérant : un état écrit avant le v4 (sans ses champs) se relit.
extension BrocolisV3Stored {
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        v = try c.decodeIfPresent(Int.self, forKey: .v) ?? 1
        peers = try c.decodeIfPresent([String: BrocolisV3Peer.StoredPeer].self, forKey: .peers) ?? [:]
        psk = try c.decodeIfPresent([String: BrocolisV3Peer.StoredPeer].self, forKey: .psk) ?? [:]
        pskSeen = try c.decodeIfPresent([String].self, forKey: .pskSeen) ?? []
        pskReplay = try c.decodeIfPresent(String.self, forKey: .pskReplay)
        opened = try c.decodeIfPresent([Opened].self, forKey: .opened) ?? []
        peers4 = try c.decodeIfPresent([String: BrocolisV3Peer.StoredPeer].self, forKey: .peers4) ?? [:]
        psk4 = try c.decodeIfPresent([String: BrocolisV3Peer.StoredPeer].self, forKey: .psk4) ?? [:]
        v4Seen = try c.decodeIfPresent([String].self, forKey: .v4Seen) ?? []
        psk4Seen = try c.decodeIfPresent([String].self, forKey: .psk4Seen) ?? []
    }
}

// MARK: - Le moteur (le temps d'une transaction, §8.3)

/// L'appareil v3 et ses sessions. Ce qui a changé se lit avec
/// `deviceDirty` / `stateDirty` : l'appelant l'écrit (l'appareil d'abord)
/// avant de rendre le jeton.
final class BrocolisV3Engine {
    let device: Device
    private var peers: [String: BrocolisV3Peer]
    private var psk: [String: BrocolisV3Peer]
    private var pskSeen: [String]
    private var pskReplay: ReplayGuard
    private var opened: [BrocolisV3Stored.Opened]
    private var peers4: [String: BrocolisV4Peer]
    private var psk4: [String: BrocolisV4Peer]
    private var v4Seen: [String]
    private var psk4Seen: [String]
    private(set) var deviceDirty: Bool
    private(set) var stateDirty = false
    private let rng = Hasard.system()

    /// Charge l'appareil et l'état (ou les crée), puis entretient l'appareil
    /// (§8.1). Un état illisible repart de zéro.
    init(deviceJson: String?, stored: BrocolisV3Stored?, now: UInt64) {
        let existing = deviceJson.flatMap { try? Device.fromJson($0) }
        device = existing ?? Device.generate(rng: rng, now: now, pq: true)
        deviceDirty = existing == nil
        let s = stored ?? BrocolisV3Stored()
        peers = s.peers.mapValues(BrocolisV3Peer.init(stored:))
        psk = s.psk.mapValues(BrocolisV3Peer.init(stored:))
        pskSeen = s.pskSeen
        pskReplay = s.pskReplay.flatMap { try? ReplayGuard.fromJson($0) } ?? ReplayGuard()
        opened = s.opened
        peers4 = s.peers4.mapValues(BrocolisV4Peer.init(stored:))
        psk4 = s.psk4.mapValues(BrocolisV4Peer.init(stored:))
        v4Seen = s.v4Seen
        psk4Seen = s.psk4Seen
        maintain(now: now)
    }

    /// SPK et PQPK neuves chaque semaine, ML-KEM dès qu'il est là (iOS 26),
    /// purge des clés remplacées depuis un mois.
    private func maintain(now: UInt64) {
        if device.needsRotation(now: now) {
            device.rotate(rng: rng, now: now)
            deviceDirty = true
        }
        if MlKem.isAvailable && !device.supportsPq {
            if (try? device.enablePq(rng: rng, now: now)) != nil { deviceDirty = true }
        }
        device.purge(now: now)
        for peer in Array(peers.values) + Array(psk.values) {
            for s in peer.sessions { s.purge(now: now) }
        }
        for peer in Array(peers4.values) + Array(psk4.values) {
            for s in peer.sessions { s.purge(now: now) }
        }
    }

    /// L'état à garder.
    var stored: BrocolisV3Stored {
        BrocolisV3Stored(
            v: 1, peers: peers.mapValues(\.stored), psk: psk.mapValues(\.stored),
            pskSeen: pskSeen, pskReplay: pskReplay.toJson(), opened: opened,
            peers4: peers4.mapValues(\.stored), psk4: psk4.mapValues(\.stored),
            v4Seen: v4Seen, psk4Seen: psk4Seen)
    }

    /// Le paquet de clés à publier dans le salon (base64).
    var bundleBase64: String? { try? device.bundle().toBase64() }

    /// Ma capacité v4 signée, à publier avec le paquet (§9.6, base64) ; `nil`
    /// sans ML-KEM ici.
    var capsBase64: String? { device.caps4().map { Base64.encode($0) } }

    /// Mon identité : IK X25519 ‖ IK Ed25519.
    var identity: [UInt8] { device.identity().dh + device.identity().sign }

    /// L'empreinte d'appairage à comparer pour `k` (§8.4, §9.7) : sous le
    /// contexte v4 si le contact a une capacité valide (la mienne est publiée
    /// dès que j'ai ML-KEM), sinon v3. `nil` sans paquet.
    func fingerprint(_ k: BrocolisV3Key) -> String? {
        guard let b = contact(k) else { return nil }
        if BrocolisV3Format.capsValid(b, k.caps) && device.supportsPq {
            return BrocolisV3Format.pairingFingerprint4(key: k.raw, identity, BrocolisV3Format.identity(of: b))
        }
        return BrocolisV3Format.pairingFingerprint(key: k.raw, identity, BrocolisV3Format.identity(of: b))
    }

    // MARK: Choix (§8.5)

    private func contact(_ k: BrocolisV3Key) -> KeyBundle? { k.group ? nil : k.bundle }

    /// Le paquet du contact s'il parle v4 (§9.6) : ML-KEM des deux côtés, et
    /// une capacité valide ou un message v4 déjà reçu de lui (on ne
    /// redescend pas).
    private func contact4(_ k: BrocolisV3Key) -> KeyBundle? {
        guard let b = contact(k), b.pq != nil, device.supportsPq else { return nil }
        let sticky = v4Seen.contains(BrocolisV3Format.hex(b.identity.dh))
        return sticky || BrocolisV3Format.capsValid(b, k.caps) ? b : nil
    }

    /// La PSK part-elle en v4 : une PSK v4 est arrivée sur la clé, ou le
    /// contact parle v4 (§9.6).
    private func psk4Allowed(_ k: BrocolisV3Key, _ now: UInt64) -> Bool {
        pskAllowed(k, now) && device.supportsPq && (psk4Seen.contains(k.id) || contact4(k) != nil)
    }

    private func fresh(_ k: BrocolisV3Key, _ now: UInt64) -> Bool {
        let (sum, overflow) = k.bundleAt.addingReportingOverflow(BrocolisV3Format.bundleMaxAge)
        return overflow || sum > now
    }

    private func pskAllowed(_ k: BrocolisV3Key, _ now: UInt64) -> Bool {
        guard !k.group else { return false }
        // Un contact v3 au paquet trop vieux est à jour : la PSK est sûre.
        return k.psk || pskSeen.contains(k.id) || (k.bundle != nil && !fresh(k, now))
    }

    /// La protection de la clé, telle que le prochain envoi la donnera (§8.8).
    func protection(_ k: BrocolisV3Key, now: UInt64) -> BrocolisProtection {
        if let b = contact4(k) {
            let live = peers4[BrocolisV3Format.hex(b.identity.dh)]?.sendingId != nil
            if live || fresh(k, now) { return .triple }
        } else if let b = contact(k) {
            if let peer = peers[BrocolisV3Format.hex(b.identity.dh)], let s = peer.sending {
                return s.isPostQuantum ? .postQuantum : .classic
            }
            if fresh(k, now) {
                return b.pq != nil && MlKem.isAvailable ? .postQuantum : .classic
            }
        }
        if psk4Allowed(k, now) { return .triplePsk }
        return pskAllowed(k, now) ? .psk : .legacy
    }

    /// Ouvre la session vers le contact s'il n'y en a pas (l'invitant, à la
    /// fin de l'appairage : §8.4). Rien ne part : le premier message la porte.
    @discardableResult
    func openSession(_ k: BrocolisV3Key, now: UInt64) -> Bool {
        if let b = contact4(k) {
            let peer = peer4(for: b)
            if peer.sendingId != nil { return true }
            guard fresh(k, now), let s = try? device.initiate4(bundle: b, rng: rng) else { return false }
            peer.put(s)
            stateDirty = true
            return true
        }
        guard let b = contact(k), fresh(k, now) else { return false }
        let peer = peer(for: b)
        if peer.sendingId != nil { return true }
        guard let s = try? device.initiateBest(bundle: b, rng: rng) else { return false }
        peer.put(s)
        stateDirty = true
        return true
    }

    private func peer(for b: KeyBundle) -> BrocolisV3Peer {
        let owner = BrocolisV3Format.hex(b.identity.dh)
        if let p = peers[owner] { return p }
        let p = BrocolisV3Peer()
        peers[owner] = p
        return p
    }

    private func pskPeer(_ id: String) -> BrocolisV3Peer {
        if let p = psk[id] { return p }
        let p = BrocolisV3Peer()
        psk[id] = p
        return p
    }

    private func peer4(for b: KeyBundle) -> BrocolisV4Peer {
        peer4(owner: BrocolisV3Format.hex(b.identity.dh))
    }

    private func peer4(owner: String) -> BrocolisV4Peer {
        if let p = peers4[owner] { return p }
        let p = BrocolisV4Peer()
        peers4[owner] = p
        return p
    }

    private func psk4Peer(_ id: String) -> BrocolisV4Peer {
        if let p = psk4[id] { return p }
        let p = BrocolisV4Peer()
        psk4[id] = p
        return p
    }

    // MARK: Envoi

    /// Chiffre `text` pour `k` en v3 (§8.5) : session de contact, session
    /// neuve vers son paquet, ou PSK. `nil` : l'appelant chiffre en v1/v2.
    func seal(_ text: String, for k: BrocolisV3Key, now: UInt64) -> String? {
        guard text.utf8.count <= Session.maxPlaintext else { return nil }
        // Un contact v4 ne reçoit plus que du v4 (§9.6) : sans session ni
        // paquet frais, la PSK (v4) prend le relais, jamais le v3.
        let viaContact = contact4(k) != nil ? sealContact4(text, k, now) : sealContact(text, k, now)
        let sealed = viaContact ?? (psk4Allowed(k, now) ? sealPsk4(text, k) : sealPsk(text, k, now))
        guard let token = sealed else { return nil }
        remember(token: token, text: text, mine: true, now: now)
        return token
    }

    private func sealContact4(_ text: String, _ k: BrocolisV3Key, _ now: UInt64) -> String? {
        guard let b = contact4(k) else { return nil }
        let peer = peer4(for: b)
        if let s = peer.sending {
            if let token = try? s.encrypt(text) {
                stateDirty = true
                return token
            }
            // Chaîne épuisée ou état abîmé : une session neuve.
            peer.sessions.removeAll()
        }
        guard fresh(k, now), let s = try? device.initiate4(bundle: b, rng: rng),
              let token = try? s.encrypt(text) else { return nil }
        peer.put(s)
        stateDirty = true
        return token
    }

    private func sealPsk4(_ text: String, _ k: BrocolisV3Key) -> String? {
        guard k.raw.count == 32 else { return nil }
        let peer = psk4Peer(k.id)
        if let s = peer.sending {
            if let token = try? s.encrypt(text) {
                stateDirty = true
                return token
            }
            peer.sessions.removeAll()
        }
        guard let s = try? Session4.initiatePsk(key: k.raw, rng: rng), let token = try? s.encrypt(text) else {
            return nil
        }
        peer.put(s)
        stateDirty = true
        return token
    }

    private func sealContact(_ text: String, _ k: BrocolisV3Key, _ now: UInt64) -> String? {
        guard let b = contact(k) else { return nil }
        let peer = peer(for: b)
        if let s = peer.sending {
            if let token = try? s.encrypt(text) {
                stateDirty = true
                return token
            }
            // Chaîne épuisée ou état abîmé : une session neuve.
            peer.sessions.removeAll()
        }
        guard fresh(k, now), let s = try? device.initiateBest(bundle: b, rng: rng),
              let token = try? s.encrypt(text) else { return nil }
        peer.put(s)
        stateDirty = true
        return token
    }

    private func sealPsk(_ text: String, _ k: BrocolisV3Key, _ now: UInt64) -> String? {
        guard pskAllowed(k, now), k.raw.count == 32 else { return nil }
        let peer = pskPeer(k.id)
        if let s = peer.sending {
            if let token = try? s.encrypt(text) {
                stateDirty = true
                return token
            }
            peer.sessions.removeAll()
        }
        guard let s = try? Session.initiatePsk(key: k.raw, rng: rng), let token = try? s.encrypt(text) else {
            return nil
        }
        peer.put(s)
        stateDirty = true
        return token
    }

    // MARK: Messages ouverts

    /// Le clair gardé d'un jeton, s'il l'est.
    func recall(_ token: String) -> String? {
        let h = BrocolisV3Format.tokenHash(token)
        return opened.first { $0.h == h }?.text
    }

    /// Garde le clair d'un jeton (§8.2).
    func remember(token: String, text: String, mine: Bool, now: UInt64) {
        let h = BrocolisV3Format.tokenHash(token)
        guard !opened.contains(where: { $0.h == h }) else { return }
        opened.append(.init(h: h, text: text, at: now, mine: mine))
        var total = opened.reduce(0) { $0 + $1.text.utf8.count }
        while opened.count > BrocolisV3Format.openedMax
                || (total > BrocolisV3Format.openedMaxBytes && opened.count > 1) {
            total -= opened.removeFirst().text.utf8.count
        }
        stateDirty = true
    }

    // MARK: Réception (§8.6)

    /// Ouvre un jeton v3 reçu : clair gardé, sinon session, sinon premier
    /// message d'un contact (ou PSK d'une de `keys`).
    func open(_ token: String, keys: [BrocolisV3Key], now: UInt64) -> BrocolisV3Opened {
        if let text = recall(token) { return .text(text) }
        let clean = BrocolisV3Format.normalize(token)
        do {
            let text: String
            if BrocolisV3Format.isV4(clean) {
                text = try decrypt4(try Token4.decode(clean), keys: keys, now: now)
            } else {
                text = try decrypt(try Token.decode(clean), keys: keys, now: now)
            }
            remember(token: token, text: text, mine: false, now: now)
            return .text(text)
        } catch Erreur.rejoue {
            return .replay
        } catch {
            return .failed(error as? Erreur ?? .format)
        }
    }

    private func decrypt(_ token: Token, keys: [BrocolisV3Key], now: UInt64) throws -> String {
        guard let id = token.sessionId else { throw Erreur.sessionInconnue }
        for peer in Array(peers.values) + Array(psk.values) {
            guard let s = peer.get(id) else { continue }
            do {
                let content = try s.decrypt(token, now: now, rng: rng)
                peer.current = id
                stateDirty = true
                return try text(content)
            } catch Erreur.nouvelleSession {
                // L'autre a ouvert une session neuve (il avait perdu la sienne).
                break
            }
        }
        guard case .initial(let first) = token else { throw Erreur.sessionInconnue }
        if first.mode == .psk {
            for k in keys where !k.group && k.raw.count == 32 {
                do {
                    let (s, content) = try Session.acceptPsk(
                        keys: [k.raw], message: first, guard: &pskReplay, now: now, rng: rng)
                    pskPeer(k.id).put(s)
                    if !pskSeen.contains(k.id) { pskSeen.append(k.id) }
                    stateDirty = true
                    return try text(content)
                } catch Erreur.sessionInconnue {
                    continue
                }
            }
            throw Erreur.sessionInconnue
        }
        // X25519 ou hybride : seulement d'un contact (paquet de l'appairage).
        guard let b = keys.lazy.compactMap({ self.contact($0) }).first(where: { $0.identity.dh == first.identity })
        else { throw Erreur.sessionInconnue }
        let (s, content) = try device.accept(first, now: now, rng: rng)
        deviceDirty = true
        peer(for: b).put(s)
        stateDirty = true
        return try text(content)
    }

    /// Reçoit un jeton v4 (§9) : chaque session v4 l'essaie
    /// (`.sessionInconnue` : « pas celle-ci ») ; sinon un premier message
    /// d'un contact, ou une PSK v4 d'une de `keys`.
    private func decrypt4(_ token: Token4, keys: [BrocolisV3Key], now: UInt64) throws -> String {
        for (isPsk, table) in [(false, peers4), (true, psk4)] {
            for (owner, peer) in table {
                for s in peer.sessions {
                    let content: Content
                    do {
                        content = try s.decrypt(token, now: now, rng: rng)
                    } catch Erreur.sessionInconnue {
                        continue
                    }
                    peer.current = s.sessionId
                    if !isPsk && !v4Seen.contains(owner) { v4Seen.append(owner) }
                    stateDirty = true
                    return try text(content)
                }
            }
        }
        switch token {
        case .initial:
            let (s, content) = try device.accept4(token, now: now, rng: rng)
            // Seulement d'un contact (paquet reçu à l'appairage).
            guard let ik = s.peerIdentity,
                  keys.contains(where: { self.contact($0)?.identity.dh == ik })
            else { throw Erreur.sessionInconnue }
            deviceDirty = true
            let owner = BrocolisV3Format.hex(ik)
            if !v4Seen.contains(owner) { v4Seen.append(owner) }
            peer4(owner: owner).put(s)
            stateDirty = true
            return try text(content)
        case .message:
            for k in keys where !k.group && k.raw.count == 32 {
                do {
                    let (s, content) = try Session4.acceptPsk(
                        keys: [k.raw], token: token, guard: &pskReplay, now: now, rng: rng)
                    psk4Peer(k.id).put(s)
                    if !pskSeen.contains(k.id) { pskSeen.append(k.id) }
                    if !psk4Seen.contains(k.id) { psk4Seen.append(k.id) }
                    stateDirty = true
                    return try text(content)
                } catch Erreur.sessionInconnue {
                    continue
                }
            }
            throw Erreur.sessionInconnue
        }
    }

    private func text(_ content: Content) throws -> String {
        guard case .text(let t) = content else { throw Erreur.format }
        return t
    }

    /// Oublie les sessions du contact de `k` : le prochain envoi en ouvre une
    /// neuve (§8.6, réparation).
    func repair(_ k: BrocolisV3Key) {
        guard let b = k.bundle else { return }
        let owner = BrocolisV3Format.hex(b.identity.dh)
        let v3 = peers.removeValue(forKey: owner) != nil
        if peers4.removeValue(forKey: owner) != nil || v3 { stateDirty = true }
    }

    /// Oublie tout ce qui touche à une clé supprimée (sessions PSK) ; les
    /// sessions du contact restent si une autre clé le désigne.
    func forget(keyId: String) {
        if psk.removeValue(forKey: keyId) != nil { stateDirty = true }
        if psk4.removeValue(forKey: keyId) != nil { stateDirty = true }
        if pskSeen.contains(keyId) || psk4Seen.contains(keyId) {
            pskSeen.removeAll { $0 == keyId }
            psk4Seen.removeAll { $0 == keyId }
            stateDirty = true
        }
    }

    /// Nombre de sessions avec le contact de `k` (tests, affichage).
    func sessionCount(_ k: BrocolisV3Key) -> Int {
        let owner = k.bundle.map { BrocolisV3Format.hex($0.identity.dh) } ?? ""
        return (peers[owner]?.sessions.count ?? 0) + (peers4[owner]?.sessions.count ?? 0)
            + (psk[k.id]?.sessions.count ?? 0) + (psk4[k.id]?.sessions.count ?? 0)
    }

    // MARK: Messagerie (§8.7)

    /// Le champ `ciphertext` d'un message de la messagerie, en v3 si la clé
    /// le permet ; un média (ou un long texte) part dans l'enveloppe.
    func sealMessage(_ clear: String, for k: BrocolisV3Key, now: UInt64) -> String? {
        if clear.hasPrefix("BRCM1:") || clear.utf8.count > BrocolisV3Format.mediaThreshold {
            let mediaKey = SymmetricKey(size: .bits256)
            let raw = mediaKey.withUnsafeBytes { Array($0) }
            guard let media = try? BrocolisCrypto.encryptToken(Data(clear.utf8), key: mediaKey),
                  let head = seal(BrocolisV3Format.mediaPrefix + Base64.encode(raw), for: k, now: now)
            else { return nil }
            return head + media
        }
        return seal(clear, for: k, now: now)
    }

    /// Le clair d'un message de la messagerie qui porte un jeton v3 (`nil`
    /// s'il n'en porte pas : l'appelant essaie v1). `mine` : un de mes
    /// envois, relu seulement dans les messages ouverts (jamais déchiffré ni
    /// réparé). `k` : la clé de la conversation (réparation).
    func openMessage(_ ciphertext: String, keys: [BrocolisV3Key], conversation k: BrocolisV3Key,
                     mine: Bool, now: UInt64) -> BrocolisV3Opened? {
        guard let range = BrocolisV3Format.findTokens(ciphertext).first else { return nil }
        let token = String(ciphertext[range])
        let result: BrocolisV3Opened
        if mine {
            result = recall(token).map { .text($0) } ?? .replay
        } else {
            result = open(token, keys: keys, now: now)
            // En v4, un jeton qu'aucune session n'ouvre ne dit pas laquelle
            // est perdue (pas d'identifiant en clair, §9.6) : pas de
            // réparation, l'envoi suivant ouvre une session s'il n'y en a plus.
            if case .failed(let e) = result, BrocolisV3Format.needsRepair(e), !BrocolisV3Format.isV4(token) {
                repair(k)
            }
        }
        guard case .text(let t) = result else { return result }
        guard t.hasPrefix(BrocolisV3Format.mediaPrefix) else { return result }
        let rest = String(ciphertext[range.upperBound...])
        guard let raw = Base64.decode(String(t.dropFirst(BrocolisV3Format.mediaPrefix.count))), raw.count == 32
        else { return .failed(.dechiffrement) }
        let (media, n) = BrocolisCrypto.decryptTokens(rest, keys: [SymmetricKey(data: raw)])
        return n > 0 ? .text(media) : .failed(.dechiffrement)
    }
}
