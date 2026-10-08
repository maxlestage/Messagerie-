//
//  BrocolisStore.swift
//  Brocolis 🥦 (app uniquement)
//
//  Achats intégrés (StoreKit 2) : les deux abonnements mensuels, Brocolis+ et
//  Brocolis Pro. Seule source qui écrit `BrocolisPlan.tier`.
//
//  Pourquoi StoreKit et pas Stripe : Apple l'EXIGE dès qu'un paiement débloque
//  une fonction de l'app. Un lien vers un paiement externe est un motif de
//  rejet. Voir docs/ios-achats-integres.md.
//

import Foundation
import StoreKit

@MainActor
final class BrocolisStore: ObservableObject {
    static let shared = BrocolisStore()

    /// Les deux offres, prêtes à afficher (prix localisés par l'App Store).
    @Published private(set) var products: [Product] = []
    /// Palier actif. Miroir observable de `BrocolisPlan.tier`.
    @Published private(set) var tier = BrocolisPlan.tier
    /// Un achat ou une restauration est en cours.
    @Published private(set) var isWorking = false
    /// Dernier échec à montrer à l'utilisateur (nil si tout va bien).
    @Published var lastError: String?
    /// E-mail Apple rattaché à cet appareil (accès offert par e-mail).
    @Published private(set) var linkedEmail = BrocolisPlan.linkedEmail

    private var updates: Task<Void, Never>?

    private init() {}

    // MARK: Cycle de vie

    /// À appeler une fois au lancement.
    func start() {
        guard updates == nil else { return }
        // Transactions arrivées d'ailleurs : achat sur un autre appareil,
        // renouvellement, « Demander à acheter » approuvé plus tard…
        updates = Task(priority: .background) { [weak self] in
            for await result in Transaction.updates {
                guard let self else { return }
                if case .verified(let transaction) = result {
                    await transaction.finish()
                }
                await self.refreshEntitlement()
            }
        }
        Task {
            await loadProducts()
            await refreshEntitlement()
            await refreshGrantedAccess()
        }
    }

    // MARK: Les offres

    func loadProducts() async {
        do {
            let found = try await Product.products(for: BrocolisPlan.productIds)
            // On garde l'ordre voulu, pas celui de l'App Store.
            products = BrocolisPlan.productIds.compactMap { id in
                found.first { $0.id == id }
            }
        } catch {
            // Hors ligne, ou produits pas encore approuvés : l'écran d'offres
            // le dira, l'app continue de fonctionner normalement.
            products = []
        }
    }

    // MARK: Acheter / restaurer

    /// Renvoie vrai si l'achat a abouti.
    @discardableResult
    func purchase(_ product: Product) async -> Bool {
        isWorking = true
        defer { isWorking = false }
        do {
            switch try await product.purchase() {
            case .success(let verification):
                if case .verified(let transaction) = verification {
                    await transaction.finish()
                    await refreshEntitlement()
                    return tier > .free
                }
                // Signature invalide : on ne débloque RIEN.
                lastError = loc("Achat non vérifié par l'App Store.",
                                "Purchase not verified by the App Store.",
                                "Compra no verificada por la App Store.")
                return false
            case .userCancelled:
                return false
            case .pending:
                // « Demander à acheter » : la validation viendra plus tard,
                // `Transaction.updates` la récupérera.
                lastError = loc("Achat en attente d'approbation.",
                                "Purchase awaiting approval.",
                                "Compra pendiente de aprobación.")
                return false
            @unknown default:
                return false
            }
        } catch {
            lastError = error.localizedDescription
            return false
        }
    }

    /// Apple EXIGE un bouton « Restaurer » dans toute app à achats intégrés.
    func restore() async {
        isWorking = true
        defer { isWorking = false }
        try? await AppStore.sync()
        await refreshEntitlement()
        if tier == .free {
            lastError = loc("Aucun achat à restaurer sur ce compte.",
                            "No purchase to restore on this account.",
                            "No hay compras que restaurar en esta cuenta.")
        }
    }

    /// Accès offert par le serveur (liste `BROCOLIS_PRO_IDS`). Sans réseau,
    /// on garde la dernière valeur connue : on ne retire pas un accès pour une
    /// coupure de connexion.
    func refreshGrantedAccess() async {
        guard let client = grantClient(), let grant = await client.fetchGrant() else { return }
        apply(grant)
    }

    /// « Se connecter avec Apple » : envoie le jeton d'identité au serveur.
    /// Renvoie le message à afficher, ou nil si l'accès offert est ouvert.
    func linkApple(identityToken: String) async -> String? {
        guard let client = grantClient() else {
            return loc("Serveur non configuré.", "Server not configured.", "Servidor no configurado.")
        }
        isWorking = true
        defer { isWorking = false }
        switch await client.linkAppleIdentity(identityToken) {
        case .success(let grant):
            // E-mail hors liste : le serveur ne l'a pas gardé, on ne l'affiche
            // donc pas comme « connecté ».
            if grant.tierName == "free" {
                let email = grant.email ?? ""
                return loc("Aucun accès offert pour \(email).",
                           "No complimentary access for \(email).",
                           "Ningún acceso de cortesía para \(email).")
            }
            apply(grant)
            return nil
        case .failure(.noVerifiedEmail):
            return loc("Apple n'a pas transmis d'e-mail vérifié. Choisis « Partager mon e-mail ».",
                       "Apple didn't share a verified email. Choose “Share My Email”.",
                       "Apple no compartió un correo verificado. Elige «Compartir mi correo».")
        case .failure(.rejected):
            return loc("Connexion refusée par le serveur.", "Sign-in rejected by the server.",
                       "El servidor rechazó el inicio de sesión.")
        case .failure(.unreachable):
            return loc("Serveur injoignable, réessaie.", "Server unreachable, try again.",
                       "Servidor inaccesible, inténtalo de nuevo.")
        }
    }

    /// Détache l'e-mail Apple de cet appareil.
    func unlinkApple() async {
        guard let client = grantClient() else { return }
        if let grant = await client.unlinkApple() { apply(grant) }
    }

    private func grantClient() -> BrocolisMessagingClient? {
        guard let base = URL(string: MessagingPrefs.serverURL), MessagingPrefs.isConfigured
        else { return nil }
        return BrocolisMessagingClient(baseURL: base, deviceId: MessagingPrefs.deviceId)
    }

    private func apply(_ grant: BrocolisMessagingClient.GrantStatus) {
        if let granted = BrocolisPlan.tier(forServerName: grant.tierName) {
            BrocolisPlan.grantedTier = granted
        }
        BrocolisPlan.linkedEmail = grant.email
        linkedEmail = grant.email
        tier = BrocolisPlan.tier
    }

    // MARK: L'état réel, d'après l'App Store

    /// Recalcule le palier à partir des transactions courantes. C'est l'App
    /// Store qui fait foi — jamais un drapeau qu'on aurait posé nous-mêmes.
    /// Si les deux abonnements se chevauchent (le temps d'un changement de
    /// formule), le plus ouvert l'emporte : on ne retire jamais à quelqu'un ce
    /// qu'il vient de payer.
    func refreshEntitlement() async {
        var best = BrocolisTier.free
        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result,
                  // Un abonnement révoqué (remboursement) ne donne plus rien.
                  transaction.revocationDate == nil,
                  let earned = BrocolisPlan.tier(forProductId: transaction.productID)
            else { continue }
            best = max(best, earned)
        }
        BrocolisPlan.purchasedTier = best
        tier = BrocolisPlan.tier
    }
}
