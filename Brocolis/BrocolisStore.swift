//
//  BrocolisStore.swift
//  Brocolis 🥦 (app uniquement)
//
//  Achats intégrés (StoreKit 2) : les deux offres Brocolis+, l'abonnement
//  mensuel et l'achat à vie. Seule source qui écrit `BrocolisPlan.isPlus`.
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
    /// Brocolis+ est-il actif ? Miroir observable de `BrocolisPlan.isPlus`.
    @Published private(set) var isPlus = BrocolisPlan.isPlus
    /// Un achat ou une restauration est en cours.
    @Published private(set) var isWorking = false
    /// Dernier échec à montrer à l'utilisateur (nil si tout va bien).
    @Published var lastError: String?

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
                    return isPlus
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
        if !isPlus {
            lastError = loc("Aucun achat à restaurer sur ce compte.",
                            "No purchase to restore on this account.",
                            "No hay compras que restaurar en esta cuenta.")
        }
    }

    // MARK: L'état réel, d'après l'App Store

    /// Recalcule le droit à partir des transactions courantes. C'est l'App
    /// Store qui fait foi — jamais un drapeau qu'on aurait posé nous-mêmes.
    func refreshEntitlement() async {
        var entitled = false
        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result,
                  BrocolisPlan.productIds.contains(transaction.productID) else { continue }
            // Un abonnement révoqué (remboursement) ne donne plus droit à rien.
            if transaction.revocationDate == nil { entitled = true }
        }
        BrocolisPlan.isPlus = entitled
        isPlus = entitled
    }
}
