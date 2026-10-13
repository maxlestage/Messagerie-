//
//  PaywallView.swift
//  Brocolis 🥦 (app uniquement)
//
//  Les deux abonnements mensuels : Brocolis+ et Brocolis Pro. Apple impose, pour un abonnement
//  auto-renouvelable, que cet écran affiche : le nom de l'offre, sa durée, son
//  prix, un bouton « Restaurer », et des liens vers les conditions et la
//  politique de confidentialité. Tout est là — un oubli vaut un rejet.
//

import SwiftUI
import StoreKit

/// Conditions d'utilisation : à défaut d'un contrat propre, Apple accepte son
/// contrat type (EULA standard), qui s'applique par défaut à toute app.
private let termsURL = URL(string: "https://www.apple.com/legal/internet-services/itunes/dev/stdeula/")!
private let privacyURL = URL(string: "https://maxlestage.github.io/brocolis/")!

struct PaywallView: View {
    /// Ce que l'utilisateur essayait de faire : on le lui rappelle plutôt que
    /// de lui opposer un mur générique.
    let reason: BrocolisPaidFeature?

    @ObservedObject private var store = BrocolisStore.shared
    @Environment(\.dismiss) private var dismiss

    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    header
                    if let reason { reasonLine(reason) }
                    freeReassurance
                    unlocked
                    offers
                    if let error = store.lastError { errorLine(error) }
                    legal
                }
                .padding()
            }
            .navigationTitle(loc("S'abonner", "Subscribe", "Suscribirse"))
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button(loc("Fermer", "Close", "Cerrar")) { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button(loc("Restaurer", "Restore", "Restaurar")) {
                        Task { await store.restore(); if store.tier > .free { dismiss() } }
                    }
                    .disabled(store.isWorking)
                }
            }
            .task { await store.loadProducts() }
        }
    }

    // MARK: Morceaux

    private var header: some View {
        HStack(spacing: 10) {
            Text("🥦").font(.largeTitle)
            VStack(alignment: .leading) {
                Text(loc("Deux formules, au mois", "Two plans, monthly", "Dos planes, mensuales"))
                    .font(.title2.bold())
                Text(loc("Sans engagement. Résiliable à tout moment.",
                         "No commitment. Cancel anytime.",
                         "Sin compromiso. Cancela cuando quieras."))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func reasonLine(_ feature: BrocolisPaidFeature) -> some View {
        let text: String
        switch feature {
        case .moreKeys:
            text = loc("Tu as atteint tes \(BrocolisPlan.freeKeyLimit) clés offertes.",
                       "You've reached your \(BrocolisPlan.freeKeyLimit) free keys.",
                       "Has alcanzado tus \(BrocolisPlan.freeKeyLimit) claves gratuitas.")
        case .photo:
            text = loc("Envoyer une photo chiffrée demande Brocolis Pro.",
                       "Sending an encrypted photo needs Brocolis Pro.",
                       "Enviar una foto cifrada requiere Brocolis Pro.")
        case .voiceNote:
            text = loc("Envoyer un message vocal chiffré demande Brocolis Pro.",
                       "Sending an encrypted voice note needs Brocolis Pro.",
                       "Enviar una nota de voz cifrada requiere Brocolis Pro.")
        case .keyExpiry:
            text = loc("Faire expirer une clé automatiquement demande Brocolis+.",
                       "Automatic key expiry needs Brocolis+.",
                       "La caducidad automática de claves requiere Brocolis+.")
        }
        return Text(text)
            .font(.subheadline)
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10).fill(brocoliGreen.opacity(0.12)))
    }

    /// Dire franchement ce qui reste gratuit vaut mieux que de le cacher :
    /// personne n'achète une app dont il croit la fonction principale bridée.
    private var freeReassurance: some View {
        Text(loc("Le chiffrement reste gratuit, sans limite, pour toujours — tout comme recevoir photos et vocaux, et l'app Apple Watch. S'abonner ne verrouille rien de ce qui marche déjà chez toi.",
                 "Encryption stays free, unlimited, forever — and so do receiving photos and voice notes, and the Apple Watch app. Subscribing locks nothing that already works for you.",
                 "El cifrado sigue siendo gratuito, sin límite, para siempre — igual que recibir fotos y notas de voz, y la app de Apple Watch. Suscribirte no bloquea nada de lo que ya funciona."))
            .font(.footnote)
            .foregroundStyle(.secondary)
    }

    private var unlocked: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Brocolis+").font(.headline)
            perk("key.fill", loc("Clés illimitées", "Unlimited keys", "Claves ilimitadas"))
            perk("timer", loc("Expiration automatique des clés",
                              "Automatic key expiry", "Caducidad automática de claves"))
            Divider().padding(.vertical, 2)
            Text("Brocolis Pro").font(.headline)
            Text(loc("Tout Brocolis+, et en plus :", "Everything in Brocolis+, plus:",
                     "Todo Brocolis+, y además:"))
                .font(.caption).foregroundStyle(.secondary)
            perk("photo.fill", loc("Envoyer des photos chiffrées",
                                   "Send encrypted photos", "Enviar fotos cifradas"))
            perk("mic.fill", loc("Envoyer des messages vocaux chiffrés",
                                 "Send encrypted voice notes", "Enviar notas de voz cifradas"))
        }
    }

    private func perk(_ symbol: String, _ text: String) -> some View {
        HStack(spacing: 10) {
            Image(systemName: symbol).foregroundStyle(brocoliGreen).frame(width: 22)
            Text(text).font(.subheadline)
        }
    }

    @ViewBuilder
    private var offers: some View {
        if store.products.isEmpty {
            Text(loc("Offres indisponibles pour le moment. Vérifie ta connexion.",
                     "Offers unavailable right now. Check your connection.",
                     "Ofertas no disponibles ahora. Comprueba tu conexión."))
                .font(.footnote)
                .foregroundStyle(.secondary)
        } else {
            VStack(spacing: 10) {
                ForEach(store.products, id: \.id) { product in
                    offerButton(product)
                }
            }
        }
    }

    private func offerButton(_ product: Product) -> some View {
        Button {
            Task { if await store.purchase(product) { dismiss() } }
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(product.displayName).font(.headline)
                    // Durée pour l'abonnement, « paiement unique » pour l'autre :
                    // Apple exige que la durée soit explicite.
                    Text(subtitle(for: product))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Text(product.displayPrice).font(.headline)
            }
            .padding()
            .frame(maxWidth: .infinity)
            .background(RoundedRectangle(cornerRadius: 12).fill(brocoliGreen.opacity(0.15)))
        }
        .buttonStyle(.plain)
        .disabled(store.isWorking)
    }

    private func subtitle(for product: Product) -> String {
        if let period = product.subscription?.subscriptionPeriod {
            let unit: String
            switch period.unit {
            case .day:   unit = loc("jour", "day", "día")
            case .week:  unit = loc("semaine", "week", "semana")
            case .month: unit = loc("mois", "month", "mes")
            case .year:  unit = loc("an", "year", "año")
            @unknown default: unit = ""
            }
            return loc("Abonnement, renouvelé tous les \(period.value) \(unit). Résiliable à tout moment.",
                       "Subscription, renewed every \(period.value) \(unit). Cancel anytime.",
                       "Suscripción, renovada cada \(period.value) \(unit). Cancela cuando quieras.")
        }
        // Les deux offres sont des abonnements. Si l'App Store ne renvoie pas
        // de période, on ne l'invente pas : mieux vaut muet que faux.
        return ""
    }

    private func errorLine(_ error: String) -> some View {
        Text(error).font(.footnote).foregroundStyle(.orange)
    }

    private var legal: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(loc("L'abonnement se renouvelle automatiquement sauf résiliation au moins 24 h avant la fin de la période en cours. Gère-le dans les réglages de ton compte App Store.",
                     "The subscription renews automatically unless cancelled at least 24 h before the end of the current period. Manage it in your App Store account settings.",
                     "La suscripción se renueva automáticamente salvo cancelación al menos 24 h antes del fin del período. Gestiónala en los ajustes de tu cuenta de App Store."))
                .font(.caption2)
                .foregroundStyle(.secondary)
            HStack(spacing: 14) {
                Link(loc("Conditions", "Terms", "Condiciones"), destination: termsURL)
                Link(loc("Confidentialité", "Privacy", "Privacidad"), destination: privacyURL)
            }
            .font(.caption2)
        }
    }
}
