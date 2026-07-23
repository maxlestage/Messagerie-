//
//  BrocolisSplashView.swift
//  Brocolis 🥦
//
//  Page de GARDE + page de CHARGEMENT de l'app : le logo brocoli (repris de
//  l'icône) sur le fond vert de la marque, le nom, une accroche, et un
//  indicateur de chargement. Affichée au démarrage par `BrocolisApp`, puis
//  effacée en fondu pour laisser place à `RootView`.
//

import SwiftUI

struct BrocolisSplashView: View {
    /// Animations d'entrée (logo qui grandit + textes en fondu).
    @State private var appeared = false
    /// L'indicateur de chargement n'apparaît qu'après la page de garde.
    @State private var showLoader = false

    // Couleurs de la marque (explicites, donc identiques en thème clair/sombre).
    private let bgTop = Color(red: 238.0 / 255, green: 248.0 / 255, blue: 226.0 / 255)   // #EEF8E2
    private let bgBottom = Color(red: 220.0 / 255, green: 239.0 / 255, blue: 208.0 / 255) // #DCEFD0
    private let brocoliGreen = Color(red: 47.0 / 255, green: 158.0 / 255, blue: 74.0 / 255)
    private let deepGreen = Color(red: 34.0 / 255, green: 96.0 / 255, blue: 48.0 / 255)

    var body: some View {
        ZStack {
            // Fond vert doux de la marque, plein écran.
            LinearGradient(colors: [bgTop, bgBottom], startPoint: .top, endPoint: .bottom)
                .ignoresSafeArea()

            VStack(spacing: 22) {
                Spacer()

                // Logo repris de l'icône, dans une tuile arrondie « app icon ».
                Image("BrocolisLogo")
                    .resizable()
                    .scaledToFill()
                    .frame(width: 132, height: 132)
                    .clipShape(RoundedRectangle(cornerRadius: 30, style: .continuous))
                    .overlay(
                        RoundedRectangle(cornerRadius: 30, style: .continuous)
                            .stroke(.white.opacity(0.6), lineWidth: 1)
                    )
                    .shadow(color: brocoliGreen.opacity(0.28), radius: 18, x: 0, y: 10)
                    .scaleEffect(appeared ? 1 : 0.82)
                    .opacity(appeared ? 1 : 0)

                VStack(spacing: 8) {
                    Text("Brocolis")
                        .font(.system(size: 40, weight: .bold, design: .rounded))
                        .foregroundStyle(deepGreen)

                    Text(loc("Messagerie chiffrée de bout en bout",
                             "End-to-end encrypted messaging",
                             "Mensajería cifrada de extremo a extremo"))
                        .font(.subheadline)
                        .foregroundStyle(deepGreen.opacity(0.75))
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .opacity(appeared ? 1 : 0)
                .offset(y: appeared ? 0 : 12)

                Spacer()

                // Page de chargement : indicateur discret, en bas.
                VStack(spacing: 10) {
                    ProgressView()
                        .progressViewStyle(.circular)
                        .tint(brocoliGreen)
                    Text(loc("Chargement…", "Loading…", "Cargando…"))
                        .font(.footnote)
                        .foregroundStyle(deepGreen.opacity(0.6))
                }
                .opacity(showLoader ? 1 : 0)
                .padding(.bottom, 44)
            }
        }
        .onAppear {
            withAnimation(.spring(response: 0.55, dampingFraction: 0.72)) {
                appeared = true
            }
            withAnimation(.easeIn(duration: 0.4).delay(0.5)) {
                showLoader = true
            }
        }
    }
}

#Preview {
    BrocolisSplashView()
}
