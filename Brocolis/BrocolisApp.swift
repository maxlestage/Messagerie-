//
//  BrocolisApp.swift
//  Brocolis 🥦
//
//  App hôte minimale : elle sert à gérer la clé partagée. Le vrai travail se
//  fait dans l'Action Extension, qui se greffe sur les apps de messagerie via
//  le menu Partager.
//

import SwiftUI

@main
struct BrocolisApp: App {
    var body: some Scene {
        WindowGroup {
            RootView()
                .tint(.green)
        }
    }
}
