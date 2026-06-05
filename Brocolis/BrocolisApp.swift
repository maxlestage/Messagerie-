//
//  BrocolisApp.swift
//  Messagerie 🥦
//
//  Application de messagerie chiffrée pour iPhone, bâtie sur le chiffrement
//  sélectif de brocolis 🥦.
//

import SwiftUI

@main
struct BrocolisApp: App {
    @StateObject private var keyStore = KeyStore()
    @StateObject private var chatStore = ChatStore()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(keyStore)
                .environmentObject(chatStore)
                .tint(.green)
        }
    }
}
