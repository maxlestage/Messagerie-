//
//  Message.swift
//  Messagerie 🥦
//

import Foundation

/// Un message tel qu'il « voyage » : les segments secrets y sont déjà sous
/// forme de jetons chiffrés `[[BROCOLIS:v1:...]]`. Le stockage ne contient
/// donc jamais le clair des parties marquées.
struct Message: Identifiable, Codable, Equatable {

    enum Sender: String, Codable {
        case me
        case them
    }

    let id: UUID
    /// Texte « sur le fil » (les parties secrètes sont des jetons chiffrés).
    var wireText: String
    var sender: Sender
    var date: Date

    init(id: UUID = UUID(), wireText: String, sender: Sender, date: Date = Date()) {
        self.id = id
        self.wireText = wireText
        self.sender = sender
        self.date = date
    }

    /// `true` si le message contient au moins une partie chiffrée.
    var isEncrypted: Bool { BrocolisCrypto.containsToken(wireText) }
}
