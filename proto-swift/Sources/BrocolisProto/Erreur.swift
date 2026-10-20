// Les erreurs, typées : une entrée hostile ne fait jamais planter, elle donne
// une de ces erreurs. Ce sont exactement celles de la référence Rust
// (`brocolis_proto::Erreur`), cas pour cas. Les messages sont faits pour les
// journaux de développement (ils ne contiennent jamais de secret).

/// Tout ce qui peut échouer. Chaque fonction du paquet qui `throws` ne lance
/// que des `Erreur`.
public enum Erreur: Error, Equatable, Hashable, Sendable, CustomStringConvertible {
    /// Le texte ne contient pas le jeton attendu, ou son enveloppe
    /// (`[[…:` / `]]`) est abîmée.
    case jetonAbsent
    /// Le base64 est invalide (alphabet standard avec `=`, strict).
    case base64
    /// Un encodage binaire est malformé : longueur, octet de type ou de
    /// version, champ réservé non nul…
    case format
    /// L'entrée dépasse la taille maximale acceptée.
    case tropGrand
    /// Des paramètres Argon2id hors des bornes acceptées (§3.2).
    case parametres
    /// La phrase secrète est trop courte pour protéger une clé.
    case phraseTropCourte
    /// Le déchiffrement authentifié a échoué : mauvaise clé ou phrase,
    /// message modifié.
    case dechiffrement
    /// Le remplissage (§3.3) est absent ou malformé.
    case remplissage
    /// Le texte déchiffré n'est pas de l'UTF-8.
    case utf8
    /// Une signature Ed25519 est fausse.
    case signature
    /// Une clé publique est invalide (X25519 de petit ordre, ML-KEM mal
    /// formée, Ed25519 faible…).
    case cleInvalide
    /// Le paquet ne propose pas de clé ML-KEM alors qu'elle est demandée,
    /// ou cet appareil ne sait pas faire ML-KEM (iOS avant 26).
    case pqIndisponible
    /// La clé pré-signée (ou ML-KEM) désignée par le message n'existe pas ou
    /// plus sur cet appareil.
    case cleInconnue
    /// Le message n'appartient pas à cette session (identifiant différent).
    case sessionInconnue
    /// Un premier message (type 0x01) avec une autre clé éphémère pour le
    /// même identifiant : c'est une nouvelle session, à accepter par
    /// `Device.accept`.
    case nouvelleSession
    /// Un message déjà lu (rejeu) : à ignorer.
    case rejoue
    /// Le message demanderait de sauter plus de `Protocole.maxSkip` clés.
    case tropDeClesSautees
    /// Ce message de groupe vient d'un expéditeur (ou d'un groupe) dont on
    /// n'a pas la chaîne.
    case expediteurInconnu
    /// L'état sérialisé (JSON) est invalide, ou l'opération est impossible
    /// dans l'état courant.
    case etat
    /// Un compteur est arrivé au bout (2³² messages sur une chaîne).
    case epuise

    public var description: String {
        switch self {
        case .jetonAbsent: "jeton absent ou abîmé"
        case .base64: "base64 invalide"
        case .format: "encodage malformé"
        case .tropGrand: "entrée trop grande"
        case .parametres: "paramètres Argon2id refusés"
        case .phraseTropCourte: "phrase secrète trop courte"
        case .dechiffrement: "déchiffrement impossible (clé, phrase ou message altéré)"
        case .remplissage: "remplissage invalide"
        case .utf8: "texte non UTF-8"
        case .signature: "signature invalide"
        case .cleInvalide: "clé publique invalide"
        case .pqIndisponible: "pas de clé post-quantique dans le paquet"
        case .cleInconnue: "clé pré-signée inconnue ou expirée"
        case .sessionInconnue: "message d'une autre session"
        case .nouvelleSession: "premier message d'une nouvelle session"
        case .rejoue: "message déjà lu (rejeu ignoré)"
        case .tropDeClesSautees: "trop de messages sautés"
        case .expediteurInconnu: "expéditeur ou groupe inconnu"
        case .etat: "état invalide"
        case .epuise: "compteur épuisé"
        }
    }
}

/// Les constantes communes du protocole (`brocolis_proto::{JOUR, MAX_SKIP,
/// MAX_SKIP_AGE}`).
public enum Protocole {
    /// Un jour, en secondes. L'heure est un nombre de secondes depuis
    /// l'époque Unix, fourni par l'appelant.
    public static let jour: UInt64 = 24 * 60 * 60
    /// Le nombre maximal de clés sautées gardées par session (ou par chaîne
    /// de groupe), et le plus grand saut accepté en un message (§4.3).
    public static let maxSkip: UInt32 = 1_000
    /// L'âge maximal d'une clé sautée : 30 jours (§4.3).
    public static let maxSkipAge: UInt64 = 30 * jour
}
