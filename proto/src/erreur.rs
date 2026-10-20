//! Les erreurs, typées : une entrée hostile ne fait jamais paniquer, elle
//! donne une de ces erreurs. Les messages sont faits pour les journaux de
//! développement (ils ne contiennent jamais de secret).

use core::fmt;

/// Tout ce qui peut échouer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Erreur {
    /// Le texte ne contient pas le jeton attendu, ou son enveloppe
    /// (`[[…:` / `]]`) est abîmée.
    JetonAbsent,
    /// Le base64 est invalide (alphabet standard avec `=`, strict).
    Base64,
    /// Un encodage binaire est malformé : longueur, octet de type ou de
    /// version, champ réservé non nul…
    Format,
    /// L'entrée dépasse la taille maximale acceptée.
    TropGrand,
    /// Des paramètres Argon2id hors des bornes acceptées (§3.2).
    Parametres,
    /// La phrase secrète est trop courte pour protéger une clé.
    PhraseTropCourte,
    /// Le déchiffrement authentifié a échoué : mauvaise clé ou phrase,
    /// message modifié.
    Dechiffrement,
    /// Le remplissage (§3.3) est absent ou malformé.
    Remplissage,
    /// Le texte déchiffré n'est pas de l'UTF-8.
    Utf8,
    /// Une signature Ed25519 est fausse.
    Signature,
    /// Une clé publique est invalide (X25519 de petit ordre, ML-KEM mal
    /// formée, Ed25519 faible…).
    CleInvalide,
    /// Le paquet ne propose pas de clé ML-KEM alors qu'elle est demandée.
    PqIndisponible,
    /// La clé pré-signée (ou ML-KEM) désignée par le message n'existe pas ou
    /// plus sur cet appareil.
    CleInconnue,
    /// Le message n'appartient pas à cette session (identifiant différent).
    SessionInconnue,
    /// Un premier message (type 0x01) avec une autre clé éphémère pour le
    /// même identifiant : c'est une nouvelle session, à accepter par
    /// [`crate::Device::accept`].
    NouvelleSession,
    /// Un message déjà lu (rejeu) : à ignorer.
    Rejoue,
    /// Le message demanderait de sauter plus de [`crate::MAX_SKIP`] clés.
    TropDeClesSautees,
    /// Ce message de groupe vient d'un expéditeur (ou d'un groupe) dont on
    /// n'a pas la chaîne.
    ExpediteurInconnu,
    /// L'état sérialisé (JSON) est invalide, ou l'opération est impossible
    /// dans l'état courant.
    Etat,
    /// Un compteur est arrivé au bout (2³² messages sur une chaîne).
    Epuise,
}

impl fmt::Display for Erreur {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Erreur::JetonAbsent => "jeton absent ou abîmé",
            Erreur::Base64 => "base64 invalide",
            Erreur::Format => "encodage malformé",
            Erreur::TropGrand => "entrée trop grande",
            Erreur::Parametres => "paramètres Argon2id refusés",
            Erreur::PhraseTropCourte => "phrase secrète trop courte",
            Erreur::Dechiffrement => "déchiffrement impossible (clé, phrase ou message altéré)",
            Erreur::Remplissage => "remplissage invalide",
            Erreur::Utf8 => "texte non UTF-8",
            Erreur::Signature => "signature invalide",
            Erreur::CleInvalide => "clé publique invalide",
            Erreur::PqIndisponible => "pas de clé post-quantique dans le paquet",
            Erreur::CleInconnue => "clé pré-signée inconnue ou expirée",
            Erreur::SessionInconnue => "message d'une autre session",
            Erreur::NouvelleSession => "premier message d'une nouvelle session",
            Erreur::Rejoue => "message déjà lu (rejeu ignoré)",
            Erreur::TropDeClesSautees => "trop de messages sautés",
            Erreur::ExpediteurInconnu => "expéditeur ou groupe inconnu",
            Erreur::Etat => "état invalide",
            Erreur::Epuise => "compteur épuisé",
        })
    }
}

impl std::error::Error for Erreur {}
