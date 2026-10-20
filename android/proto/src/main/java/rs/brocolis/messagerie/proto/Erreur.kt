package rs.brocolis.messagerie.proto

/**
 * Tout ce qui peut échouer (`brocolis_proto::Erreur`) : une entrée hostile ne
 * fait jamais planter, elle donne une de ces erreurs, levée dans une
 * [BrocolisException]. Les messages sont faits pour les journaux de
 * développement (ils ne contiennent jamais de secret).
 */
enum class Erreur(val message: String) {
    /** Le texte ne contient pas le jeton attendu, ou son enveloppe (`[[…:` / `]]`) est abîmée. */
    JetonAbsent("jeton absent ou abîmé"),
    /** Le base64 est invalide (alphabet standard avec `=`, strict). */
    Base64("base64 invalide"),
    /** Un encodage binaire est malformé : longueur, octet de type ou de version, champ réservé non nul… */
    Format("encodage malformé"),
    /** L'entrée dépasse la taille maximale acceptée. */
    TropGrand("entrée trop grande"),
    /** Des paramètres Argon2id hors des bornes acceptées (§3.2). */
    Parametres("paramètres Argon2id refusés"),
    /** La phrase secrète est trop courte pour protéger une clé. */
    PhraseTropCourte("phrase secrète trop courte"),
    /** Le déchiffrement authentifié a échoué : mauvaise clé ou phrase, message modifié. */
    Dechiffrement("déchiffrement impossible (clé, phrase ou message altéré)"),
    /** Le remplissage (§3.3) est absent ou malformé. */
    Remplissage("remplissage invalide"),
    /** Le texte déchiffré n'est pas de l'UTF-8. */
    Utf8("texte non UTF-8"),
    /** Une signature Ed25519 est fausse. */
    Signature("signature invalide"),
    /** Une clé publique est invalide (X25519 de petit ordre, ML-KEM mal formée, Ed25519 faible…). */
    CleInvalide("clé publique invalide"),
    /** Le paquet ne propose pas de clé ML-KEM alors qu'elle est demandée. */
    PqIndisponible("pas de clé post-quantique dans le paquet"),
    /** La clé pré-signée (ou ML-KEM) désignée par le message n'existe pas ou plus sur cet appareil. */
    CleInconnue("clé pré-signée inconnue ou expirée"),
    /** Le message n'appartient pas à cette session (identifiant différent). */
    SessionInconnue("message d'une autre session"),
    /**
     * Un premier message (type 0x01) avec une autre clé éphémère pour le même
     * identifiant : c'est une nouvelle session, à accepter par [Device.accept].
     */
    NouvelleSession("premier message d'une nouvelle session"),
    /** Un message déjà lu (rejeu) : à ignorer. */
    Rejoue("message déjà lu (rejeu ignoré)"),
    /** Le message demanderait de sauter plus de [Protocole.MAX_SKIP] clés. */
    TropDeClesSautees("trop de messages sautés"),
    /** Ce message de groupe vient d'un expéditeur (ou d'un groupe) dont on n'a pas la chaîne. */
    ExpediteurInconnu("expéditeur ou groupe inconnu"),
    /** L'état sérialisé (JSON) est invalide, ou l'opération est impossible dans l'état courant. */
    Etat("état invalide"),
    /** Un compteur est arrivé au bout (2³² messages sur une chaîne). */
    Epuise("compteur épuisé"),
}

/** L'exception levée par toutes les opérations du protocole. */
class BrocolisException(val erreur: Erreur) : Exception(erreur.message)

internal fun echec(e: Erreur): Nothing = throw BrocolisException(e)

/** Les constantes du protocole (`brocolis_proto::{JOUR, MAX_SKIP, MAX_SKIP_AGE}`). */
object Protocole {
    /** Un jour, en secondes. L'heure est un nombre de secondes depuis l'époque Unix, fourni par l'appelant. */
    const val JOUR: Long = 24L * 60 * 60

    /**
     * Le nombre maximal de clés sautées gardées par session (ou par chaîne de
     * groupe), et le plus grand saut accepté en un message (§4.3).
     */
    const val MAX_SKIP: Long = 1_000

    /** L'âge maximal d'une clé sautée : 30 jours (§4.3). */
    const val MAX_SKIP_AGE: Long = 30 * JOUR
}
