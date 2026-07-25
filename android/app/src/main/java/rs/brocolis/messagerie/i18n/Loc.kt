package rs.brocolis.messagerie.i18n

import java.util.Locale

/**
 * Localisation par CODE, adaptée à la langue du téléphone, avec REPLI ANGLAIS.
 * Français et espagnol sont traduits ; toute autre langue retombe sur l'anglais.
 * Équivalent exact du `loc(fr, en, es)` de l'app iOS (Shared/BrocolisKeyStore.swift).
 *
 *   Text(loc("Bonjour", "Hello", "Hola"))
 */
fun loc(fr: String, en: String, es: String): String =
    when (Locale.getDefault().language.lowercase()) {
        "fr" -> fr
        "es" -> es
        else -> en
    }
