package rs.brocolis.messagerie.proto

/**
 * Le remplissage (§3.3, §7.2) : la longueur d'un message ne se lit pas sur le
 * jeton. Avant chiffrement : texte ‖ `0x80` ‖ des `0x00` jusqu'au multiple
 * de 160 octets suivant (comme Signal). Au déchiffrement : retirer les
 * `0x00` de fin puis le `0x80` ; absent → refusé.
 */
object Remplissage {
    /** La taille des blocs de remplissage. */
    const val BLOC = 160

    /**
     * `données ‖ 0x80 ‖ 0x00…` jusqu'au multiple de 160 suivant (au moins un
     * octet de remplissage : 159 octets donnent 160, 160 en donnent 320).
     */
    fun pad(data: ByteArray): ByteArray {
        val out = ByteArray((data.size / BLOC + 1) * BLOC)
        System.arraycopy(data, 0, out, 0, data.size)
        out[data.size] = 0x80.toByte()
        return out
    }

    /**
     * Retire le remplissage. Refuse ([Erreur.Remplissage]) une longueur qui
     * n'est pas un multiple non nul de 160 (§7.2) ou l'absence du `0x80`.
     */
    fun unpad(padded: ByteArray): ByteArray {
        if (padded.isEmpty() || padded.size % BLOC != 0) echec(Erreur.Remplissage)
        var end = padded.size - 1
        while (end >= 0 && padded[end].toInt() == 0) end--
        if (end < 0 || padded[end] != 0x80.toByte()) echec(Erreur.Remplissage)
        return padded.copyOfRange(0, end)
    }
}
