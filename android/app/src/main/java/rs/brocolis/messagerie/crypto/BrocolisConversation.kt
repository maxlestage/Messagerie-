package rs.brocolis.messagerie.crypto

/**
 * Rendu « à la volée » d'une conversation entière collée : chaque ligne est
 * rendue en clair, DÉCHIFFRÉE (🔓) si une de tes clés l'ouvre, ou LAISSÉE
 * CHIFFRÉE (🔒) si aucune clé ne convient. Port de Shared/BrocolisConversation.swift.
 */
object BrocolisConversation {

    enum class Status { CLEAR, DECRYPTED, LOCKED, MIXED }

    data class Line(val id: Int, val display: String, val raw: String, val status: Status)

    data class Rendered(
        val lines: List<Line>,
        val decryptedCount: Int,
        val lockedCount: Int
    ) {
        val fullText: String get() = lines.joinToString("\n") { it.display }
    }

    fun render(input: String, keys: List<ByteArray>): Rendered {
        val lines = ArrayList<Line>()
        var totalDecrypted = 0
        var totalLocked = 0

        // Conserve les lignes vides (split sans les omettre).
        val rawLines = input.split("\n")
        for ((index, raw) in rawLines.withIndex()) {
            val r = renderLine(raw, keys)
            totalDecrypted += r.decrypted
            totalLocked += r.locked
            lines.add(Line(index, r.display, raw, r.status))
        }
        return Rendered(lines, totalDecrypted, totalLocked)
    }

    data class LineResult(val display: String, val status: Status, val decrypted: Int, val locked: Int)

    fun renderLine(raw: String, keys: List<ByteArray>): LineResult {
        if (!BrocolisCrypto.containsToken(raw)) {
            return LineResult(raw, Status.CLEAR, 0, 0)
        }
        val totalTokens = BrocolisCrypto.countTokens(raw)
        val (display, opened) = BrocolisCrypto.decryptTokens(raw, keys)
        val locked = maxOf(0, totalTokens - opened)
        val status = when {
            opened == 0 -> Status.LOCKED
            locked == 0 -> Status.DECRYPTED
            else -> Status.MIXED
        }
        return LineResult(display, status, opened, locked)
    }
}
