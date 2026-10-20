package rs.brocolis.messagerie.proto

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.security.MessageDigest

/**
 * Les petits outils sur les octets : base64 **strict** (comme le `STANDARD`
 * de la crate `base64` : alphabet standard, `=` obligatoires, bits de
 * remplissage nuls), hexadécimal, entiers gros-boutistes, UTF-8 strict,
 * comparaison en temps constant, effacement.
 */
object Octets {
    private val encoder = java.util.Base64.getEncoder()
    private val decoder = java.util.Base64.getDecoder()

    /** Base64 standard, avec `=`. */
    fun b64(data: ByteArray): String = encoder.encodeToString(data)

    /**
     * Décode du base64 standard **canonique** (refuse les `=` manquants, les
     * espaces, les bits de fin non nuls), ou `null`.
     */
    fun unb64(text: String): ByteArray? {
        val out = try {
            decoder.decode(text)
        } catch (_: IllegalArgumentException) {
            return null
        }
        // java.util.Base64 tolère l'absence de `=` et des bits de fin non
        // nuls : n'est accepté que ce qui se réécrit à l'identique.
        if (encoder.encodeToString(out) != text) {
            wipe(out)
            return null
        }
        return out
    }

    /** Comme [unb64], ou [Erreur.Base64]. */
    fun unb64OrThrow(text: String): ByteArray = unb64(text) ?: echec(Erreur.Base64)

    /** Hexadécimal minuscule. */
    fun hex(data: ByteArray): String {
        val digits = "0123456789abcdef"
        val sb = StringBuilder(data.size * 2)
        for (b in data) {
            sb.append(digits[(b.toInt() shr 4) and 0x0f])
            sb.append(digits[b.toInt() and 0x0f])
        }
        return sb.toString()
    }

    /** L'inverse de [hex] (longueur paire, chiffres hexadécimaux), ou une exception. */
    fun unhex(text: String): ByteArray {
        require(text.length % 2 == 0) { "longueur impaire" }
        return ByteArray(text.length / 2) { i ->
            text.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        }
    }

    /** Un u32 (0 ≤ v < 2³²) en 4 octets gros-boutistes. */
    fun u32be(v: Long): ByteArray = byteArrayOf(
        (v ushr 24).toByte(), (v ushr 16).toByte(), (v ushr 8).toByte(), v.toByte(),
    )

    /** Le u32 gros-boutiste à la position `off`. */
    fun readU32(data: ByteArray, off: Int): Long =
        ((data[off].toLong() and 0xff) shl 24) or
            ((data[off + 1].toLong() and 0xff) shl 16) or
            ((data[off + 2].toLong() and 0xff) shl 8) or
            (data[off + 3].toLong() and 0xff)

    /** Un u64 en 8 octets gros-boutistes. */
    fun u64be(v: Long): ByteArray = ByteArray(8) { i -> (v ushr (56 - 8 * i)).toByte() }

    /** Concatène des tableaux. */
    fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var off = 0
        for (p in parts) {
            System.arraycopy(p, 0, out, off, p.size)
            off += p.size
        }
        return out
    }

    /** Égalité en temps constant (la longueur, elle, n'est pas secrète). */
    fun ctEq(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /** Vrai si tous les octets sont nuls, en temps constant. */
    fun isZero(a: ByteArray): Boolean {
        var acc = 0
        for (b in a) acc = acc or b.toInt()
        return acc == 0
    }

    /** Efface un secret (au mieux : la JVM a pu en faire des copies). */
    fun wipe(vararg arrays: ByteArray?) {
        for (a in arrays) a?.fill(0)
    }

    /** Le texte en UTF-8. */
    fun utf8(text: String): ByteArray = text.toByteArray(Charsets.UTF_8)

    /** Décode de l'UTF-8 **strict** (comme `String::from_utf8`), ou [Erreur.Utf8]. */
    fun fromUtf8(data: ByteArray): String = try {
        Charsets.UTF_8.newDecoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .decode(ByteBuffer.wrap(data))
            .toString()
    } catch (_: CharacterCodingException) {
        echec(Erreur.Utf8)
    }

    /** La longueur UTF-8 d'un texte (le `str::len` de Rust), sans l'encoder. */
    fun utf8Len(text: String): Long {
        var n = 0L
        var i = 0
        while (i < text.length) {
            val c = text[i]
            n += when {
                c.code < 0x80 -> 1
                c.code < 0x800 -> 2
                Character.isHighSurrogate(c) && i + 1 < text.length && Character.isLowSurrogate(text[i + 1]) -> {
                    i++
                    4
                }
                else -> 3
            }
            i++
        }
        return n
    }

    /** `a + b` sans dépasser `Long.MAX_VALUE` (le `saturating_add` de Rust). */
    fun satAdd(a: Long, b: Long): Long = if (a > Long.MAX_VALUE - b) Long.MAX_VALUE else a + b

    /**
     * `char::is_whitespace` de Rust : la propriété Unicode White_Space (ni
     * `Character.isWhitespace`, qui omet les espaces insécables et ajoute
     * U+001C–U+001F, ni `Char.isWhitespace` de Kotlin).
     */
    fun isRustWhitespace(cp: Int): Boolean = when (cp) {
        in 0x09..0x0D, 0x20, 0x85, 0xA0, 0x1680, in 0x2000..0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000 -> true
        else -> false
    }

    /** `str::trim` de Rust. */
    fun rustTrim(text: String): String {
        var start = 0
        var end = text.length
        while (start < end) {
            val cp = text.codePointAt(start)
            if (!isRustWhitespace(cp)) break
            start += Character.charCount(cp)
        }
        while (end > start) {
            val cp = text.codePointBefore(end)
            if (!isRustWhitespace(cp)) break
            end -= Character.charCount(cp)
        }
        return text.substring(start, end)
    }

    /** Le plus grand u32. */
    const val U32_MAX: Long = 0xFFFF_FFFFL
}

internal fun ByteArray.sub(from: Int, to: Int): ByteArray = copyOfRange(from, to)
