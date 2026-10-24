package com.signalwall.core.dns

/** The single question of a standard DNS query, plus what is needed to answer it. */
class DnsQuery(
    val id: Int,
    val flags: Int,
    /** Lower-case, no trailing dot. */
    val name: String,
    val qtype: Int,
    val qclass: Int,
    /** The raw question section, copied verbatim into any reply. */
    val question: ByteArray,
)

/**
 * Minimal DNS for a blocking resolver: parse one query, answer it as blocked or failed.
 * Allowed queries are forwarded upstream byte-for-byte, so no general response parser is needed.
 */
object Dns {
    const val TYPE_A = 1
    const val TYPE_AAAA = 28
    const val CLASS_IN = 1
    const val RCODE_SERVFAIL = 2
    private const val HEADER = 12
    private const val MAX_NAME = 253
    private const val MAX_LABEL = 63
    private const val MAX_POINTER_HOPS = 16
    private const val BLOCKED_TTL = 60

    /** Null for anything that is not a well-formed single-question standard query. */
    fun parseQuery(msg: ByteArray): DnsQuery? {
        if (msg.size < HEADER + 5) return null
        val flags = u16(msg, 2)
        val isResponse = flags and 0x8000 != 0
        val opcode = (flags ushr 11) and 0xF
        if (isResponse || opcode != 0 || u16(msg, 4) != 1) return null
        val (name, end) = readName(msg, HEADER) ?: return null
        if (end + 4 > msg.size) return null
        return DnsQuery(
            id = u16(msg, 0),
            flags = flags,
            name = name,
            qtype = u16(msg, end),
            qclass = u16(msg, end + 2),
            question = msg.copyOfRange(HEADER, end + 4),
        )
    }

    /** The response ID of an upstream answer, or null if the bytes cannot be a DNS response. */
    fun responseId(msg: ByteArray, len: Int = msg.size): Int? =
        if (len < HEADER || u16(msg, 2) and 0x8000 == 0) null else u16(msg, 0)

    /**
     * Answers a blocked name the way most DNS blockers do: A → 0.0.0.0, AAAA → ::, so the
     * app's connection fails at once instead of retrying a "domain does not exist". Other
     * record types get an empty NOERROR answer.
     */
    fun blockedResponse(q: DnsQuery): ByteArray {
        val rdata = when {
            q.qclass != CLASS_IN -> null
            q.qtype == TYPE_A -> ByteArray(4)
            q.qtype == TYPE_AAAA -> ByteArray(16)
            else -> null
        }
        val answer = if (rdata == null) ByteArray(0) else ByteArray(12 + rdata.size).also {
            put16(it, 0, 0xC000 or HEADER) // name: pointer to the question
            put16(it, 2, q.qtype)
            put16(it, 4, CLASS_IN)
            put16(it, 6, BLOCKED_TTL ushr 16)
            put16(it, 8, BLOCKED_TTL and 0xFFFF)
            put16(it, 10, rdata.size)
            rdata.copyInto(it, 12)
        }
        return response(q, rcode = 0, answers = if (rdata == null) 0 else 1, answer = answer)
    }

    fun servFail(q: DnsQuery): ByteArray = response(q, RCODE_SERVFAIL, 0, ByteArray(0))

    /** Header and question with TC set: the upstream answer was too large to relay over the tun. */
    fun truncated(q: DnsQuery): ByteArray =
        response(q, 0, 0, ByteArray(0)).also { it[2] = (it[2].toInt() or 0x02).toByte() }

    private fun response(q: DnsQuery, rcode: Int, answers: Int, answer: ByteArray): ByteArray {
        val out = ByteArray(HEADER + q.question.size + answer.size)
        put16(out, 0, q.id)
        // QR=1, same opcode, RD copied, RA=1.
        put16(out, 2, 0x8000 or (q.flags and 0x7800) or (q.flags and 0x0100) or 0x0080 or (rcode and 0xF))
        put16(out, 4, 1)
        put16(out, 6, answers)
        q.question.copyInto(out, HEADER)
        answer.copyInto(out, HEADER + q.question.size)
        return out
    }

    /** Returns the name and the offset just after it in the original (unpointered) position. */
    private fun readName(msg: ByteArray, start: Int): Pair<String, Int>? {
        val sb = StringBuilder()
        var pos = start
        var end = -1
        var hops = 0
        while (true) {
            if (pos >= msg.size) return null
            val len = msg[pos].toInt() and 0xFF
            when {
                len == 0 -> {
                    if (end < 0) end = pos + 1
                    break
                }
                len and 0xC0 == 0xC0 -> {
                    if (pos + 1 >= msg.size || ++hops > MAX_POINTER_HOPS) return null
                    if (end < 0) end = pos + 2
                    val target = ((len and 0x3F) shl 8) or (msg[pos + 1].toInt() and 0xFF)
                    if (target >= pos) return null // pointers must go backwards; blocks loops
                    pos = target
                }
                len and 0xC0 != 0 || len > MAX_LABEL -> return null
                else -> {
                    if (pos + 1 + len > msg.size) return null
                    if (sb.isNotEmpty()) sb.append('.')
                    for (i in pos + 1..pos + len) {
                        val c = (msg[i].toInt() and 0xFF).toChar()
                        // Hostname characters only: anything else cannot match a rule and is suspicious.
                        if (!(c.isLetterOrDigit() && c.code < 128) && c != '-' && c != '_') return null
                        sb.append(c.lowercaseChar())
                    }
                    if (sb.length > MAX_NAME) return null
                    pos += 1 + len
                }
            }
        }
        if (sb.isEmpty()) return null
        return sb.toString() to end
    }

    private fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    private fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }
}
