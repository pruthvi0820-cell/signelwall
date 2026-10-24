package com.signalwall.core.dns

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import kotlin.random.Random

class DnsTest {
    @Test fun parsesAStandardQuery() {
        val q = Dns.parseQuery(query("T.AppsFlyer.com.", Dns.TYPE_A, id = 0xBEEF))!!
        assertEquals(0xBEEF, q.id)
        assertEquals("t.appsflyer.com", q.name)
        assertEquals(Dns.TYPE_A, q.qtype)
        assertEquals(Dns.CLASS_IN, q.qclass)
    }

    @Test fun blockedAAnswersZeroAddress() {
        val q = Dns.parseQuery(query("ads.example", Dns.TYPE_A, id = 7))!!
        val r = Dns.blockedResponse(q)
        assertEquals(7, u16(r, 0))
        assertEquals("QR, RD, RA set, NOERROR", 0x8180, u16(r, 2))
        assertEquals(1, u16(r, 4))
        assertEquals("one answer", 1, u16(r, 6))
        val ans = 12 + q.question.size
        assertEquals(0xC00C, u16(r, ans))
        assertEquals(Dns.TYPE_A, u16(r, ans + 2))
        assertEquals(4, u16(r, ans + 10))
        assertArrayEquals(ByteArray(4), r.copyOfRange(ans + 12, ans + 16))
        assertEquals(r.size, ans + 16)
        assertEquals("a blocked answer is itself a response", 7, Dns.responseId(r))
    }

    @Test fun blockedAaaaAnswersUnspecifiedAddress() {
        val r = Dns.blockedResponse(Dns.parseQuery(query("ads.example", Dns.TYPE_AAAA))!!)
        assertEquals(16, u16(r, r.size - 18))
        assertArrayEquals(ByteArray(16), r.copyOfRange(r.size - 16, r.size))
    }

    @Test fun otherTypesGetEmptyNoError() {
        val q = Dns.parseQuery(query("ads.example", 65))!! // HTTPS record
        val r = Dns.blockedResponse(q)
        assertEquals(0, u16(r, 6))
        assertEquals(0, u16(r, 2) and 0xF)
        assertEquals(12 + q.question.size, r.size)
    }

    @Test fun servFailCarriesRcode2() {
        val r = Dns.servFail(Dns.parseQuery(query("x.example", Dns.TYPE_A))!!)
        assertEquals(Dns.RCODE_SERVFAIL, u16(r, 2) and 0xF)
    }

    @Test fun truncatedSetsTcAndKeepsQuestion() {
        val q = Dns.parseQuery(query("big.example", Dns.TYPE_A, id = 9))!!
        val r = Dns.truncated(q)
        assertEquals(9, u16(r, 0))
        assertEquals("TC bit", 0x0200, u16(r, 2) and 0x0200)
        assertEquals(0, u16(r, 6))
        assertArrayEquals(q.question, r.copyOfRange(12, r.size))
    }

    @Test fun rejectsResponsesMultiQuestionAndGarbage() {
        val ok = query("x.example", Dns.TYPE_A)
        assertNotNull(Dns.parseQuery(ok))
        assertNull("response bit", Dns.parseQuery(ok.copyOf().also { it[2] = 0x81.toByte() }))
        assertNull("2 questions", Dns.parseQuery(ok.copyOf().also { it[5] = 2 }))
        assertNull("truncated", Dns.parseQuery(ok.copyOf(ok.size - 2)))
        assertNull("bad char", Dns.parseQuery(query("x!y.example", Dns.TYPE_A)))
        assertNull("empty name", Dns.parseQuery(query("", Dns.TYPE_A)))
    }

    @Test fun rejectsPointerLoops() {
        // Question name is a pointer to itself.
        val msg = header() + byteArrayOf(0xC0.toByte(), 12, 0, 1, 0, 1)
        assertNull(Dns.parseQuery(msg))
    }

    @Test fun responseIdNeedsResponseBit() {
        assertNull(Dns.responseId(query("x.example", Dns.TYPE_A)))
        assertNull(Dns.responseId(ByteArray(4)))
    }

    @Test fun randomBytesNeverThrow() {
        val rnd = Random(11)
        repeat(20_000) {
            val b = ByteArray(rnd.nextInt(0, 64)).also(rnd::nextBytes)
            if (b.size > 5) { b[2] = 1; b[3] = 0; b[4] = 0; b[5] = 1 }
            Dns.parseQuery(b)?.let { Dns.blockedResponse(it) }
        }
    }

    private fun header(id: Int = 1) = byteArrayOf((id ushr 8).toByte(), id.toByte(), 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)

    private fun query(name: String, type: Int, id: Int = 1): ByteArray {
        val out = header(id).toMutableList()
        name.removeSuffix(".").split('.').filter { it.isNotEmpty() }.forEach { label ->
            out += label.length.toByte()
            out += label.toByteArray().toList()
        }
        out += 0
        out += listOf((type ushr 8).toByte(), type.toByte(), 0, 1)
        return out.toByteArray()
    }

    private fun u16(b: ByteArray, i: Int) = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)
}
