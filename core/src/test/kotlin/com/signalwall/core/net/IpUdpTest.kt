package com.signalwall.core.net

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class IpUdpTest {
    private val v4a = byteArrayOf(10, 111, 222.toByte(), 1)
    private val v4b = byteArrayOf(10, 111, 222.toByte(), 53)
    private val v6a = ByteArray(16) { if (it == 15) 1 else 0xFD.toByte() }
    private val v6b = ByteArray(16) { if (it == 15) 0x53 else 0xFD.toByte() }
    private val payload = "hello dns".toByteArray()

    @Test fun ipv4RoundTripWithValidChecksums() {
        val pkt = IpUdp.build(4, v4a, v4b, 40000, 53, payload)
        val p = IpUdp.parse(pkt)!!
        assertEquals(4, p.ipVersion)
        assertArrayEquals(v4a, p.srcAddr)
        assertArrayEquals(v4b, p.dstAddr)
        assertEquals(40000, p.srcPort)
        assertEquals(53, p.dstPort)
        assertArrayEquals(payload, p.payload)
        assertTrue(IpUdp.udpChecksumValid(pkt))
        assertEquals("IPv4 header checksum", 0xFFFF, onesSum(pkt, 0, 20))
    }

    @Test fun ipv6RoundTripWithValidChecksum() {
        val pkt = IpUdp.build(6, v6a, v6b, 5353, 53, payload)
        val p = IpUdp.parse(pkt)!!
        assertEquals(6, p.ipVersion)
        assertArrayEquals(payload, p.payload)
        assertTrue(IpUdp.udpChecksumValid(pkt))
    }

    @Test fun replySwapsEndpoints() {
        val req = IpUdp.parse(IpUdp.build(4, v4a, v4b, 40000, 53, payload))!!
        val reply = IpUdp.parse(IpUdp.buildReply(req, byteArrayOf(1, 2, 3)))!!
        assertArrayEquals(v4b, reply.srcAddr)
        assertArrayEquals(v4a, reply.dstAddr)
        assertEquals(53, reply.srcPort)
        assertEquals(40000, reply.dstPort)
    }

    @Test fun trailingBytesBeyondTotalLengthAreIgnored() {
        val pkt = IpUdp.build(4, v4a, v4b, 1, 53, payload) + ByteArray(10)
        assertArrayEquals(payload, IpUdp.parse(pkt)!!.payload)
    }

    @Test fun rejectsNonUdpFragmentsAndTruncation() {
        val pkt = IpUdp.build(4, v4a, v4b, 1, 53, payload)
        assertNull("TCP", IpUdp.parse(pkt.copyOf().also { it[9] = 6 }))
        assertNull("more-fragments", IpUdp.parse(pkt.copyOf().also { it[6] = 0x20 }))
        assertNull("fragment offset", IpUdp.parse(pkt.copyOf().also { it[7] = 1 }))
        assertNull("truncated", IpUdp.parse(pkt, pkt.size - 1))
        assertNull("udp length past end", IpUdp.parse(pkt.copyOf().also { IpUdp.put16(it, 24, 500) }))
        assertNull("bad version", IpUdp.parse(pkt.copyOf().also { it[0] = 0x55 }))
        assertNull("len > buffer", IpUdp.parse(pkt, pkt.size + 1))
    }

    @Test fun randomBytesNeverThrow() {
        val rnd = Random(7)
        repeat(20_000) {
            val b = ByteArray(rnd.nextInt(0, 80)).also(rnd::nextBytes)
            if (b.isNotEmpty()) b[0] = (if (rnd.nextBoolean()) 0x45 else 0x60).toByte()
            IpUdp.parse(b)
        }
    }

    private fun onesSum(b: ByteArray, off: Int, len: Int): Int {
        var s = 0L
        for (i in off until off + len step 2) s += IpUdp.u16(b, i)
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return s.toInt()
    }
}
