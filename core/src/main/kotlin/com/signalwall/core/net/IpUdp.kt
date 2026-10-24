package com.signalwall.core.net

/** One UDP datagram lifted out of a raw IPv4 or IPv6 packet read from the VPN tun device. */
class UdpPacket(
    val ipVersion: Int,
    val srcAddr: ByteArray,
    val dstAddr: ByteArray,
    val srcPort: Int,
    val dstPort: Int,
    val payload: ByteArray,
)

/**
 * Parses and builds the only packets the wall handles: UDP over IPv4/IPv6.
 *
 * Everything read from the tun is untrusted: any malformed, fragmented or non-UDP packet
 * parses to null and is dropped, never thrown on.
 */
object IpUdp {
    const val PROTO_UDP = 17
    private const val IPV4_MIN_HEADER = 20
    private const val IPV6_HEADER = 40
    private const val UDP_HEADER = 8
    private const val TTL = 64

    fun parse(buf: ByteArray, len: Int = buf.size): UdpPacket? {
        if (len < 1 || len > buf.size) return null
        return when (buf[0].toInt() ushr 4) {
            4 -> parseV4(buf, len)
            6 -> parseV6(buf, len)
            else -> null
        }
    }

    private fun parseV4(b: ByteArray, len: Int): UdpPacket? {
        if (len < IPV4_MIN_HEADER) return null
        val ihl = (b[0].toInt() and 0x0F) * 4
        val total = u16(b, 2)
        if (ihl < IPV4_MIN_HEADER || total > len || total < ihl + UDP_HEADER) return null
        if (b[9].toInt() and 0xFF != PROTO_UDP) return null
        val fragment = u16(b, 6)
        if (fragment and 0x2000 != 0 || fragment and 0x1FFF != 0) return null // MF set or non-zero offset
        return parseUdp(4, b.copyOfRange(12, 16), b.copyOfRange(16, 20), b, ihl, total)
    }

    private fun parseV6(b: ByteArray, len: Int): UdpPacket? {
        if (len < IPV6_HEADER + UDP_HEADER) return null
        // Extension headers are not followed: a DNS query from the system resolver never carries one.
        if (b[6].toInt() and 0xFF != PROTO_UDP) return null
        val end = IPV6_HEADER + u16(b, 4)
        if (end > len) return null
        return parseUdp(6, b.copyOfRange(8, 24), b.copyOfRange(24, 40), b, IPV6_HEADER, end)
    }

    private fun parseUdp(version: Int, src: ByteArray, dst: ByteArray, b: ByteArray, off: Int, end: Int): UdpPacket? {
        if (end - off < UDP_HEADER) return null
        val udpLen = u16(b, off + 4)
        if (udpLen < UDP_HEADER || off + udpLen > end) return null
        return UdpPacket(
            ipVersion = version,
            srcAddr = src,
            dstAddr = dst,
            srcPort = u16(b, off),
            dstPort = u16(b, off + 2),
            payload = b.copyOfRange(off + UDP_HEADER, off + udpLen),
        )
    }

    /** A reply to [request]: addresses and ports swapped, carrying [payload], checksums filled in. */
    fun buildReply(request: UdpPacket, payload: ByteArray): ByteArray =
        build(request.ipVersion, request.dstAddr, request.srcAddr, request.dstPort, request.srcPort, payload)

    fun build(version: Int, src: ByteArray, dst: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = UDP_HEADER + payload.size
        require(udpLen <= 0xFFFF) { "UDP payload too large: ${payload.size}" }
        val header = when (version) {
            4 -> { require(src.size == 4 && dst.size == 4) { "IPv4 addresses must be 4 bytes" }; IPV4_MIN_HEADER }
            6 -> { require(src.size == 16 && dst.size == 16) { "IPv6 addresses must be 16 bytes" }; IPV6_HEADER }
            else -> throw IllegalArgumentException("IP version must be 4 or 6, got $version")
        }
        val total = header + udpLen
        require(version == 6 || total <= 0xFFFF) { "IPv4 packet too large: $total" }
        val out = ByteArray(total)
        if (version == 4) {
            out[0] = 0x45
            put16(out, 2, total)
            put16(out, 6, 0x4000) // don't fragment
            out[8] = TTL.toByte()
            out[9] = PROTO_UDP.toByte()
            src.copyInto(out, 12)
            dst.copyInto(out, 16)
            put16(out, 10, checksum(out, 0, IPV4_MIN_HEADER, 0))
        } else {
            out[0] = 0x60
            put16(out, 4, udpLen)
            out[6] = PROTO_UDP.toByte()
            out[7] = TTL.toByte()
            src.copyInto(out, 8)
            dst.copyInto(out, 24)
        }
        put16(out, header, srcPort)
        put16(out, header + 2, dstPort)
        put16(out, header + 4, udpLen)
        payload.copyInto(out, header + UDP_HEADER)
        // The UDP checksum is optional on IPv4 and mandatory on IPv6; fill it in for both.
        val pseudo = sum(src, 0, src.size) + sum(dst, 0, dst.size) + PROTO_UDP + udpLen
        val udpSum = checksum(out, header, udpLen, pseudo)
        put16(out, header + 6, if (udpSum == 0) 0xFFFF else udpSum)
        return out
    }

    /** Verifies the UDP checksum of a packet built or received with [build] semantics. Used by tests. */
    fun udpChecksumValid(packet: ByteArray): Boolean {
        val p = parse(packet) ?: return false
        val header = if (p.ipVersion == 4) (packet[0].toInt() and 0x0F) * 4 else IPV6_HEADER
        val udpLen = UDP_HEADER + p.payload.size
        if (u16(packet, header + 6) == 0) return p.ipVersion == 4 // "no checksum" is only legal on IPv4
        val pseudo = sum(p.srcAddr, 0, p.srcAddr.size) + sum(p.dstAddr, 0, p.dstAddr.size) + PROTO_UDP + udpLen
        return checksum(packet, header, udpLen, pseudo) == 0
    }

    private fun sum(b: ByteArray, off: Int, len: Int): Long {
        var s = 0L
        var i = off
        while (i + 1 < off + len) { s += u16(b, i); i += 2 }
        if (i < off + len) s += (b[i].toInt() and 0xFF) shl 8
        return s
    }

    private fun checksum(b: ByteArray, off: Int, len: Int, initial: Long): Int {
        var s = initial + sum(b, off, len)
        while (s ushr 16 != 0L) s = (s and 0xFFFF) + (s ushr 16)
        return s.inv().toInt() and 0xFFFF
    }

    internal fun u16(b: ByteArray, i: Int): Int = ((b[i].toInt() and 0xFF) shl 8) or (b[i + 1].toInt() and 0xFF)

    internal fun put16(b: ByteArray, i: Int, v: Int) {
        b[i] = (v ushr 8).toByte()
        b[i + 1] = v.toByte()
    }
}
