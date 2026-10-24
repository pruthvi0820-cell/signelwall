package com.signalwall.app

import android.content.Intent
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import com.signalwall.core.audit.AccessEvent
import com.signalwall.core.dns.Dns
import com.signalwall.core.dns.DnsQuery
import com.signalwall.core.net.IpUdp
import com.signalwall.core.net.UdpPacket
import com.signalwall.core.policy.Action
import com.signalwall.core.policy.SignalPolicy
import java.io.IOException
import java.io.InterruptedIOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit

/**
 * A DNS-only VPN for the chosen apps, the design proven by DNS66 and Blokada: the tun routes
 * nothing but a virtual DNS address, so app traffic itself never passes through this process.
 * Each query is checked against the policy; blocked names get 0.0.0.0, the rest are relayed
 * to the network's own resolver.
 *
 * Bypassed by: apps doing their own DNS-over-HTTPS, Private DNS in strict (hostname) mode,
 * and hard-coded IP addresses. The access log is the check that the wall is actually seeing
 * an app's lookups.
 */
class WallVpnService : VpnService() {
    private val lock = Any()
    private var session: Session? = null
    @Volatile private var upstream: List<InetAddress> = emptyList()
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }

    /** One established tun; a restart builds a new one rather than reusing state. */
    private inner class Session(
        val tun: ParcelFileDescriptor,
        val policy: SignalPolicy,
        val selected: Set<String>,
    ) {
        @Volatile var stopping = false
        val workers = ThreadPoolExecutor(
            WORKERS, WORKERS, 30, TimeUnit.SECONDS, ArrayBlockingQueue(QUEUE),
            ThreadPoolExecutor.AbortPolicy(),
        )
        val reader = Thread({ readLoop(this) }, "signalwall-tun")
        val writeLock = Any()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopWall(intent.getStringExtra(EXTRA_REASON) ?: "Stopped.")
            stopSelf()
            return START_NOT_STICKY
        }
        val error = startWall()
        if (error != null) {
            stopWall(error)
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopWall("Turned off by the system or another VPN.")
        super.onRevoke()
    }

    override fun onDestroy() {
        stopWall(WallState.message)
        super.onDestroy()
    }

    /** Returns a user-facing error, or null when the wall is up. */
    private fun startWall(): String? = synchronized(lock) {
        if (session != null) return null
        val selected = AppSelection.load(this)
        if (selected.isEmpty()) return "Choose at least one app to protect first."
        val loaded = PolicyStore.load(this)

        watchUpstream()
        if (upstream.isEmpty()) return "No DNS server found on the current network. Connect to Wi-Fi or mobile data."

        val builder = Builder()
            .setSession("SignalWall")
            .setMtu(MTU)
            .setBlocking(false) // polled with a timeout so stopping never hangs on a blocked read
            .setMetered(false)
            .addAddress(TUN_ADDR4, 32).addDnsServer(DNS4).addRoute(DNS4, 32)
            .addAddress(TUN_ADDR6, 128).addDnsServer(DNS6).addRoute(DNS6, 128)
        val protectedApps = selected.filterTo(HashSet()) { pkg ->
            try {
                builder.addAllowedApplication(pkg)
                true
            } catch (e: PackageManager.NameNotFoundException) {
                false // uninstalled since it was chosen
            }
        }
        if (protectedApps.isEmpty()) return "None of the chosen apps is installed any more."

        val tun = try {
            builder.establish()
        } catch (e: RuntimeException) { // IllegalStateException / IllegalArgumentException / SecurityException
            return "Could not start the VPN: ${e.message}"
        } ?: return "VPN permission is not granted. Tap Start again to allow it."

        val s = Session(tun, loaded.policy, protectedApps)
        session = s
        s.reader.start()
        val skipped = selected.size - protectedApps.size
        WallState.started(listOfNotNull(
            "Protecting ${protectedApps.size} app(s) with the ${loaded.source} policy.",
            loaded.warning,
            if (skipped > 0) "$skipped chosen app(s) are no longer installed." else null,
        ).joinToString(" "))
        null
    }

    /** [only]: stop only if that session is still the current one (a failing reader stops itself, not its successor). */
    private fun stopWall(reason: String?, only: Session? = null): Unit = synchronized(lock) {
        val s = session
        if (only != null && s !== only) return
        session = null
        if (s != null) {
            // The reader closes the tun itself on its way out, so no thread ever reads a closed fd number.
            s.stopping = true
            s.workers.shutdownNow()
        }
        networkCallback?.let {
            try { cm.unregisterNetworkCallback(it) } catch (_: IllegalArgumentException) {}
        }
        networkCallback = null
        WallState.stopped(reason)
    }

    private fun readLoop(s: Session) {
        val fd = s.tun.fileDescriptor
        val buf = ByteArray(READ_BUFFER)
        val poll = StructPollfd().apply { this.fd = fd; events = OsConstants.POLLIN.toShort() }
        var failure: String? = null
        try {
            while (!s.stopping) {
                poll.revents = 0
                val ready = try {
                    Os.poll(arrayOf(poll), POLL_MS)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EINTR) continue
                    throw e
                }
                if (ready == 0) continue
                if (poll.revents.toInt() and (OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL) != 0) {
                    if (!s.stopping) failure = "The VPN interface closed unexpectedly."
                    break
                }
                val n = try {
                    Os.read(fd, buf, 0, buf.size)
                } catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EAGAIN || e.errno == OsConstants.EINTR) continue
                    throw e
                }
                if (n <= 0) continue
                val pkt = IpUdp.parse(buf, n) ?: continue
                if (pkt.dstPort != 53) continue
                val query = Dns.parseQuery(pkt.payload) ?: continue
                try {
                    s.workers.execute { answer(s, pkt, query) }
                } catch (e: RejectedExecutionException) {
                    // Queue full or shutting down: drop it; the system resolver retries on its own.
                }
            }
        } catch (e: ErrnoException) {
            if (!s.stopping) failure = "VPN read failed: ${e.message}"
        } catch (e: InterruptedIOException) {
            if (!s.stopping) failure = "VPN read interrupted."
        } finally {
            try { s.tun.close() } catch (_: IOException) {}
        }
        if (failure != null) {
            stopWall(failure, only = s)
            stopSelf()
        }
    }

    private fun answer(s: Session, pkt: UdpPacket, q: DnsQuery) {
        val app = attribute(pkt, s.selected)
        val d = s.policy.decide(app, q.name)
        if (d.action != Action.ALLOW || d.tracker != null) {
            WallState.log.record(AccessEvent(System.currentTimeMillis(), app, q.name, q.qtype, d.action, d.reason))
        } else {
            WallState.allowedQueries.incrementAndGet()
        }
        var reply = if (d.action == Action.BLOCK) Dns.blockedResponse(q) else forward(pkt.payload, q.id) ?: Dns.servFail(q)
        val header = if (pkt.ipVersion == 4) 28 else 48
        if (reply.size + header > MTU) reply = Dns.truncated(q)
        write(s, IpUdp.buildReply(pkt, reply))
    }

    private fun write(s: Session, packet: ByteArray) {
        if (s.stopping) return
        try {
            synchronized(s.writeLock) { Os.write(s.tun.fileDescriptor, packet, 0, packet.size) }
        } catch (e: ErrnoException) {
            // EAGAIN (tun queue full) or EBADF (closing): drop; the resolver will retry.
        } catch (e: InterruptedIOException) {
        }
    }

    /**
     * Ties a query to a protected app. On many Android versions the system resolver sends
     * queries under its own uid, so this falls back to "the only protected app" and otherwise
     * to null, which the policy treats with its defaults. Test one app at a time for exact attribution.
     */
    private fun attribute(pkt: UdpPacket, selected: Set<String>): String? {
        val uid = try {
            cm.getConnectionOwnerUid(
                OsConstants.IPPROTO_UDP,
                InetSocketAddress(InetAddress.getByAddress(pkt.srcAddr), pkt.srcPort),
                InetSocketAddress(InetAddress.getByAddress(pkt.dstAddr), pkt.dstPort),
            )
        } catch (e: RuntimeException) { // SecurityException / IllegalArgumentException
            Process.INVALID_UID
        } catch (e: UnknownHostException) {
            Process.INVALID_UID
        }
        if (uid != Process.INVALID_UID) {
            packageManager.getPackagesForUid(uid)?.firstOrNull { it in selected }?.let { return it }
        }
        return selected.singleOrNull()
    }

    /** Relays a query to each upstream in turn; null if none answered with the matching ID. */
    private fun forward(query: ByteArray, id: Int): ByteArray? {
        for (server in upstream) {
            try {
                DatagramSocket().use { socket ->
                    if (!protect(socket)) return@use
                    socket.soTimeout = UPSTREAM_TIMEOUT_MS
                    socket.connect(InetSocketAddress(server, 53)) // accept replies from this server only
                    socket.send(DatagramPacket(query, query.size))
                    val buf = ByteArray(MAX_DNS_RESPONSE)
                    val resp = DatagramPacket(buf, buf.size)
                    socket.receive(resp)
                    if (Dns.responseId(buf, resp.length) == id) return buf.copyOf(resp.length)
                }
            } catch (e: IOException) {
                // Timeout or unreachable: try the next server.
            }
        }
        return null
    }

    /**
     * Tracks the DNS servers of this app's default network. This app is not routed into its
     * own VPN, so that is the real Wi-Fi or mobile network, and it follows network switches.
     */
    private fun watchUpstream() {
        cm.activeNetwork?.let { net -> upstream = usable(cm.getLinkProperties(net)) }
        if (networkCallback != null) return
        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
                val servers = usable(lp)
                if (servers.isNotEmpty()) upstream = servers
            }
        }
        try {
            cm.registerDefaultNetworkCallback(cb)
            networkCallback = cb
        } catch (e: RuntimeException) {
            // Too many callbacks registered (system limit); keep the snapshot taken above.
        }
    }

    private fun usable(lp: LinkProperties?): List<InetAddress> =
        lp?.dnsServers.orEmpty().filter { it.hostAddress != DNS4 && it.hostAddress?.startsWith("fd00:5157") != true }

    companion object {
        const val ACTION_STOP = "com.signalwall.app.STOP"
        const val EXTRA_REASON = "reason"
        private const val MTU = 1500
        private const val READ_BUFFER = 32767
        private const val MAX_DNS_RESPONSE = 4096
        private const val POLL_MS = 1000
        private const val UPSTREAM_TIMEOUT_MS = 4000
        private const val WORKERS = 4
        private const val QUEUE = 256
        // Private ranges reserved for the wall's virtual interface and resolver.
        private const val TUN_ADDR4 = "10.111.222.1"
        private const val DNS4 = "10.111.222.53"
        private const val TUN_ADDR6 = "fd00:5157:57a1::1"
        private const val DNS6 = "fd00:5157:57a1::53"
    }
}
