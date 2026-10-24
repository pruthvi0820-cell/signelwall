package com.signalwall.app

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.ViewGroup.LayoutParams.MATCH_PARENT
import android.view.ViewGroup.LayoutParams.WRAP_CONTENT
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import java.io.IOException
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.Executors

/** Start/stop the wall, see what it caught, export the evidence, import a policy. */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var toggle: Button
    private lateinit var logView: TextView
    private val io = Executors.newSingleThreadExecutor()
    private val ui = Handler(Looper.getMainLooper())
    private val ticker = object : Runnable {
        override fun run() { refresh(); ui.postDelayed(this, REFRESH_MS) }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val column = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        status = TextView(this).apply { textSize = 16f }
        toggle = button("") { onToggle() }
        logView = TextView(this).apply { typeface = Typeface.MONOSPACE; textSize = 12f; setTextIsSelectable(true) }

        column.addView(status)
        column.addView(toggle)
        column.addView(button("Choose apps and scan trackers") { startActivity(Intent(this, AppsActivity::class.java)) })
        column.addView(button("Export evidence log (JSON Lines)") { exportLog() })
        column.addView(button("Import policy (JSON)") { pickPolicy() })
        column.addView(ScrollView(this).apply { addView(logView) }, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))

        // fitsSystemWindows keeps content clear of the status and navigation bars under edge-to-edge.
        setContentView(FrameLayout(this).apply {
            fitsSystemWindows = true
            addView(column, FrameLayout.LayoutParams(MATCH_PARENT, MATCH_PARENT))
        })
    }

    override fun onResume() { super.onResume(); ui.post(ticker) }
    override fun onPause() { ui.removeCallbacks(ticker); super.onPause() }
    override fun onDestroy() { io.shutdown(); super.onDestroy() }

    private fun button(label: String, onClick: () -> Unit) = Button(this).apply {
        text = label
        layoutParams = LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT)
        setOnClickListener { onClick() }
    }

    private fun onToggle() {
        if (WallState.running) {
            startService(Intent(this, WallVpnService::class.java).setAction(WallVpnService.ACTION_STOP))
            return
        }
        if (AppSelection.load(this).isEmpty()) {
            toast("Choose at least one app first.")
            startActivity(Intent(this, AppsActivity::class.java))
            return
        }
        val consent = VpnService.prepare(this)
        if (consent != null) startActivityForResult(consent, REQ_VPN) else startWall()
    }

    private fun startWall() { startService(Intent(this, WallVpnService::class.java)) }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        when {
            requestCode == REQ_VPN && resultCode == RESULT_OK -> startWall()
            requestCode == REQ_VPN -> toast("SignalWall needs the VPN permission to filter DNS.")
            resultCode != RESULT_OK || uri == null -> Unit
            requestCode == REQ_EXPORT -> writeLog(uri)
            requestCode == REQ_IMPORT -> readPolicy(uri)
        }
    }

    private fun exportLog() {
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date())
        @Suppress("DEPRECATION")
        startActivityForResult(
            Intent(Intent.ACTION_CREATE_DOCUMENT)
                .addCategory(Intent.CATEGORY_OPENABLE)
                .setType("application/json")
                .putExtra(Intent.EXTRA_TITLE, "signalwall-$stamp.jsonl"),
            REQ_EXPORT,
        )
    }

    private fun writeLog(uri: Uri) = io.execute {
        val text = WallState.log.toJsonLines()
        val msg = try {
            contentResolver.openOutputStream(uri)?.use { it.write(text.toByteArray()) } ?: throw IOException("no stream")
            "Exported ${WallState.log.snapshot().size} events."
        } catch (e: IOException) {
            "Export failed: ${e.message}"
        } catch (e: SecurityException) {
            "Export failed: no access to that location."
        }
        runOnUiThread { toast(msg) }
    }

    private fun pickPolicy() {
        @Suppress("DEPRECATION")
        startActivityForResult(
            Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"),
            REQ_IMPORT,
        )
    }

    private fun readPolicy(uri: Uri) = io.execute {
        val msg = try {
            val bytes = contentResolver.openInputStream(uri)?.use { it.readNBytesCompat(PolicyStore.MAX_BYTES + 1) }
                ?: throw IOException("no stream")
            PolicyStore.importPolicy(this, String(bytes))
                ?.let { "Policy rejected: $it" }
                ?: "Policy imported. Restart the wall to apply it."
        } catch (e: IOException) {
            "Import failed: ${e.message}"
        } catch (e: SecurityException) {
            "Import failed: no access to that file."
        }
        runOnUiThread { toast(msg) }
    }

    private fun refresh() {
        toggle.text = if (WallState.running) "Stop wall" else "Start wall"
        status.text = buildString {
            append(if (WallState.running) "Wall is ON" else "Wall is OFF")
            WallState.message?.let { append("\n").append(it) }
            append("\nAllowed lookups: ").append(WallState.allowedQueries.get())
        }
        val fmt = SimpleDateFormat("HH:mm:ss", Locale.US)
        val events = WallState.log.snapshot().takeLast(SHOWN_EVENTS).asReversed()
        logView.text = if (events.isEmpty()) "No tracker lookups yet." else events.joinToString("\n") { e ->
            "${fmt.format(Date(e.timeMillis))} ${e.action.name.padEnd(5)} ${e.packageName ?: "(app?)"}\n  ${e.domain} · ${e.reason}"
        }
    }

    private fun toast(msg: String) = Toast.makeText(this, msg, Toast.LENGTH_LONG).show()

    /** InputStream.readNBytes is API 33+; read at most [limit] bytes on any version. */
    private fun java.io.InputStream.readNBytesCompat(limit: Int): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        val buf = ByteArray(8192)
        while (out.size() < limit) {
            val n = read(buf, 0, minOf(buf.size, limit - out.size()))
            if (n < 0) break
            out.write(buf, 0, n)
        }
        return out.toByteArray()
    }

    companion object {
        private const val REQ_VPN = 1
        private const val REQ_EXPORT = 2
        private const val REQ_IMPORT = 3
        private const val REFRESH_MS = 2000L
        private const val SHOWN_EVENTS = 100
    }
}
