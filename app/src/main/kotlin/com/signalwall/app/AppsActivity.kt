package com.signalwall.app

import android.app.Activity
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Bundle
import android.widget.ArrayAdapter
import android.widget.ListView
import com.signalwall.core.scan.ApkScanner
import com.signalwall.core.scan.ScanReport
import java.io.File
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * Pick the apps to put behind the wall. Each row shows which tracker SDKs the app ships and
 * which device signals its code can read, scanned on the device from the installed APKs.
 */
class AppsActivity : Activity() {
    private class Row(val pkg: String, val label: String, val info: ApplicationInfo) {
        @Volatile var report: ScanReport? = null
        override fun toString(): String = buildString {
            append(label).append("\n").append(pkg)
            val r = report
            if (r == null) { append("\nscanning…"); return@buildString }
            append("\ntrackers: ").append(r.trackers.joinToString { it.name }.ifEmpty { "none found" })
            append("\nreads: ").append(r.signals.joinToString { it.label }.ifEmpty { "none found" })
            if (r.dexFilesScanned == 0 && r.errors.isNotEmpty()) append("\nscan failed: ").append(r.errors.first())
        }
    }

    private lateinit var list: ListView
    private lateinit var adapter: ArrayAdapter<Row>
    private val rows = mutableListOf<Row>()
    private var scanner: ExecutorService? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "Apps behind the wall"
        list = ListView(this).apply {
            choiceMode = ListView.CHOICE_MODE_MULTIPLE
            fitsSystemWindows = true
        }
        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_multiple_choice, rows)
        list.adapter = adapter
        list.setOnItemClickListener { _, _, _, _ -> saveSelection() }
        setContentView(list)
        loadApps()
    }

    override fun onDestroy() {
        scanner?.shutdownNow()
        super.onDestroy()
    }

    private fun loadApps() {
        val launcher = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
        @Suppress("DEPRECATION") // the flags overload is API 33+
        val found = packageManager.queryIntentActivities(launcher, 0)
            .mapNotNull { it.activityInfo?.applicationInfo }
            .filter { it.packageName != packageName }
            .distinctBy { it.packageName }
            .map { Row(it.packageName, it.loadLabel(packageManager).toString(), it) }
            .sortedBy { it.label.lowercase() }
        rows.clear()
        rows.addAll(found)
        adapter.notifyDataSetChanged()
        val selected = AppSelection.load(this)
        rows.forEachIndexed { i, r -> list.setItemChecked(i, r.pkg in selected) }
        scan()
    }

    private fun scan() {
        val pool = Executors.newSingleThreadExecutor().also { scanner = it }
        val snapshot = rows.toList()
        pool.execute {
            val apkScanner = ApkScanner()
            for (row in snapshot) {
                if (Thread.currentThread().isInterrupted) return@execute
                val apks = listOfNotNull(row.info.sourceDir) + row.info.splitSourceDirs.orEmpty()
                row.report = apkScanner.scan(apks.map(::File))
                runOnUiThread { if (!isDestroyed) adapter.notifyDataSetChanged() }
            }
        }
    }

    private fun saveSelection() {
        val checked = list.checkedItemPositions
        val chosen = rows.indices.filter { checked.get(it) }.map { rows[it].pkg }.toSet()
        AppSelection.save(this, chosen)
        if (WallState.running) {
            startService(
                Intent(this, WallVpnService::class.java)
                    .setAction(WallVpnService.ACTION_STOP)
                    .putExtra(WallVpnService.EXTRA_REASON, "App selection changed. Start the wall again to apply it."),
            )
        }
    }
}
