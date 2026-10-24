package com.signalwall.core.scan

import com.signalwall.core.tracker.DeviceSignal
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class ApkScannerTest {
    @get:Rule val tmp = TemporaryFolder()

    @Test fun readsDexStringTable() {
        val strings = listOf("Lcom/appsflyer/AppsFlyerLib;", "android.intent.action.BATTERY_CHANGED", "hello")
        assertEquals(strings.toSet(), DexStrings.read(dex(strings)))
    }

    @Test fun rejectsNonDexAndCorruptTables() {
        assertNull(DexStrings.read(ByteArray(0x70)))
        val d = dex(listOf("a"))
        assertNull("string offset out of range", DexStrings.read(d.copyOf().also { putU32(it, 0x70, 0x7FFF_0000) }))
        assertNull("count larger than file", DexStrings.read(d.copyOf().also { putU32(it, 0x38, 1_000_000) }))
        assertNull("unterminated string", DexStrings.read(d.copyOf(d.size - 1)))
    }

    @Test fun findsTrackersAndSignalsAcrossSplitApks() {
        val base = apk("base.apk", "classes.dex" to dex(listOf("Lcom/appsflyer/AppsFlyerLib;", "Lcom/example/Main;")))
        val split = apk("split.apk",
            "classes2.dex" to dex(listOf("Lcom/lexisnexisrisk/threatmetrix/TMXProfiling;", "isPowerSaveMode",
                "android.intent.action.BATTERY_CHANGED")),
            "assets/classes.dex.txt" to dex(listOf("Lcom/adjust/sdk/Adjust;"))) // not a dex entry name
        val r = ApkScanner().scan(listOf(base, split))
        assertEquals(setOf("AppsFlyer", "ThreatMetrix (LexisNexis)"), r.trackers.map { it.name }.toSet())
        assertEquals(setOf(DeviceSignal.BATTERY, DeviceSignal.POWER_SAVE), r.signals)
        assertEquals(2, r.dexFilesScanned)
        assertTrue(r.errors.isEmpty())
    }

    @Test fun prefixMatchNeedsTheWholeSignature() {
        val r = ApkScanner().match(setOf("Lcom/appsflyerx/Foo;", "Lio/brancher/X;"))
        assertTrue(r.trackers.isEmpty())
    }

    @Test fun badFilesBecomeErrorsNotCrashes() {
        val notZip = tmp.newFile("x.apk").apply { writeText("nope") }
        val badDex = apk("bad.apk", "classes.dex" to "not a dex".toByteArray())
        val r = ApkScanner().scan(listOf(notZip, badDex, File(tmp.root, "missing.apk")))
        assertEquals(3, r.errors.size)
        assertEquals(0, r.dexFilesScanned)
    }

    private fun apk(name: String, vararg entries: Pair<String, ByteArray>): File =
        tmp.newFile(name).also { f ->
            ZipOutputStream(f.outputStream()).use { z ->
                for ((n, b) in entries) { z.putNextEntry(ZipEntry(n)); z.write(b); z.closeEntry() }
            }
        }

    /** Minimal dex: header, string_ids at 0x70, string data after. Only what DexStrings reads. */
    private fun dex(strings: List<String>): ByteArray {
        val idsOff = 0x70
        var dataOff = idsOff + 4 * strings.size
        val data = strings.map { s -> byteArrayOf(s.length.toByte()) + s.toByteArray() + 0 }
        val out = ByteArray(dataOff + data.sumOf { it.size })
        "dex\n039\u0000".toByteArray().copyInto(out)
        putU32(out, 0x38, strings.size)
        putU32(out, 0x3C, idsOff)
        data.forEachIndexed { i, d -> putU32(out, idsOff + 4 * i, dataOff); d.copyInto(out, dataOff); dataOff += d.size }
        return out
    }

    private fun putU32(b: ByteArray, i: Int, v: Int) { for (k in 0..3) b[i + k] = (v ushr (8 * k)).toByte() }
}
