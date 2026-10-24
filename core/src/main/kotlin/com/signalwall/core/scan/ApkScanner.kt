package com.signalwall.core.scan

import com.signalwall.core.tracker.DeviceSignal
import com.signalwall.core.tracker.Tracker
import com.signalwall.core.tracker.TrackerCatalog
import java.io.File
import java.io.IOException
import java.util.TreeSet
import java.util.zip.ZipException
import java.util.zip.ZipFile

/** What an app's code contains. Capability, not proof of use: see [TrackerCatalog.SIGNAL_STRINGS]. */
class ScanReport(
    val trackers: Set<Tracker>,
    val signals: Set<DeviceSignal>,
    val dexFilesScanned: Int,
    val errors: List<String>,
)

/**
 * Finds tracker SDKs and signal-reading APIs in installed APKs by reading the string table of
 * each classes*.dex, the same idea as Exodus Privacy's scanner, done on the device.
 */
class ApkScanner(private val catalog: List<Tracker> = TrackerCatalog.ALL) {

    /** [apks]: base.apk plus any split APKs of one app. Never throws for a bad file. */
    fun scan(apks: List<File>): ScanReport {
        val strings = HashSet<String>()
        val errors = mutableListOf<String>()
        var dexCount = 0
        for (apk in apks) {
            try {
                ZipFile(apk).use { zip ->
                    for (entry in zip.entries()) {
                        if (!DEX_ENTRY.matches(entry.name)) continue
                        if (entry.size > MAX_DEX_BYTES) { errors += "${apk.name}!${entry.name}: too large, skipped"; continue }
                        val bytes = zip.getInputStream(entry).use { it.readBytes() }
                        val found = DexStrings.read(bytes)
                        if (found == null) errors += "${apk.name}!${entry.name}: not a readable dex"
                        else { strings += found; dexCount++ }
                    }
                }
            } catch (e: ZipException) {
                errors += "${apk.name}: not a zip (${e.message})"
            } catch (e: IOException) {
                errors += "${apk.name}: ${e.message}"
            } catch (e: SecurityException) {
                errors += "${apk.name}: not readable"
            }
        }
        return match(strings, dexCount, errors)
    }

    /** Matches an already-extracted set of dex strings. Separate so it can be tested without APKs. */
    fun match(strings: Set<String>, dexCount: Int = 1, errors: List<String> = emptyList()): ScanReport {
        // Sorted, so a prefix lookup is one ceiling() call instead of a pass over every string.
        val sorted = TreeSet(strings)
        val trackers = catalog.filterTo(LinkedHashSet()) { t ->
            t.codeSignatures.any { sig -> sorted.ceiling(sig)?.startsWith(sig) == true }
        }
        val signals = TrackerCatalog.SIGNAL_STRINGS.filterKeys { it in strings }.values.toSortedSet()
        return ScanReport(trackers, signals, dexCount, errors)
    }

    companion object {
        private val DEX_ENTRY = Regex("^classes\\d*\\.dex$")
        private const val MAX_DEX_BYTES = 64L * 1024 * 1024
    }
}

/** Reads the string_ids table of a dex file. */
object DexStrings {
    private const val HEADER_SIZE = 0x70

    /**
     * Strings are decoded as Latin-1, not MUTF-8: multi-byte MUTF-8 sequences never contain
     * ASCII bytes, so an ASCII signature matches exactly when the real string equals it, and
     * non-ASCII strings can never false-match. Returns null for anything that is not a dex.
     */
    fun read(dex: ByteArray): Set<String>? {
        if (dex.size < HEADER_SIZE) return null
        if (!(dex[0] == 'd'.code.toByte() && dex[1] == 'e'.code.toByte() && dex[2] == 'x'.code.toByte() && dex[3] == '\n'.code.toByte())) return null
        val count = u32(dex, 0x38)
        val idsOff = u32(dex, 0x3C)
        if (count < 0 || idsOff < 0 || count > (dex.size - idsOff) / 4) return null
        val out = HashSet<String>(count * 2)
        for (i in 0 until count) {
            var p = u32(dex, idsOff + i * 4)
            if (p < 0 || p >= dex.size) return null
            // uleb128 utf16 length; skip it, the data is NUL-terminated.
            var guard = 0
            while (p < dex.size && dex[p].toInt() and 0x80 != 0) { p++; if (++guard > 5) return null }
            p++
            val start = p
            while (p < dex.size && dex[p] != 0.toByte()) p++
            if (p >= dex.size) return null
            out += String(dex, start, p - start, Charsets.ISO_8859_1)
        }
        return out
    }

    private fun u32(b: ByteArray, i: Int): Int =
        (b[i].toInt() and 0xFF) or ((b[i + 1].toInt() and 0xFF) shl 8) or
            ((b[i + 2].toInt() and 0xFF) shl 16) or ((b[i + 3].toInt() and 0xFF) shl 24)
}
