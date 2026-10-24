package com.signalwall.app

import android.content.Context
import com.signalwall.core.policy.PolicyException
import com.signalwall.core.policy.SignalPolicy
import java.io.File
import java.io.IOException

/**
 * Loads the active policy: an imported one if present and valid, else the bundled default,
 * else the built-in one. A broken file never leaves the wall without rules.
 */
object PolicyStore {
    private const val FILE = "policy.json"
    private const val ASSET = "default_policy.json"
    const val MAX_BYTES = 256 * 1024

    class Loaded(val policy: SignalPolicy, val source: String, val warning: String?)

    fun load(ctx: Context): Loaded {
        var warning: String? = null
        val custom = File(ctx.filesDir, FILE)
        if (custom.exists()) {
            try {
                return Loaded(SignalPolicy.parse(custom.readText()), "imported", null)
            } catch (e: PolicyException) {
                warning = "Imported policy ignored: ${e.message}"
            } catch (e: IOException) {
                warning = "Imported policy unreadable: ${e.message}"
            }
        }
        return try {
            val text = ctx.assets.open(ASSET).bufferedReader().use { it.readText() }
            Loaded(SignalPolicy.parse(text), "default", warning)
        } catch (e: Exception) {
            // IOException or PolicyException: a packaging bug, but the wall must still run.
            Loaded(SignalPolicy.DEFAULT, "built-in", listOfNotNull(warning, "Bundled policy unusable: ${e.message}").joinToString("; "))
        }
    }

    /** Validates before saving, then replaces atomically. Returns an error message or null. */
    fun importPolicy(ctx: Context, text: String): String? {
        if (text.length > MAX_BYTES) return "Policy is larger than ${MAX_BYTES / 1024} KB."
        try {
            SignalPolicy.parse(text)
        } catch (e: PolicyException) {
            return e.message
        }
        return try {
            val tmp = File(ctx.filesDir, "$FILE.tmp")
            tmp.writeText(text)
            if (!tmp.renameTo(File(ctx.filesDir, FILE))) "Could not save the policy." else null
        } catch (e: IOException) {
            "Could not save the policy: ${e.message}"
        }
    }

    fun reset(ctx: Context): Boolean = File(ctx.filesDir, FILE).let { !it.exists() || it.delete() }
}
