package com.signalwall.app

import android.content.Context
import com.signalwall.core.audit.AccessLog
import java.util.concurrent.atomic.AtomicLong

/** Process-wide state shared by the VPN service and the UI (same process). */
object WallState {
    val log = AccessLog(capacity = 2000)
    val allowedQueries = AtomicLong()

    @Volatile var running = false
        private set
    @Volatile var message: String? = null
        private set

    fun started(note: String?) { running = true; message = note }
    fun stopped(reason: String?) { running = false; message = reason }
}

/** The apps the user chose to put behind the wall. */
object AppSelection {
    private const val PREFS = "selection"
    private const val KEY = "packages"

    fun load(ctx: Context): Set<String> =
        // getStringSet's result must not be modified, so copy it.
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getStringSet(KEY, emptySet()).orEmpty().toSet()

    fun save(ctx: Context, packages: Set<String>) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putStringSet(KEY, packages.toSet()).apply()
    }
}
