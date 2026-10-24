package com.signalwall.core.audit

import com.signalwall.core.policy.Action
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

class AccessEvent(
    val timeMillis: Long,
    /** Null when the query could not be tied to one protected app. */
    val packageName: String?,
    val domain: String,
    val qtype: Int,
    val action: Action,
    val reason: String,
)

/**
 * Fixed-size, thread-safe ring of recent decisions. It is the evidence trail: exported as
 * JSON Lines, it shows which tracker each app tried to reach and what the wall did.
 */
class AccessLog(private val capacity: Int = 2000) {
    init { require(capacity > 0) { "capacity must be positive" } }

    private val ring = ArrayDeque<AccessEvent>(capacity)

    @Synchronized
    fun record(e: AccessEvent) {
        if (ring.size == capacity) ring.removeFirst()
        ring.addLast(e)
    }

    /** Oldest first. */
    @Synchronized
    fun snapshot(): List<AccessEvent> = ring.toList()

    @Synchronized
    fun clear() = ring.clear()

    fun toJsonLines(events: List<AccessEvent> = snapshot()): String = buildString {
        for (e in events) {
            append(buildJsonObject {
                put("t", JsonPrimitive(e.timeMillis))
                put("app", e.packageName?.let(::JsonPrimitive) ?: JsonNull)
                put("domain", JsonPrimitive(e.domain))
                put("qtype", JsonPrimitive(e.qtype))
                put("action", JsonPrimitive(e.action.name))
                put("reason", JsonPrimitive(e.reason))
            }.toString())
            append('\n')
        }
    }
}
