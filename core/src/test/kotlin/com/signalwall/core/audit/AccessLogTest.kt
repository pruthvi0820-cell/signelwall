package com.signalwall.core.audit

import com.signalwall.core.policy.Action
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Test

class AccessLogTest {
    @Test fun ringEvictsOldest() {
        val log = AccessLog(capacity = 3)
        (1..5).forEach { log.record(event(it.toLong())) }
        assertEquals(listOf(3L, 4L, 5L), log.snapshot().map { it.timeMillis })
    }

    @Test fun jsonLinesEscapeAndKeepNullApp() {
        val log = AccessLog()
        log.record(event(1, reason = "quote \" and \n newline"))
        log.record(event(2, app = "com.ubercab"))
        val lines = log.toJsonLines().trimEnd().lines()
        assertEquals(2, lines.size)
        val first = Json.parseToJsonElement(lines[0]).jsonObject
        assertEquals(JsonNull, first["app"])
        assertEquals("quote \" and \n newline", first["reason"]!!.jsonPrimitive.content)
        assertEquals("com.ubercab", Json.parseToJsonElement(lines[1]).jsonObject["app"]!!.jsonPrimitive.content)
    }

    private fun event(t: Long, app: String? = null, reason: String = "r") =
        AccessEvent(t, app, "x.example", 1, Action.BLOCK, reason)
}
