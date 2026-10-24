package com.signalwall.core.policy

import com.signalwall.core.tracker.TrackerCategory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SignalPolicyTest {
    @Test fun matcherRespectsLabelBoundaries() {
        val m = DomainMatcher(listOf("AppsFlyer.com."))
        assertEquals("appsflyer.com", m.match("appsflyer.com"))
        assertEquals("appsflyer.com", m.match("t.sdk.appsflyer.com"))
        assertNull(m.match("notappsflyer.com"))
        assertNull(m.match("com"))
    }

    @Test fun matcherRejectsNonDomains() {
        for (bad in listOf("", "a..b", "-a.com", "a b.com", "a/b.com", "x".repeat(64) + ".com")) {
            assertThrows(bad, IllegalArgumentException::class.java) { DomainMatcher(listOf(bad)) }
        }
    }

    @Test fun defaultsBlockTrackersLogFingerprintingAllowTheRest() {
        val p = SignalPolicy.DEFAULT
        assertEquals(Action.BLOCK, p.decide(null, "t.appsflyersdk.com").action)
        assertEquals(Action.BLOCK, p.decide("com.ubercab", "app-measurement.com").action)
        assertEquals(Action.LOG, p.decide(null, "h.online-metrix.net").action)
        assertEquals(Action.ALLOW, p.decide(null, "cn-geo1.uber.com").action)
        assertEquals("AppsFlyer", p.decide(null, "appsflyer.com").tracker?.name)
    }

    @Test fun precedenceAppAllowBeatsEverything() {
        val p = SignalPolicy.parse(
            """
            { "version": 1,
              "defaults": { "blockDomains": ["uber.com"], "allowDomains": ["branch.io"] },
              "apps": {
                "com.ubercab": { "allowDomains": ["m.uber.com"], "blockDomains": ["branch.io"],
                                 "categories": { "FINGERPRINTING": "BLOCK" } } } }
            """,
        )
        assertEquals(Action.ALLOW, p.decide("com.ubercab", "m.uber.com").action)
        assertEquals(Action.BLOCK, p.decide("com.ubercab", "x.uber.com").action)
        assertEquals("app block beats default allow", Action.BLOCK, p.decide("com.ubercab", "api2.branch.io").action)
        assertEquals(Action.ALLOW, p.decide("in.swiggy.android", "api2.branch.io").action)
        assertEquals(Action.BLOCK, p.decide("com.ubercab", "h.online-metrix.net").action)
        assertEquals("other apps inherit defaults", Action.LOG, p.decide("in.swiggy.android", "h.online-metrix.net").action)
        assertEquals("unattributed queries use defaults", Action.LOG, p.decide(null, "h.online-metrix.net").action)
    }

    @Test fun defaultsSectionKeepsBuiltInCategoriesItDoesNotName() {
        val p = SignalPolicy.parse("""{ "version": 1, "defaults": { "categories": { "ANALYTICS": "LOG" } } }""")
        assertEquals(Action.LOG, p.defaults.categories[TrackerCategory.ANALYTICS])
        assertEquals(Action.BLOCK, p.defaults.categories[TrackerCategory.ATTRIBUTION])
    }

    @Test fun malformedPoliciesFailLoudly() {
        val cases = mapOf(
            "not json" to "{",
            "wrong version" to """{ "version": 2 }""",
            "missing version" to "{}",
            "typo key" to """{ "version": 1, "defaults": { "blockDomain": [] } }""",
            "bad action" to """{ "version": 1, "defaults": { "categories": { "ANALYTICS": "MAYBE" } } }""",
            "bad category" to """{ "version": 1, "defaults": { "categories": { "ADS": "BLOCK" } } }""",
            "bad domain" to """{ "version": 1, "defaults": { "blockDomains": ["not a domain"] } }""",
            "non-string domain" to """{ "version": 1, "defaults": { "blockDomains": [3] } }""",
            "bad package" to """{ "version": 1, "apps": { "uber": {} } }""",
            "array root" to "[]",
        )
        for ((label, json) in cases) {
            val e = assertThrows(label, PolicyException::class.java) { SignalPolicy.parse(json) }
            assertTrue(label, e.message!!.isNotBlank())
        }
    }
}
