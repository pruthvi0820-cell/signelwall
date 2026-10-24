package com.signalwall.core.policy

/**
 * Suffix matching on whole labels: a rule "appsflyer.com" matches "appsflyer.com" and
 * "t.appsflyer.com", never "notappsflyer.com". Lookup costs one hash probe per label.
 */
class DomainMatcher(domains: Iterable<String>) {
    private val rules: Set<String> = domains.map(::normalize).toHashSet()

    val size: Int get() = rules.size

    /** The rule that matched, or null. [name] is expected lower-case without a trailing dot. */
    fun match(name: String): String? {
        var candidate = name
        while (true) {
            if (candidate in rules) return candidate
            val dot = candidate.indexOf('.')
            if (dot < 0) return null
            candidate = candidate.substring(dot + 1)
        }
    }

    companion object {
        private val LABEL = Regex("^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")

        /** Lower-cases, strips one trailing dot, and rejects anything that is not a hostname. */
        fun normalize(raw: String): String {
            val d = raw.trim().lowercase().removeSuffix(".")
            require(d.isNotEmpty() && d.length <= 253) { "not a domain: '$raw'" }
            require(d.split('.').all { LABEL.matches(it) }) { "not a domain: '$raw'" }
            return d
        }
    }
}
