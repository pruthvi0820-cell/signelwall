package com.signalwall.core.policy

import com.signalwall.core.tracker.Tracker
import com.signalwall.core.tracker.TrackerCatalog
import com.signalwall.core.tracker.TrackerCategory
import kotlinx.serialization.SerializationException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/** LOG lets the request through but records it, for SDKs whose blocking would break the app. */
enum class Action { ALLOW, LOG, BLOCK }

class Decision(val action: Action, val reason: String, val tracker: Tracker? = null)

class PolicyException(message: String) : Exception(message)

/** One app's (or the defaults') rules. A null category action means "inherit from defaults". */
class AppRules(
    val categories: Map<TrackerCategory, Action>,
    val blockDomains: DomainMatcher,
    val allowDomains: DomainMatcher,
)

/**
 * Which network names each protected app may resolve.
 *
 * Precedence, first hit wins: app allow, app block, default allow, default block,
 * tracker category (app override, then default), else ALLOW.
 */
class SignalPolicy(
    val defaults: AppRules,
    val apps: Map<String, AppRules>,
    private val catalog: List<Tracker> = TrackerCatalog.ALL,
) {
    private val trackerByDomain: Map<String, Tracker> = catalog.flatMap { t -> t.domains.map { it to t } }.toMap()
    private val trackerMatcher = DomainMatcher(trackerByDomain.keys)

    fun decide(packageName: String?, name: String): Decision {
        val app = packageName?.let { apps[it] }
        app?.allowDomains?.match(name)?.let { return Decision(Action.ALLOW, "app allow: $it") }
        app?.blockDomains?.match(name)?.let { return Decision(Action.BLOCK, "app block: $it") }
        defaults.allowDomains.match(name)?.let { return Decision(Action.ALLOW, "allow: $it") }
        defaults.blockDomains.match(name)?.let { return Decision(Action.BLOCK, "block: $it") }
        val rule = trackerMatcher.match(name) ?: return Decision(Action.ALLOW, "no rule")
        val tracker = trackerByDomain.getValue(rule)
        val action = app?.categories?.get(tracker.category)
            ?: defaults.categories[tracker.category]
            ?: Action.ALLOW
        return Decision(action, "${tracker.name} (${tracker.category.name.lowercase()})", tracker)
    }

    companion object {
        val DEFAULT_CATEGORIES = mapOf(
            TrackerCategory.ADVERTISING to Action.BLOCK,
            TrackerCategory.ATTRIBUTION to Action.BLOCK,
            TrackerCategory.ANALYTICS to Action.BLOCK,
            TrackerCategory.FINGERPRINTING to Action.LOG,
        )

        val DEFAULT = SignalPolicy(
            AppRules(DEFAULT_CATEGORIES, DomainMatcher(emptyList()), DomainMatcher(emptyList())),
            emptyMap(),
        )

        /**
         * Parses a policy document. Unknown keys are rejected rather than ignored, so a typo
         * like "blockDomain" fails loudly instead of silently protecting nothing.
         *
         * ```json
         * { "version": 1,
         *   "defaults": { "categories": { "FINGERPRINTING": "LOG" }, "blockDomains": [], "allowDomains": [] },
         *   "apps": { "com.ubercab": { "categories": { "ANALYTICS": "BLOCK" } } } }
         * ```
         */
        fun parse(text: String): SignalPolicy {
            val root = try {
                Json.parseToJsonElement(text)
            } catch (e: SerializationException) {
                throw PolicyException("policy is not valid JSON: ${e.message}")
            }
            val obj = root.asObject("policy")
            obj.onlyKeys("policy", setOf("version", "defaults", "apps"))
            val version = (obj["version"] as? JsonPrimitive)?.intOrNull
            if (version != 1) throw PolicyException("policy.version must be 1, got ${obj["version"]}")
            val defaults = obj["defaults"]?.let { parseRules(it, "defaults", DEFAULT_CATEGORIES) }
                ?: DEFAULT.defaults
            val apps = obj["apps"]?.asObject("apps")?.mapValues { (pkg, v) ->
                if (!PACKAGE.matches(pkg)) throw PolicyException("apps: '$pkg' is not an Android package name")
                parseRules(v, "apps.$pkg", emptyMap())
            } ?: emptyMap()
            return SignalPolicy(defaults, apps)
        }

        private val PACKAGE = Regex("^[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+$")

        private fun parseRules(el: JsonElement, where: String, base: Map<TrackerCategory, Action>): AppRules {
            val o = el.asObject(where)
            o.onlyKeys(where, setOf("categories", "blockDomains", "allowDomains"))
            val categories = base.toMutableMap()
            o["categories"]?.asObject("$where.categories")?.forEach { (k, v) ->
                val cat = enumOrThrow<TrackerCategory>(k, "$where.categories key")
                categories[cat] = enumOrThrow<Action>(v.asString("$where.categories.$k"), "$where.categories.$k")
            }
            return AppRules(categories, domains(o["blockDomains"], "$where.blockDomains"),
                domains(o["allowDomains"], "$where.allowDomains"))
        }

        private fun domains(el: JsonElement?, where: String): DomainMatcher {
            if (el == null) return DomainMatcher(emptyList())
            val arr = el as? JsonArray ?: throw PolicyException("$where must be an array")
            return try {
                DomainMatcher(arr.mapIndexed { i, d -> d.asString("$where[$i]") })
            } catch (e: IllegalArgumentException) {
                throw PolicyException("$where: ${e.message}")
            }
        }

        private fun JsonElement.asObject(where: String): JsonObject =
            this as? JsonObject ?: throw PolicyException("$where must be an object")

        private fun JsonElement.asString(where: String): String =
            (this as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: throw PolicyException("$where must be a string")

        private fun JsonObject.onlyKeys(where: String, allowed: Set<String>) {
            val unknown = keys - allowed
            if (unknown.isNotEmpty()) throw PolicyException("$where has unknown keys $unknown; allowed: $allowed")
        }

        private inline fun <reified E : Enum<E>> enumOrThrow(v: String, where: String): E =
            enumValues<E>().firstOrNull { it.name == v }
                ?: throw PolicyException("$where: '$v' is not one of ${enumValues<E>().map { it.name }}")
    }
}
