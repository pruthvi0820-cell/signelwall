package com.signalwall.core.tracker

/**
 * Why a tracker exists decides the default action:
 * ads, attribution and analytics serve the company and are blocked; fingerprinting SDKs also
 * guard payments and sign-ups, so blocking them can break checkout and they are only logged.
 */
enum class TrackerCategory { ADVERTISING, ATTRIBUTION, ANALYTICS, FINGERPRINTING }

class Tracker(
    val name: String,
    val category: TrackerCategory,
    /** Network endpoints, matched as domain suffixes. */
    val domains: List<String>,
    /** Dex type-descriptor prefixes of the SDK's code, e.g. "Lcom/appsflyer/". */
    val codeSignatures: List<String>,
)

/** A device signal an app can read without any permission prompt. */
enum class DeviceSignal(val label: String) {
    BATTERY("battery level / charging"),
    POWER_SAVE("battery-saver mode"),
    INSTALLED_APPS("list of installed apps"),
    DEVICE_PROPS("raw device properties"),
    ROOT_EMULATOR_CHECK("root / emulator checks"),
}

/**
 * Built-in catalog. Domains are SDK endpoints only: shared infrastructure (googleapis.com,
 * firebaseio.com, graph.facebook.com, app.link deep links, crash reporting) is deliberately
 * absent because blocking it breaks logins, data sync or links rather than tracking.
 */
object TrackerCatalog {
    val ALL: List<Tracker> = listOf(
        Tracker("Google Ads", TrackerCategory.ADVERTISING,
            listOf("doubleclick.net", "googleadservices.com", "googlesyndication.com"),
            listOf("Lcom/google/android/gms/ads/")),
        Tracker("AppsFlyer", TrackerCategory.ATTRIBUTION,
            listOf("appsflyer.com", "appsflyersdk.com"), listOf("Lcom/appsflyer/")),
        Tracker("Adjust", TrackerCategory.ATTRIBUTION,
            listOf("adjust.com", "adjust.world", "adjust.net.in"), listOf("Lcom/adjust/sdk/")),
        Tracker("Branch", TrackerCategory.ATTRIBUTION, listOf("branch.io"), listOf("Lio/branch/")),
        Tracker("Meta App Events", TrackerCategory.ATTRIBUTION, emptyList(), listOf("Lcom/facebook/appevents/")),
        Tracker("Firebase Analytics", TrackerCategory.ANALYTICS,
            listOf("app-measurement.com"),
            listOf("Lcom/google/firebase/analytics/", "Lcom/google/android/gms/measurement/")),
        Tracker("CleverTap", TrackerCategory.ANALYTICS,
            listOf("clevertap-prod.com", "wzrkt.com"), listOf("Lcom/clevertap/android/")),
        Tracker("MoEngage", TrackerCategory.ANALYTICS, listOf("moengage.com"), listOf("Lcom/moengage/")),
        Tracker("WebEngage", TrackerCategory.ANALYTICS, listOf("webengage.com"), listOf("Lcom/webengage/")),
        Tracker("Mixpanel", TrackerCategory.ANALYTICS, listOf("mixpanel.com"), listOf("Lcom/mixpanel/android/")),
        Tracker("Amplitude", TrackerCategory.ANALYTICS, listOf("amplitude.com"), listOf("Lcom/amplitude/")),
        Tracker("Segment", TrackerCategory.ANALYTICS, listOf("segment.io"), listOf("Lcom/segment/analytics/")),
        Tracker("ThreatMetrix (LexisNexis)", TrackerCategory.FINGERPRINTING,
            listOf("online-metrix.net"),
            listOf("Lcom/threatmetrix/", "Lcom/lexisnexisrisk/threatmetrix/")),
        Tracker("Sift", TrackerCategory.FINGERPRINTING, listOf("siftscience.com"), listOf("Lsiftscience/android/")),
        Tracker("SEON", TrackerCategory.FINGERPRINTING, listOf("seon.io"), listOf("Lio/seon/")),
        Tracker("Fingerprint", TrackerCategory.FINGERPRINTING,
            listOf("fpjs.io"), listOf("Lcom/fingerprintjs/android/")),
        Tracker("Incognia", TrackerCategory.FINGERPRINTING, listOf("incognia.com"), listOf("Lcom/incognia/")),
    )

    /**
     * Exact dex strings that show an app's code can read a signal. Intent action strings are
     * compile-time constants, so they land in the dex string table of any app that uses them.
     * Presence in code proves capability, not that the value feeds a price.
     */
    val SIGNAL_STRINGS: Map<String, DeviceSignal> = mapOf(
        "android.intent.action.BATTERY_CHANGED" to DeviceSignal.BATTERY,
        "Landroid/os/BatteryManager;" to DeviceSignal.BATTERY,
        "isPowerSaveMode" to DeviceSignal.POWER_SAVE,
        "getInstalledPackages" to DeviceSignal.INSTALLED_APPS,
        "getInstalledApplications" to DeviceSignal.INSTALLED_APPS,
        "ro.product.model" to DeviceSignal.DEVICE_PROPS,
        "ro.product.manufacturer" to DeviceSignal.DEVICE_PROPS,
        "ro.kernel.qemu" to DeviceSignal.ROOT_EMULATOR_CHECK,
        "/system/xbin/su" to DeviceSignal.ROOT_EMULATOR_CHECK,
    )
}
