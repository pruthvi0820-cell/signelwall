# SignalWall (Android)

A privacy wall for Android that stops apps from quietly phoning home with the device
signals that some companies have been accused of using to personalise prices — battery
level, phone model, and the tracking/attribution data that ties it all to you.

This is **phase 1: the Android DNS firewall and tracker scanner.**

## What it does today

| Capability | How | Works on a stock phone? |
|---|---|---|
| **Block tracker/analytics/attribution SDKs** | A DNS-filtering VPN (the DNS66/Blokada design): the chosen apps' DNS lookups are checked against a policy; blocked names resolve to `0.0.0.0` | **Yes**, no root |
| **See what each app ships** | On-device scan of installed APKs' dex string tables for known SDKs and signal-reading APIs (the Exodus Privacy idea) | **Yes**, no root |
| **Evidence log** | Every blocked/logged lookup is recorded and exports as JSON Lines | **Yes**, no root |
| **Fingerprinting SDKs** (ThreatMetrix, Sift, …) | Logged, not blocked by default — they also guard real logins and payments, so you decide per app | **Yes**, no root |

### The honest limits
- **Reading** battery level and phone model needs no permission and never touches the network,
  so a no-root app cannot stop an app from *reading* them. It can stop the app from *sending*
  the usual tracking payloads, and show you which apps have the capability.
- Apps using **DNS-over-HTTPS**, **Private DNS (strict mode)**, or **hard-coded IPs** bypass a
  DNS filter. The evidence log is how you check whether a given app is actually being filtered.
- Normalising the signals to a single value for every device (so they carry no information)
  requires an OS-level hook (a rooted phone / GrapheneOS-style build) and is intentionally **not**
  part of this phase.

## The three-box model

Every signal falls into one box, encoded in `SignalPolicy`:

1. **Needed for the service** → allowed (e.g. the app's own API).
2. **Needed for trust (fraud)** → the app should rely on a signed yes/no attestation
   (Play Integrity / App Attest), not raw fingerprints. Fingerprinting SDKs are **logged** so
   you can see who still collects the raw data.
3. **Exploitable situation** (battery, model, charging, installed apps) → the tracking that
   carries it off-device is **blocked**.

## Policy format

```json
{
  "version": 1,
  "defaults": {
    "categories": { "ADVERTISING": "BLOCK", "ATTRIBUTION": "BLOCK",
                    "ANALYTICS": "BLOCK", "FINGERPRINTING": "LOG" },
    "blockDomains": [],
    "allowDomains": []
  },
  "apps": {
    "com.ubercab": { "categories": { "FINGERPRINTING": "BLOCK" },
                     "allowDomains": ["uber.com"] }
  }
}
```

Precedence, first match wins: app `allowDomains` → app `blockDomains` → default `allowDomains`
→ default `blockDomains` → tracker category (app override, then default) → allow.
Parsing is strict: unknown keys, bad actions and malformed domains are rejected rather than
silently protecting nothing.

## Layout

```
.
├── core/      # plain-JVM logic, fully unit-tested without a device
│   └── com/signalwall/core/
│       ├── net/      IpUdp          — parse/build IPv4+IPv6 UDP, checksums
│       ├── dns/      Dns            — parse one query; blocked / servfail / truncated replies
│       ├── policy/   DomainMatcher  — whole-label suffix matching
│       │             SignalPolicy   — three-box engine + strict JSON parser
│       ├── tracker/  TrackerCatalog — SDK domains + dex signatures, signal API strings
│       ├── scan/     ApkScanner     — read dex string tables, match SDKs/signals
│       └── audit/    AccessLog      — fixed-size ring, JSON Lines export
└── app/       # Android: VpnService DNS firewall + UI (minSdk 29)
    └── com/signalwall/app/
        ├── WallVpnService  — DNS-only VPN, per-app routing, upstream relay
        ├── MainActivity    — start/stop, live log, export, import policy
        ├── AppsActivity     — choose apps, on-device tracker scan
        ├── PolicyStore      — imported → bundled → built-in fallback
        └── WallState        — shared log + status
```

## Verify

**Core logic (no Android SDK, runs in CI and locally):**

```bash
./gradlew :core:test
```

30 tests cover packet round-trips and checksums, DNS parsing/pointer-loops/blocked answers,
policy precedence and malformed-input rejection, the APK/dex scanner, and the audit log.
Fuzz tests feed 20k random buffers through the packet and DNS parsers to prove they never throw.

**The Android app** needs the Android SDK (`ANDROID_HOME`); build with `./gradlew :app:assembleDebug`.
It is not built in CI here because the SDK is not provisioned in this environment.

## Roadmap

- **Phase 2 (iPhone):** website protection via a Safari extension; the fare auditor (works on
  any phone — it compares quotes, catching device-based pricing even where it can't block it).
- **Phase 3:** OS-level signal normalisation for rooted / GrapheneOS devices.
- **Phase 4:** a policy spec + compliance attestation for companies and regulators.

## Limitations

See [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md) for an honest account of what SignalWall
can and cannot do, the bypasses, and the risks to the user (app breakage, account flags).

## License

[MIT](LICENSE).
