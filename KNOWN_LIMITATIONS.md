# Known limitations

SignalWall is honest about what it can and cannot do on a stock (non-rooted) Android phone.
Read this before relying on it.

## What it genuinely does
- **Shows** which tracker/analytics/fingerprinting SDKs and signal-reading APIs each installed
  app carries (on-device APK scan).
- **Blocks** the DNS lookups those trackers use, so the usual tracking/analytics/attribution
  payloads never leave the device.
- **Records** every blocked or logged lookup as an exportable evidence trail.

## What it cannot do
1. **It cannot stop an app from *reading* device signals.** Battery level, phone model and
   similar values need no permission and never touch the network, so no no-root app can block
   the read. SignalWall stops the data being *sent* and tells you which apps *can* read it.
2. **It can be bypassed.** Apps using DNS-over-HTTPS, Private DNS in strict mode, or hard-coded
   IP addresses skip a DNS filter entirely. Use the access log to confirm a given app is
   actually being filtered — do not assume it is.
3. **It does not normalise signals.** Making every device report the same battery/model (so the
   values carry no information) needs an OS-level hook (rooted / GrapheneOS-style build) and is
   intentionally out of scope for this phase.

## Risks to the user
- **Apps may break.** A blocked domain can take out login, push notifications, in-app support,
  deep links or maps, not just ads. Fix by allow-listing that domain in the policy.
- **Accounts may be flagged.** Fraud systems can read a blocked tracker call or a suddenly
  "clean" device as bot-like behaviour, which may trigger extra verification or account locks.
  This is why fingerprinting SDKs are **logged, not blocked, by default** — you opt in per app.
- **One VPN at a time.** Android allows a single active VPN, so SignalWall cannot run alongside
  another VPN.
- **You must trust SignalWall itself.** A DNS-filtering VPN sees every domain your chosen apps
  look up. SignalWall keeps that data on-device and never uploads it, but that is a property you
  should verify in the source, not take on faith.

## Scope
- **Android only** in this phase. iPhone support (a Safari content blocker and a device-neutral
  price/fare auditor) is future work.
- The tracker catalog is a snapshot and needs ongoing updates as SDKs and their domains change.
- The APK scan reports **capability** (an SDK is present), not **proof** that the app uses a
  signal for a given purpose such as pricing.
