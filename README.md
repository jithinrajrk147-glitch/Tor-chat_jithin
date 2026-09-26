# TorChatto

Direct Tor hidden-service chat between two Android phones. No server, no
accounts — each phone runs a real Tor v3 hidden service; the two phones
connect to each other directly over Tor.

## What's real here, and what I changed from your spec

- **`org.torproject:tor-android:0.4.7.13` does not exist.** The real
  library is published by Guardian Project as
  `info.guardianproject:tor-android` (I pinned `0.4.8.11`, a real released
  version), hosted at Guardian Project's own Maven repo
  (`https://raw.githubusercontent.com/guardianproject/gpmaven/master`) —
  it is **not** on Maven Central, so the CI workflow adds that repo.
- Rather than binding to that library's internal `TorService` Java class
  (whose exact method/broadcast names have changed across releases and I
  cannot verify against every version without a real Android build
  environment), `TorPlugin.java` launches the real native `tor` binary the
  library ships (as a subprocess, via a real generated `torrc`), and talks
  to it purely over the loopback SOCKS port and the hidden service's local
  TCP listener. This is the same mechanism Orbot itself is built on, and
  it's real, complete, non-stubbed code — every method does exactly what
  its name says.
- Peer discovery is fully manual, as you asked: each phone shows its own
  `xxxx.onion#hash` link, you send that link to the other person by any
  channel you like (SMS, another app, in person), they paste it in and hit
  **Connect**. The `#hash` is a short SHA-256 check-digit of the onion
  address, purely so a mistyped/garbled link is obviously wrong — it is
  not used by Tor itself.

## Honest limitations you should know about before treating this as "done"

1. **I could not compile or run this.** This sandbox has no Android SDK,
   no emulator, and no network access to Guardian Project's Maven repo, so
   I cannot guarantee a first-try green build. The GitHub Actions workflow
   is where it will actually get compiled for the first time — read its
   log if `assembleDebug` fails, the error will usually point at one of
   the two genuinely version-sensitive spots: the exact native library
   filename inside the AAR (`locateTorBinary()` in `TorPlugin.java` tries
   both `libTor.so` and `libtor.so`), and the exact Gradle repo block
   layout in whatever Capacitor 6 currently scaffolds (the CI script
   patches either `settings.gradle` or `android/build.gradle`, whichever
   exists).
2. **First hidden-service bootstrap is slow.** Publishing a v3 onion
   descriptor over Tor typically takes 15–60 seconds on a fresh circuit,
   sometimes longer on bad networks. The UI shows live Tor bootstrap
   percentage while this happens.
3. **No message persistence, no encryption layer of our own, no offline
   delivery.** Tor's own onion-service handshake already gives you
   authentication + encryption in transit; there's no additional
   end-to-end layer, no message history, and if either phone's Tor isn't
   running, messages simply fail to send — this mirrors Briar's "both
   devices must be online" model for direct sync, not its full
   store-and-forward mailbox system, which is a much bigger project.
4. **Foreground/background survival isn't handled.** The current plugin
   keeps Tor and the sockets alive only while the app process is alive.
   For a real product you'd want a foreground `Service` with a
   persistent notification so Android doesn't kill the Tor subprocess —
   I left that out to keep this reviewable; it's a straightforward
   addition (wrap the existing thread logic in a `Service`) once the
   core Tor plumbing above is confirmed working on a device.

## Build

```
npm install
npx cap add android
# then either open android/ in Android Studio, or let
# .github/workflows/build-apk.yml build it via `./gradlew assembleDebug`
```

## Files

- `www/index.html` — the whole UI + JS (WhatsApp-style bubbles, top bar
  connect field, tap-to-copy onion link, message input).
- `android/app/src/main/java/com/torchat/TorPlugin.java` — the real Tor
  plugin (start hidden service, SOCKS5 connect, send/receive).
- `.github/workflows/build-apk.yml` — scaffolds the Android project,
  wires the plugin + dependency in, builds `app-debug.apk`.
