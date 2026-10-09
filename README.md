# NetBand Flutter (Android / root)

Flutter front end with a native Kotlin root-command backend. It does not require Termux or an embedded Python runtime.

## Features in this source build

- Reads Android's IPv4 route and neighbor (`ip neigh`) tables.
- Can populate the neighbor table by pinging addresses in the active interface's `/24` subnet.
- Uses `su -c` for root operations.
- Adds an HTB traffic-control qdisc and per-IP filters for traffic egressing the phone's active default-route interface.
- Adds/removes `iptables FORWARD` DROP rules for a target IPv4 address.
- Dark Flutter UI with scan, per-device limit, block, and rule-removal controls.

## Important networking limitations

This is a native standalone APK architecture, but it is **not a router-wide controller**. Linux `tc` and `iptables FORWARD` only affect packets that traverse the Android device. On a normal Wi-Fi client connected to a separate router, traffic between other clients and the internet does not pass through this phone; therefore the app cannot reliably throttle/block those clients. Use it on a rooted Android device that is actually routing/forwarding the target's traffic, or implement router/AP integration for router-wide control.

The first rate-limit operation refuses to replace an existing root qdisc. The implementation is conservative about not overwriting other QoS setups. `Unlimit` removes the target's rules/classes, while `Cleanup` (not yet exposed in the UI) removes the HTB qdisc only if the app's ownership marker exists. If the phone reboots, kernel rules normally disappear; firewall and qdisc state is not persisted by the app.

Root command availability varies by ROM/kernel. `su`, `ip`, `ping`, `tc` with HTB/u32, and `iptables` must be available. Android vendors frequently omit or restrict `tc` features. This app does not perform ARP MITM/spoofing; the original Python script's ARP-spoofing workflow is not reproduced by the current native backend.

## Build APK

Requirements: Flutter stable (3.24+ recommended), Android SDK platform/build-tools installed, JDK 17, and Android licenses accepted.

```bash
flutter doctor
flutter pub get
flutter analyze
flutter build apk --release
```

Output: `build/app/outputs/flutter-apk/app-release.apk`.

On a new checkout, Flutter generates `android/local.properties` with your Flutter SDK path during build. This archive does not include generated SDK/build caches or a prebuilt APK.

## Install / permissions

Install the APK normally, then grant root access to NetBand in the installed root manager (Magisk/KernelSU/etc.). Android does not have a normal manifest permission that grants root. Do not use on networks you do not own or administer.

## Build automatically with GitHub Actions

1. Create a GitHub repository and upload/push the contents of this folder to its root (so `.github/workflows/build-apk.yml` is at the repository root).
2. Open **Actions** and enable workflows if GitHub asks.
3. Run **Build NetBand APK** with **Run workflow**, or push a commit to `main`/`master`.
4. When the run succeeds, open that workflow run and download the `netband-release-apk` artifact. It contains `app-release.apk`.

The workflow sets up Java 17 and Flutter stable, completes missing generated Android wrapper scaffolding, runs `flutter pub get` and `flutter analyze`, builds the release APK, and uploads it as a downloadable artifact. A failed analysis/build will fail the workflow instead of uploading a fake or empty APK.
