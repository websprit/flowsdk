# Android QUIC Stability Example

Android example for holding MQTT over QUIC connections without publish/subscribe traffic.

Scenario:

- Target host/port/server name: entered in the app UI
- Username/password: entered in the app UI
- Connections: `10`
- Duration: `120s`
- MQTT keep alive: `30s`
- TLS verification: enabled
- Publish/subscribe: disabled

The password field uses Android's password input mode, so the value is masked on screen.
TLS verification uses Android's platform verifier via `rustls-platform-verifier`.

## Build

Generate Kotlin UniFFI bindings first:

```bash
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home \
  ./scripts/build_kotlin_bindings.sh
```

Build Android native libraries for the target ABIs and copy them into:

```text
kotlin/examples/android_quic_stability/src/main/jniLibs/<abi>/libflowsdk_ffi.so
```

For example:

```bash
PATH="$HOME/.cargo/bin:$PATH" \
ANDROID_HOME="$HOME/Library/Android/sdk" \
cargo ndk -t arm64-v8a -o kotlin/examples/android_quic_stability/src/main/jniLibs \
  build -p flowsdk_ffi --features quic --release
```

Then build the APK:

```bash
cd kotlin
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home \
ANDROID_HOME="$HOME/Library/Android/sdk" \
  ./gradlew :examples:android_quic_stability:assembleDebug
```

Install:

```bash
adb install -r examples/android_quic_stability/build/outputs/apk/debug/android_quic_stability-debug.apk
```
