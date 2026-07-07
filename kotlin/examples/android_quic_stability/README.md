# Android QUIC Stability Example

Android example for holding MQTT over QUIC connections without publish/subscribe traffic.
The UI owns only configuration, start/stop, and log display. The default runner
uses native UDP transport inside `libflowsdk_ffi.so`, while Rust continues to
own the QUIC and MQTT protocol state machines.

Scenario:

- Target host/port/server name: entered in the app UI
- Username/password: entered in the app UI
- Connections: `10`
- Duration: entered in the app UI, default `120s`
- MQTT keep alive: `30s`
- TLS verification: enabled
- Publish/subscribe: disabled

The password field uses Android's password input mode, so the value is masked on screen.
TLS verification uses Android's platform verifier via `rustls-platform-verifier`.

## Runtime Architecture

```text
Android UI
  -> NativeQuicStabilityRunner.startNative(...)
  -> libflowsdk_ffi.so native runner
  -> UDP socket send/receive in native code
  -> QuicMqttEngineFFI / QuicMqttEngine
  -> MQTT over QUIC events
  -> NativeLogCallback.onLog(...)
  -> Android UI log view
```

The previous Kotlin UDP loop remains in the source as `KotlinQuicStabilityRunner`
for comparison, but the app starts `NativeQuicStabilityRunnerInstance` by
default.

## Build

Generate Kotlin UniFFI bindings first. This creates the Kotlin wrapper used by
the Android app:

```bash
JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home \
  ./scripts/build_kotlin_bindings.sh
```

Build the Android native library next. `libflowsdk_ffi.so` is produced from the
Rust crate `flowsdk_ffi`, whose `Cargo.toml` declares `cdylib` output. The
Android app loads this library with `System.loadLibrary("flowsdk_ffi")`.

The easiest way to build and place it correctly is `cargo ndk`. It cross
compiles `flowsdk_ffi` for the selected Android ABI and copies the output into:

```text
kotlin/examples/android_quic_stability/src/main/jniLibs/<abi>/libflowsdk_ffi.so
```

For example, for an arm64 phone:

```bash
PATH="$HOME/.cargo/bin:$PATH" \
ANDROID_HOME="$HOME/Library/Android/sdk" \
cargo ndk -t arm64-v8a -o kotlin/examples/android_quic_stability/src/main/jniLibs \
  build -p flowsdk_ffi --features quic --release
```

After this command, the expected generated file is:

```text
kotlin/examples/android_quic_stability/src/main/jniLibs/arm64-v8a/libflowsdk_ffi.so
```

For other devices, replace `arm64-v8a` with the ABI you need, such as `x86_64`
for many emulators. The `jniLibs/` directory is generated build output and is
ignored by git.

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
