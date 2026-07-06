// SPDX-License-Identifier: MPL-2.0
use flowsdk::mqtt_client::commands::PublishCommand;
use flowsdk::mqtt_client::engine::{MqttEngine, MqttEvent};
use flowsdk::mqtt_client::opts::MqttClientOptions;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::time::{Duration, Instant};

pub mod ffi_types;
use ffi_types::*;

use std::sync::Mutex;

#[cfg(all(target_os = "android", any(feature = "tls", feature = "quic")))]
use jni::{
    jni_sig, jni_str,
    objects::{Global, JClass, JObject, JString, Reference},
    sys::{jboolean, jint, jlong},
    EnvUnowned, JValue, JavaVM, Outcome,
};

#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct MqttEngineFFI {
    engine: Mutex<MqttEngine>,
    start_time: Instant,
    events: Mutex<Vec<MqttEventFFI>>,
}

#[cfg(feature = "quic")]
use flowsdk::mqtt_client::engine::QuicMqttEngine;
#[cfg(feature = "tls")]
use flowsdk::mqtt_client::tls_engine::TlsMqttEngine;
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(all(target_os = "android", any(feature = "tls", feature = "quic")))]
#[export_name = "Java_io_emqx_flowsdk_examples_quicstability_PlatformVerifierNative_init"]
pub extern "C" fn android_platform_verifier_init(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    context: JObject<'_>,
) -> jboolean {
    let outcome = env
        .with_env(|env| rustls_platform_verifier::android::init_with_env(env, context))
        .into_outcome();

    match outcome {
        Outcome::Ok(()) => true,
        Outcome::Err(_) | Outcome::Panic(_) => false,
    }
}

#[cfg(all(target_os = "android", feature = "quic"))]
struct NativeQuicRunnerHandle {
    running: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(all(target_os = "android", feature = "quic"))]
#[derive(Clone)]
struct NativeQuicRunnerConfig {
    host: String,
    port: u16,
    server_name: String,
    username: Option<String>,
    password: Option<String>,
    clients: usize,
    duration_secs: u64,
    keep_alive_secs: u16,
    insecure_skip_verify: bool,
}

#[cfg(all(target_os = "android", feature = "quic"))]
#[derive(Default)]
struct NativeQuicRunnerStats {
    connected: std::sync::atomic::AtomicU64,
    completed: std::sync::atomic::AtomicU64,
    connect_failed: std::sync::atomic::AtomicU64,
    ping_responses: std::sync::atomic::AtomicU64,
    errors: std::sync::atomic::AtomicU64,
    connection_lost: std::sync::atomic::AtomicU64,
    disconnected: std::sync::atomic::AtomicU64,
}

#[cfg(all(target_os = "android", feature = "quic"))]
#[export_name = "Java_io_emqx_flowsdk_examples_quicstability_NativeQuicStabilityRunner_startNative"]
pub extern "C" fn android_native_quic_stability_start(
    mut env: EnvUnowned<'_>,
    _class: JClass<'_>,
    host: JString<'_>,
    port: jint,
    server_name: JString<'_>,
    username: JString<'_>,
    password: JString<'_>,
    clients: jint,
    duration_secs: jlong,
    keep_alive_secs: jint,
    insecure_skip_verify: jboolean,
    callback: JObject<'_>,
) -> jlong {
    let outcome = env
        .with_env(|env| {
            let host = java_string(env, &host).unwrap_or_default();
            let server_name = java_string(env, &server_name).unwrap_or_else(|| host.clone());
            let username = java_string(env, &username).filter(|s| !s.is_empty());
            let password = java_string(env, &password).filter(|s| !s.is_empty());
            let callback = Arc::new(env.new_global_ref(callback)?);
            let vm = Arc::new(env.get_java_vm()?);
            let running = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let config = NativeQuicRunnerConfig {
                host,
                port: port.clamp(1, u16::MAX as jint) as u16,
                server_name,
                username,
                password,
                clients: clients.max(1) as usize,
                duration_secs: duration_secs.max(1) as u64,
                keep_alive_secs: keep_alive_secs.clamp(1, u16::MAX as jint) as u16,
                insecure_skip_verify,
            };
            let thread_running = Arc::clone(&running);
            let thread = std::thread::spawn(move || {
                run_native_quic_stability(config, thread_running, vm, callback);
            });
            let handle = Box::new(NativeQuicRunnerHandle {
                running,
                thread: Some(thread),
            });
            Ok::<jlong, jni::errors::Error>(Box::into_raw(handle) as jlong)
        })
        .into_outcome();

    match outcome {
        Outcome::Ok(handle) => handle,
        Outcome::Err(_) | Outcome::Panic(_) => 0,
    }
}

#[cfg(all(target_os = "android", feature = "quic"))]
#[export_name = "Java_io_emqx_flowsdk_examples_quicstability_NativeQuicStabilityRunner_stopNative"]
pub extern "C" fn android_native_quic_stability_stop(
    _env: EnvUnowned<'_>,
    _class: JClass<'_>,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }

    let mut handle = unsafe { Box::from_raw(handle as *mut NativeQuicRunnerHandle) };
    handle
        .running
        .store(false, std::sync::atomic::Ordering::Relaxed);
    if let Some(thread) = handle.thread.take() {
        let _ = thread.join();
    }
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn java_string(env: &jni::Env<'_>, value: &JString<'_>) -> Option<String> {
    if value.is_null() {
        return None;
    }
    value.mutf8_chars(env).ok().map(|chars| chars.to_string())
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn native_log(vm: &JavaVM, callback: &Global<JObject>, line: impl AsRef<str>) {
    let line = line.as_ref().to_string();
    let _ = vm.attach_current_thread(|env| {
        let jline = env.new_string(line)?;
        env.call_method(
            callback.as_ref(),
            jni_str!("onLog"),
            jni_sig!("(Ljava/lang/String;)V"),
            &[JValue::Object(jline.as_ref())],
        )?;
        Ok::<(), jni::errors::Error>(())
    });
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn run_native_quic_stability(
    config: NativeQuicRunnerConfig,
    running: Arc<std::sync::atomic::AtomicBool>,
    vm: Arc<JavaVM>,
    callback: Arc<Global<JObject>>,
) {
    let stats = Arc::new(NativeQuicRunnerStats::default());
    let connect_latencies_ms = Arc::new(Mutex::new(Vec::with_capacity(config.clients)));

    native_log(
        &vm,
        &callback,
        "MQTT over QUIC Android connection stability check",
    );
    native_log(
        &vm,
        &callback,
        format!("  target: quic://{}:{}", config.host, config.port),
    );
    native_log(
        &vm,
        &callback,
        format!("  server_name: {}", config.server_name),
    );
    native_log(&vm, &callback, format!("  clients: {}", config.clients));
    native_log(
        &vm,
        &callback,
        format!("  duration: {}s", config.duration_secs),
    );
    native_log(
        &vm,
        &callback,
        format!("  keep_alive: {}s", config.keep_alive_secs),
    );
    native_log(&vm, &callback, "  publish/subscribe: disabled");
    native_log(
        &vm,
        &callback,
        format!(
            "  tls_verify: {}",
            if config.insecure_skip_verify {
                "off"
            } else {
                "on"
            }
        ),
    );
    native_log(
        &vm,
        &callback,
        format!(
            "  auth: {}",
            if config.username.is_some() || config.password.is_some() {
                "configured"
            } else {
                "disabled"
            }
        ),
    );
    native_log(&vm, &callback, "  runner: native");

    let mut client_threads = Vec::with_capacity(config.clients);
    for index in 0..config.clients {
        let client_config = config.clone();
        let client_running = Arc::clone(&running);
        let client_stats = Arc::clone(&stats);
        let client_latencies = Arc::clone(&connect_latencies_ms);
        let client_vm = Arc::clone(&vm);
        let client_callback = Arc::clone(&callback);
        client_threads.push(std::thread::spawn(move || {
            native_run_client(
                index,
                client_config,
                client_running,
                client_stats,
                client_latencies,
                client_vm,
                client_callback,
            )
        }));
    }

    let mut next_report = Instant::now() + Duration::from_secs(5);
    while running.load(std::sync::atomic::Ordering::Relaxed) {
        std::thread::sleep(Duration::from_millis(100));
        if Instant::now() >= next_report {
            native_log(&vm, &callback, native_snapshot_line(&stats));
            next_report = Instant::now() + Duration::from_secs(5);
        }
        if stats.completed.load(std::sync::atomic::Ordering::Relaxed) >= config.clients as u64 {
            running.store(false, std::sync::atomic::Ordering::Relaxed);
            break;
        }
    }

    for thread in client_threads {
        if thread.join().is_err() {
            stats
                .errors
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    if stats.completed.load(std::sync::atomic::Ordering::Relaxed) >= config.clients as u64 {
        native_log(&vm, &callback, "Final result");
        native_log(&vm, &callback, native_snapshot_line(&stats));
        native_log(
            &vm,
            &callback,
            native_connect_latency_summary(&connect_latencies_ms),
        );
        let failed = stats
            .connect_failed
            .load(std::sync::atomic::Ordering::Relaxed)
            + stats.errors.load(std::sync::atomic::Ordering::Relaxed)
            + stats
                .connection_lost
                .load(std::sync::atomic::Ordering::Relaxed)
            + stats
                .disconnected
                .load(std::sync::atomic::Ordering::Relaxed);
        native_log(
            &vm,
            &callback,
            format!("status: {}", if failed == 0 { "PASS" } else { "FAIL" }),
        );
    } else {
        native_log(&vm, &callback, "Stopped");
        native_log(&vm, &callback, native_snapshot_line(&stats));
        native_log(
            &vm,
            &callback,
            native_connect_latency_summary(&connect_latencies_ms),
        );
    }
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn native_run_client(
    index: usize,
    config: NativeQuicRunnerConfig,
    running: Arc<std::sync::atomic::AtomicBool>,
    stats: Arc<NativeQuicRunnerStats>,
    connect_latencies_ms: Arc<Mutex<Vec<u128>>>,
    vm: Arc<JavaVM>,
    callback: Arc<Global<JObject>>,
) {
    let started = Instant::now();
    let client_id = format!(
        "android_quic_stability_native_{}_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0),
        index
    );

    if let Err(err) = native_run_client_inner(
        index,
        &config,
        Arc::clone(&running),
        Arc::clone(&stats),
        Arc::clone(&connect_latencies_ms),
        &vm,
        &callback,
        &client_id,
        started,
    ) {
        stats
            .errors
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        native_log(
            &vm,
            &callback,
            format!("client {} exception: {}", index, err),
        );
        running.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn native_run_client_inner(
    index: usize,
    config: &NativeQuicRunnerConfig,
    running: Arc<std::sync::atomic::AtomicBool>,
    stats: Arc<NativeQuicRunnerStats>,
    connect_latencies_ms: Arc<Mutex<Vec<u128>>>,
    vm: &JavaVM,
    callback: &Global<JObject>,
    client_id: &str,
    started: Instant,
) -> Result<(), String> {
    use std::io::ErrorKind;
    use std::net::{ToSocketAddrs, UdpSocket};

    let broker_addr = format!("{}:{}", config.host, config.port)
        .to_socket_addrs()
        .map_err(|e| format!("resolve broker: {}", e))?
        .next()
        .ok_or_else(|| "resolve broker: no address".to_string())?;
    let server_addr = broker_addr.to_string();
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("bind UDP: {}", e))?;
    socket
        .connect(broker_addr)
        .map_err(|e| format!("connect UDP: {}", e))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| format!("set nonblocking: {}", e))?;

    let opts = MqttOptionsFFI {
        client_id: client_id.to_string(),
        mqtt_version: 5,
        clean_start: true,
        keep_alive: config.keep_alive_secs,
        username: config.username.clone(),
        password: config.password.clone(),
        reconnect_base_delay_ms: 1000,
        reconnect_max_delay_ms: 10000,
        max_reconnect_attempts: 0,
    };
    let engine = QuicMqttEngineFFI::new(opts);
    let tls_opts = MqttTlsOptionsFFI {
        ca_cert_file: None,
        client_cert_file: None,
        client_key_file: None,
        insecure_skip_verify: config.insecure_skip_verify,
        alpn_protocols: Vec::new(),
        enable_key_log: false,
    };

    let connect_started = Instant::now();
    engine.connect(
        server_addr.clone(),
        config.server_name.clone(),
        tls_opts,
        started.elapsed().as_millis() as u64,
    );
    engine.handle_tick(started.elapsed().as_millis() as u64);
    native_send_outgoing(&engine, &socket, true)?;

    let mut recv_buf = [0u8; 65536];
    let mut connected = false;
    let mut completed = false;

    while running.load(std::sync::atomic::Ordering::Relaxed)
        && started.elapsed() < Duration::from_secs(config.duration_secs)
    {
        loop {
            match socket.recv(&mut recv_buf) {
                Ok(len) => engine.handle_datagram(
                    recv_buf[..len].to_vec(),
                    server_addr.clone(),
                    started.elapsed().as_millis() as u64,
                ),
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(err) => return Err(format!("recv UDP: {}", err)),
            }
        }

        for event in engine.handle_tick(started.elapsed().as_millis() as u64) {
            match event {
                MqttEventFFI::Connected(result) => {
                    if result.reason_code == 0 && !connected {
                        connected = true;
                        let latency_ms = connect_started.elapsed().as_millis();
                        connect_latencies_ms.lock().unwrap().push(latency_ms);
                        stats
                            .connected
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        native_log(
                            vm,
                            callback,
                            format!("client {} connected in {}ms", index, latency_ms),
                        );
                    } else if result.reason_code != 0 {
                        stats
                            .connect_failed
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        native_log(
                            vm,
                            callback,
                            format!(
                                "client {} connect rejected reason={}",
                                index, result.reason_code
                            ),
                        );
                        running.store(false, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                MqttEventFFI::PingResponse { success } => {
                    if success {
                        stats
                            .ping_responses
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
                MqttEventFFI::Disconnected { reason_code } => {
                    stats
                        .disconnected
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    native_log(
                        vm,
                        callback,
                        format!("client {} disconnected reason={:?}", index, reason_code),
                    );
                    running.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                MqttEventFFI::ReconnectNeeded => {
                    stats
                        .connection_lost
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    native_log(
                        vm,
                        callback,
                        format!("client {} connection lost: reconnect needed", index),
                    );
                    running.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                MqttEventFFI::Error { message } => {
                    stats
                        .errors
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    native_log(vm, callback, format!("client {} error: {}", index, message));
                    running.store(false, std::sync::atomic::Ordering::Relaxed);
                }
                _ => {}
            }
        }
        native_send_outgoing(&engine, &socket, true)?;
        std::thread::sleep(Duration::from_millis(10));
    }

    if connected && started.elapsed() >= Duration::from_secs(config.duration_secs) {
        completed = true;
        stats
            .completed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    engine.disconnect();
    engine.handle_tick(started.elapsed().as_millis() as u64);
    let _ = native_send_outgoing(&engine, &socket, false);
    if !completed && connected {
        native_log(
            vm,
            callback,
            format!("client {} stopped before completion", index),
        );
    }
    Ok(())
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn native_send_outgoing(
    engine: &QuicMqttEngineFFI,
    socket: &std::net::UdpSocket,
    fail_on_error: bool,
) -> Result<(), String> {
    for datagram in engine.take_outgoing_datagrams() {
        if let Err(err) = socket.send(&datagram.data) {
            if fail_on_error {
                return Err(format!("send UDP: {}", err));
            }
        }
    }
    Ok(())
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn native_snapshot_line(stats: &NativeQuicRunnerStats) -> String {
    format!(
        "connected: {} | completed: {} | connect_failed: {} | ping_responses: {} | errors: {} | connection_lost: {} | disconnected: {}",
        stats.connected.load(std::sync::atomic::Ordering::Relaxed),
        stats.completed.load(std::sync::atomic::Ordering::Relaxed),
        stats.connect_failed.load(std::sync::atomic::Ordering::Relaxed),
        stats.ping_responses.load(std::sync::atomic::Ordering::Relaxed),
        stats.errors.load(std::sync::atomic::Ordering::Relaxed),
        stats.connection_lost.load(std::sync::atomic::Ordering::Relaxed),
        stats.disconnected.load(std::sync::atomic::Ordering::Relaxed),
    )
}

#[cfg(all(target_os = "android", feature = "quic"))]
fn native_connect_latency_summary(connect_latencies_ms: &Arc<Mutex<Vec<u128>>>) -> String {
    let values = connect_latencies_ms.lock().unwrap();
    if values.is_empty() {
        return "connect_latency_ms: no successful connections".to_string();
    }
    let min = values.iter().min().copied().unwrap_or(0);
    let max = values.iter().max().copied().unwrap_or(0);
    let sum: u128 = values.iter().sum();
    let avg = sum as f64 / values.len() as f64;
    format!(
        "connect_latency_ms: count={} min={} avg={:.2} max={}",
        values.len(),
        min,
        avg,
        max
    )
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl MqttEngineFFI {
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new(client_id: Option<String>, mqtt_version: u8) -> Self {
        let client_id = client_id.unwrap_or_else(|| "mqtt_client".to_string());
        let options = MqttClientOptions::builder()
            .client_id(client_id)
            .mqtt_version(mqtt_version)
            .build();

        let engine = MqttEngine::new(options);
        MqttEngineFFI {
            engine: Mutex::new(engine),
            start_time: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new_with_opts(opts: MqttOptionsFFI) -> Self {
        let mut builder = MqttClientOptions::builder()
            .client_id(opts.client_id)
            .mqtt_version(opts.mqtt_version)
            .clean_start(opts.clean_start)
            .keep_alive(opts.keep_alive)
            .reconnect_base_delay_ms(opts.reconnect_base_delay_ms)
            .reconnect_max_delay_ms(opts.reconnect_max_delay_ms)
            .max_reconnect_attempts(opts.max_reconnect_attempts);

        if let Some(username) = opts.username {
            builder = builder.username(username);
        }

        if let Some(password) = opts.password {
            builder = builder.password(password);
        }

        let engine = MqttEngine::new(builder.build());
        MqttEngineFFI {
            engine: Mutex::new(engine),
            start_time: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn handle_connection_lost(&self) {
        self.engine.lock().unwrap().handle_connection_lost();
    }

    pub fn connect(&self) {
        self.engine.lock().unwrap().connect();
    }

    pub fn handle_incoming(&self, data: Vec<u8>) -> Vec<MqttEventFFI> {
        let mut engine = self.engine.lock().unwrap();
        let events = engine.handle_incoming(&data);
        let mapped: Vec<_> = events.into_iter().map(map_event).collect();
        self.events.lock().unwrap().extend(mapped.iter().cloned());
        mapped
    }

    pub fn handle_tick(&self, now_ms: u64) -> Vec<MqttEventFFI> {
        let now = self.start_time + Duration::from_millis(now_ms);
        let mut engine = self.engine.lock().unwrap();
        let events = engine.handle_tick(now);
        let mapped: Vec<_> = events.into_iter().map(map_event).collect();
        self.events.lock().unwrap().extend(mapped.iter().cloned());
        mapped
    }

    pub fn next_tick_ms(&self) -> i64 {
        match self.engine.lock().unwrap().next_tick_at() {
            Some(tick) => {
                if tick <= self.start_time {
                    0
                } else {
                    let duration = tick.duration_since(self.start_time);
                    duration.as_millis() as i64
                }
            }
            None => -1,
        }
    }

    pub fn take_outgoing(&self) -> Vec<u8> {
        self.engine.lock().unwrap().take_outgoing()
    }

    pub fn take_events(&self) -> Vec<MqttEventFFI> {
        let mut events = std::mem::take(&mut *self.events.lock().unwrap());
        let engine_events = self.engine.lock().unwrap().take_events();
        events.extend(engine_events.into_iter().map(map_event));
        events
    }

    // Internal helper for C bridge
    pub fn push_event_ffi(&self, event: MqttEventFFI) {
        self.events.lock().unwrap().push(event);
    }

    pub fn publish(&self, topic: String, payload: Vec<u8>, qos: u8, priority: Option<u8>) -> i32 {
        let mut builder = PublishCommand::builder()
            .topic(topic)
            .payload(payload)
            .qos(qos);

        if let Some(p) = priority {
            builder = builder.priority(p);
        }

        let command = match builder.build() {
            Ok(c) => c,
            Err(_) => return -1,
        };

        match self.engine.lock().unwrap().publish(command) {
            Ok(Some(pid)) => pid as i32,
            Ok(None) => 0,
            Err(_) => -1,
        }
    }

    pub fn subscribe(&self, topic_filter: String, qos: u8) -> i32 {
        let command = flowsdk::mqtt_client::commands::SubscribeCommand::single(topic_filter, qos);

        match self.engine.lock().unwrap().subscribe(command) {
            Ok(pid) => pid as i32,
            Err(_) => -1,
        }
    }

    pub fn unsubscribe(&self, topic_filter: String) -> i32 {
        let command =
            flowsdk::mqtt_client::commands::UnsubscribeCommand::from_topics(vec![topic_filter]);

        match self.engine.lock().unwrap().unsubscribe(command) {
            Ok(pid) => pid as i32,
            Err(_) => -1,
        }
    }

    pub fn disconnect(&self) {
        self.engine.lock().unwrap().disconnect();
    }

    pub fn is_connected(&self) -> bool {
        self.engine.lock().unwrap().is_connected()
    }

    pub fn get_version(&self) -> u8 {
        self.engine.lock().unwrap().mqtt_version()
    }

    pub fn auth(&self, reason_code: u8) {
        self.engine.lock().unwrap().auth(reason_code, Vec::new());
    }
}

fn map_event(event: MqttEvent) -> MqttEventFFI {
    match event {
        MqttEvent::Connected(res) => MqttEventFFI::Connected(ConnectionResultFFI {
            reason_code: res.reason_code,
            session_present: res.session_present,
        }),
        MqttEvent::Disconnected(code) => MqttEventFFI::Disconnected { reason_code: code },
        MqttEvent::MessageReceived(msg) => MqttEventFFI::MessageReceived(MqttMessageFFI {
            topic: msg.topic_name,
            payload: msg.payload,
            qos: msg.qos,
            retain: msg.retain,
        }),
        MqttEvent::Published(res) => MqttEventFFI::Published(PublishResultFFI {
            packet_id: res.packet_id,
            reason_code: res.reason_code,
            qos: res.qos,
        }),
        MqttEvent::Subscribed(res) => MqttEventFFI::Subscribed(SubscribeResultFFI {
            packet_id: res.packet_id,
            reason_codes: res.reason_codes,
        }),
        MqttEvent::Unsubscribed(res) => MqttEventFFI::Unsubscribed(UnsubscribeResultFFI {
            packet_id: res.packet_id,
            reason_codes: res.reason_codes,
        }),
        MqttEvent::PingResponse(res) => MqttEventFFI::PingResponse {
            success: res.success,
        },
        MqttEvent::Error(err) => MqttEventFFI::Error {
            message: format!("{:?}", err),
        },
        MqttEvent::ReconnectNeeded => MqttEventFFI::ReconnectNeeded,
        MqttEvent::ReconnectScheduled { attempt, delay } => MqttEventFFI::ReconnectScheduled {
            attempt,
            delay_ms: delay.as_millis() as u64,
        },
    }
}

#[cfg(feature = "tls")]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct TlsMqttEngineFFI {
    engine: Mutex<TlsMqttEngine>,
    start_time: Instant,
    events: Mutex<Vec<MqttEventFFI>>,
}

#[cfg(feature = "tls")]
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl TlsMqttEngineFFI {
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new(opts: MqttOptionsFFI, tls_opts: MqttTlsOptionsFFI, server_name: String) -> Self {
        let options = MqttClientOptions::builder()
            .client_id(opts.client_id)
            .mqtt_version(opts.mqtt_version)
            .clean_start(opts.clean_start)
            .keep_alive(opts.keep_alive)
            .reconnect_base_delay_ms(opts.reconnect_base_delay_ms)
            .reconnect_max_delay_ms(opts.reconnect_max_delay_ms)
            .max_reconnect_attempts(opts.max_reconnect_attempts)
            .build();

        #[cfg(feature = "quic-openssl")]
        let _ = rustls_openssl::default_provider().install_default();
        #[cfg(not(feature = "quic-openssl"))]
        let _ = rustls::crypto::ring::default_provider().install_default();
        let crypto_builder = rustls::ClientConfig::builder();

        let mut config = if tls_opts.insecure_skip_verify {
            crypto_builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
                .with_no_client_auth()
        } else if tls_opts.ca_cert_file.is_none() {
            #[cfg(target_os = "android")]
            {
                use rustls_platform_verifier::BuilderVerifierExt;

                crypto_builder
                    .with_platform_verifier()
                    .expect("Android platform verifier must be initialized before QUIC connect")
                    .with_no_client_auth()
            }
            #[cfg(not(target_os = "android"))]
            {
                let mut root_store = rustls::RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                    root_store.add(cert).ok();
                }
                crypto_builder
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            }
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(ca_path) = tls_opts.ca_cert_file {
                if let Ok(file) = std::fs::File::open(ca_path) {
                    let mut reader = std::io::BufReader::new(file);
                    let certs = rustls_pemfile::certs(&mut reader)
                        .filter_map(|r| r.ok())
                        .collect::<Vec<_>>();
                    for cert in certs {
                        root_store.add(cert).ok();
                    }
                }
            } else {
                for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                    root_store.add(cert).ok();
                }
            }

            let mut client_auth = None;
            if let (Some(cert_path), Some(key_path)) =
                (tls_opts.client_cert_file, tls_opts.client_key_file)
            {
                if let (Ok(cert_file), Ok(key_file)) = (
                    std::fs::File::open(cert_path),
                    std::fs::File::open(key_path),
                ) {
                    let mut cert_reader = std::io::BufReader::new(cert_file);
                    let mut key_reader = std::io::BufReader::new(key_file);
                    let certs = rustls_pemfile::certs(&mut cert_reader)
                        .filter_map(|r| r.ok())
                        .collect::<Vec<_>>();
                    let key = rustls_pemfile::private_key(&mut key_reader).ok().flatten();
                    if !certs.is_empty() {
                        if let Some(key) = key {
                            client_auth = Some((certs, key));
                        }
                    }
                }
            }

            let builder = crypto_builder.with_root_certificates(root_store);
            if let Some((certs, key)) = client_auth {
                builder.with_client_auth_cert(certs, key).unwrap()
            } else {
                builder.with_no_client_auth()
            }
        };

        if !tls_opts.alpn_protocols.is_empty() {
            config.alpn_protocols = tls_opts
                .alpn_protocols
                .into_iter()
                .map(|s| s.into_bytes())
                .collect();
        } else {
            config.alpn_protocols = vec![b"mqtt".to_vec()];
        }

        if tls_opts.enable_key_log {
            config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        let engine = TlsMqttEngine::new(options, &server_name, Arc::new(config)).unwrap();
        TlsMqttEngineFFI {
            engine: Mutex::new(engine),
            start_time: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn handle_socket_data(&self, data: Vec<u8>) {
        self.engine.lock().unwrap().handle_socket_data(&data).ok();
    }

    pub fn take_socket_data(&self) -> Vec<u8> {
        self.engine.lock().unwrap().take_socket_data()
    }

    pub fn handle_tick(&self, now_ms: u64) -> Vec<MqttEventFFI> {
        let now = self.start_time + Duration::from_millis(now_ms);
        let events = self.engine.lock().unwrap().handle_tick(now);
        let mapped: Vec<_> = events.into_iter().map(map_event).collect();
        self.events.lock().unwrap().extend(mapped.iter().cloned());
        mapped
    }

    pub fn take_events(&self) -> Vec<MqttEventFFI> {
        let mut events = std::mem::take(&mut *self.events.lock().unwrap());
        let engine_events = self.engine.lock().unwrap().take_events();
        events.extend(engine_events.into_iter().map(map_event));
        events
    }

    pub fn connect(&self) {
        self.engine.lock().unwrap().connect();
    }

    pub fn publish(&self, topic: String, payload: Vec<u8>, qos: u8) -> i32 {
        let command = PublishCommand::builder()
            .topic(topic)
            .payload(payload)
            .qos(qos)
            .build()
            .unwrap();
        match self.engine.lock().unwrap().publish(command) {
            Ok(Some(pid)) => pid as i32,
            Ok(None) => 0,
            Err(_) => -1,
        }
    }

    pub fn subscribe(&self, topic_filter: String, qos: u8) -> i32 {
        let command = flowsdk::mqtt_client::commands::SubscribeCommand::single(topic_filter, qos);
        match self.engine.lock().unwrap().subscribe(command) {
            Ok(pid) => pid as i32,
            Err(_) => -1,
        }
    }

    pub fn unsubscribe(&self, topic_filter: String) -> i32 {
        let command =
            flowsdk::mqtt_client::commands::UnsubscribeCommand::from_topics(vec![topic_filter]);
        match self.engine.lock().unwrap().unsubscribe(command) {
            Ok(pid) => pid as i32,
            Err(_) => -1,
        }
    }

    pub fn disconnect(&self) {
        self.engine.lock().unwrap().disconnect();
    }

    pub fn is_connected(&self) -> bool {
        self.engine.lock().unwrap().is_connected()
    }
}

#[cfg(not(feature = "tls"))]
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct TlsMqttEngineFFI {
    start_time: Instant,
    events: Mutex<Vec<MqttEventFFI>>,
}

#[cfg(not(feature = "tls"))]
#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl TlsMqttEngineFFI {
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new(_opts: MqttOptionsFFI, _tls_opts: MqttTlsOptionsFFI, _server_name: String) -> Self {
        TlsMqttEngineFFI {
            start_time: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn handle_socket_data(&self, _data: Vec<u8>) {}

    pub fn take_socket_data(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn handle_tick(&self, _now_ms: u64) -> Vec<MqttEventFFI> {
        let _ = self.start_time;
        Vec::new()
    }

    pub fn take_events(&self) -> Vec<MqttEventFFI> {
        std::mem::take(&mut *self.events.lock().unwrap())
    }

    pub fn connect(&self) {}

    pub fn publish(&self, _topic: String, _payload: Vec<u8>, _qos: u8) -> i32 {
        -1
    }

    pub fn subscribe(&self, _topic_filter: String, _qos: u8) -> i32 {
        -1
    }

    pub fn unsubscribe(&self, _topic_filter: String) -> i32 {
        -1
    }

    pub fn disconnect(&self) {}

    pub fn is_connected(&self) -> bool {
        false
    }
}

#[derive(Debug)]
struct InsecureServerCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureServerCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        ]
    }
}

#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct QuicMqttEngineFFI {
    engine: Mutex<QuicMqttEngine>,
    start_time: Instant,
    events: Mutex<Vec<MqttEventFFI>>,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl QuicMqttEngineFFI {
    #[cfg_attr(feature = "uniffi-bindings", uniffi::constructor)]
    pub fn new(opts: MqttOptionsFFI) -> Self {
        let mut builder = MqttClientOptions::builder()
            .client_id(opts.client_id)
            .mqtt_version(opts.mqtt_version)
            .clean_start(opts.clean_start)
            .keep_alive(opts.keep_alive)
            .reconnect_base_delay_ms(opts.reconnect_base_delay_ms)
            .reconnect_max_delay_ms(opts.reconnect_max_delay_ms)
            .max_reconnect_attempts(opts.max_reconnect_attempts);

        if let Some(username) = opts.username {
            builder = builder.username(username);
        }

        if let Some(password) = opts.password {
            builder = builder.password(password);
        }

        let options = builder.build();

        let engine = QuicMqttEngine::new(options).unwrap();
        QuicMqttEngineFFI {
            engine: Mutex::new(engine),
            start_time: Instant::now(),
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn connect(
        &self,
        server_addr: String,
        server_name: String,
        tls_opts: MqttTlsOptionsFFI,
        now_ms: u64,
    ) {
        let addr: SocketAddr = server_addr.parse().unwrap();
        let now = self.start_time + Duration::from_millis(now_ms);

        #[cfg(feature = "quic-openssl")]
        let _ = rustls_openssl::default_provider().install_default();
        #[cfg(not(feature = "quic-openssl"))]
        let _ = rustls::crypto::ring::default_provider().install_default();
        let crypto_builder = rustls::ClientConfig::builder();

        let mut config = if tls_opts.insecure_skip_verify {
            crypto_builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureServerCertVerifier))
                .with_no_client_auth()
        } else if tls_opts.ca_cert_file.is_none() {
            #[cfg(target_os = "android")]
            {
                use rustls_platform_verifier::BuilderVerifierExt;

                crypto_builder
                    .with_platform_verifier()
                    .expect("Android platform verifier must be initialized before QUIC connect")
                    .with_no_client_auth()
            }
            #[cfg(not(target_os = "android"))]
            {
                let mut root_store = rustls::RootCertStore::empty();
                for cert in rustls_native_certs::load_native_certs().unwrap_or_default() {
                    root_store.add(cert).ok();
                }
                crypto_builder
                    .with_root_certificates(root_store)
                    .with_no_client_auth()
            }
        } else {
            let mut root_store = rustls::RootCertStore::empty();
            if let Some(ca_path) = tls_opts.ca_cert_file {
                if let Ok(file) = std::fs::File::open(ca_path) {
                    let mut reader = std::io::BufReader::new(file);
                    let certs = rustls_pemfile::certs(&mut reader)
                        .filter_map(|r| r.ok())
                        .collect::<Vec<_>>();
                    for cert in certs {
                        root_store.add(cert).ok();
                    }
                }
            }
            crypto_builder
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

        if !tls_opts.alpn_protocols.is_empty() {
            config.alpn_protocols = tls_opts
                .alpn_protocols
                .into_iter()
                .map(|s| s.into_bytes())
                .collect();
        } else {
            config.alpn_protocols = vec![b"mqtt".to_vec()];
        }

        if tls_opts.enable_key_log {
            config.key_log = Arc::new(rustls::KeyLogFile::new());
        }

        self.engine
            .lock()
            .unwrap()
            .connect(addr, &server_name, config, now)
            .ok();
    }

    fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }

    pub fn handle_datagram(&self, data: Vec<u8>, remote_addr: String, now_ms: u64) {
        let addr: SocketAddr = remote_addr.parse().unwrap();
        let now = self.start_time + Duration::from_millis(now_ms);
        self.engine.lock().unwrap().handle_datagram(data, addr, now);
    }

    pub fn take_outgoing_datagrams(&self) -> Vec<MqttDatagramFFI> {
        let datagrams = self.engine.lock().unwrap().take_outgoing_datagrams();
        datagrams
            .into_iter()
            .map(|(addr, data)| MqttDatagramFFI {
                addr: addr.to_string(),
                data,
            })
            .collect()
    }

    pub fn handle_tick(&self, now_ms: u64) -> Vec<MqttEventFFI> {
        let now = self.start_time + Duration::from_millis(now_ms);
        let mut engine = self.engine.lock().unwrap();
        let events = engine.handle_tick(now);
        let mapped: Vec<_> = events.into_iter().map(map_event).collect();
        self.events.lock().unwrap().extend(mapped.iter().cloned());
        mapped
    }

    pub fn take_events(&self) -> Vec<MqttEventFFI> {
        let mut events = std::mem::take(&mut *self.events.lock().unwrap());
        let engine_events = self.engine.lock().unwrap().take_events();
        events.extend(engine_events.into_iter().map(map_event));
        events
    }

    pub fn publish(&self, topic: String, payload: Vec<u8>, qos: u8) -> i32 {
        let command = PublishCommand::builder()
            .topic(topic)
            .payload(payload)
            .qos(qos)
            .build()
            .unwrap();
        match self.engine.lock().unwrap().publish(command) {
            Ok(Some(pid)) => pid as i32,
            Ok(None) => 0,
            Err(_) => -1,
        }
    }

    pub fn subscribe(&self, topic_filter: String, qos: u8) -> i32 {
        let command = flowsdk::mqtt_client::commands::SubscribeCommand::single(topic_filter, qos);
        match self.engine.lock().unwrap().subscribe(command) {
            Ok(pid) => pid as i32,
            Err(_) => -1,
        }
    }

    pub fn unsubscribe(&self, topic_filter: String) -> i32 {
        let command =
            flowsdk::mqtt_client::commands::UnsubscribeCommand::from_topics(vec![topic_filter]);
        match self.engine.lock().unwrap().unsubscribe(command) {
            Ok(pid) => pid as i32,
            Err(_) => -1,
        }
    }

    pub fn disconnect(&self) {
        self.engine.lock().unwrap().disconnect();
    }

    pub fn is_connected(&self) -> bool {
        self.engine.lock().unwrap().is_connected()
    }
}

// --- C-Compatible FFI Layer ---
// This layer provides a stable ABI for the C examples, mapping to the UniFFI objects.

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer for `client_id`
/// and returns a raw pointer to a new `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_new(
    client_id: *const c_char,
    mqtt_version: u8,
) -> *mut MqttEngineFFI {
    let client_id = if client_id.is_null() {
        None
    } else {
        Some(CStr::from_ptr(client_id).to_string_lossy().into_owned())
    };
    Box::into_raw(Box::new(MqttEngineFFI::new(client_id, mqtt_version)))
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer for `opts`
/// and returns a raw pointer to a new `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_new_with_opts(
    opts: *const MqttOptionsC,
) -> *mut MqttEngineFFI {
    if opts.is_null() {
        return std::ptr::null_mut();
    }
    let r = &*opts;
    let client_id = if r.client_id.is_null() {
        "mqtt_client".to_string()
    } else {
        CStr::from_ptr(r.client_id).to_string_lossy().into_owned()
    };
    let username = if r.username.is_null() {
        None
    } else {
        Some(CStr::from_ptr(r.username).to_string_lossy().into_owned())
    };
    let password = if r.password.is_null() {
        None
    } else {
        Some(CStr::from_ptr(r.password).to_string_lossy().into_owned())
    };

    let new_opts = MqttOptionsFFI {
        client_id,
        mqtt_version: r.mqtt_version,
        clean_start: r.clean_start,
        keep_alive: r.keep_alive,
        username,
        password,
        reconnect_base_delay_ms: r.reconnect_base_delay_ms,
        reconnect_max_delay_ms: r.reconnect_max_delay_ms,
        max_reconnect_attempts: r.max_reconnect_attempts,
    };
    Box::into_raw(Box::new(MqttEngineFFI::new_with_opts(new_opts)))
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`
/// and performs manual memory deallocation.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_free(ptr: *mut MqttEngineFFI) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_connect(ptr: *mut MqttEngineFFI) {
    if let Some(engine) = ptr.as_ref() {
        engine.connect();
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `data`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_handle_incoming(
    ptr: *mut MqttEngineFFI,
    data: *const u8,
    len: usize,
) {
    if let (Some(engine), true) = (ptr.as_ref(), !data.is_null()) {
        let buf = std::slice::from_raw_parts(data, len);
        engine.handle_incoming(buf.to_vec());
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_handle_tick(ptr: *mut MqttEngineFFI, now_ms: u64) {
    if let Some(engine) = ptr.as_ref() {
        engine.handle_tick(now_ms);
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_next_tick_ms(ptr: *mut MqttEngineFFI) -> i64 {
    if let Some(engine) = ptr.as_ref() {
        engine.next_tick_ms()
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_take_outgoing(
    ptr: *mut MqttEngineFFI,
    out_len: *mut usize,
) -> *mut u8 {
    if let Some(engine) = ptr.as_ref() {
        let bytes = engine.take_outgoing();
        if bytes.is_empty() {
            if !out_len.is_null() {
                *out_len = 0;
            }
            return std::ptr::null_mut();
        }
        if !out_len.is_null() {
            *out_len = bytes.len();
        }
        let mut b = bytes.into_boxed_slice();
        let p = b.as_mut_ptr();
        std::mem::forget(b);
        p
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it performs manual memory deallocation.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)));
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr`, `topic`, and `payload`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_publish(
    ptr: *mut MqttEngineFFI,
    topic: *const c_char,
    payload: *const u8,
    payload_len: usize,
    qos: u8,
) -> i32 {
    if let (Some(engine), true, true) = (ptr.as_ref(), !topic.is_null(), !payload.is_null()) {
        let topic = CStr::from_ptr(topic).to_string_lossy().into_owned();
        let payload = std::slice::from_raw_parts(payload, payload_len).to_vec();
        engine.publish(topic, payload, qos, None)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `topic_filter`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_subscribe(
    ptr: *mut MqttEngineFFI,
    topic_filter: *const c_char,
    qos: u8,
) -> i32 {
    if let (Some(engine), true) = (ptr.as_ref(), !topic_filter.is_null()) {
        let topic = CStr::from_ptr(topic_filter).to_string_lossy().into_owned();
        engine.subscribe(topic, qos)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `topic_filter`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_unsubscribe(
    ptr: *mut MqttEngineFFI,
    topic_filter: *const c_char,
) -> i32 {
    if let (Some(engine), true) = (ptr.as_ref(), !topic_filter.is_null()) {
        let topic = CStr::from_ptr(topic_filter).to_string_lossy().into_owned();
        engine.unsubscribe(topic)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_disconnect(ptr: *mut MqttEngineFFI) {
    if let Some(engine) = ptr.as_ref() {
        engine.disconnect();
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_is_connected(ptr: *mut MqttEngineFFI) -> c_int {
    if let Some(engine) = ptr.as_ref() {
        if engine.is_connected() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_get_version(ptr: *mut MqttEngineFFI) -> u8 {
    if let Some(engine) = ptr.as_ref() {
        engine.get_version()
    } else {
        0
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_auth(ptr: *mut MqttEngineFFI, reason_code: u8) {
    if let Some(engine) = ptr.as_ref() {
        engine.auth(reason_code);
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_handle_connection_lost(ptr: *mut MqttEngineFFI) {
    if let Some(engine) = ptr.as_ref() {
        engine.handle_connection_lost();
    }
}

/// # Safety
///
/// This function is unsafe because it performs manual memory deallocation of a `CString`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// TLS Engine C wrappers
/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `client_id`,
/// `server_name`, and `tls_opts`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_new(
    client_id: *const c_char,
    mqtt_version: u8,
    server_name: *const c_char,
    tls_opts: *const MqttTlsOptionsC,
) -> *mut TlsMqttEngineFFI {
    let client_id = if client_id.is_null() {
        "mqtt_client".to_string()
    } else {
        CStr::from_ptr(client_id).to_string_lossy().into_owned()
    };
    let server_name = if server_name.is_null() {
        "localhost".to_string()
    } else {
        CStr::from_ptr(server_name).to_string_lossy().into_owned()
    };

    let opts = MqttOptionsFFI {
        client_id,
        mqtt_version,
        clean_start: true,
        keep_alive: 60,
        username: None,
        password: None,
        reconnect_base_delay_ms: 1000,
        reconnect_max_delay_ms: 30000,
        max_reconnect_attempts: 0,
    };

    let tls_opts_v = if tls_opts.is_null() {
        MqttTlsOptionsFFI {
            ca_cert_file: None,
            client_cert_file: None,
            client_key_file: None,
            insecure_skip_verify: false,
            alpn_protocols: vec!["mqtt".to_string()],
            enable_key_log: false,
        }
    } else {
        let r = &*tls_opts;
        let ca_cert_file = if r.ca_cert_file.is_null() {
            None
        } else {
            Some(
                CStr::from_ptr(r.ca_cert_file)
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        let client_cert_file = if r.client_cert_file.is_null() {
            None
        } else {
            Some(
                CStr::from_ptr(r.client_cert_file)
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        let client_key_file = if r.client_key_file.is_null() {
            None
        } else {
            Some(
                CStr::from_ptr(r.client_key_file)
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        let alpn_protocols = if r.alpn.is_null() {
            vec!["mqtt".to_string()]
        } else {
            vec![CStr::from_ptr(r.alpn).to_string_lossy().into_owned()]
        };
        MqttTlsOptionsFFI {
            ca_cert_file,
            client_cert_file,
            client_key_file,
            insecure_skip_verify: r.insecure_skip_verify != 0,
            alpn_protocols,
            enable_key_log: r.enable_key_log != 0,
        }
    };

    Box::into_raw(Box::new(TlsMqttEngineFFI::new(
        opts,
        tls_opts_v,
        server_name,
    )))
}

/// # Safety
///
/// This function is unsafe because it performs manual memory deallocation of a `TlsMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_free(ptr: *mut TlsMqttEngineFFI) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `TlsMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_connect(ptr: *mut TlsMqttEngineFFI) {
    if let Some(engine) = ptr.as_ref() {
        engine.connect();
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `data`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_handle_socket_data(
    ptr: *mut TlsMqttEngineFFI,
    data: *const u8,
    len: usize,
) {
    if let (Some(engine), true) = (ptr.as_ref(), !data.is_null()) {
        let buf = std::slice::from_raw_parts(data, len);
        engine.handle_socket_data(buf.to_vec());
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `out_len`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_take_socket_data(
    ptr: *mut TlsMqttEngineFFI,
    out_len: *mut usize,
) -> *mut u8 {
    if let Some(engine) = ptr.as_ref() {
        let bytes = engine.take_socket_data();
        if bytes.is_empty() {
            if !out_len.is_null() {
                *out_len = 0;
            }
            return std::ptr::null_mut();
        }
        if !out_len.is_null() {
            *out_len = bytes.len();
        }
        let mut b = bytes.into_boxed_slice();
        let p = b.as_mut_ptr();
        std::mem::forget(b);
        p
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `TlsMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_handle_tick(ptr: *mut TlsMqttEngineFFI, now_ms: u64) {
    if let Some(engine) = ptr.as_ref() {
        engine.handle_tick(now_ms);
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr`, `topic`, and `payload`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_publish(
    ptr: *mut TlsMqttEngineFFI,
    topic: *const c_char,
    payload: *const u8,
    payload_len: usize,
    qos: u8,
) -> i32 {
    if let (Some(engine), true, true) = (ptr.as_ref(), !topic.is_null(), !payload.is_null()) {
        let topic = CStr::from_ptr(topic).to_string_lossy().into_owned();
        let payload = std::slice::from_raw_parts(payload, payload_len).to_vec();
        engine.publish(topic, payload, qos)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `topic_filter`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_subscribe(
    ptr: *mut TlsMqttEngineFFI,
    topic_filter: *const c_char,
    qos: u8,
) -> i32 {
    if let (Some(engine), true) = (ptr.as_ref(), !topic_filter.is_null()) {
        let topic = CStr::from_ptr(topic_filter).to_string_lossy().into_owned();
        engine.subscribe(topic, qos)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `topic_filter`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_unsubscribe(
    ptr: *mut TlsMqttEngineFFI,
    topic_filter: *const c_char,
) -> i32 {
    if let (Some(engine), true) = (ptr.as_ref(), !topic_filter.is_null()) {
        let topic = CStr::from_ptr(topic_filter).to_string_lossy().into_owned();
        engine.unsubscribe(topic)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `TlsMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_disconnect(ptr: *mut TlsMqttEngineFFI) {
    if let Some(engine) = ptr.as_ref() {
        engine.disconnect();
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `TlsMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_is_connected(ptr: *mut TlsMqttEngineFFI) -> i32 {
    if let Some(engine) = ptr.as_ref() {
        if engine.is_connected() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`
/// and returns an allocated `c_char` pointer that must be freed using `mqtt_engine_free_string`.
#[no_mangle]
#[cfg(feature = "uniffi-bindings")]
pub unsafe extern "C" fn mqtt_engine_take_events(ptr: *mut MqttEngineFFI) -> *mut c_char {
    if let Some(engine) = ptr.as_ref() {
        let events = engine.take_events();
        let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
        CString::new(json).unwrap().into_raw()
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `TlsMqttEngineFFI`
/// and returns an allocated `c_char` pointer that must be freed using `mqtt_engine_free_string`.
#[no_mangle]
#[cfg(feature = "uniffi-bindings")]
pub unsafe extern "C" fn mqtt_tls_engine_take_events(ptr: *mut TlsMqttEngineFFI) -> *mut c_char {
    if let Some(engine) = ptr.as_ref() {
        let events = engine.take_events();
        let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
        CString::new(json).unwrap().into_raw()
    } else {
        std::ptr::null_mut()
    }
}

// QUIC Engine C wrappers
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer for `client_id`
/// and returns a raw pointer to a new `QuicMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_new(
    client_id: *const c_char,
    mqtt_version: u8,
) -> *mut QuicMqttEngineFFI {
    let client_id = if client_id.is_null() {
        "mqtt_client".to_string()
    } else {
        CStr::from_ptr(client_id).to_string_lossy().into_owned()
    };
    let opts = MqttOptionsFFI {
        client_id,
        mqtt_version,
        clean_start: true,
        keep_alive: 60,
        username: None,
        password: None,
        reconnect_base_delay_ms: 1000,
        reconnect_max_delay_ms: 30000,
        max_reconnect_attempts: 0,
    };
    Box::into_raw(Box::new(QuicMqttEngineFFI::new(opts)))
}

/// # Safety
///
/// This function is unsafe because it performs manual memory deallocation of a `QuicMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_free(ptr: *mut QuicMqttEngineFFI) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr`, `server_addr`,
/// `server_name`, and `tls_opts`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_connect(
    ptr: *mut QuicMqttEngineFFI,
    server_addr: *const c_char,
    server_name: *const c_char,
    tls_opts: *const MqttTlsOptionsC,
) -> i32 {
    if let (Some(engine), true, true) =
        (ptr.as_ref(), !server_addr.is_null(), !server_name.is_null())
    {
        let server_addr = CStr::from_ptr(server_addr).to_string_lossy().into_owned();
        let server_name = CStr::from_ptr(server_name).to_string_lossy().into_owned();

        let tls_opts_v = if tls_opts.is_null() {
            MqttTlsOptionsFFI {
                ca_cert_file: None,
                client_cert_file: None,
                client_key_file: None,
                insecure_skip_verify: false,
                alpn_protocols: vec!["mqtt".to_string()],
                enable_key_log: false,
            }
        } else {
            let r = &*tls_opts;
            let ca_cert_file = if r.ca_cert_file.is_null() {
                None
            } else {
                Some(
                    CStr::from_ptr(r.ca_cert_file)
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            let client_cert_file = if r.client_cert_file.is_null() {
                None
            } else {
                Some(
                    CStr::from_ptr(r.client_cert_file)
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            let client_key_file = if r.client_key_file.is_null() {
                None
            } else {
                Some(
                    CStr::from_ptr(r.client_key_file)
                        .to_string_lossy()
                        .into_owned(),
                )
            };
            MqttTlsOptionsFFI {
                ca_cert_file,
                client_cert_file,
                client_key_file,
                insecure_skip_verify: r.insecure_skip_verify != 0,
                alpn_protocols: vec!["mqtt".to_string()],
                enable_key_log: r.enable_key_log != 0,
            }
        };

        engine.connect(server_addr, server_name, tls_opts_v, engine.elapsed_ms());
        0
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr`, `data`, and `remote_addr`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_handle_datagram(
    ptr: *mut QuicMqttEngineFFI,
    data: *const u8,
    len: usize,
    remote_addr: *const c_char,
) {
    if let (Some(engine), true, true) = (ptr.as_ref(), !data.is_null(), !remote_addr.is_null()) {
        let buf = std::slice::from_raw_parts(data, len);
        let remote_addr = CStr::from_ptr(remote_addr).to_string_lossy().into_owned();
        engine.handle_datagram(buf.to_vec(), remote_addr, engine.elapsed_ms());
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `out_count`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_take_outgoing_datagrams(
    ptr: *mut QuicMqttEngineFFI,
    out_count: *mut usize,
) -> *mut MqttDatagramC {
    if let Some(engine) = ptr.as_ref() {
        let dgs = engine.take_outgoing_datagrams();
        if dgs.is_empty() {
            if !out_count.is_null() {
                *out_count = 0;
            }
            return std::ptr::null_mut();
        }

        let mut result = Vec::with_capacity(dgs.len());
        for dg in dgs {
            let addr = CString::new(dg.addr).unwrap().into_raw();
            let data_len = dg.data.len();
            let mut b = dg.data.into_boxed_slice();
            let data = b.as_mut_ptr();
            std::mem::forget(b);
            result.push(MqttDatagramC {
                addr,
                data,
                data_len,
            });
        }

        if !out_count.is_null() {
            *out_count = result.len();
        }
        let mut b = result.into_boxed_slice();
        let p = b.as_mut_ptr();
        std::mem::forget(b);
        p
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it performs manual memory deallocation of a datagram slice.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_free_datagrams(ptr: *mut MqttDatagramC, count: usize) {
    if !ptr.is_null() {
        let slice = std::slice::from_raw_parts_mut(ptr, count);
        for dg in &mut *slice {
            if !dg.addr.is_null() {
                drop(CString::from_raw(dg.addr));
            }
            if !dg.data.is_null() {
                drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                    dg.data,
                    dg.data_len,
                )));
            }
        }
        drop(Box::from_raw(slice));
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `QuicMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_handle_tick(ptr: *mut QuicMqttEngineFFI, now_ms: u64) {
    if let Some(engine) = ptr.as_ref() {
        engine.handle_tick(now_ms);
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `QuicMqttEngineFFI`
/// and returns an allocated `c_char` pointer that must be freed using `mqtt_engine_free_string`.
#[no_mangle]
#[cfg(feature = "uniffi-bindings")]
pub unsafe extern "C" fn mqtt_quic_engine_take_events(ptr: *mut QuicMqttEngineFFI) -> *mut c_char {
    if let Some(engine) = ptr.as_ref() {
        let events = engine.take_events();
        let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
        CString::new(json).unwrap().into_raw()
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr`, `topic`, and `payload`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_publish(
    ptr: *mut QuicMqttEngineFFI,
    topic: *const c_char,
    payload: *const u8,
    payload_len: usize,
    qos: u8,
) -> i32 {
    if let (Some(engine), true, true) = (ptr.as_ref(), !topic.is_null(), !payload.is_null()) {
        let topic = CStr::from_ptr(topic).to_string_lossy().into_owned();
        let payload = std::slice::from_raw_parts(payload, payload_len).to_vec();
        engine.publish(topic, payload, qos)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `topic_filter`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_subscribe(
    ptr: *mut QuicMqttEngineFFI,
    topic_filter: *const c_char,
    qos: u8,
) -> i32 {
    if let (Some(engine), true) = (ptr.as_ref(), !topic_filter.is_null()) {
        let topic = CStr::from_ptr(topic_filter).to_string_lossy().into_owned();
        engine.subscribe(topic, qos)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `topic_filter`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_unsubscribe(
    ptr: *mut QuicMqttEngineFFI,
    topic_filter: *const c_char,
) -> i32 {
    if let (Some(engine), true) = (ptr.as_ref(), !topic_filter.is_null()) {
        let topic = CStr::from_ptr(topic_filter).to_string_lossy().into_owned();
        engine.unsubscribe(topic)
    } else {
        -1
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `QuicMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_disconnect(ptr: *mut QuicMqttEngineFFI) {
    if let Some(engine) = ptr.as_ref() {
        engine.disconnect();
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `QuicMqttEngineFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_is_connected(ptr: *mut QuicMqttEngineFFI) -> i32 {
    if let Some(engine) = ptr.as_ref() {
        if engine.is_connected() {
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[repr(C)]
pub struct MqttOptionsC {
    pub client_id: *const c_char,
    pub mqtt_version: u8,
    pub clean_start: bool,
    pub keep_alive: u16,
    pub username: *const c_char,
    pub password: *const c_char,
    pub reconnect_base_delay_ms: u64,
    pub reconnect_max_delay_ms: u64,
    pub max_reconnect_attempts: u32,
}

#[repr(C)]
pub struct MqttTlsOptionsC {
    pub ca_cert_file: *const c_char,
    pub client_cert_file: *const c_char,
    pub client_key_file: *const c_char,
    pub alpn: *const c_char,
    pub insecure_skip_verify: u8,
    pub enable_key_log: u8,
}

#[repr(C)]
pub struct MqttDatagramC {
    pub addr: *mut c_char,
    pub data: *mut u8,
    pub data_len: usize,
}

// Event Inspection API for C (Native Structs)

// Actually, let's just use a dedicated "C Event List" object to manage the lifetime.
#[cfg_attr(feature = "uniffi-bindings", derive(uniffi::Object))]
pub struct MqttEventListFFI {
    events: Vec<MqttEventFFI>,
}

#[cfg_attr(feature = "uniffi-bindings", uniffi::export)]
impl MqttEventListFFI {
    pub fn len(&self) -> u32 {
        self.events.len() as u32
    }
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }
    pub fn get(&self, index: u32) -> Option<MqttEventFFI> {
        self.events.get(index as usize).cloned()
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEngineFFI`
/// and returns an allocated `MqttEventListFFI` pointer that must be freed with `mqtt_event_list_free`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_engine_take_events_list(
    ptr: *mut MqttEngineFFI,
) -> *mut MqttEventListFFI {
    if let Some(engine) = ptr.as_ref() {
        let events = engine.take_events();
        Box::into_raw(Box::new(MqttEventListFFI { events }))
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it performs manual memory deallocation of a `MqttEventListFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_free(ptr: *mut MqttEventListFFI) {
    if !ptr.is_null() {
        drop(Box::from_raw(ptr));
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_len(ptr: *const MqttEventListFFI) -> usize {
    if let Some(list) = ptr.as_ref() {
        list.events.len()
    } else {
        0
    }
}

// I'll provide a way to get event details as raw types
/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_tag(ptr: *const MqttEventListFFI, index: usize) -> u8 {
    if let Some(list) = ptr.as_ref() {
        if let Some(event) = list.events.get(index) {
            match event {
                MqttEventFFI::Connected(_) => 1,
                MqttEventFFI::Disconnected { .. } => 2,
                MqttEventFFI::MessageReceived(_) => 3,
                MqttEventFFI::Published(_) => 4,
                MqttEventFFI::Subscribed(_) => 5,
                MqttEventFFI::Unsubscribed(_) => 6,
                MqttEventFFI::PingResponse { .. } => 7,
                MqttEventFFI::Error { .. } => 8,
                MqttEventFFI::ReconnectNeeded => 9,
                MqttEventFFI::ReconnectScheduled { .. } => 10,
            }
        } else {
            0
        }
    } else {
        0
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_connected_rc(
    ptr: *const MqttEventListFFI,
    index: usize,
) -> u8 {
    if let Some(list) = ptr.as_ref() {
        if let Some(MqttEventFFI::Connected(res)) = list.events.get(index) {
            res.reason_code
        } else {
            0
        }
    } else {
        0
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`
/// and returns an allocated `c_char` pointer that must be freed using `mqtt_engine_free_string`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_message_topic(
    ptr: *const MqttEventListFFI,
    index: usize,
) -> *mut c_char {
    if let Some(list) = ptr.as_ref() {
        if let Some(MqttEventFFI::MessageReceived(msg)) = list.events.get(index) {
            return CString::new(msg.topic.clone()).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

/// # Safety
///
/// This function is unsafe because it dereferences raw pointers for `ptr` and `out_len`,
/// and returns an allocated `u8` pointer that must be freed with `mqtt_engine_free_bytes`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_message_payload(
    ptr: *const MqttEventListFFI,
    index: usize,
    out_len: *mut usize,
) -> *mut u8 {
    if let Some(list) = ptr.as_ref() {
        if let Some(MqttEventFFI::MessageReceived(msg)) = list.events.get(index) {
            if !out_len.is_null() {
                *out_len = msg.payload.len();
            }
            let mut b = msg.payload.clone().into_boxed_slice();
            let p = b.as_mut_ptr();
            std::mem::forget(b);
            return p;
        }
    }
    std::ptr::null_mut()
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_published_pid(
    ptr: *const MqttEventListFFI,
    index: usize,
) -> i32 {
    if let Some(list) = ptr.as_ref() {
        if let Some(MqttEventFFI::Published(res)) = list.events.get(index) {
            return res.packet_id.map(|id| id as i32).unwrap_or(0);
        }
    }
    -1
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_subscribed_pid(
    ptr: *const MqttEventListFFI,
    index: usize,
) -> i32 {
    if let Some(list) = ptr.as_ref() {
        if let Some(MqttEventFFI::Subscribed(res)) = list.events.get(index) {
            return res.packet_id as i32;
        }
    }
    -1
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `MqttEventListFFI`
/// and returns an allocated `c_char` pointer that must be freed using `mqtt_engine_free_string`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_event_list_get_error_message(
    ptr: *const MqttEventListFFI,
    index: usize,
) -> *mut c_char {
    if let Some(list) = ptr.as_ref() {
        if let Some(MqttEventFFI::Error { message }) = list.events.get(index) {
            return CString::new(message.clone()).unwrap().into_raw();
        }
    }
    std::ptr::null_mut()
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `QuicMqttEngineFFI`
/// and returns an allocated `MqttEventListFFI` pointer that must be freed with `mqtt_event_list_free`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_quic_engine_take_events_list(
    ptr: *mut QuicMqttEngineFFI,
) -> *mut MqttEventListFFI {
    if let Some(engine) = ptr.as_ref() {
        let events = engine.take_events();
        Box::into_raw(Box::new(MqttEventListFFI { events }))
    } else {
        std::ptr::null_mut()
    }
}

/// # Safety
///
/// This function is unsafe because it dereferences a raw pointer to `TlsMqttEngineFFI`
/// and returns an allocated `MqttEventListFFI` pointer that must be freed with `mqtt_event_list_free`.
#[no_mangle]
pub unsafe extern "C" fn mqtt_tls_engine_take_events_list(
    ptr: *mut TlsMqttEngineFFI,
) -> *mut MqttEventListFFI {
    if let Some(engine) = ptr.as_ref() {
        let events = engine.take_events();
        Box::into_raw(Box::new(MqttEventListFFI { events }))
    } else {
        std::ptr::null_mut()
    }
}
