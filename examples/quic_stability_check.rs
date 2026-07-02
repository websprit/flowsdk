// SPDX-License-Identifier: MPL-2.0

use clap::Parser;
use flowsdk::mqtt_client::client::{ConnectionResult, PingResult};
use flowsdk::mqtt_client::{
    MqttClientError, MqttClientOptions, TokioAsyncClientConfig, TokioAsyncMqttClient,
    TokioMqttEventHandler,
};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Parser)]
#[command(
    name = "quic_stability_check",
    about = "Small macOS-friendly MQTT over QUIC stability checker"
)]
struct Args {
    #[arg(long)]
    host: String,

    #[arg(long)]
    port: u16,

    #[arg(long = "server-name")]
    server_name: Option<String>,

    #[arg(long)]
    username: Option<String>,

    #[arg(long)]
    password: Option<String>,

    #[arg(long, default_value_t = 10)]
    clients: usize,

    #[arg(long = "duration-secs", default_value_t = 120)]
    duration_secs: u64,

    #[arg(long = "keep-alive", default_value_t = 30)]
    keep_alive: u16,

    #[arg(long = "manual-ping-interval-secs", default_value_t = 0)]
    manual_ping_interval_secs: u64,

    #[arg(long = "connect-timeout-ms", default_value_t = 15000)]
    connect_timeout_ms: u64,

    #[arg(long = "quic-insecure", default_value_t = false)]
    quic_insecure: bool,

    #[arg(long = "quic-enable-0rtt", default_value_t = false)]
    quic_enable_0rtt: bool,
}

#[derive(Default)]
struct Stats {
    connected: AtomicU64,
    connect_failed: AtomicU64,
    handler_errors: AtomicU64,
    disconnected: AtomicU64,
    connection_lost: AtomicU64,
    manual_pings_sent: AtomicU64,
    ping_responses: AtomicU64,
    completed: AtomicU64,
}

#[derive(Clone)]
struct CountingHandler {
    client_index: usize,
    stats: Arc<Stats>,
    connection_lost: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl TokioMqttEventHandler for CountingHandler {
    async fn on_connected(&mut self, result: &ConnectionResult) {
        if !result.is_success() {
            self.stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn on_disconnected(&mut self, _reason: Option<u8>) {
        self.stats.disconnected.fetch_add(1, Ordering::Relaxed);
    }

    async fn on_error(&mut self, error: &MqttClientError) {
        self.stats.handler_errors.fetch_add(1, Ordering::Relaxed);
        eprintln!("client {} error: {}", self.client_index, error);
    }

    async fn on_ping_response(&mut self, result: &PingResult) {
        if result.success {
            self.stats.ping_responses.fetch_add(1, Ordering::Relaxed);
        }
    }

    async fn on_connection_lost(&mut self) {
        self.stats.connection_lost.fetch_add(1, Ordering::Relaxed);
        self.connection_lost.store(true, Ordering::Relaxed);
        eprintln!("client {} connection lost", self.client_index);
    }
}

#[tokio::main]
async fn main() {
    init_crypto_provider();

    let args = Args::parse();
    if args.clients == 0 {
        eprintln!("--clients must be greater than 0");
        std::process::exit(2);
    }

    let stats = Arc::new(Stats::default());
    let connect_latencies_ms = Arc::new(Mutex::new(Vec::with_capacity(args.clients)));
    let run_id = unique_run_id();

    println!("MQTT over QUIC connection stability check");
    println!("  target: quic://{}:{}", args.host, args.port);
    println!(
        "  server_name: {}",
        args.server_name.as_deref().unwrap_or(&args.host)
    );
    println!("  clients: {}", args.clients);
    println!("  duration: {} seconds", args.duration_secs);
    println!("  keep_alive: {} seconds", args.keep_alive);
    println!(
        "  manual_ping_interval: {}",
        if args.manual_ping_interval_secs == 0 {
            "disabled".to_string()
        } else {
            format!("{} seconds", args.manual_ping_interval_secs)
        }
    );
    println!("  publish/subscribe: disabled");
    println!(
        "  tls_verify: {}",
        if args.quic_insecure { "off" } else { "on" }
    );
    println!(
        "  auth: {}",
        if args.username.is_some() || args.password.is_some() {
            "configured"
        } else {
            "disabled"
        }
    );
    println!(
        "  quic_0rtt: {}",
        if args.quic_enable_0rtt { "on" } else { "off" }
    );
    println!();

    let mut tasks = Vec::with_capacity(args.clients);
    for index in 0..args.clients {
        let args = args.clone();
        let stats = Arc::clone(&stats);
        let connect_latencies_ms = Arc::clone(&connect_latencies_ms);
        let client_id = format!("flowsdk_quic_stability_{}_{}", run_id, index);
        tasks.push(tokio::spawn(async move {
            run_client(index, client_id, args, stats, connect_latencies_ms).await
        }));
    }

    let reporter_stats = Arc::clone(&stats);
    let reporter = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            print_snapshot(&reporter_stats);
        }
    });

    let mut task_failures = 0u64;
    for task in tasks {
        match task.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                task_failures += 1;
                eprintln!("client task failed: {}", err);
            }
            Err(err) => {
                task_failures += 1;
                eprintln!("client task panicked or was cancelled: {}", err);
            }
        }
    }
    reporter.abort();

    println!();
    println!("Final result");
    print_snapshot(&stats);
    print_connect_latency_summary(&connect_latencies_ms);
    println!("  task_failures: {}", task_failures);

    let connected = stats.connected.load(Ordering::Relaxed);
    let completed = stats.completed.load(Ordering::Relaxed);
    let failed = stats.connect_failed.load(Ordering::Relaxed)
        + stats.handler_errors.load(Ordering::Relaxed)
        + stats.connection_lost.load(Ordering::Relaxed)
        + task_failures;

    if connected == args.clients as u64 && completed == args.clients as u64 && failed == 0 {
        println!("status: PASS");
    } else {
        println!("status: FAIL");
        std::process::exit(1);
    }
}

async fn run_client(
    index: usize,
    client_id: String,
    args: Args,
    stats: Arc<Stats>,
    connect_latencies_ms: Arc<Mutex<Vec<u128>>>,
) -> Result<(), String> {
    let peer = format!("quic://{}:{}", args.host, args.port);
    let mut mqtt_options = MqttClientOptions::builder()
        .peer(peer)
        .client_id(client_id)
        .keep_alive(args.keep_alive)
        .clean_start(true)
        .mqtt_version(5);

    if let Some(username) = args.username.clone() {
        mqtt_options = mqtt_options.username(username);
    }

    if let Some(password) = args.password.clone() {
        mqtt_options = mqtt_options.password(password.into_bytes());
    }

    let mqtt_options = mqtt_options.build();

    let mut config = TokioAsyncClientConfig::builder()
        .auto_reconnect(false)
        .connect_timeout_ms(args.connect_timeout_ms)
        .quic_enable_0rtt(args.quic_enable_0rtt)
        .quic_datagram_receive_buffer_size(0);

    if args.quic_insecure {
        config = config.quic_insecure_skip_verify(true);
    }

    let connection_lost = Arc::new(AtomicBool::new(false));
    let client = TokioAsyncMqttClient::new(
        mqtt_options,
        Box::new(CountingHandler {
            client_index: index,
            stats: Arc::clone(&stats),
            connection_lost: Arc::clone(&connection_lost),
        }),
        config.build(),
    )
    .await
    .map_err(|e| format!("create client {}: {}", index, e))?;

    let connect_started = Instant::now();
    let connected = client.connect_sync().await.map_err(|e| {
        stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        format!("connect client {}: {}", index, e)
    })?;
    let connect_elapsed_ms = connect_started.elapsed().as_millis();
    if !connected.is_success() {
        stats.connect_failed.fetch_add(1, Ordering::Relaxed);
        return Err(format!(
            "connect client {} rejected with reason code {}",
            index, connected.reason_code
        ));
    }
    stats.connected.fetch_add(1, Ordering::Relaxed);
    {
        let mut latencies = connect_latencies_ms.lock().unwrap();
        latencies.push(connect_elapsed_ms);
    }
    println!("client {} connected in {} ms", index, connect_elapsed_ms);

    let mut elapsed_secs = 0;
    while elapsed_secs < args.duration_secs {
        tokio::time::sleep(Duration::from_secs(1)).await;
        elapsed_secs += 1;
        if connection_lost.load(Ordering::Relaxed) {
            let _ = client.disconnect().await;
            let _ = client.shutdown().await;
            return Err(format!("client {} lost connection during hold", index));
        }
        if args.manual_ping_interval_secs > 0 && elapsed_secs % args.manual_ping_interval_secs == 0
        {
            client.ping().await.map_err(|e| {
                stats.handler_errors.fetch_add(1, Ordering::Relaxed);
                format!("manual ping client {}: {}", index, e)
            })?;
            stats.manual_pings_sent.fetch_add(1, Ordering::Relaxed);
        }
    }
    stats.completed.fetch_add(1, Ordering::Relaxed);

    client
        .disconnect()
        .await
        .map_err(|e| format!("disconnect client {}: {}", index, e))?;
    client
        .shutdown()
        .await
        .map_err(|e| format!("shutdown client {}: {}", index, e))?;
    Ok(())
}

fn print_snapshot(stats: &Stats) {
    println!(
        "  connected: {} | completed: {} | connect_failed: {} | manual_pings: {} | ping_responses: {} | handler_errors: {} | connection_lost: {} | disconnected: {}",
        stats.connected.load(Ordering::Relaxed),
        stats.completed.load(Ordering::Relaxed),
        stats.connect_failed.load(Ordering::Relaxed),
        stats.manual_pings_sent.load(Ordering::Relaxed),
        stats.ping_responses.load(Ordering::Relaxed),
        stats.handler_errors.load(Ordering::Relaxed),
        stats.connection_lost.load(Ordering::Relaxed),
        stats.disconnected.load(Ordering::Relaxed),
    );
}

fn print_connect_latency_summary(connect_latencies_ms: &Arc<Mutex<Vec<u128>>>) {
    let latencies = connect_latencies_ms.lock().unwrap();
    if latencies.is_empty() {
        println!("  connect_latency_ms: no successful connections");
        return;
    }

    let min = latencies.iter().min().copied().unwrap_or(0);
    let max = latencies.iter().max().copied().unwrap_or(0);
    let sum: u128 = latencies.iter().sum();
    let avg = sum as f64 / latencies.len() as f64;

    println!(
        "  connect_latency_ms: count={} min={} avg={:.2} max={}",
        latencies.len(),
        min,
        avg,
        max
    );
}

fn unique_run_id() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

fn init_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
