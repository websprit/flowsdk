package io.emqx.flowsdk.examples.quicstability

import android.app.Activity
import android.content.Context
import android.content.SharedPreferences
import android.graphics.Color
import android.graphics.Rect
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.text.method.TransformationMethod
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import java.net.InetSocketAddress
import java.net.URI
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.util.Locale
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import uniffi.flowsdk_ffi.MqttEventFfi
import uniffi.flowsdk_ffi.MqttOptionsFfi
import uniffi.flowsdk_ffi.MqttTlsOptionsFfi
import uniffi.flowsdk_ffi.QuicMqttEngineFfi

class MainActivity : Activity() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private var runner: StabilityRunner? = null
    private lateinit var prefs: SharedPreferences

    private lateinit var logView: TextView
    private lateinit var hostInput: EditText
    private lateinit var portInput: EditText
    private lateinit var serverNameInput: EditText
    private lateinit var usernameInput: EditText
    private lateinit var passwordInput: EditText
    private lateinit var startButton: Button
    private lateinit var stopButton: Button

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        actionBar?.hide()
        prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val verifierInitialized = PlatformVerifierNative.init(applicationContext)

        logView = TextView(this).apply {
            textSize = 12f
            setTextColor(Color.rgb(17, 24, 39))
            setPadding(dp(16), dp(12), dp(16), dp(12))
            setTextIsSelectable(true)
            text = if (verifierInitialized) {
                "Ready. Tap Start to hold 10 MQTT over QUIC connections for 120s.\n"
            } else {
                "Android platform verifier init failed. TLS verification may fail.\n"
            }
        }
        hostInput = EditText(this).apply {
            hint = "Host"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            setText(prefs.getString(PREF_HOST, ""))
        }
        portInput = EditText(this).apply {
            hint = "Port"
            inputType = InputType.TYPE_CLASS_NUMBER
            setSingleLine(true)
            setText(prefs.getString(PREF_PORT, ""))
        }
        serverNameInput = EditText(this).apply {
            hint = "Server name (optional)"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            setSingleLine(true)
            setText(prefs.getString(PREF_SERVER_NAME, ""))
        }
        usernameInput = EditText(this).apply {
            hint = "Username"
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_NORMAL
            setSingleLine(true)
            setText(prefs.getString(PREF_USERNAME, ""))
        }
        passwordInput = EditText(this).apply {
            hint = "Password"
            setSingleLine(true)
            inputType = InputType.TYPE_CLASS_TEXT or
                InputType.TYPE_TEXT_VARIATION_PASSWORD or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            transformationMethod = AlwaysMaskedTransformationMethod
            setText(prefs.getString(PREF_PASSWORD, ""))
        }
        startButton = Button(this).apply {
            text = "Start 10 connections / 120s"
            setOnClickListener {
                logView.text = ""
                runner?.stop()
                val target = parseTargetInput(
                    rawHost = hostInput.text.toString(),
                    rawPort = portInput.text.toString(),
                    rawServerName = serverNameInput.text.toString(),
                )
                if (target == null) {
                    appendLog("Host and valid port are required.")
                    return@setOnClickListener
                }
                hostInput.setText(target.host)
                portInput.setText(target.port.toString())
                if (serverNameInput.text.toString().trim().isBlank()) {
                    serverNameInput.setText("")
                }
                saveInputs()
                val activeRunner = NativeQuicStabilityRunnerInstance(
                    config = StabilityConfig(
                        host = target.host,
                        port = target.port,
                        serverName = target.serverName,
                        username = usernameInput.text.toString().ifBlank { null },
                        password = passwordInput.text.toString().ifBlank { null },
                        clients = 10,
                        durationSecs = 120,
                        keepAliveSecs = 30u,
                        insecureSkipVerify = false,
                    ),
                    onLog = ::appendLog,
                )
                runner = activeRunner
                activeRunner.start()
            }
        }
        stopButton = Button(this).apply {
            text = "Stop"
            setOnClickListener { runner?.stop() }
        }

        val inputs = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(12), 0, dp(12), dp(8))
            addView(
                hostInput,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
            addView(
                portInput,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
            addView(
                serverNameInput,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
            addView(
                usernameInput,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
            addView(
                passwordInput,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                ),
            )
        }
        val buttons = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            setPadding(dp(12), 0, dp(12), dp(8))
            addView(
                startButton,
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
            )
            addView(
                stopButton,
                LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f),
            )
        }
        val scroll = ScrollView(this).apply {
            setBackgroundColor(Color.WHITE)
            addView(logView)
        }
        val title = TextView(this).apply {
            text = "FlowSDK QUIC Stability"
            textSize = 20f
            setTextColor(Color.rgb(17, 24, 39))
            setPadding(dp(16), dp(20), dp(16), dp(4))
        }
        val subtitle = TextView(this).apply {
            text = "Enter QUIC target and credentials"
            textSize = 13f
            setTextColor(Color.rgb(75, 85, 99))
            setPadding(dp(16), 0, dp(16), dp(12))
        }
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.rgb(248, 250, 252))
            setPadding(0, statusBarHeight(), 0, 0)
            addView(title)
            addView(subtitle)
            addView(inputs)
            addView(buttons)
            addView(
                scroll,
                LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    0,
                    1f,
                ),
            )
        }
        setContentView(root)
    }

    override fun onDestroy() {
        runner?.stop()
        super.onDestroy()
    }

    private fun appendLog(line: String) {
        mainHandler.post {
            logView.append(line)
            logView.append("\n")
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun statusBarHeight(): Int {
        val resourceId = resources.getIdentifier("status_bar_height", "dimen", "android")
        return if (resourceId > 0) resources.getDimensionPixelSize(resourceId) else 0
    }

    private fun saveInputs() {
        prefs.edit()
            .putString(PREF_HOST, hostInput.text.toString().trim())
            .putString(PREF_PORT, portInput.text.toString().trim())
            .putString(PREF_SERVER_NAME, serverNameInput.text.toString().trim())
            .putString(PREF_USERNAME, usernameInput.text.toString())
            .putString(PREF_PASSWORD, passwordInput.text.toString())
            .apply()
    }
}

private const val PREFS_NAME = "quic_stability_check"
private const val PREF_HOST = "host"
private const val PREF_PORT = "port"
private const val PREF_SERVER_NAME = "server_name"
private const val PREF_USERNAME = "username"
private const val PREF_PASSWORD = "password"

private object PlatformVerifierNative {
    init {
        System.loadLibrary("flowsdk_ffi")
    }

    @JvmStatic
    external fun init(context: Context): Boolean
}

private object AlwaysMaskedTransformationMethod : TransformationMethod {
    override fun getTransformation(source: CharSequence?, view: View?): CharSequence {
        return MaskedCharSequence(source ?: "")
    }

    override fun onFocusChanged(
        view: View?,
        sourceText: CharSequence?,
        focused: Boolean,
        direction: Int,
        previouslyFocusedRect: Rect?,
    ) = Unit
}

private class MaskedCharSequence(private val source: CharSequence) : CharSequence {
    override val length: Int
        get() = source.length

    override fun get(index: Int): Char = '*'

    override fun subSequence(startIndex: Int, endIndex: Int): CharSequence =
        "*".repeat((endIndex - startIndex).coerceAtLeast(0))
}

private data class StabilityConfig(
    val host: String,
    val port: Int,
    val serverName: String,
    val username: String?,
    val password: String?,
    val clients: Int,
    val durationSecs: Long,
    val keepAliveSecs: UShort,
    val insecureSkipVerify: Boolean,
)

private data class TargetInput(
    val host: String,
    val port: Int,
    val serverName: String,
)

private fun parseTargetInput(
    rawHost: String,
    rawPort: String,
    rawServerName: String,
): TargetInput? {
    val hostText = rawHost.trim()
    val portText = rawPort.trim()
    if (hostText.isBlank()) {
        return null
    }

    val parsedUri = parseTargetUri(hostText)
    val host = parsedUri?.host ?: hostText.substringBeforeLast(':').takeIf {
        hostText.count { ch -> ch == ':' } == 1 && hostText.substringAfterLast(':').toIntOrNull() != null
    } ?: hostText.removePrefix("quic://").substringBefore('/')

    val embeddedPort = parsedUri?.port?.takeIf { it > 0 } ?: hostText.substringAfterLast(':')
        .toIntOrNull()
        ?.takeIf { hostText.count { ch -> ch == ':' } == 1 }
    val port = portText.toIntOrNull() ?: embeddedPort
    if (host.isBlank() || port == null || port !in 1..65535) {
        return null
    }

    val explicitServerName = rawServerName.trim()
    val serverName = if (explicitServerName.isBlank()) {
        host
    } else {
        parseTargetUri(explicitServerName)?.host
            ?: explicitServerName.removePrefix("quic://").substringBefore('/').substringBefore(':')
    }

    return TargetInput(host = host, port = port, serverName = serverName)
}

private fun parseTargetUri(value: String): URI? {
    return try {
        val uri = URI(value)
        if (uri.scheme != null && !uri.host.isNullOrBlank()) uri else null
    } catch (_: Throwable) {
        null
    }
}

private interface StabilityRunner {
    fun start()
    fun stop()
}

private object NativeQuicStabilityRunner {
    init {
        System.loadLibrary("flowsdk_ffi")
    }

    @JvmStatic
    external fun startNative(
        host: String,
        port: Int,
        serverName: String,
        username: String?,
        password: String?,
        clients: Int,
        durationSecs: Long,
        keepAliveSecs: Int,
        insecureSkipVerify: Boolean,
        callback: NativeLogCallback,
    ): Long

    @JvmStatic
    external fun stopNative(handle: Long)
}

private class NativeLogCallback(
    private val onLog: (String) -> Unit,
) {
    fun onLog(line: String) {
        onLog.invoke(line)
    }
}

private class NativeQuicStabilityRunnerInstance(
    private val config: StabilityConfig,
    private val onLog: (String) -> Unit,
) : StabilityRunner {
    private var handle: Long = 0

    override fun start() {
        if (handle != 0L) {
            onLog("already running")
            return
        }
        handle = NativeQuicStabilityRunner.startNative(
            host = config.host,
            port = config.port,
            serverName = config.serverName,
            username = config.username,
            password = config.password,
            clients = config.clients,
            durationSecs = config.durationSecs,
            keepAliveSecs = config.keepAliveSecs.toInt(),
            insecureSkipVerify = config.insecureSkipVerify,
            callback = NativeLogCallback(onLog),
        )
        if (handle == 0L) {
            onLog("native runner failed to start")
        }
    }

    override fun stop() {
        val activeHandle = handle
        handle = 0
        if (activeHandle != 0L) {
            NativeQuicStabilityRunner.stopNative(activeHandle)
        }
    }
}

private class KotlinQuicStabilityRunner(
    private val config: StabilityConfig,
    private val onLog: (String) -> Unit,
) : StabilityRunner {
    private val running = AtomicBoolean(false)
    private val executor = Executors.newCachedThreadPool()
    private val stats = StabilityStats()
    private val connectLatenciesMs = mutableListOf<Long>()
    private val connectLatencyLock = Any()

    override fun start() {
        if (!running.compareAndSet(false, true)) {
            onLog("already running")
            return
        }
        stats.reset()
        synchronized(connectLatencyLock) {
            connectLatenciesMs.clear()
        }

        onLog("MQTT over QUIC Android connection stability check")
        onLog("  target: quic://${config.host}:${config.port}")
        onLog("  server_name: ${config.serverName}")
        onLog("  clients: ${config.clients}")
        onLog("  duration: ${config.durationSecs}s")
        onLog("  keep_alive: ${config.keepAliveSecs}s")
        onLog("  publish/subscribe: disabled")
        onLog("  tls_verify: ${if (config.insecureSkipVerify) "off" else "on"}")
        onLog("  auth: ${if (config.username != null || config.password != null) "configured" else "disabled"}")

        repeat(config.clients) { index ->
            executor.execute { runClient(index) }
        }
        executor.execute { reportLoop() }
    }

    override fun stop() {
        running.set(false)
    }

    private fun runClient(index: Int) {
        val startMs = System.currentTimeMillis()
        var channel: DatagramChannel? = null
        var selector: Selector? = null

        try {
            val opts = MqttOptionsFfi(
                clientId = "android_quic_stability_${startMs}_$index",
                mqttVersion = 5.toUByte(),
                cleanStart = true,
                keepAlive = config.keepAliveSecs,
                username = config.username,
                password = config.password,
                reconnectBaseDelayMs = 1000.toULong(),
                reconnectMaxDelayMs = 10000.toULong(),
                maxReconnectAttempts = 0.toUInt(),
            )
            val engine = QuicMqttEngineFfi(opts)
            val tlsOpts = MqttTlsOptionsFfi(
                caCertFile = null,
                clientCertFile = null,
                clientKeyFile = null,
                insecureSkipVerify = config.insecureSkipVerify,
                alpnProtocols = listOf(),
                enableKeyLog = false,
            )

            val brokerAddr = InetSocketAddress(config.host, config.port)
            channel = DatagramChannel.open().apply {
                configureBlocking(false)
                connect(brokerAddr)
            }
            selector = Selector.open()
            channel.register(selector, SelectionKey.OP_READ)

            val serverAddr = "${brokerAddr.address.hostAddress}:${config.port}"
            val connectStartedNs = System.nanoTime()
            engine.connect(serverAddr, config.serverName, tlsOpts, nowMs(startMs))
            engine.handleTick(nowMs(startMs))
            sendOutgoing(engine, channel)

            val recvBuf = ByteBuffer.allocateDirect(RECV_BUFFER_SIZE)
            var connected = false
            var completed = false
            while (running.get() && System.currentTimeMillis() - startMs < config.durationSecs * 1000) {
                selector.select(TICK_INTERVAL_MS)
                recvBuf.clear()
                while (channel.receive(recvBuf) != null) {
                    recvBuf.flip()
                    val data = ByteArray(recvBuf.limit())
                    recvBuf.get(data)
                    engine.handleDatagram(data, serverAddr, nowMs(startMs))
                    recvBuf.clear()
                }

                val events = engine.handleTick(nowMs(startMs))
                for (event in events) {
                    when (event) {
                        is MqttEventFfi.Connected -> {
                            if (event.v1.reasonCode.toInt() == 0 && !connected) {
                                connected = true
                                val latencyMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - connectStartedNs)
                                synchronized(connectLatencyLock) {
                                    connectLatenciesMs.add(latencyMs)
                                }
                                stats.connected.incrementAndGet()
                                onLog("client $index connected in ${latencyMs}ms")
                            } else if (event.v1.reasonCode.toInt() != 0) {
                                stats.connectFailed.incrementAndGet()
                                onLog("client $index connect rejected reason=${event.v1.reasonCode}")
                                running.set(false)
                            }
                        }
                        is MqttEventFfi.PingResponse -> {
                            if (event.success) {
                                stats.pingResponses.incrementAndGet()
                            }
                        }
                        is MqttEventFfi.Disconnected -> {
                            stats.disconnected.incrementAndGet()
                            onLog("client $index disconnected reason=${event.reasonCode}")
                            running.set(false)
                        }
                        is MqttEventFfi.ReconnectNeeded -> {
                            stats.connectionLost.incrementAndGet()
                            onLog("client $index connection lost: reconnect needed")
                            running.set(false)
                        }
                        is MqttEventFfi.Error -> {
                            stats.errors.incrementAndGet()
                            onLog("client $index error: ${event.message}")
                            running.set(false)
                        }
                        else -> Unit
                    }
                }
                sendOutgoing(engine, channel)
            }

            val elapsed = System.currentTimeMillis() - startMs
            val durationReached = elapsed >= config.durationSecs * 1000
            if (connected && durationReached) {
                completed = true
                stats.completed.incrementAndGet()
            }
            engine.disconnect()
            engine.handleTick(nowMs(startMs))
            sendOutgoing(engine, channel, failOnError = false)
            if (!completed && connected) {
                onLog("client $index stopped before completion")
            }
        } catch (t: Throwable) {
            stats.errors.incrementAndGet()
            onLog("client $index exception: ${t.message}")
            running.set(false)
        } finally {
            try {
                selector?.close()
            } catch (_: Throwable) {
            }
            try {
                channel?.close()
            } catch (_: Throwable) {
            }
        }
    }

    private fun reportLoop() {
        while (running.get()) {
            Thread.sleep(5_000)
            onLog(snapshotLine())
            if (stats.completed.get() >= config.clients.toLong()) {
                running.set(false)
                onLog("Final result")
                onLog(snapshotLine())
                onLog(connectLatencySummary())
                val failed = stats.connectFailed.get() + stats.errors.get() +
                    stats.connectionLost.get() + stats.disconnected.get()
                onLog("status: ${if (failed == 0L) "PASS" else "FAIL"}")
                return
            }
        }
        if (stats.completed.get() >= config.clients.toLong()) {
            onLog("Final result")
            onLog(snapshotLine())
            onLog(connectLatencySummary())
            val failed = stats.connectFailed.get() + stats.errors.get() +
                stats.connectionLost.get() + stats.disconnected.get()
            onLog("status: ${if (failed == 0L) "PASS" else "FAIL"}")
        } else {
            onLog("Stopped")
            onLog(snapshotLine())
            onLog(connectLatencySummary())
        }
    }

    private fun snapshotLine(): String =
        "connected: ${stats.connected.get()} | completed: ${stats.completed.get()} | " +
            "connect_failed: ${stats.connectFailed.get()} | ping_responses: ${stats.pingResponses.get()} | " +
            "errors: ${stats.errors.get()} | connection_lost: ${stats.connectionLost.get()} | " +
            "disconnected: ${stats.disconnected.get()}"

    private fun connectLatencySummary(): String {
        val values = synchronized(connectLatencyLock) { connectLatenciesMs.toList() }
        if (values.isEmpty()) {
            return "connect_latency_ms: no successful connections"
        }
        val min = values.minOrNull() ?: 0
        val max = values.maxOrNull() ?: 0
        val avg = values.average()
        return String.format(
            Locale.US,
            "connect_latency_ms: count=%d min=%d avg=%.2f max=%d",
            values.size,
            min,
            avg,
            max,
        )
    }
}

private class StabilityStats {
    val connected = AtomicLong()
    val connectFailed = AtomicLong()
    val completed = AtomicLong()
    val pingResponses = AtomicLong()
    val errors = AtomicLong()
    val connectionLost = AtomicLong()
    val disconnected = AtomicLong()

    fun reset() {
        connected.set(0)
        connectFailed.set(0)
        completed.set(0)
        pingResponses.set(0)
        errors.set(0)
        connectionLost.set(0)
        disconnected.set(0)
    }
}

private const val TICK_INTERVAL_MS = 10L
private const val RECV_BUFFER_SIZE = 65536

private fun nowMs(startTimeMs: Long): ULong =
    (System.currentTimeMillis() - startTimeMs).coerceAtLeast(0).toULong()

private fun sendOutgoing(
    engine: QuicMqttEngineFfi,
    channel: DatagramChannel,
    failOnError: Boolean = true,
) {
    for (datagram in engine.takeOutgoingDatagrams()) {
        try {
            channel.write(ByteBuffer.wrap(datagram.data))
        } catch (t: Throwable) {
            if (failOnError) {
                throw t
            }
        }
    }
}
