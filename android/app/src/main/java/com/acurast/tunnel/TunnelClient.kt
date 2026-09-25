package com.acurast.tunnel

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.DelicateCoroutinesApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import uniffi.tunnel_client_ffi.Handler
import uniffi.tunnel_client_ffi.TunnelConfig
import uniffi.tunnel_client_ffi.TunnelEvent
import uniffi.tunnel_client_ffi.TunnelInfo
import uniffi.tunnel_client_ffi.TunnelKey
import kotlin.coroutines.CoroutineContext
import uniffi.tunnel_client_ffi.TunnelClient as UniffiTunnelClient

/**
 * Idiomatic wrapper around the uniffi-generated [UniffiTunnelClient]; construct
 * it with the [CoroutineScope.TunnelClient] factory.
 *
 * [TunnelEvent.Started] means the tunnel is carrying traffic, not that `run()`
 * was called, and the `Connection*` events report that per connection (`tag` is
 * `"PRI"` or `"SEC"`). Exactly one terminal event — [TunnelEvent.Stopped] or
 * [TunnelEvent.Failed] — always ends [events]. Cancelling the parent scope
 * stops the tunnel like [close] does.
 */
public class TunnelClient internal constructor(
    coroutineContext: CoroutineContext,
    config: TunnelConfig,
    secondaryKey: TunnelKey?,
) : AutoCloseable {
    private val scope = CoroutineScope(coroutineContext + SupervisorJob(coroutineContext[Job]))
    private val handler = EventHandler()
    private val inner: UniffiTunnelClient = UniffiTunnelClient(config, secondaryKey, handler)

    public val info: TunnelInfo = inner.info()
    public val events: SharedFlow<TunnelEvent> get() = handler.events

    // ATOMIC: a start cancelled before its first dispatch would leak the handle.
    @OptIn(ExperimentalCoroutinesApi::class)
    private val runJob: Job = scope.launch(start = CoroutineStart.ATOMIC) {
        // Cancellation becomes a graceful stop; the native run is never dropped.
        val stopOnCancel = launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                awaitCancellation()
            } finally {
                stopQuietly()
            }
        }
        try {
            withContext(NonCancellable) { inner.run() }
        } catch (e: CancellationException) {
            throw e
        } catch (e: Throwable) {
            handler.onEvent(TunnelEvent.Failed(e.message ?: e.toString()))
        } finally {
            stopOnCancel.cancel()
            inner.close()
        }
    }

    private val cleanupLock = Any()
    private var cleanupJob: Job? = null

    /** Starts teardown once; later calls return the same job. */
    @OptIn(DelicateCoroutinesApi::class)
    private fun startCleanup(): Job = synchronized(cleanupLock) {
        cleanupJob ?: run {
            stopQuietly()
            GlobalScope.launch(Dispatchers.IO) {
                withTimeoutOrNull(CLOSE_JOIN_TIMEOUT_MS) { runJob.join() }
                scope.cancel()
                // `runJob`'s `finally` normally did this; it may have timed out above.
                inner.close()
            }
        }.also { cleanupJob = it }
    }

    private fun stopQuietly() {
        try {
            inner.stop()
        } catch (e: IllegalStateException) {
            // `runJob` already finished and destroyed the handle; nothing to stop.
        }
    }

    /** Stops the tunnel and releases the native handle in the background. */
    public override fun close() {
        startCleanup()
    }

    /** [close], then suspends until teardown has finished. */
    public suspend fun closeAndJoin() {
        startCleanup().join()
    }

    private class EventHandler : Handler {
        private val _events: MutableSharedFlow<TunnelEvent> =
            MutableSharedFlow(replay = BUFFER_CAPACITY)
        val events: SharedFlow<TunnelEvent>
            get() = _events.asSharedFlow()

        override suspend fun onEvent(event: TunnelEvent) {
            _events.emit(event)
        }

        companion object {
            private const val BUFFER_CAPACITY = 64
        }
    }

    public companion object {
        private const val CLOSE_JOIN_TIMEOUT_MS: Long = 5_000

        init {
            System.loadLibrary("tunnel_client_ffi")
        }

        /**
         * Wires the Rust-side `android_logger` so transitive logs reach logcat.
         * Call once before constructing any [TunnelClient]. [filterSpec] is an
         * env_logger-style filter string (`"info"`, `"debug"`,
         * `"tunnel_client=trace,hyper=info"`); invalid strings fall back to
         * `"info"`.
         */
        @JvmStatic
        public external fun initAndroid(filterSpec: String)
    }
}

/**
 * Builds a [TunnelClient] bound to this scope, off [Dispatchers.Default]: the
 * native constructor blocks on a foreign signature that uniffi dispatches there.
 *
 * [config]'s `reconnect` field is optional; unset means retry forever with a
 * 2s → 60s backoff and a 10s connect timeout. Set `maxAttempts` to a non-zero
 * value to let the tunnel give up instead — then [TunnelEvent.ConnectionGaveUp]
 * and, once every connection has, [TunnelEvent.Failed] follow.
 * A relay rejection counts as a failed attempt on that relay's connection only,
 * retried at the maximum backoff. An ACME rate limit does not count; it is
 * retried at the CA's retry time. Each failed attempt of a connection that is not
 * up is reported as [TunnelEvent.ConnectionAttemptFailed].
 */
public suspend fun CoroutineScope.TunnelClient(
    config: TunnelConfig,
    secondaryKey: TunnelKey? = null,
): TunnelClient {
    val context = this.coroutineContext
    return withContext(Dispatchers.IO) { TunnelClient(context, config, secondaryKey) }
}
