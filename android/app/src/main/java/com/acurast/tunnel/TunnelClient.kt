package com.acurast.tunnel

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import uniffi.tunnel_client_ffi.Handler
import uniffi.tunnel_client_ffi.TunnelConfig
import uniffi.tunnel_client_ffi.TunnelEvent
import uniffi.tunnel_client_ffi.TunnelInfo
import uniffi.tunnel_client_ffi.TunnelKey
import kotlin.coroutines.CoroutineContext
import uniffi.tunnel_client_ffi.TunnelClient as UniffiTunnelClient

/**
 * Idiomatic wrapper around the uniffi-generated [UniffiTunnelClient].
 *
 * The constructor synchronously binds the underlying tunnel (resolves the
 * primary URL/clientId, registers keys), then launches [UniffiTunnelClient.run]
 * on the supplied [coroutineContext]. Lifecycle and ACME events flow through
 * [events]. Call [close] (or rely on the parent coroutine scope) to stop the
 * tunnel and release native resources.
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

    init {
        scope.launch {
            try {
                inner.run()
            } finally {
                inner.close()
            }
        }
    }

    public override fun close() {
        inner.stop()
        scope.cancel()
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
}

public fun CoroutineScope.TunnelClient(
    config: TunnelConfig,
    secondaryKey: TunnelKey? = null,
): TunnelClient = TunnelClient(coroutineContext, config, secondaryKey)
