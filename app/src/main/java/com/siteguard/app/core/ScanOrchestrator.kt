package com.siteguard.app.core

import android.content.Context

/** Device-aware facade. The app stays foreground-bound; it does not promise hidden continuous work. */
class ScanOrchestrator(private val context: Context) : ScannerAdapterV1 {
    override val adapterId: String = "siteguard.passive-web.v1"
    private val engine = ScanEngine()

    fun capabilities(): DeviceCapabilities = DeviceCapabilityDetector.inspect(context)

    override suspend fun scan(request: ScannerRequestV1): ScanResult {
        val capability = capabilities()
        if (!capability.canRunLightweightAudit) {
            return ScanResult(
                host = "", findings = emptyList(),
                message = "اسکن به‌دلیل محدودیت منابع دستگاه شروع نشد: ${capability.warnings.joinToString(" ")}",
                authorizationId = request.authorization.authorizationId
            )
        }
        val scopeDecision = ScopeEnforcer.validate(request.target, request.authorization)
        if (!scopeDecision.allowed) {
            return ScanResult("", emptyList(), "بررسی متوقف شد: ${scopeDecision.reason}", authorizationId = request.authorization.authorizationId)
        }
        // The request budget is consumed inside ScanEngine.scan (single choke point); consuming here too would double-count.
        return engine.scan(request.target, request.allowPrivateNetwork, request.authorization)
    }
}
