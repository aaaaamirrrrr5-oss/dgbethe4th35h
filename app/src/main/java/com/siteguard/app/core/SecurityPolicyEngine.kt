package com.siteguard.app.core

import java.net.InetAddress
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicBoolean


data class AuthorizationPolicyV1(
    val schemaVersion: Int = 1,
    val authorizationId: String,
    val ownerOrAuthorizer: String,
    val organization: String,
    val authorizedDomains: Set<String>,
    val authorizedIpRanges: Set<String>,
    val excludedDomains: Set<String>,
    val excludedIpRanges: Set<String>,
    val allowedTestClasses: Set<String>,
    val prohibitedMethods: Set<String>,
    val validFromEpochMs: Long,
    val expiresAtEpochMs: Long,
    val maxRequests: Int,
    val maxConcurrency: Int,
    val requestsPerMinute: Int,
    val emergencyContact: String,
    val proofOrNotes: String,
    val explicitThirdPartyAuthorization: Set<String> = emptySet(),
    val allowPrivateInternalRanges: Boolean = false
)

data class PolicyDecisionV1(
    val allowed: Boolean,
    val reason: String,
    val authorizationId: String,
    val checkedAtEpochMs: Long
)

object SecurityPolicyEngineV1 {
    fun validate(
        policy: AuthorizationPolicyV1?,
        host: String,
        ip: String?,
        port: Int,
        testClass: String,
        method: String,
        nowEpochMs: Long = System.currentTimeMillis(),
        thirdPartyServiceName: String? = null
    ): PolicyDecisionV1 {
        fun deny(reason: String, id: String = policy?.authorizationId.orEmpty()) = PolicyDecisionV1(false, reason, id, nowEpochMs)
        val p = policy ?: return deny("مانیفست مجوز وجود ندارد.")
        if (p.schemaVersion != 1 || p.authorizationId.isBlank() || p.ownerOrAuthorizer.isBlank()) return deny("ساختار مجوز ناقص یا پشتیبانی‌نشده است.")
        if (p.validFromEpochMs <= 0 || nowEpochMs !in p.validFromEpochMs..p.expiresAtEpochMs) return deny("مجوز خارج از بازه زمانی معتبر است.")
        if (p.maxRequests !in 1..100_000 || p.maxConcurrency !in 1..8 || p.requestsPerMinute !in 1..10_000) return deny("حدود نرخ/همزمانی مجوز معتبر نیست.")
        if (port !in 1..65535 || testClass !in p.allowedTestClasses) return deny("درگاه یا کلاس تست در مانیفست مجاز نیست.")
        if (method.uppercase() in p.prohibitedMethods.map { it.uppercase() } || method.isBlank()) return deny("روش در مجوز ممنوع است یا مشخص نشده است.")
        val normalizedHost = canonicalHost(host) ?: return deny("نام میزبان نامعتبر است.")
        val allowedDomains = p.authorizedDomains.mapNotNull(::canonicalHost).toSet()
        val excludedDomains = p.excludedDomains.mapNotNull(::canonicalHost).toSet()
        if (normalizedHost in excludedDomains || normalizedHost !in allowedDomains) return deny("میزبان خارج از محدوده یا در فهرست استثنا است.")
        if (thirdPartyServiceName != null && thirdPartyServiceName !in p.explicitThirdPartyAuthorization) return deny("سرویس شخص ثالث بدون مجوز جداگانه رد شد.")
        if (ip != null) {
            val address = NetworkTargetPolicy.parseNumericAddress(ip) ?: return deny("فقط IP عددی صریح پذیرفته می‌شود؛ DNS در این مرحله انجام نمی‌شود.")
            val excluded = p.excludedIpRanges.any { CidrV1.contains(it, address) }
            val allowed = p.authorizedIpRanges.any { CidrV1.contains(it, address) }
            if (excluded || !allowed) return deny("IP خارج از محدوده مجاز یا در فهرست استثنا است.")
            if (AddressPolicy.isNonPublic(address) && !p.allowPrivateInternalRanges) return deny("IP خصوصی/رزرو شده بدون اجازه صریح قابل بررسی نیست.")
        }
        return PolicyDecisionV1(true, "هدف، درگاه، کلاس تست، زمان و IP با مانیفست مجاز تطبیق دارند.", p.authorizationId, nowEpochMs)
    }
}

/** CIDR matcher for IPv4 and IPv6; it performs no DNS lookup. */
object CidrV1 {
    fun contains(cidr: String, address: InetAddress): Boolean = runCatching {
        val parts = cidr.trim().split('/')
        require(parts.size in 1..2)
        val networkAddress = NetworkTargetPolicy.parseNumericAddress(parts[0]) ?: return@runCatching false
        val network = networkAddress.address
        val candidate = address.address
        require(network.size == candidate.size)
        val prefix = parts.getOrNull(1)?.toInt() ?: network.size * 8
        require(prefix in 0..network.size * 8)
        val whole = prefix / 8
        val remainder = prefix % 8
        for (i in 0 until whole) if (network[i] != candidate[i]) return@runCatching false
        if (remainder > 0) {
            val mask = (0xff shl (8 - remainder)) and 0xff
            if ((network[whole].toInt() and mask) != (candidate[whole].toInt() and mask)) return@runCatching false
        }
        true
    }.getOrDefault(false)
}

class GlobalEmergencyStopV1 {
    private val stopped = AtomicBoolean(false)
    fun stop(): Boolean = stopped.compareAndSet(false, true)
    fun resetAfterReview() { stopped.set(false) }
    fun isStopped(): Boolean = stopped.get()
    fun requireActive() { check(!stopped.get()) { "Emergency Stop فعال است؛ اجرای جدید مسدود است." } }
}

data class SecurityAuditEventV1(
    val sequence: Long,
    val actor: String,
    val toolId: String,
    val toolVersion: String,
    val target: String,
    val action: String,
    val result: String,
    val atEpochMs: Long,
    val authorizationId: String
)

class BoundedSecurityAuditTrailV1(private val capacity: Int = 2000) {
    private val lock = Any()
    private val items = ArrayDeque<SecurityAuditEventV1>()
    init { require(capacity in 10..100_000) }

    fun append(event: SecurityAuditEventV1): SecurityAuditEventV1 = synchronized(lock) {
        require(event.actor.isNotBlank() && event.action.isNotBlank() && event.atEpochMs > 0)
        val numbered = event.copy(sequence = (items.lastOrNull()?.sequence ?: 0L) + 1L)
        items.addLast(numbered)
        while (items.size > capacity) items.removeFirst()
        numbered
    }
    fun snapshot(): List<SecurityAuditEventV1> = synchronized(lock) { items.toList() }
}
