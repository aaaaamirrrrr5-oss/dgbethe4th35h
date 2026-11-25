package com.siteguard.app.core

import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Technical proof of control over a host: the owner publishes a random one-time token at
 * https://<host>/.well-known/siteguard-verification.txt and the app reads it back over validated HTTPS.
 *
 * What this proves: whoever answered for <host> over a certificate valid on this device served the token.
 * What it does not prove: legal authorization from a third-party owner, control of other hosts, or control of a
 * different path/port. DNS TXT proof is NOT implemented (plain Android has no TXT resolver API; it would need DoH).
 */
data class OwnershipChallengeV1(
    val host: String,
    val token: String,
    val path: String,
    val createdAtEpochMs: Long,
    val expiresAtEpochMs: Long
) {
    val expectedLine: String get() = OwnershipProofV1.TOKEN_PREFIX + token
    val proofUrl: String get() = "https://$host$path"
}

enum class OwnershipProofStatusV1 { VERIFIED, NOT_VERIFIED, EXPIRED, ERROR }

data class OwnershipProofResultV1(
    val status: OwnershipProofStatusV1,
    val host: String,
    val url: String,
    val reason: String,
    val checkedAtEpochMs: Long,
    val connectedIp: String = ""
)

object OwnershipProofV1 {
    const val WELL_KNOWN_PATH = "/.well-known/siteguard-verification.txt"
    const val TOKEN_PREFIX = "siteguard-verification="
    private const val DEFAULT_TTL_MS = 24L * 60 * 60 * 1000

    /** Returns null for IP literals or invalid hostnames: control of an address is not proven by a hostname file. */
    fun newChallenge(
        rawHost: String,
        nowEpochMs: Long = System.currentTimeMillis(),
        ttlMs: Long = DEFAULT_TTL_MS,
        random: SecureRandom = SecureRandom()
    ): OwnershipChallengeV1? {
        val host = canonicalHost(rawHost) ?: return null
        if (host.contains(':') || host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || !host.contains('.')) return null
        val bytes = ByteArray(16).also(random::nextBytes)
        val token = bytes.joinToString("") { "%02x".format(it) }
        return OwnershipChallengeV1(host, token, WELL_KNOWN_PATH, nowEpochMs, nowEpochMs + ttlMs.coerceIn(60_000L, 7L * 24 * 60 * 60 * 1000))
    }

    fun instructions(challenge: OwnershipChallengeV1): String =
        "برای اثبات کنترل ${challenge.host}، فایلی متنی با این مسیر بسازید:\n${challenge.proofUrl}\n" +
            "و فقط این یک خط را داخل آن بگذارید:\n${challenge.expectedLine}\n" +
            "فایل باید روی HTTPS با گواهی معتبر و بدون redirect پاسخ ۲۰۰ بدهد. پس از تأیید می‌توانید فایل را حذف کنید."

    /** Exact whole-line match of the token; comparison is constant-time. */
    fun bodyContainsToken(body: String, expectedLine: String): Boolean {
        val expected = expectedLine.trim().toByteArray(Charsets.UTF_8)
        var found = false
        body.lineSequence().take(50).forEach { line ->
            if (MessageDigest.isEqual(line.trim().toByteArray(Charsets.UTF_8), expected)) found = true
        }
        return found
    }

    /** Blocking network call; run it on Dispatchers.IO. `internal` because the injectable fetch type is module-internal. */
    internal fun verify(
        challenge: OwnershipChallengeV1,
        manifest: WebsiteEngagementManifestV2,
        nowEpochMs: Long = System.currentTimeMillis(),
        fetch: (String, WebsiteEngagementManifestV2) -> WebsiteDiscoveryEngineV1.OwnershipProofFetchV1 = WebsiteDiscoveryEngineV1::fetchForOwnershipProof
    ): OwnershipProofResultV1 {
        fun result(status: OwnershipProofStatusV1, reason: String, ip: String = "") =
            OwnershipProofResultV1(status, challenge.host, challenge.proofUrl, reason, nowEpochMs, ip)
        if (nowEpochMs > challenge.expiresAtEpochMs) return result(OwnershipProofStatusV1.EXPIRED, "توکن منقضی شده است؛ چالش جدید بسازید.")
        if (challenge.host !in manifest.allowedHosts.mapNotNull(::canonicalHost)) {
            return result(OwnershipProofStatusV1.ERROR, "میزبان چالش در allowedHosts مانیفست نیست.")
        }
        return try {
            val response = fetch(challenge.proofUrl, manifest)
            when {
                response.status != 200 && response.status != 206 ->
                    result(OwnershipProofStatusV1.NOT_VERIFIED, "پاسخ HTTP ${response.status}؛ فایل اثبات با وضعیت ۲۰۰ در دسترس نیست (redirect دنبال نمی‌شود).", response.ip)
                response.contentType.isNotEmpty() && !response.contentType.startsWith("text/") ->
                    result(OwnershipProofStatusV1.NOT_VERIFIED, "نوع محتوا text/* نیست (${response.contentType}).", response.ip)
                !bodyContainsToken(response.body, challenge.expectedLine) ->
                    result(OwnershipProofStatusV1.NOT_VERIFIED, "توکن مورد انتظار در فایل پیدا نشد.", response.ip)
                else -> result(OwnershipProofStatusV1.VERIFIED, "توکن روی HTTPS معتبر همین میزبان خوانده شد.", response.ip)
            }
        } catch (e: Exception) {
            val tls = TlsFailureClassifier.classify(e)
            result(
                OwnershipProofStatusV1.ERROR,
                if (tls != null) "خطای اعتبارسنجی TLS (${tls.kind.name})؛ اثبات روی گواهی نامعتبر پذیرفته نمی‌شود."
                else "${e.javaClass.simpleName}: ${EvidenceSanitizer.sanitize(e.message.orEmpty()).take(160)}"
            )
        }
    }

    /** Upgrades the manifest's proof only on VERIFIED; any other status returns the manifest unchanged. */
    fun applyTo(manifest: WebsiteEngagementManifestV2, result: OwnershipProofResultV1): WebsiteEngagementManifestV2 =
        if (result.status == OwnershipProofStatusV1.VERIFIED && result.host in manifest.allowedHosts.mapNotNull(::canonicalHost)) {
            manifest.copy(
                proofMethod = WebsiteAuthorizationProofV2.TECHNICAL_OWNERSHIP,
                proofReference = "well-known token verified at ${result.url} on ${result.checkedAtEpochMs}"
            )
        } else manifest
}

/** Bridges the legacy single-target manifest to SecurityPolicyEngineV1 so the scan path is checked by the shared policy engine. */
object ScanPolicyBridgeV1 {
    private fun cidrFor(address: java.net.InetAddress): String {
        val literal = address.hostAddress.orEmpty().substringBefore('%')
        return "$literal/${address.address.size * 8}"
    }

    fun policyFor(manifest: AuthorizationManifest, resolved: List<java.net.InetAddress>): AuthorizationPolicyV1 =
        AuthorizationPolicyV1(
            authorizationId = manifest.authorizationId,
            ownerOrAuthorizer = manifest.ownerDeclaration,
            organization = "single-target",
            authorizedDomains = manifest.authorizedHosts,
            authorizedIpRanges = resolved.map(::cidrFor).toSet(),
            excludedDomains = manifest.excludedHosts,
            excludedIpRanges = emptySet(),
            allowedTestClasses = setOf("PASSIVE_REVIEW"),
            prohibitedMethods = setOf("POST", "PUT", "PATCH", "DELETE"),
            validFromEpochMs = manifest.validFromEpochMs,
            expiresAtEpochMs = manifest.validUntilEpochMs,
            maxRequests = manifest.maxRequests,
            maxConcurrency = 1,
            requestsPerMinute = manifest.requestsPerMinute,
            emergencyContact = "in-app cancel",
            proofOrNotes = manifest.ownerDeclaration,
            allowPrivateInternalRanges = manifest.allowPrivateNetwork
        )

    /** Returns the first denial reason, or null when every resolved address passes. */
    fun firstDenial(manifest: AuthorizationManifest, host: String, port: Int, resolved: List<java.net.InetAddress>): String? {
        val policy = policyFor(manifest, resolved)
        for (address in resolved) {
            val decision = SecurityPolicyEngineV1.validate(
                policy, host, address.hostAddress.orEmpty().substringBefore('%'), port, "PASSIVE_REVIEW", "GET"
            )
            if (!decision.allowed) return decision.reason
        }
        return null
    }
}
