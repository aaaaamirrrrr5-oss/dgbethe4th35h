package com.siteguard.app.core

import java.security.MessageDigest

/** Metadata for locally bundled public references; bundled records are not a live vulnerability feed. */
data class KnowledgeSourceRecord(
    val sourceId: String,
    val publisher: String,
    val url: String,
    val topic: String,
    val retrievalMode: String = "public reference; no content fetched by this build"
)

data class KnowledgePackStatus(
    val packVersion: String,
    val mode: String,
    val lastUpdatedEpochMs: Long?,
    val isLiveFeed: Boolean,
    val note: String
)

object LocalSecurityKnowledgePack {
    const val VERSION = "siteguard-knowledge-0.8.0"
    val sources = listOf(
        KnowledgeSourceRecord("mitre-attack", "MITRE", "https://attack.mitre.org/", "Defensive ATT&CK technique references"),
        KnowledgeSourceRecord("mitre-cwe", "MITRE", "https://cwe.mitre.org/", "Weakness taxonomy"),
        KnowledgeSourceRecord("nist-nvd", "NIST", "https://nvd.nist.gov/", "Vulnerability metadata reference"),
        KnowledgeSourceRecord("cisa-kev", "CISA", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "Known exploited vulnerability catalog reference"),
        KnowledgeSourceRecord("github-advisories", "GitHub", "https://github.com/advisories", "Package advisory reference"),
        KnowledgeSourceRecord("owasp", "OWASP", "https://owasp.org/", "Application security guidance"),
        KnowledgeSourceRecord("android-bulletins", "Android", "https://source.android.com/docs/security/bulletin", "Android security bulletin reference"),
        KnowledgeSourceRecord("wordpress", "WordPress", "https://wordpress.org/news/category/security/", "WordPress security announcements"),
        KnowledgeSourceRecord("kubernetes", "Kubernetes", "https://kubernetes.io/docs/concepts/security/", "Kubernetes security documentation")
    )

    fun status(): KnowledgePackStatus = KnowledgePackStatus(
        packVersion = VERSION,
        mode = "offline-curated-reference",
        lastUpdatedEpochMs = null,
        isLiveFeed = false,
        note = "فقط کاتالوگ‌های محلی و metadata منبع در دسترس‌اند؛ این نسخه CVE/NVD/KEV زنده یا تازه‌بودن advisoryها را ادعا نمی‌کند."
    )

    /** SHA-256 checks integrity only; it does not authenticate the publisher or replace a digital signature. */
    fun verifySha256(bytes: ByteArray, expectedHex: String): Boolean {
        if (!expectedHex.matches(Regex("(?i)^[0-9a-f]{64}$"))) return false
        val actual = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        return actual.equals(expectedHex, ignoreCase = true)
    }
}
