package com.siteguard.app.core

import org.json.JSONArray
import org.json.JSONObject

/** JSON section for the report: ownership-proof status, passive hygiene observations and the TLS session this device saw. */
object PassiveHygieneJsonV1 {
    fun toJson(report: PassiveHygieneReportV1, proof: OwnershipProofResultV1?): JSONObject = JSONObject().apply {
        put("host", report.host)
        put("ownership_proof", proof?.let { p ->
            JSONObject().apply {
                put("status", p.status.name)
                put("host", p.host)
                put("url", EvidenceSanitizer.sanitize(p.url))
                put("reason", EvidenceSanitizer.sanitize(p.reason))
                put("checked_at_epoch_ms", p.checkedAtEpochMs)
                put("connected_ip", p.connectedIp)
            }
        } ?: JSONObject.NULL)
        put("requests_used", report.requestsUsed)
        put("finding_ids", JSONArray(report.findings.map { it.id }))
        put("robots", report.robots?.let { r ->
            JSONObject().apply {
                put("disallow_count", r.disallowPaths.size)
                put("sensitive_path_hints", JSONArray(r.sensitivePathHints))
                put("sitemap_urls_same_host", JSONArray(r.sitemapUrls))
                put("external_sitemap_count", r.externalSitemapCount)
                put("crawl_delay_seconds", r.crawlDelaySeconds ?: JSONObject.NULL)
            }
        } ?: JSONObject.NULL)
        put("sitemap_same_host_url_count", report.sitemapUrlCount)
        put("tls_session", report.tls?.let { t ->
            JSONObject().apply {
                put("protocol", t.protocol)
                put("cipher_suite", t.cipherSuite)
                put("subject", EvidenceSanitizer.sanitize(t.subject))
                put("issuer", EvidenceSanitizer.sanitize(t.issuer))
                put("not_before_epoch_ms", t.notBeforeEpochMs)
                put("not_after_epoch_ms", t.notAfterEpochMs)
                put("signature_algorithm", t.signatureAlgorithm)
                put("key_algorithm", t.keyAlgorithm)
                put("key_bits", t.keyBits)
                put("san_dns_count", t.sanDnsCount)
                put("chain_length_presented", t.chainLength)
            }
        } ?: JSONObject.NULL)
        put("security_txt", report.securityTxt?.let { x ->
            JSONObject().apply {
                put("contacts", JSONArray(x.contacts.map { EvidenceSanitizer.sanitize(it).take(200) }))
                put("valid_contact_count", x.validContacts.size)
                put("expires_raw", x.expiresRaw?.let { EvidenceSanitizer.sanitize(it) } ?: JSONObject.NULL)
                put("expires_epoch_ms", x.expiresEpochMs ?: JSONObject.NULL)
                put("canonical", JSONArray(x.canonical))
                put("has_policy", x.hasPolicy)
                put("has_encryption", x.hasEncryption)
                put("signed", x.signed)
            }
        } ?: JSONObject.NULL)
        put("hsts", report.hsts?.let { h ->
            JSONObject().apply {
                put("header", EvidenceSanitizer.sanitize(h.raw))
                put("max_age_seconds", h.maxAgeSeconds ?: JSONObject.NULL)
                put("include_subdomains", h.includeSubDomains)
                put("preload", h.preload)
            }
        } ?: JSONObject.NULL)
        put("events", JSONArray().apply {
            report.events.take(50).forEach { e ->
                put(JSONObject().apply {
                    put("url", EvidenceSanitizer.sanitize(e.url).take(300))
                    put("status", e.status)
                    put("reason", EvidenceSanitizer.sanitize(e.reason).take(300))
                })
            }
        })
        put("limitations", JSONArray(report.limitations))
    }
}
