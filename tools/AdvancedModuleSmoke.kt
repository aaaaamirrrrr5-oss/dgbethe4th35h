package com.siteguard.smoke

import com.siteguard.app.advanced.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

private fun assertTrue(value: Boolean, message: String) { check(value) { message } }
private var passed = 0
private fun test(name: String, body: () -> Unit) {
    body(); passed++; println("PASS: $name")
}

private class FakeHttpConnection(url: URL, private val response: String) : HttpURLConnection(url) {
    val sent = ByteArrayOutputStream()
    override fun connect() { connected = true }
    override fun disconnect() { connected = false }
    override fun usingProxy() = false
    override fun getResponseCode() = 200
    override fun getInputStream() = ByteArrayInputStream(response.toByteArray(Charsets.UTF_8))
    override fun getOutputStream() = sent
}

private fun zipBytes(vararg rows: Pair<String, ByteArray>): ByteArray {
    val out = ByteArrayOutputStream()
    ZipOutputStream(out).use { zip -> rows.forEach { (name, bytes) -> zip.putNextEntry(ZipEntry(name)); zip.write(bytes); zip.closeEntry() } }
    return out.toByteArray()
}
private fun u16(v: Int) = byteArrayOf((v and 255).toByte(), ((v ushr 8) and 255).toByte())
private fun u32(v: Int) = byteArrayOf((v and 255).toByte(), ((v ushr 8) and 255).toByte(), ((v ushr 16) and 255).toByte(), ((v ushr 24) and 255).toByte())
private fun binaryManifestFixture(): ByteArray {
    val strings = listOf("manifest", "package", "com.example.fixture", "uses-sdk", "minSdkVersion", "26", "targetSdkVersion", "35", "uses-permission", "name", "android.permission.CAMERA", "application", "debuggable", "true", "activity", "MainActivity", "exported", "true")
    val data = ByteArrayOutputStream(); val offsets = mutableListOf<Int>()
    strings.forEach { text -> val raw = text.toByteArray(Charsets.UTF_8); offsets += data.size(); data.write(byteArrayOf(text.length.toByte(), raw.size.toByte())); data.write(raw); data.write(0) }
    fun chunk(type: Int, headerSize: Int, body: ByteArray): ByteArray = u16(type) + u16(headerSize) + u32(8 + body.size) + body
    val poolHeader = u32(strings.size) + u32(0) + u32(0x100) + u32(28 + strings.size * 4) + u32(0)
    val pool = chunk(1, 28, poolHeader + offsets.fold(ByteArray(0)) { acc, v -> acc + u32(v) } + data.toByteArray())
    fun start(nameIndex: Int, attrs: List<Triple<Int, Int, Int>>): ByteArray {
        val ext = u32(-1) + u32(nameIndex) + u16(20) + u16(20) + u16(attrs.size) + u16(0) + u16(0) + u16(0)
        val attrBytes = attrs.fold(ByteArray(0)) { acc, a -> acc + u32(-1) + u32(a.first) + u32(-1) + u16(8) + byteArrayOf(0, 3) + u32(a.second) }
        val body = u32(1) + u32(-1) + ext + attrBytes
        return u16(0x0102) + u16(16) + u32(8 + body.size) + body
    }
    val chunks = pool + start(0, listOf(Triple(1, 2, 0))) + start(3, listOf(Triple(4, 5, 0), Triple(6, 7, 0))) + start(8, listOf(Triple(9, 10, 0))) + start(11, listOf(Triple(12, 13, 0))) + start(14, listOf(Triple(9, 15, 0), Triple(16, 17, 0)))
    return u16(3) + u16(8) + u32(8 + chunks.size) + chunks
}

fun main() {
    test("bounded JSON parser and duplicate-key rejection") {
        val parsed = MiniJsonV1.objectValue(MiniJsonV1.parse("{\"a\":\"x\\nq\",\"b\":[1,true,null]}"))
        assertTrue(parsed["a"] == "x\nq", "escape parse failed")
        runCatching { MiniJsonV1.parse("{\"a\":1,\"a\":2}") }.onSuccess { error("duplicate JSON key accepted") }
        runCatching { MiniJsonV1.parse("[1,2,3] trailing") }.onSuccess { error("trailing JSON accepted") }
    }
    test("local evidence reasoning ranks critical finding") {
        val r = LocalReasoningEngineV1.reason(listOf(
            LocalSecuritySignalV1("LOW", "low", LocalRiskV1.LOW, 90, asset = "a"),
            LocalSecuritySignalV1("CRIT", "critical", LocalRiskV1.CRITICAL, 80, asset = "a", source = "web"),
            LocalSecuritySignalV1("HIGH", "high", LocalRiskV1.HIGH, 75, asset = "a", source = "code")
        ))
        assertTrue(r.actions.first().linkedSignals.first() == "CRIT", "critical did not rank first")
        assertTrue(r.overallScore in 1..100, "score out of range")
    }
    test("CISA KEV fixture parse, date and count validation") {
        val feed = """{"catalogVersion":"2026.11.20","dateReleased":"2026-11-20","count":1,"vulnerabilities":[{"cveID":"CVE-2026-12345","vendorProject":"Vendor","product":"Product","vulnerabilityName":"Example","dateAdded":"2026-11-19","shortDescription":"desc","requiredAction":"patch","dueDate":"2026-11-30","knownRansomwareCampaignUse":"Known","notes":""}]}"""
        val snapshot = CisaKevFeedParserV1.parse(feed, 123L)
        assertTrue(snapshot.count == 1 && snapshot.entries.single().ransomwareKnown, "CISA fixture parse failed")
        runCatching { CisaKevFeedParserV1.parse(feed.replace("\"count\":1", "\"count\":2")) }.onSuccess { error("CISA count mismatch accepted") }
        runCatching { CisaKevFeedParserV1.parse(feed.replace("2026-11-19", "2026-99-99")) }.onSuccess { error("invalid CISA date accepted") }
    }
    test("OSV POST request uses fixed endpoint and escaped query") {
        val response = """{"vulns":[{"id":"GHSA-xxxx-yyyy-zzzz","summary":"fixture","aliases":["CVE-2026-10000"],"references":[{"url":"https://example.test/advisory"}]}]}"""
        var called = false
        val report = OsvVulnerabilityLookupV1().query("npm", "pkg\"name", "1.2.3") { url ->
            assertTrue(url.host == "api.osv.dev" && url.path == "/v1/query" && url.protocol == "https", "OSV endpoint escaped")
            called = true; FakeHttpConnection(url, response)
        }
        assertTrue(called && report.vulnerabilities.single().id == "GHSA-xxxx-yyyy-zzzz", "OSV response not parsed")
        var invalidCalled = false
        runCatching { OsvVulnerabilityLookupV1().query("unknown", "pkg", "1") { invalidCalled = true; FakeHttpConnection(it, "{}") } }
            .onSuccess { error("unsupported ecosystem accepted") }
        assertTrue(!invalidCalled, "OSV network factory called for unsupported ecosystem")
    }
    test("WordPress runtime rejects plain HTTP before network") {
        var called = false
        runCatching { WordPressReadOnlyClientV1().inspect("http://example.test", "user", "app-password") { called = true; FakeHttpConnection(it, "{}") } }
            .onSuccess { error("plaintext WordPress URL accepted") }
        assertTrue(!called, "WordPress connection factory called on HTTP")
    }
    test("passive web analyzer rejects loopback by default") {
        var called = false
        runCatching { WebSurfaceAnalyzerV1().assess("https://127.0.0.1") { called = true; FakeHttpConnection(it, "{}") } }
            .onSuccess { error("loopback target accepted") }
        assertTrue(!called, "web connection factory called for loopback")
    }
    test("AST/Taint identifies PHP request input to SQL query with source line") {
        val dollar = '$'
        val src = """<?php
${dollar}id = ${dollar}_GET['id'];
${dollar}sql = "SELECT * FROM users WHERE id=" . ${dollar}id;
${dollar}db->query(${dollar}sql);
"""
        val r = CodeAstTaintAnalyzerV1.analyze("controller.php", src)
        val flow = r.flows.firstOrNull { it.cwe == "CWE-89" } ?: error("SQL taint flow not detected: ${r.flows}")
        assertTrue(flow.sourceLine == 2 && flow.sinkLine == 4, "source/sink lines wrong: $flow")
    }
    test("Cloud analyzer detects root, public ingress and multi-line IAM wildcard") {
        val r = CloudNetworkPostureAnalyzerV1.analyze("deployment.yaml", """spec:
  hostNetwork: true
  securityContext:
    privileged: true
  cidr: 0.0.0.0/0
  effect: Allow
  Action: "*"
""")
        assertTrue(r.findings.any { it.id == "CLOUD-K8S-PRIVILEGED" }, "privileged not flagged")
        assertTrue(r.findings.any { it.id == "CLOUD-WIDE-INGRESS" }, "wide ingress not flagged")
        assertTrue(r.findings.any { it.id == "CLOUD-IAM-WILDCARD" }, "multi-line IAM wildcard not flagged")
    }
    test("Android binary manifest decoded; APK ZIP traversal rejected") {
        val apk = zipBytes("AndroidManifest.xml" to binaryManifestFixture(), "classes.dex" to "dex\n039\u0000http://example.test".toByteArray(Charsets.ISO_8859_1))
        val report = BinaryAndroidAnalyzerV1.analyze("fixture.apk", apk)
        assertTrue(report.packageName == "com.example.fixture" && report.minSdk == "26" && report.targetSdk == "35", "manifest metadata mismatch")
        assertTrue(report.permissions.contains("android.permission.CAMERA"), "permission missing")
        assertTrue(report.findings.any { it.id == "APK-DEBUGGABLE" }, "debuggable finding missing")
        val evil = zipBytes("../escape.txt" to byteArrayOf(1), "AndroidManifest.xml" to binaryManifestFixture())
        runCatching { BinaryAndroidAnalyzerV1.analyze("evil.apk", evil) }.onSuccess { error("ZIP traversal accepted") }
    }
    test("local patch apply/rollback is hash guarded and ABA resistant") {
        val root = kotlin.io.path.createTempDirectory("sg-work-").toFile(); val backups = kotlin.io.path.createTempDirectory("sg-backup-").toFile()
        try {
            val file = File(root, "config.txt"); file.writeText("before enabled=true after")
            val tx = LocalPatchTransactionV1(root, backups)
            val preview = tx.preview(file.readText(), "enabled=true", "enabled=false")
            val receipt = tx.apply("config.txt", preview.beforeSha256, preview)
            assertTrue(file.readText().contains("enabled=false"), "patch not applied")
            assertTrue(tx.rollback(receipt) && file.readText().contains("enabled=true"), "rollback failed")
            val next = tx.preview(file.readText(), "enabled=true", "enabled=false")
            val second = tx.apply("config.txt", next.beforeSha256, next)
            file.appendText(" changed")
            runCatching { tx.rollback(second) }.onSuccess { error("rollback overwrote user edit") }
        } finally { root.deleteRecursively(); backups.deleteRecursively() }
    }
    test("comparative reports classify new/resolved/changed and stable") {
        val before = listOf(ReportSnapshotFindingV1("A", "HIGH", "host", "/", "old", "1"), ReportSnapshotFindingV1("B", "LOW", "host", "/b", "gone", "2"), ReportSnapshotFindingV1("D", "INFO", "host", "/d", "stable", "4"))
        val after = listOf(ReportSnapshotFindingV1("A", "MEDIUM", "host", "/", "updated", "3"), ReportSnapshotFindingV1("C", "HIGH", "host", "/c", "new", "5"), ReportSnapshotFindingV1("D", "INFO", "host", "/d", "stable", "4"))
        val r = ComparativeReportEngineV1.compare(before, after, 10L, 20L, 30L)
        assertTrue(r.newFindings == 1 && r.resolvedFindings == 1 && r.changedFindings == 1 && r.unchangedFindings == 1, "report buckets wrong")
    }
    test("automation policy blocks credentials and non-persisted file handles") {
        val wp = AdvancedAutomationPolicyV1.validate(AutomationDefinitionV1(AutomationKindV1.WORDPRESS_READ_ONLY, AutomationTriggerV1.DAILY, "https://site.test", true, credentialPersisted = true))
        val apk = AdvancedAutomationPolicyV1.validate(AutomationDefinitionV1(AutomationKindV1.APK_ARCHIVE, AutomationTriggerV1.DAILY, "content://temp", true, contentUriPersisted = false))
        assertTrue(!wp.allowed && !apk.allowed, "unsafe automation was allowed")
        assertTrue(AdvancedAutomationPolicyV1.validate(AutomationDefinitionV1(AutomationKindV1.THREAT_INTEL_REFRESH, AutomationTriggerV1.DAILY, authorizationConfirmed = false)).allowed, "public feed refresh blocked")
    }
    println("TOTAL: $passed/$passed smoke tests passed")
}
