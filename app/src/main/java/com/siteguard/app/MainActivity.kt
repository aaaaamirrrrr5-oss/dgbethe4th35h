package com.siteguard.app

import android.content.Intent
import android.provider.OpenableColumns
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.background
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.relocation.BringIntoViewRequester
import androidx.compose.foundation.relocation.bringIntoViewRequester
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.siteguard.app.core.Finding
import com.siteguard.app.core.ScanEngine
import com.siteguard.app.core.ScanResult
import com.siteguard.app.core.SourceCodeAnalyzer
import com.siteguard.app.core.CodeAuditResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import com.siteguard.app.core.Severity
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

private val Bg = Color(0xFF090A0D)
private val Panel = Color(0xFF15171D)
private val PanelRaised = Color(0xFF1B1E26)
private val Outline = Color(0xFF303541)
private val Red = Color(0xFFE32645)
private val Muted = Color(0xFF9AA0AA)
private val White = Color(0xFFF4F5F7)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        com.siteguard.app.core.AuthorizationBudget.attachStore(com.siteguard.app.core.SharedPrefsAuthorizationBudgetStore(applicationContext))
        // Hardening: no screenshots / recent-apps thumbnails of findings or credentials, and ignore touches while another
        // window overlaps the app (tapjacking over consent and credential screens).
        window.setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE, android.view.WindowManager.LayoutParams.FLAG_SECURE)
        window.decorView.filterTouchesWhenObscured = true
        setContent { SiteGuardApp() }
    }
}

@Composable
private fun SiteGuardApp() {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val prefs = remember { context.getSharedPreferences("siteguard_local", 0) }
    val localHistory = remember { com.siteguard.app.core.LocalAuditHistory.get(context) }
    val assessmentArchive = remember { com.siteguard.app.core.LocalAssessmentArchive.get(context) }
    val assetDriftStore = remember { com.siteguard.app.core.LocalAssetDriftStore(context) }
    val automationQueue = remember { com.siteguard.app.core.PersistentAssessmentQueueV1.get(context) }
    val localKnowledgeStore = remember { com.siteguard.app.core.LocalSecurityKnowledgeStore(context) }
    val forensicLedger = remember {
        com.siteguard.app.core.PersistentChainOfCustodyLedgerV1(java.io.File(context.filesDir, "siteguard/forensics/custody.ledger"))
    }
    var url by remember { mutableStateOf("https://example.com") }
    var authorized by remember { mutableStateOf(false) }
    var allowPrivate by remember { mutableStateOf(false) }
    var discoverInternalPages by remember { mutableStateOf(false) }
    var discoverySummary by remember { mutableStateOf("") }
    var discoveryPages by remember { mutableStateOf<List<com.siteguard.app.core.WebsiteDiscoveredPageV1>>(emptyList()) }
    var discoveryResult by remember { mutableStateOf<com.siteguard.app.core.WebsiteDiscoveryResultV1?>(null) }
    var scanning by remember { mutableStateOf(false) }
    var hygieneReport by remember { mutableStateOf<com.siteguard.app.core.PassiveHygieneReportV1?>(null) }
    var ownershipProof by remember { mutableStateOf<com.siteguard.app.core.OwnershipProofResultV1?>(null) }
    var activeScanJob by remember { mutableStateOf<Job?>(null) }
    var status by remember { mutableStateOf("آماده برای بررسی") }
    var findings by remember { mutableStateOf<List<Finding>>(emptyList()) }
    var passiveWebsiteCoverage by remember { mutableStateOf<List<com.siteguard.app.core.WebsiteControlCoverageV2>>(emptyList()) }
    var scannedHost by remember { mutableStateOf("") }
    var httpStatus by remember { mutableStateOf<Int?>(null) }
    var scannedAt by remember { mutableLongStateOf(0L) }
    var authorizationId by remember { mutableStateOf("") }
    var connectedAddress by remember { mutableStateOf("") }
    var previousSummary by remember { mutableStateOf(localHistory.latestSummary() ?: prefs.getString("last_summary", "هنوز اسکن قبلی ذخیره نشده است") ?: "") }
    var codeAudit by remember { mutableStateOf<CodeAuditResult?>(null) }
    var codeAuditStatus by remember { mutableStateOf("برای تحلیل ایستای کد، یک فایل PHP، JS، TS، Python، Java/Kotlin، C# یا Go انتخاب کنید.") }
    var codeAuditBusy by remember { mutableStateOf(false) }
    var projectAudit by remember { mutableStateOf<com.siteguard.app.core.ProjectAuditResult?>(null) }
    var projectAuditStatus by remember { mutableStateOf("برای بررسی چندفایلی و WordPress، فایل ZIP پروژه را انتخاب کنید.") }
    var projectAuditBusy by remember { mutableStateOf(false) }
    var knowledgeQuery by remember { mutableStateOf("") }
    var knowledgeResults by remember { mutableStateOf<List<com.siteguard.app.core.LocalKnowledgeSearchHit>>(emptyList()) }
    var knowledgeSearchStatus by remember { mutableStateOf("پایگاه دانش آفلاین پس از راه‌اندازی آماده جست‌وجو است.") }
    var knowledgeSearchBusy by remember { mutableStateOf(false) }
    var archivedAssessments by remember { mutableStateOf(assessmentArchive.entries()) }
    var lastAssetDrift by remember { mutableStateOf<com.siteguard.app.core.AssetDriftV1?>(null) }
    var assetDriftSummary by remember { mutableStateOf("هنوز baseline تغییرات امنیتی ثبت نشده است.") }
    var automationSnapshot by remember { mutableStateOf(automationQueue.snapshot()) }
    var automationDelayMinutes by remember { mutableStateOf("5") }
    var automationBusy by remember { mutableStateOf(false) }
    var activeAutomationJob by remember { mutableStateOf<Job?>(null) }
    var automationStatus by remember { mutableStateOf("کارهای زمان‌بندی‌شده به‌صورت رمزگذاری‌شده نگه‌داری می‌شوند؛ WorkManager اجرای پس‌زمینه را با زمان‌بندی شناور پیگیری می‌کند و پیش از اجرا مجوز را دوباره می‌سنجد.") }
    var dnsPosture by remember { mutableStateOf<com.siteguard.app.core.DnsPostureResultV1?>(null) }
    var dnsPostureBusy by remember { mutableStateOf(false) }
    var dnsPostureStatus by remember { mutableStateOf("برای بررسی SPF، DMARC و CAA، دامنه‌ای را وارد و مالکیت/مجوز آن را تأیید کنید.") }
    var pdfReportText by remember { mutableStateOf("") }
    var pdfExportStatus by remember { mutableStateOf("") }
    LaunchedEffect(localKnowledgeStore) {
        try {
            withContext(Dispatchers.IO) { localKnowledgeStore.initialize() }
            knowledgeSearchStatus = "پایگاه دانش آفلاین آماده است؛ SQLite/FTS4 یا جست‌وجوی جایگزین فعال شد."
        } catch (e: Exception) {
            knowledgeSearchStatus = "راه‌اندازی پایگاه دانش انجام نشد: ${e.message ?: e.javaClass.simpleName}"
        }
    }
    var networkProbeIp by remember { mutableStateOf("192.0.2.10") }
    var networkProbePorts by remember { mutableStateOf("443,80") }
    var networkTlsServerName by remember { mutableStateOf("") }
    var networkProbeAuthorized by remember { mutableStateOf(false) }
    var networkProbeBusy by remember { mutableStateOf(false) }
    var networkProbeStatus by remember { mutableStateOf("برای تست اتصال، IP عددی و پورت‌های دقیق مجاز را وارد کنید.") }
    var networkProbeResults by remember { mutableStateOf<List<com.siteguard.app.core.TcpProbeResult>>(emptyList()) }
    var networkTlsSummary by remember { mutableStateOf<List<String>>(emptyList()) }
    var labResults by remember { mutableStateOf<List<com.siteguard.app.core.LabSimulationResultV1>>(emptyList()) }
    var labStatus by remember { mutableStateOf("سناریوهای آزمایشگاهی فقط روی fixture مصنوعی و به‌صورت آفلاین اجرا می‌شوند.") }
    var labBusy by remember { mutableStateOf(false) }
    var selectedRemediation by remember { mutableStateOf<com.siteguard.app.core.RemediationCaseV1?>(null) }
    var findingSearchQuery by remember { mutableStateOf("") }
    var findingFilter by remember { mutableStateOf("ALL") }
    val specificationCoverage = remember { com.siteguard.app.core.SpecificationCoverageRegistryV080.snapshot() }
    val allCurrentFindings = remember(findings, codeAudit, projectAudit) {
        (findings + codeAudit?.findings.orEmpty() + projectAudit?.findings.orEmpty())
            .distinctBy { listOf(it.id, it.affectedAsset, it.exactLocation).joinToString("|") }
            .sortedBy { it.severity.ordinal }
    }
    val visibleFindings = remember(allCurrentFindings, findingSearchQuery, findingFilter) {
        val query = findingSearchQuery.trim().lowercase(Locale.ROOT)
        allCurrentFindings.filter { finding ->
            val severityMatches = when (findingFilter) {
                "HIGH" -> finding.severity == Severity.CRITICAL || finding.severity == Severity.HIGH
                "MEDIUM" -> finding.severity == Severity.MEDIUM
                "LOW" -> finding.severity == Severity.LOW || finding.severity == Severity.INFO
                else -> true
            }
            val textMatches = query.isEmpty() || listOf(
                finding.id, finding.title, finding.description, finding.affectedAsset,
                finding.exactLocation, finding.cwe
            ).any { it.lowercase(Locale.ROOT).contains(query) }
            severityMatches && textMatches
        }
    }
    val evidenceGraph = remember(allCurrentFindings) {
        com.siteguard.app.core.AttackGraphV1.fromFindings(allCurrentFindings)
    }
    val tcpProbe = remember { com.siteguard.app.core.AuthorizedTcpConnectProbe() }
    val tlsProbe = remember { com.siteguard.app.core.AuthorizedTlsCertificateProbe() }
    val scope = rememberCoroutineScope()
    LaunchedEffect(automationQueue) { automationSnapshot = automationQueue.snapshot() }
    DisposableEffect(lifecycleOwner, automationQueue, assessmentArchive) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                automationSnapshot = automationQueue.snapshot()
                archivedAssessments = assessmentArchive.entries()
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    var selectedNavigationItem by remember { mutableIntStateOf(0) }
    val dashboardAnchor = remember { BringIntoViewRequester() }
    val scanAnchor = remember { BringIntoViewRequester() }
    val reportAnchor = remember { BringIntoViewRequester() }
    val settingsAnchor = remember { BringIntoViewRequester() }
    val createRemediationPlan: (Finding) -> Unit = { finding ->
        selectedRemediation = com.siteguard.app.core.RemediationPatchEngineV1.createPlan(finding)
    }
    val codePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            codeAuditBusy = true
            codeAuditStatus = "در حال خواندن فایل به‌صورت محلی..."
            try {
                val audit = withContext(Dispatchers.IO) {
                    val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) cursor.getString(0) else null
                    } ?: "source.txt"
                    val input = context.contentResolver.openInputStream(uri)
                        ?: error("فایل قابل خواندن نیست")
                    val bytes = input.use { stream ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        var total = 0
                        while (true) {
                            val count = stream.read(buffer)
                            if (count < 0) break
                            total += count
                            require(total <= 2_000_000) { "حداکثر حجم فایل برای این نسخه ۲ مگابایت است." }
                            output.write(buffer, 0, count)
                        }
                        output.toByteArray()
                    }
                    val source = bytes.toString(Charsets.UTF_8)
                    com.siteguard.app.core.WebsiteSecuritySpecialist(context).assessSingleSource(name, source)
                }
                codeAudit = audit
                val archived = JSONObject().apply {
                    put("schema_version", com.siteguard.app.core.SiteGuardBuildInfo.REPORT_SCHEMA_VERSION)
                    put("kind", "source-code-audit"); put("file", audit.fileName); put("language", audit.language)
                    put("lines_scanned", audit.linesScanned); put("root_cause_hints", JSONArray(audit.rootCauseSummary))
                    put("findings", JSONArray().apply { audit.findings.forEach { put(com.siteguard.app.core.JsonReportExporter.findingJson(it)) } })
                    put("limitations", JSONArray(listOf("تحلیل ایستا و heuristic است؛ اجرای کد یا اثبات exploit انجام نشده است.")))
                }.toString(2)
                val archiveSave = withContext(Dispatchers.IO) { runCatching { assessmentArchive.add("source", audit.fileName, audit.language, audit.findings.size, archived) } }
                archivedAssessments = assessmentArchive.entries()
                codeAuditStatus = "${audit.language} • ${audit.linesScanned} خط بررسی شد • ${audit.findings.size} نشانه پیدا شد" +
                    if (archiveSave.isSuccess) " • در آرشیو رمزگذاری‌شده ذخیره شد" else " • ذخیره آرشیو انجام نشد: ${archiveSave.exceptionOrNull()?.message ?: "خطای محلی"}"
            } catch (e: Exception) {
                codeAuditStatus = "تحلیل انجام نشد: ${e.message ?: e.javaClass.simpleName}"
            } finally { codeAuditBusy = false }
        }
    }
    val projectPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            projectAuditBusy = true
            projectAuditStatus = "در حال بررسی امن ZIP در حافظه موقت؛ هیچ فایلی استخراج نمی‌شود..."
            try {
                val audit = withContext(Dispatchers.IO) {
                    val name = context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                        if (cursor.moveToFirst()) cursor.getString(0) else null
                    } ?: "project.zip"
                    val input = context.contentResolver.openInputStream(uri) ?: error("فایل ZIP قابل خواندن نیست")
                    val archiveBytes = input.use { stream ->
                        val output = java.io.ByteArrayOutputStream()
                        val buffer = ByteArray(8192)
                        var total = 0
                        while (true) {
                            val count = stream.read(buffer)
                            if (count < 0) break
                            total += count
                            require(total <= 25 * 1024 * 1024) { "حجم فایل از سقف ۲۵ مگابایت عبور کرد." }
                            output.write(buffer, 0, count)
                        }
                        output.toByteArray()
                    }
                    val acquiredAt = System.currentTimeMillis()
                    val evidence = com.siteguard.app.core.ThreatForensicsEngineV1.createEvidence(
                        logicalName = name, mediaType = if (name.endsWith(".apk", true)) "application/vnd.android.package-archive" else "application/zip",
                        bytes = archiveBytes, capturedAtEpochMs = acquiredAt,
                        timeZone = java.util.TimeZone.getDefault().id,
                        sourceDescription = "فایل انتخاب‌شده توسط کاربر از Storage Access Framework؛ اصل ورودی در برنامه تغییر داده نشد.",
                        readOnlyAcquisition = true
                    )
                    forensicLedger.append(evidence.evidenceId, "ACQUIRED_READ_ONLY", "local-device-user", acquiredAt, "size=${evidence.sizeBytes}; sha256=${evidence.sha256}")
                    val audit = com.siteguard.app.core.WebsiteSecuritySpecialist(context).assessWebsiteSourceArchive(
                        java.io.ByteArrayInputStream(archiveBytes), name
                    )
                    forensicLedger.append(evidence.evidenceId, "STATIC_ANALYSIS_COMPLETED", "siteguard-local-engine", System.currentTimeMillis(), "files=${audit.filesScanned}; findings=${audit.findings.size}")
                    require(forensicLedger.verify()) { "اعتبار زنجیره تحویل شواهد پس از تحلیل تأیید نشد." }
                    audit
                }
                projectAudit = audit
                val projectReport = com.siteguard.app.core.JsonReportExporter.projectJson(audit).toString(2)
                val archiveSave = withContext(Dispatchers.IO) { runCatching { assessmentArchive.add("project", audit.archiveName, if (audit.isWooCommerce) "WordPress + WooCommerce" else if (audit.isWordPress) "WordPress" else "project ZIP", audit.findings.size, projectReport) } }
                archivedAssessments = assessmentArchive.entries()
                val platform = when {
                    audit.isWooCommerce -> "WordPress + WooCommerce"
                    audit.isWordPress -> "WordPress"
                    else -> "پروژه عمومی"
                }
                projectAuditStatus = "$platform • ${audit.filesScanned} فایل بررسی شد • ${audit.findings.size} یافته • ${audit.dependencies.records.size} وابستگی" +
                    if (archiveSave.isSuccess) " • آرشیو شد" else " • خطای آرشیو: ${archiveSave.exceptionOrNull()?.message ?: "نامشخص"}"
            } catch (e: Exception) {
                projectAuditStatus = "بررسی پروژه انجام نشد: ${e.message ?: e.javaClass.simpleName}"
            } finally { projectAuditBusy = false }
        }
    }

    val pdfLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri != null) scope.launch {
            pdfExportStatus = "در حال آماده‌سازی PDF..."
            try {
                val bytes = withContext(Dispatchers.Default) { PdfReportRenderer.render(pdfReportText) }
                withContext(Dispatchers.IO) {
                    val output = context.contentResolver.openOutputStream(uri) ?: error("فایل مقصد قابل نوشتن نیست.")
                    output.use { it.write(bytes) }
                }
                pdfExportStatus = "گزارش PDF ذخیره شد (${bytes.size / 1024} KB)."
            } catch (e: Exception) {
                pdfExportStatus = "ساخت PDF انجام نشد: ${e.message ?: e.javaClass.simpleName}"
            }
        }
    }

    fun createPdfReportText(): String = buildString {
        appendLine("گزارش ارزیابی امنیتی SiteGuard")
        appendLine("نسخه: ${com.siteguard.app.core.SiteGuardBuildInfo.VERSION_NAME}")
        appendLine("هدف: ${scannedHost.ifBlank { projectAudit?.archiveName ?: codeAudit?.fileName ?: "—" }}")
        appendLine("زمان تولید: ${SimpleDateFormat("yyyy/MM/dd HH:mm:ss", Locale.getDefault()).format(Date())}")
        appendLine("وضعیت HTTP: ${httpStatus ?: "بررسی نشده"} • شناسه مجوز: ${authorizationId.ifBlank { "ندارد/محلی" }}")
        appendLine("تعداد یافته‌ها: ${allCurrentFindings.size}")
        appendLine("تغییرات نسبت به baseline: $assetDriftSummary")
        appendLine("------------------------------------------------------------")
        allCurrentFindings.forEachIndexed { index, finding ->
            val confidence = com.siteguard.app.core.EvidenceConfidenceEngineV1.assess(finding)
            appendLine("${index + 1}. ${finding.title}")
            appendLine("شدت: ${finding.severity} • وضعیت: ${finding.status} • اطمینان شواهد: ${confidence.score}/100 (${confidence.band})")
            appendLine("دارایی: ${finding.affectedAsset} • موقعیت: ${finding.exactLocation}")
            appendLine("شرح: ${com.siteguard.app.core.EvidenceSanitizer.sanitize(finding.description)}")
            appendLine("شواهد: ${com.siteguard.app.core.EvidenceSanitizer.sanitize(finding.evidence)}")
            appendLine("اصلاح: ${com.siteguard.app.core.EvidenceSanitizer.sanitize(finding.remediation)}")
            appendLine("------------------------------------------------------------")
        }
        dnsPosture?.let { dns ->
            appendLine("بررسی DNS دامنه ${dns.domain}")
            dns.checks.forEach { appendLine("${it.title}: ${it.state} — ${it.detail}") }
            appendLine("منبع: ${dns.resolver}")
        }
        projectAudit?.let { appendLine("تحلیل ZIP: ${it.archiveName} • ${it.filesScanned} فایل • ${it.dependencies.records.size} وابستگی") }
        codeAudit?.let { appendLine("تحلیل سورس: ${it.fileName} • ${it.linesScanned} خط") }
        appendLine("محدودیت: بررسی passive/ایستا است؛ نبود یافته به معنی امنیت کامل نیست. اصلاح production، exploit یا brute force انجام نشده است.")
    }

    fun exportPdfReport() {
        pdfReportText = createPdfReportText()
        pdfExportStatus = ""
        pdfLauncher.launch("SiteGuard-Report-${System.currentTimeMillis()}.pdf")
    }

    fun exportReport() {
        val report = JSONObject().apply {
            put("schema_version", com.siteguard.app.core.SiteGuardBuildInfo.REPORT_SCHEMA_VERSION)
            put("product", "SiteGuard Android")
            put("version", com.siteguard.app.core.SiteGuardBuildInfo.VERSION_NAME)
            put("target", scannedHost)
            put("http_status", httpStatus ?: JSONObject.NULL)
            put("scanned_at_epoch_ms", scannedAt)
            put("authorization", "single exact host/port/path authorization manifest; expires in 60 minutes")
            put("authorization_id", authorizationId)
            put("connected_address", connectedAddress)
            put("scope", "authorized passive HTTP GET; DNS answer pinned; redirects not followed")
            put("passive_hygiene", hygieneReport
                ?.takeIf { it.host.isNotBlank() && it.host.equals(scannedHost, ignoreCase = true) }
                ?.let { com.siteguard.app.core.PassiveHygieneJsonV1.toJson(it, ownershipProof) } ?: JSONObject.NULL)
            put("specification_coverage", JSONObject().apply {
                put("expected_documents", specificationCoverage.expectedDocuments)
                put("present_documents", specificationCoverage.presentDocuments)
                put("sequence_valid", specificationCoverage.sequenceValid)
                put("whole_documents_tested", specificationCoverage.testedWholeDocuments)
                put("whole_documents_implemented", specificationCoverage.implementedWholeDocuments)
                put("partially_supported_documents", specificationCoverage.partiallySupportedDocuments)
                put("unsupported_or_blocked_documents", specificationCoverage.unsupportedDocuments)
                put("items", JSONArray().apply { specificationCoverage.items.forEach { item -> put(JSONObject().apply {
                    put("number", item.number); put("file", item.fileName); put("title", item.title)
                    put("status", item.status.name); put("implemented_areas", JSONArray(item.implementedAreas))
                    put("verified_checks", JSONArray(item.verifiedChecks)); put("remaining_work", JSONArray(item.remainingWork))
                }) } })
            })
            put("website_discovery", discoveryResult?.let { discovery -> JSONObject().apply {
                put("engagement_id", discovery.engagementId); put("started_at_epoch_ms", discovery.startedAtEpochMs)
                put("completed_at_epoch_ms", discovery.completedAtEpochMs); put("requests_used", discovery.requestsUsed)
                put("pages", JSONArray().apply { discovery.pages.forEach { page -> put(JSONObject().apply {
                    put("url", page.url); put("status", page.statusCode); put("content_type", page.contentType)
                    put("title", page.title); put("depth", page.depth); put("connected_ip", page.connectedIp)
                    put("body_sha256", page.bodySha256); put("discovered_links", page.discoveredLinks)
                    put("headers", JSONObject(page.responseHeaders))
                }) } })
                put("events", JSONArray().apply { discovery.events.forEach { event -> put(JSONObject().apply { put("url", event.url); put("status", event.status); put("reason", event.reason) }) } })
                put("limitations", JSONArray(discovery.limitations))
            } } ?: JSONObject.NULL)
            put("findings", JSONArray().apply { allCurrentFindings.forEach { put(com.siteguard.app.core.JsonReportExporter.findingJson(it)) } })
            put("code_audit", codeAudit?.let { audit -> JSONObject().apply {
                put("file", audit.fileName); put("language", audit.language); put("lines_scanned", audit.linesScanned)
                put("findings", JSONArray().apply { audit.findings.forEach { put(com.siteguard.app.core.JsonReportExporter.findingJson(it)) } })
                put("root_cause_hints", JSONArray(audit.rootCauseSummary))
            } } ?: JSONObject.NULL)
            put("project_audit", projectAudit?.let { com.siteguard.app.core.JsonReportExporter.projectJson(it) } ?: JSONObject.NULL)
            put("asset_drift", lastAssetDrift?.let { drift -> JSONObject().apply {
                put("asset_id", drift.assetId); put("previous_sha256", drift.previousHash)
                put("current_sha256", drift.currentHash); put("changed", drift.changed)
                put("changed_keys", JSONArray(drift.changedKeys)); put("summary", assetDriftSummary)
            } } ?: JSONObject().put("summary", assetDriftSummary))
            put("dns_security_posture", dnsPosture?.let { result -> JSONObject().apply {
                put("domain", result.domain); put("checked_at_epoch_ms", result.checkedAtEpochMs); put("resolver", result.resolver)
                put("checks", JSONArray().apply { result.checks.forEach { check -> put(JSONObject().apply {
                    put("id", check.id); put("title", check.title); put("state", check.state.name)
                    put("detail", check.detail); put("evidence", JSONArray(check.evidence))
                }) } })
                put("limitations", JSONArray(result.limitations))
            } } ?: JSONObject.NULL)
            put("website_security_specialist_v2", projectAudit?.let { project ->
                val specialist = com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assess(project)
                JSONObject().apply {
                    put("specification_version", specialist.specificationVersion)
                    put("generated_at_epoch_ms", specialist.generatedAtEpochMs)
                    put("engagement_mode", specialist.engagementMode)
                    put("platform", specialist.platform)
                    put("controls", JSONArray().apply { specialist.controls.forEach { control ->
                        put(JSONObject().apply {
                            put("id", control.definition.id); put("family", control.definition.family)
                            put("title", control.definition.title); put("state", control.state.name)
                            put("reason", control.reason); put("finding_ids", JSONArray(control.findingIds))
                        })
                    } })
                    put("architecture_nodes", JSONArray().apply { specialist.architectureNodes.forEach { node ->
                        put(JSONObject().apply { put("id", node.nodeId); put("type", node.type); put("label", node.label); put("evidence_ref", node.evidenceRef); put("observed", node.observed) })
                    } })
                    put("architecture_edges", JSONArray().apply { specialist.architectureEdges.forEach { edge ->
                        put(JSONObject().apply { put("from", edge.fromNodeId); put("to", edge.toNodeId); put("relation", edge.relation); put("evidence_ref", edge.evidenceRef); put("confidence", edge.confidence); put("observed", edge.observed); put("note", edge.note) })
                    } })
                    put("test_plans", JSONArray().apply { specialist.testPlans.forEach { plan ->
                        put(JSONObject().apply {
                            put("control_id", plan.controlId); put("method", plan.method); put("prerequisites", plan.prerequisites)
                            put("risk", plan.risk); put("required_test_class", plan.requiredTestClass.name)
                            put("request_budget", plan.requestBudget); put("rate_per_minute", plan.ratePerMinute)
                            put("max_concurrency", plan.maxConcurrency); put("evidence_type", plan.evidenceType)
                            put("pass_criteria", plan.passCriteria); put("fail_criteria", plan.failCriteria)
                            put("support_state", plan.supportState.name); put("requires_synthetic_accounts", plan.requiresSyntheticAccounts)
                            put("requires_separate_approval", plan.requiresSeparateApproval); put("execution_status", plan.executionStatus)
                        })
                    } })
                    put("evidence_records", JSONArray().apply { specialist.evidenceRecords.forEach { record ->
                        put(JSONObject().apply {
                            put("evidence_id", record.evidenceId); put("finding_id", record.findingId); put("asset_id", record.assetId)
                            put("timestamp_epoch_ms", record.timestampEpochMs); put("timezone", record.timezone)
                            put("source_tool", record.sourceTool); put("tool_version", record.toolVersion)
                            put("rule_id", record.ruleId); put("rule_version", record.ruleVersion)
                            put("sanitized_evidence", record.sanitizedEvidence); put("integrity_sha256", record.integritySha256)
                            put("safe_reproduction_procedure", record.safeReproductionProcedure)
                            put("test_account_class", record.testAccountClass); put("request_count", record.requestCount)
                            put("request_duration_ms", record.requestDurationMs); put("request_rate_per_minute", record.requestRatePerMinute)
                            put("scope_token_reference", record.scopeTokenReference); put("cleanup_status", record.cleanupStatus)
                            put("completeness", record.completeness)
                        })
                    } })
                    put("limitations", JSONArray(specialist.limitations))
                }
            } ?: JSONObject.NULL)
            put("local_knowledge_database", localKnowledgeStore.statusJson())
            put("forensic_chain_of_custody", JSONObject().apply {
                put("verified", forensicLedger.verify())
                put("event_count", forensicLedger.snapshot().size)
                put("note", "Hash-linked local record; it is not a hardware-backed signature or externally witnessed chain.")
            })
            put("sbom_cyclonedx_1_5", projectAudit?.let {
                JSONObject(com.siteguard.app.core.JsonReportExporter.exportSbom(it.dependencies, it.archiveName))
            } ?: JSONObject.NULL)
            put("limitations", "Deterministic rules are not general-purpose AI. No hosted AI/API, exploit, brute force, authenticated test, or production modification was performed. Heuristic results require human validation.")
        }.toString(2)
        SafeShare.shareText(context, "application/json", "SiteGuard security report - $scannedHost", report, "اشتراک گزارش امنیتی", "siteguard-security-report.json")
    }

    fun exportHtmlReport() {
        val allFindings = allCurrentFindings
        val executedTests = mutableListOf<com.siteguard.app.core.TestExecutionRecordV1>()
        if (scannedAt > 0L) executedTests += com.siteguard.app.core.TestExecutionRecordV1(
            "WEB-PASSIVE-HTTP", "web", com.siteguard.app.core.TestExecutionStatus.EXECUTED,
            "یک درخواست GET محدود با scope مجاز انجام شد؛ redirect دنبال نشد."
        )
        if (codeAudit != null) executedTests += com.siteguard.app.core.TestExecutionRecordV1(
            "SOURCE-STATIC", "source", com.siteguard.app.core.TestExecutionStatus.EXECUTED,
            "تحلیل ایستای فایل انتخاب‌شده انجام شد؛ تحلیل AST/taint کامل نیست."
        )
        if (projectAudit != null) executedTests += com.siteguard.app.core.TestExecutionRecordV1(
            "PROJECT-ZIP-STATIC", "project", com.siteguard.app.core.TestExecutionStatus.EXECUTED,
            "تحلیل ایستای ZIP در حافظه انجام شد؛ فایل‌ها روی دیسک استخراج نشدند."
        )
        val report = com.siteguard.app.core.SecurityReportV1(
            product = "SiteGuard Android", version = com.siteguard.app.core.SiteGuardBuildInfo.VERSION_NAME, generatedAtEpochMs = System.currentTimeMillis(),
            scopeDescription = scannedHost.ifBlank { "فقط فایل/پروژه محلی انتخاب‌شده؛ ارزیابی شبکه‌ای ثبت نشده است." },
            authorizationId = authorizationId.ifBlank { "برای این گزارش، مجوز شبکه‌ای اعمال نشده / فقط تحلیل محلی" },
            methodology = "قواعد deterministic و تحلیل ایستا؛ هیچ AI API، سرویس inference میزبانی‌شده، brute force، exploit یا تغییر production انجام نشده است.",
            coverage = com.siteguard.app.core.TestCoverageCalculatorV1.summarize(executedTests),
            findings = allFindings,
            limitations = (projectAudit?.limitations.orEmpty() + listOf(
                "این گزارش تنها اجرای ثبت‌شده در همین نشست را شامل می‌شود؛ موارد اجرا نشده باید جداگانه مشخص شوند.",
                "گزارش عدم یافتن مشکل را معادل امن بودن هدف نمی‌داند.",
                "پوشش کامل API DAST، APK/AAB باینری، Cloud runtime و Active Directory ادعا نمی‌شود."
            )).distinct(),
            evidenceReferences = allFindings.map { com.siteguard.app.core.DefaultEvidenceProvider.evidenceFor(it).evidenceId },
            remediationSummary = allFindings.map { "${it.id}: ${it.remediation}" },
            retestSummary = "بازآزمایی پس از اصلاح در این گزارش اجرا نشده مگر آنکه نتیجه جداگانه ثبت شده باشد.",
            websiteSpecialistCoverage = projectAudit?.let { project ->
                com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assess(project).controls.map { "${it.definition.id} • ${it.state} • ${it.reason}" }
            }.orEmpty(),
            architectureRelationships = projectAudit?.let { project ->
                com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assess(project).architectureEdges.map { "${it.relation}: ${it.fromNodeId} -> ${it.toNodeId} • ${if (it.observed) "Observed" else "Inferred"} • ${it.evidenceRef}" }
            }.orEmpty(),
            websiteTestPlans = projectAudit?.let { project ->
                com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assess(project).testPlans.map { "${it.controlId}: ${it.requiredTestClass} • ${it.supportState} • ${it.executionStatus} • ${it.prerequisites}" }
            }.orEmpty(),
            websiteEvidenceRecords = projectAudit?.let { project ->
                com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assess(project).evidenceRecords.map { "${it.evidenceId} • ${it.findingId} • ${it.completeness} • SHA-256 ${it.integritySha256}" }
            }.orEmpty()
        )
        val discoveryHtml = discoveryResult?.let { discovery ->
            "<section><h2>Website Discovery</h2><p>Pages: ${discovery.pages.size} • Requests: ${discovery.requestsUsed}</p><ul>" +
                discovery.pages.joinToString("") { page -> "<li>${page.statusCode} • ${com.siteguard.app.core.HtmlSecurityReportExporterV1.escapeHtml(page.url)} • ${page.bodySha256.take(16)}</li>" } +
                "</ul><p>Only bounded passive GET was executed; no credentials or state-changing requests were sent.</p></section>"
        }.orEmpty()
        val specificationCoverageHtml = "<section><h2>Specification Coverage 00–23</h2><p>Present: ${specificationCoverage.presentDocuments}/${specificationCoverage.expectedDocuments} • Whole documents tested: ${specificationCoverage.testedWholeDocuments} • Sequence valid: ${specificationCoverage.sequenceValid}</p><ul>" +
            specificationCoverage.items.joinToString("") { item -> "<li>${item.number} • ${item.title} • ${item.status.name} • Remaining: ${item.remainingWork.joinToString("; ")}</li>" } + "</ul><p>Partial implementation is not represented as complete or fully tested.</p></section>"
        val html = com.siteguard.app.core.HtmlSecurityReportExporterV1.export(report).removeSuffix("</body></html>") + discoveryHtml + specificationCoverageHtml +
            "<section><h2>Forensic Chain of Custody</h2><p>Verified: ${forensicLedger.verify()} • Events: ${forensicLedger.snapshot().size}</p><p>Hash-linked local ledger; not a hardware-backed signature or external witness.</p></section>" +
            "</body></html>"
        SafeShare.shareText(context, "text/html", "SiteGuard technical security report", html, "اشتراک گزارش HTML", "siteguard-technical-report.html")
    }

    MaterialTheme(colorScheme = darkColorScheme(
        background = Bg, surface = Panel, surfaceVariant = PanelRaised, primary = Red,
        onPrimary = White, onBackground = White, onSurface = White,
        onSurfaceVariant = Color(0xFFC1C5CE), secondary = Color(0xFFFF6B81),
        outline = Outline
    )) {
        val navigationColors = NavigationBarItemDefaults.colors(
            selectedIconColor = Red,
            selectedTextColor = White,
            indicatorColor = Red.copy(alpha = .15f),
            unselectedIconColor = Muted,
            unselectedTextColor = Muted
        )
        Scaffold(containerColor = Bg, bottomBar = {
            NavigationBar(containerColor = Panel, contentColor = White, tonalElevation = 10.dp) {
                NavigationBarItem(selected = selectedNavigationItem == 0, onClick = {
                    selectedNavigationItem = 0
                    scope.launch { dashboardAnchor.bringIntoView() }
                }, icon = { Icon(Icons.Default.Dashboard, contentDescription = "داشبورد") }, label = { Text("داشبورد") }, colors = navigationColors)
                NavigationBarItem(selected = selectedNavigationItem == 1, onClick = {
                    selectedNavigationItem = 1
                    scope.launch { scanAnchor.bringIntoView() }
                }, icon = { Icon(Icons.Default.Security, contentDescription = "اسکن") }, label = { Text("اسکن") }, colors = navigationColors)
                NavigationBarItem(selected = selectedNavigationItem == 2, onClick = {
                    selectedNavigationItem = 2
                    scope.launch { reportAnchor.bringIntoView() }
                }, icon = { Icon(Icons.Default.Assessment, contentDescription = "گزارش") }, label = { Text("گزارش") }, colors = navigationColors)
                NavigationBarItem(selected = selectedNavigationItem == 3, onClick = {
                    selectedNavigationItem = 3
                    scope.launch { settingsAnchor.bringIntoView() }
                }, icon = { Icon(Icons.Default.Settings, contentDescription = "تنظیمات") }, label = { Text("تنظیمات") }, colors = navigationColors)
                NavigationBarItem(selected = selectedNavigationItem == 4, onClick = {
                    selectedNavigationItem = 4
                }, icon = { Icon(Icons.Default.AutoAwesome, contentDescription = "مرکز پیشرفته") }, label = { Text("پیشرفته") }, colors = navigationColors)
            }
        }) { padding ->
            if (selectedNavigationItem == 4) {
                AdvancedModulesHub(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    findings = allCurrentFindings
                )
            } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(18.dp),
                verticalArrangement = Arrangement.spacedBy(14.dp)
            ) {
                item {
                    val busyNow = scanning || networkProbeBusy || codeAuditBusy || projectAuditBusy || knowledgeSearchBusy || labBusy
                    val activityLabel = when {
                        scanning -> "اسکن وب فعال"
                        networkProbeBusy -> "بررسی شبکه فعال"
                        codeAuditBusy -> "تحلیل سورس فعال"
                        projectAuditBusy -> "تحلیل پروژه فعال"
                        knowledgeSearchBusy -> "جست‌وجوی دانش"
                        labBusy -> "آزمایشگاه فعال"
                        scannedAt > 0L -> "آخرین بررسی ثبت شده"
                        else -> "آماده بررسی"
                    }
                    Card(
                        modifier = Modifier.bringIntoViewRequester(dashboardAnchor).fillMaxWidth(),
                        colors = CardDefaults.cardColors(containerColor = Panel),
                        shape = RoundedCornerShape(26.dp),
                        border = androidx.compose.foundation.BorderStroke(1.dp, Outline),
                        elevation = CardDefaults.cardElevation(defaultElevation = 3.dp)
                    ) {
                        Box(
                            Modifier.fillMaxWidth()
                                .background(Brush.linearGradient(listOf(Color(0xFF24202A), Color(0xFF17191F), Color(0xFF24171E))))
                                .padding(18.dp)
                        ) {
                            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Surface(color = Red.copy(alpha = .16f), shape = RoundedCornerShape(17.dp)) {
                                        Icon(Icons.Default.Shield, contentDescription = "نشان SiteGuard", tint = Red, modifier = Modifier.padding(13.dp).size(32.dp))
                                    }
                                    Spacer(Modifier.width(12.dp))
                                    Column(Modifier.weight(1f)) {
                                        Text("SITEGUARD", fontSize = 23.sp, fontWeight = FontWeight.Black, color = White, letterSpacing = 2.2.sp)
                                        Text("SECURITY INTELLIGENCE  •  v${com.siteguard.app.core.SiteGuardBuildInfo.VERSION_NAME}", fontSize = 10.sp, color = Muted, letterSpacing = 1.sp)
                                    }
                                    StatusPill("LOCAL-FIRST", Color(0xFF65D6A0))
                                }
                                Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    StatusPill(activityLabel, if (busyNow) Color(0xFFFFC857) else if (scannedAt > 0L) Color(0xFF65D6A0) else Color(0xFF9AA0AA))
                                    Text(
                                        if (scannedAt > 0L) "${SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.getDefault()).format(Date(scannedAt))}"
                                        else "تحلیل محلی • بدون AI API",
                                        color = Muted, fontSize = 10.sp, maxLines = 1
                                    )
                                }
                                if (scannedAt > 0L) Text(assetDriftSummary, color = Color(0xFFB8C0CC), fontSize = 10.sp, lineHeight = 15.sp)
                                Text(
                                    "بررسی وب‌سایت، سورس و پروژه با شواهد قابل ردیابی؛ بدون اجرای کد هدف یا تغییر خودکار production.",
                                    color = Color(0xFFD0D3DA), fontSize = 12.sp, lineHeight = 18.sp
                                )
                            }
                        }
                    }
                }
                item {
                    Card(modifier = Modifier.bringIntoViewRequester(scanAnchor), colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(22.dp)) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(11.dp)) {
                            Text("ارزیابی امنیتی", fontSize = 18.sp, fontWeight = FontWeight.Bold)
                            Text("اسکن پایه غیرفعال؛ بدون بهره‌برداری، brute force یا تغییر در سایت", color = Muted, fontSize = 12.sp)
                            OutlinedTextField(
                                value = url, onValueChange = { url = it }, modifier = Modifier.fillMaxWidth(),
                                label = { Text("آدرس وب‌سایت") }, leadingIcon = { Icon(Icons.Default.Language, null) },
                                singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Red, unfocusedBorderColor = Color(0xFF343843), focusedLabelColor = Red, cursorColor = Red)
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = authorized, onCheckedChange = { authorized = it }, colors = CheckboxDefaults.colors(checkedColor = Red))
                                Text("مالک سایت هستم یا مجوز بررسی دارم", fontSize = 12.sp, color = Muted)
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = allowPrivate, onCheckedChange = { allowPrivate = it }, colors = CheckboxDefaults.colors(checkedColor = Red))
                                Column {
                                    Text("اجازه بررسی شبکه داخلی", fontSize = 12.sp, color = White)
                                    Text("فقط برای دامنه/IP خصوصی تحت اختیار شما", fontSize = 10.sp, color = Muted)
                                }
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = discoverInternalPages, onCheckedChange = { discoverInternalPages = it }, colors = CheckboxDefaults.colors(checkedColor = Red))
                                Column {
                                    Text("کشف محدود صفحات داخلی", fontSize = 12.sp, color = White)
                                    Text("اختیاری؛ حداکثر ۸ صفحه، فقط GET بدون ورود/کوکی، همان hostname و مسیرهای غیرتراکنشی", fontSize = 10.sp, color = Muted)
                                }
                            }
                            Button(onClick = {
                                when {
                                    !authorized -> status = "برای شروع، مجوز بررسی هدف را تأیید کنید."
                                    scanning -> status = "اسکن در حال اجراست."
                                    else -> {
                                        scanning = true
                                        findings = emptyList()
                                        passiveWebsiteCoverage = emptyList()
                                        discoverySummary = ""
                                        discoveryPages = emptyList()
                                        discoveryResult = null
                                        httpStatus = null
                                        status = "در حال بررسی DNS و پاسخ HTTP..."
                                        activeScanJob = scope.launch {
                                            try {
                                                val manifest = com.siteguard.app.core.AuthorizationManifest.forSingleTarget(url, allowPrivate)
                                                val result = if (manifest == null) {
                                                    ScanResult("", emptyList(), "آدرس برای ساخت مانیفست مجوز معتبر نیست.")
                                                } else {
                                                    com.siteguard.app.core.WebsiteSecuritySpecialist(context).assessAuthorizedWebsite(
                                                        com.siteguard.app.core.ScannerRequestV1(url, manifest, allowPrivate)
                                                    )
                                                }
                                                if (manifest != null && discoverInternalPages && result.httpStatus != null) {
                                                    val normalizedTarget = com.siteguard.app.core.normalizeUrl(url)
                                                    val parsedTarget = normalizedTarget?.let { runCatching { java.net.URI(it) }.getOrNull() }
                                                    if (parsedTarget != null && !allowPrivate) {
                                                        val now = System.currentTimeMillis()
                                                        val websiteManifest = com.siteguard.app.core.WebsiteEngagementManifestV2(
                                                            projectId = manifest.authorizationId,
                                                            projectName = "Authorized website passive discovery",
                                                            assetOwner = manifest.ownerDeclaration,
                                                            authorizer = manifest.ownerDeclaration,
                                                            proofMethod = com.siteguard.app.core.WebsiteAuthorizationProofV2.USER_DECLARATION,
                                                            proofReference = "User explicitly enabled same-host limited passive discovery in the app",
                                                            allowedHosts = setOf(parsedTarget.host),
                                                            allowedPathPrefixes = setOf("/"),
                                                            excludedPaths = setOf("/wp-admin", "/wp-login.php", "/checkout", "/cart", "/my-account"),
                                                            authorizedPorts = setOf(if (parsedTarget.port >= 0) parsedTarget.port else if (parsedTarget.scheme.equals("https", true)) 443 else 80),
                                                            allowedTestClasses = setOf(com.siteguard.app.core.WebsiteTestClassV2.PASSIVE_REVIEW),
                                                            environment = "production-passive",
                                                            validFromEpochMs = now - 1_000,
                                                            validUntilEpochMs = now + 15 * 60_000L,
                                                            maxRequests = 8,
                                                            requestsPerMinute = 60,
                                                            maxConcurrency = 1,
                                                            emergencyContact = "User controlled in-app cancellation",
                                                            emergencyStopProcedure = "Cancel the current foreground job"
                                                        )
                                                        val discovery = com.siteguard.app.core.WebsiteDiscoveryEngineV1.discover(
                                                            normalizedTarget, websiteManifest,
                                                            com.siteguard.app.core.WebsiteDiscoveryOptionsV1(maxPages = 8, maxDepth = 1)
                                                        )
                                                        discoveryPages = discovery.pages
                                                        discoveryResult = discovery
                                                        discoverySummary = "کشف محدود: ${discovery.pages.size} صفحه دریافت شد، ${discovery.requestsUsed} درخواست؛ ${discovery.events.count { it.status == "LINK_NOT_FOLLOWED" || it.status == "REDIRECT_NOT_FOLLOWED" }} مقصد/لینک دنبال‌نشده."
                                                    } else if (allowPrivate) {
                                                        discoverySummary = "خزش روی IP خصوصی اجرا نشد؛ برای این کار باید CIDR دقیق در مانیفست پیشرفته ثبت شود."
                                                    }
                                                }
                                                applyResult(result) { host, list, msg, code, time ->
                                                    scannedHost = host; findings = list; status = msg; httpStatus = code; scannedAt = time
                                                    passiveWebsiteCoverage = com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assessPassiveWebScan(result)
                                                    authorizationId = result.authorizationId; connectedAddress = result.connectedAddress
                                                }
                                                if (result.host.isNotBlank() && result.httpStatus != null) {
                                                    val facts = linkedMapOf(
                                                        "http_status" to result.httpStatus.toString(),
                                                        "connected_ip" to result.connectedAddress,
                                                        "finding_count" to result.findings.size.toString(),
                                                        "findings" to result.findings.sortedBy { it.id }.joinToString(";") { "${it.id}:${it.severity}:${it.status}:${it.exactLocation}" }
                                                    )
                                                    val drift = runCatching {
                                                        assetDriftStore.compareAndUpdate(com.siteguard.app.core.AssetSnapshotV1(result.host, facts, result.scannedAt))
                                                    }.getOrNull()
                                                    lastAssetDrift = drift
                                                    assetDriftSummary = when {
                                                        drift == null -> "Baseline اولیه برای ${result.host} ذخیره شد؛ اسکن بعدی امکان مقایسه می‌دهد."
                                                        !drift.changed -> "تغییر قابل مشاهده‌ای نسبت به baseline قبلی ${result.host} ثبت نشد."
                                                        else -> "تغییر نسبت به اسکن قبلی: ${drift.changedKeys.joinToString("، ")}. هش قبلی/جدید در داده محلی محاسبه شد."
                                                    }
                                                }
                                                val summary = "${result.host.ifBlank { url }} • ${result.findings.size} یافته • ${SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.getDefault()).format(Date(result.scannedAt))}"
                                                val saveResult = withContext(Dispatchers.IO) { runCatching { localHistory.add(result, manifest) } }
                                                previousSummary = if (saveResult.isSuccess) summary else "$summary • ذخیره محلی انجام نشد"
                                                withContext(Dispatchers.IO) { runCatching { assessmentArchive.add("website", result.host, result.connectedAddress, result.findings.size, com.siteguard.app.core.JsonReportExporter.exportScan(result)) } }
                                                archivedAssessments = assessmentArchive.entries()
                                            } catch (ignored: kotlinx.coroutines.TimeoutCancellationException) {
                                                status = "حداکثر زمان مجاز عملیات به پایان رسید؛ اسکن متوقف شد و نتیجه ناقص به‌عنوان موفق ثبت نمی‌شود."
                                            } catch (ignored: CancellationException) {
                                                status = "درخواست لغو شد؛ عملیات شبکه در اولین نقطه امن متوقف می‌شود."
                                            } catch (e: Exception) {
                                                status = "اسکن ناموفق بود: ${e.message ?: e.javaClass.simpleName}"
                                            } finally {
                                                scanning = false
                                                activeScanJob = null
                                            }
                                        }
                                    }
                                }
                            }, modifier = Modifier.fillMaxWidth().height(52.dp), colors = ButtonDefaults.buttonColors(containerColor = Red), shape = RoundedCornerShape(14.dp), enabled = !scanning && !codeAuditBusy && !projectAuditBusy) {
                                if (scanning) CircularProgressIndicator(Modifier.size(19.dp), color = White, strokeWidth = 2.dp) else Icon(Icons.Default.Radar, null)
                                Spacer(Modifier.width(8.dp)); Text(if (scanning) "در حال بررسی" else "شروع اسکن ایمن", fontWeight = FontWeight.Bold)
                            }
                            if (scanning) {
                                TextButton(onClick = { activeScanJob?.cancel(); status = "درخواست لغو ثبت شد..." }) {
                                    Icon(Icons.Default.Close, null); Spacer(Modifier.width(4.dp)); Text("لغو اسکن")
                                }
                            }
                            Text(status, color = Muted, fontSize = 11.sp)
                            if (discoverySummary.isNotBlank()) {
                                Text(discoverySummary, color = Color(0xFFB8C0CC), fontSize = 10.sp)
                                discoveryPages.take(8).forEach { page ->
                                    Text("${page.statusCode} • ${page.title.ifBlank { page.url }} • ${page.connectedIp} • ${page.bodySha256.take(12)}…", color = Muted, fontSize = 9.sp)
                                }
                            }
                            OwnershipAndHygienePanel(
                                url = url,
                                authorized = authorized,
                                onFindings = { added -> findings = (findings + added).distinctBy { it.id } },
                                onReport = { report, proof -> hygieneReport = report; ownershipProof = proof }
                            )
                            Card(colors = CardDefaults.cardColors(containerColor = PanelRaised), shape = RoundedCornerShape(16.dp)) {
                                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Icon(Icons.Default.Dns, tint = Red, contentDescription = null)
                                        Spacer(Modifier.width(8.dp))
                                        Text("وضعیت DNS و ایمیل دامنه", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                    }
                                    Text("بررسی خواندنی SPF، DMARC و CAA با Google Public DNS-over-HTTPS؛ هیچ رکوردی تغییر نمی‌کند و نام دامنه برای resolve به resolver عمومی ارسال می‌شود.", color = Muted, fontSize = 10.sp)
                                    Button(
                                        onClick = {
                                            val normalized = com.siteguard.app.core.normalizeUrl(url)
                                            val host = normalized?.let { runCatching { java.net.URL(it).host }.getOrNull() }
                                            if (!authorized || host.isNullOrBlank()) {
                                                dnsPostureStatus = "ابتدا نشانی معتبر و تأیید مالکیت/مجوز را مشخص کنید."
                                            } else if (!dnsPostureBusy) {
                                                dnsPostureBusy = true
                                                scope.launch {
                                                    dnsPostureStatus = "در حال دریافت رکوردهای عمومی DNS..."
                                                    try {
                                                        val result = withContext(Dispatchers.IO) { com.siteguard.app.core.DnsSecurityPostureAnalyzerV1.analyze(host) }
                                                        dnsPosture = result
                                                        val report = JSONObject().apply {
                                                            put("domain", result.domain); put("checked_at_epoch_ms", result.checkedAtEpochMs); put("resolver", result.resolver)
                                                            put("checks", JSONArray().apply { result.checks.forEach { check -> put(JSONObject().apply {
                                                                put("id", check.id); put("title", check.title); put("state", check.state.name); put("detail", check.detail); put("evidence", JSONArray(check.evidence))
                                                            }) } })
                                                            put("limitations", JSONArray(result.limitations))
                                                        }.toString(2)
                                                        val archiveSaved = withContext(Dispatchers.IO) { runCatching { assessmentArchive.add("dns", result.domain, result.resolver, result.checks.count { it.state == com.siteguard.app.core.DnsPostureStateV1.CRITICAL || it.state == com.siteguard.app.core.DnsPostureStateV1.WARNING }, report) } }
                                                        archivedAssessments = assessmentArchive.entries()
                                                        dnsPostureStatus = "${result.checks.count { it.state == com.siteguard.app.core.DnsPostureStateV1.PASS }} کنترل مناسب • ${result.checks.count { it.state == com.siteguard.app.core.DnsPostureStateV1.WARNING }} هشدار • ${result.checks.count { it.state == com.siteguard.app.core.DnsPostureStateV1.CRITICAL }} مورد بحرانی" + if (archiveSaved.isSuccess) " • آرشیو شد" else " • ذخیره آرشیو ناموفق بود"
                                                    } catch (e: Exception) {
                                                        dnsPostureStatus = "بررسی DNS کامل نشد: ${e.message ?: e.javaClass.simpleName}"
                                                    } finally { dnsPostureBusy = false }
                                                }
                                            }
                                        }, enabled = !dnsPostureBusy && !scanning && !codeAuditBusy && !projectAuditBusy,
                                        colors = ButtonDefaults.buttonColors(containerColor = Red), modifier = Modifier.fillMaxWidth()
                                    ) {
                                        if (dnsPostureBusy) CircularProgressIndicator(Modifier.size(17.dp), color = White, strokeWidth = 2.dp)
                                        else Icon(Icons.Default.Dns, null)
                                        Spacer(Modifier.width(7.dp)); Text(if (dnsPostureBusy) "در حال بررسی DNS..." else "بررسی SPF / DMARC / CAA")
                                    }
                                    Text(dnsPostureStatus, color = Muted, fontSize = 10.sp)
                                    dnsPosture?.let { result ->
                                        result.checks.forEach { check ->
                                            val tint = when (check.state) {
                                                com.siteguard.app.core.DnsPostureStateV1.PASS -> Color(0xFF65D6A0)
                                                com.siteguard.app.core.DnsPostureStateV1.WARNING -> Color(0xFFFFC857)
                                                com.siteguard.app.core.DnsPostureStateV1.CRITICAL -> Color(0xFFFF5269)
                                                com.siteguard.app.core.DnsPostureStateV1.UNKNOWN -> Muted
                                            }
                                            Text("${check.title} • ${check.state}", color = tint, fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
                                            Text(check.detail, color = Muted, fontSize = 10.sp)
                                            check.evidence.take(2).forEach { Text("DNS: ${com.siteguard.app.core.EvidenceSanitizer.sanitize(it)}", color = Color(0xFFB8C0CC), fontSize = 9.sp) }
                                        }
                                        Text("Resolver: ${result.resolver}. ${result.limitations.firstOrNull().orEmpty()}", color = Muted, fontSize = 9.sp)
                                    }
                                }
                            }
                            if (passiveWebsiteCoverage.isNotEmpty()) {
                                Text("پوشش متخصص وب برای این اسکن", color = White, fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                                passiveWebsiteCoverage.take(6).forEach { control ->
                                    val label = when (control.state) {
                                        com.siteguard.app.core.WebsiteCoverageStateV2.PASS -> "PASS"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.FAIL -> "FAIL"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.NOT_TESTED -> "تست‌نشده"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.NOT_APPLICABLE -> "نامرتبط"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.UNSUPPORTED -> "پشتیبانی‌نشده"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.NEEDS_MANUAL_REVIEW -> "بازبینی دستی"
                                    }
                                    Text("${control.definition.title} • $label", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                                }
                                Text("اسکن passive فقط یک GET محدود است؛ هیچ کنترل دیگری از آن نتیجه‌گیری نمی‌شود.", color = Muted, fontSize = 9.sp)
                            }
                        }
                    }
                }
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(22.dp)) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Router, tint = Red, contentDescription = null)
                                Spacer(Modifier.width(8.dp))
                                Text("بررسی محدود شبکه", fontSize = 17.sp, fontWeight = FontWeight.Bold)
                            }
                            Text("فقط اتصال TCP به IP عددی و پورت‌هایی که خودتان دقیقاً مشخص می‌کنید؛ بدون اسکن رنج، DNS، banner grabbing یا اجرای payload.", color = Muted, fontSize = 11.sp)
                            OutlinedTextField(
                                value = networkProbeIp, onValueChange = { networkProbeIp = it }, modifier = Modifier.fillMaxWidth(),
                                label = { Text("IP دقیق هدف") }, singleLine = true,
                                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Red, unfocusedBorderColor = Color(0xFF343843), focusedLabelColor = Red, cursorColor = Red)
                            )
                            OutlinedTextField(
                                value = networkProbePorts, onValueChange = { networkProbePorts = it }, modifier = Modifier.fillMaxWidth(),
                                label = { Text("پورت‌های دقیق (مثلاً 443,80,22؛ حداکثر ۱۶)") }, singleLine = true,
                                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Red, unfocusedBorderColor = Color(0xFF343843), focusedLabelColor = Red, cursorColor = Red)
                            )
                            OutlinedTextField(
                                value = networkTlsServerName, onValueChange = { networkTlsServerName = it }, modifier = Modifier.fillMaxWidth(),
                                label = { Text("نام میزبان TLS/SNI مجاز (اختیاری؛ برای certificate دامنه)") }, singleLine = true,
                                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Red, unfocusedBorderColor = Color(0xFF343843), focusedLabelColor = Red, cursorColor = Red)
                            )
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Checkbox(checked = networkProbeAuthorized, onCheckedChange = { networkProbeAuthorized = it }, colors = CheckboxDefaults.colors(checkedColor = Red))
                                Text("مالک این IP/نام TLS هستم یا مجوز صریح برای بررسی این IP، نام و پورت‌ها دارم", fontSize = 11.sp, color = Muted)
                            }
                            Button(
                                enabled = !networkProbeBusy && !scanning && !codeAuditBusy && !projectAuditBusy,
                                onClick = {
                                    if (!networkProbeAuthorized) {
                                        networkProbeStatus = "برای اجرای probe باید مجوز دقیق هدف را تأیید کنید."
                                    } else {
                                        val ports = networkProbePorts.split(',').mapNotNull { it.trim().toIntOrNull() }.distinct()
                                        if (ports.isEmpty() || ports.size > 16 || ports.any { it !in 1..65535 } || ports.size != networkProbePorts.split(',').map { it.trim() }.distinct().size) {
                                            networkProbeStatus = "فهرست پورت نامعتبر است؛ ۱ تا ۱۶ پورت عددی یکتا وارد کنید."
                                        } else {
                                            networkProbeBusy = true
                                            networkProbeResults = emptyList()
                                            networkTlsSummary = emptyList()
                                            networkProbeStatus = "در حال بررسی اتصال‌های دقیق و محدود..."
                                            val manifest = com.siteguard.app.core.NetworkScopeManifest(
                                                authorizationId = java.util.UUID.randomUUID().toString(),
                                                authorizedIpAddresses = setOf(networkProbeIp.trim()), allowedPorts = ports.toSet(),
                                                allowPrivateNetwork = allowPrivate, validUntilEpochMs = System.currentTimeMillis() + 5 * 60 * 1000L,
                                                maxProbes = (ports.size + ports.count { it == 443 || it == 8443 }).coerceAtMost(32),
                                                authorizedTlsNames = networkTlsServerName.trim().takeIf { it.isNotBlank() }?.let { setOf(com.siteguard.app.core.canonicalHost(it) ?: "") } ?: emptySet()
                                            )
                                            scope.launch {
                                                try {
                                                    val resultPair = withContext(Dispatchers.IO) {
                                                        val results = ports.map { tcpProbe.probe(networkProbeIp.trim(), it, manifest) }
                                                        val tls = results.filter { it.state == com.siteguard.app.core.TcpProbeState.OPEN && (it.port == 443 || it.port == 8443) }.map { result ->
                                                            val check = tlsProbe.inspect(networkProbeIp.trim(), result.port, manifest, serverName = networkTlsServerName.trim().takeIf { it.isNotBlank() })
                                                            val cert = check.getOrNull()
                                                            if (cert != null) "TLS ${cert.address}:${cert.port} • ${cert.protocol} • ${cert.cipherSuite} • اعتبار تا ${SimpleDateFormat("yyyy/MM/dd", Locale.getDefault()).format(Date(cert.validUntilEpochMs))} • SHA-256 ${cert.sha256Fingerprint.take(20)}…"
                                                            else "TLS ${result.port}: handshake یا بررسی گواهی ناموفق بود؛ گواهی نامعتبر پذیرفته نشد."
                                                        }
                                                        results to tls
                                                    }
                                                    networkProbeResults = resultPair.first
                                                    networkTlsSummary = resultPair.second
                                                    networkProbeStatus = "${resultPair.first.count { it.state == com.siteguard.app.core.TcpProbeState.OPEN }} اتصال TCP باز از ${resultPair.first.size} پورت بررسی‌شده؛ سرویس فقط بر اساس شماره پورت حدس زده می‌شود."
                                                } catch (e: Exception) {
                                                    networkProbeStatus = "بررسی انجام نشد: ${e.message ?: e.javaClass.simpleName}"
                                                } finally { networkProbeBusy = false; networkProbeAuthorized = false }
                                            }
                                        }
                                    }
                                }, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Red)
                            ) {
                                if (networkProbeBusy) CircularProgressIndicator(Modifier.size(17.dp), color = White, strokeWidth = 2.dp) else Icon(Icons.Default.Radar, null)
                                Spacer(Modifier.width(8.dp)); Text(if (networkProbeBusy) "در حال بررسی" else "شروع بررسی TCP مجاز")
                            }
                            Text(networkProbeStatus, color = Muted, fontSize = 11.sp)
                            networkProbeResults.forEach { result ->
                                Text("${result.address}:${result.port} • ${result.state} • ${result.elapsedMs}ms • ${result.probableServiceHint} • ${result.reason}", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                            }
                            networkTlsSummary.forEach { Text(it, color = Color(0xFFB8C0CC), fontSize = 10.sp) }
                            Text("نکته: برای IP خصوصی، گزینه «اجازه بررسی شبکه داخلی» در بخش اسکن بالای صفحه نیز باید فعال باشد.", color = Muted, fontSize = 10.sp)
                        }
                    }
                }
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(22.dp)) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Code, tint = Red, contentDescription = null)
                                Spacer(Modifier.width(8.dp))
                                Text("تحلیل سورس کد", fontSize = 17.sp, fontWeight = FontWeight.Bold)
                            }
                            Text("تحلیل قطعی و محلی بدون AI API یا API Key؛ فایل اجرا یا تغییر داده نمی‌شود. پشتیبانی از PHP، JavaScript، TypeScript، Python، Java/Kotlin، C# و Go.", color = Muted, fontSize = 11.sp)
                            Button(
                                onClick = { codePicker.launch(arrayOf("text/*", "application/octet-stream", "application/x-php", "application/javascript")) },
                                enabled = !codeAuditBusy && !projectAuditBusy && !scanning,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(containerColor = Red)
                            ) {
                                if (codeAuditBusy) CircularProgressIndicator(Modifier.size(18.dp), color = White, strokeWidth = 2.dp)
                                else Icon(Icons.Default.FolderOpen, null)
                                Spacer(Modifier.width(8.dp))
                                Text(if (codeAuditBusy) "در حال تحلیل..." else "انتخاب فایل سورس")
                            }
                            Text(codeAuditStatus, color = Muted, fontSize = 11.sp)
                            OutlinedButton(
                                onClick = { projectPicker.launch(arrayOf("application/zip", "application/octet-stream")) },
                                enabled = !projectAuditBusy && !codeAuditBusy && !scanning,
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.outlinedButtonColors(contentColor = White),
                                border = androidx.compose.foundation.BorderStroke(1.dp, Red.copy(alpha = .65f))
                            ) {
                                if (projectAuditBusy) CircularProgressIndicator(Modifier.size(18.dp), color = Red, strokeWidth = 2.dp)
                                else Icon(Icons.Default.FolderOpen, null, tint = Red)
                                Spacer(Modifier.width(8.dp))
                                Text(if (projectAuditBusy) "در حال بررسی پروژه..." else "بررسی کامل پروژه ZIP")
                            }
                            Text(projectAuditStatus, color = Muted, fontSize = 11.sp)
                            projectAudit?.let { project ->
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    MetricCard("فایل‌ها", project.filesScanned.toString(), Icons.Default.Folder, Modifier.weight(1f))
                                    MetricCard("وابستگی‌ها", project.dependencies.records.size.toString(), Icons.Default.Apps, Modifier.weight(1f))
                                    MetricCard("یافته‌ها", project.findings.size.toString(), Icons.Default.BugReport, Modifier.weight(1f))
                                }
                                Text(
                                    when { project.isWooCommerce -> "تشخیص ساختار: WordPress + WooCommerce"; project.isWordPress -> "تشخیص ساختار: WordPress"; else -> "تشخیص ساختار: پروژه عمومی" },
                                    color = Color(0xFFB8C0CC), fontSize = 11.sp
                                )
                                project.websiteComponents.take(12).forEach { component ->
                                    Text("${component.type}: ${component.name} • نسخه ${component.version} • ${component.sourcePath}", color = Muted, fontSize = 10.sp)
                                }
                                val websiteSpecialist = com.siteguard.app.core.WebsiteSecuritySpecialistEngineV2.assess(project)
                                var specialistDetailsExpanded by remember(project) { mutableStateOf(false) }
                                Text("Website Security Specialist v${websiteSpecialist.specificationVersion}", color = White, fontWeight = FontWeight.Bold, fontSize = 13.sp)
                                Text("${websiteSpecialist.platform} • حالت بررسی: فایل‌های محلی • ${websiteSpecialist.controls.size} کنترل در ماتریس پوشش", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                                    MetricCard("Fail تأییدشده", websiteSpecialist.failCount.toString(), Icons.Default.Warning, Modifier.weight(1f))
                                    MetricCard("بازبینی دستی", websiteSpecialist.manualReviewCount.toString(), Icons.Default.FindInPage, Modifier.weight(1f))
                                    MetricCard("تست‌نشده/ناپشتیبانی", websiteSpecialist.notTestedCount.toString(), Icons.Default.HelpOutline, Modifier.weight(1f))
                                }
                                Text("PASS فقط با آزمون مستقیم و evidence ثبت می‌شود؛ نبود یافته یا نبود ورودی، Pass نیست.", color = Color(0xFFFFC857), fontSize = 10.sp)
                                TextButton(onClick = { specialistDetailsExpanded = !specialistDetailsExpanded }) {
                                    Icon(if (specialistDetailsExpanded) Icons.Default.ExpandLess else Icons.Default.ExpandMore, contentDescription = null)
                                    Spacer(Modifier.width(4.dp))
                                    Text(if (specialistDetailsExpanded) "بستن جزئیات فنی" else "نمایش جزئیات فنی، شواهد و نقشه معماری")
                                }
                                if (specialistDetailsExpanded) {
                                websiteSpecialist.controls.forEach { control ->
                                    val stateLabel = when (control.state) {
                                        com.siteguard.app.core.WebsiteCoverageStateV2.PASS -> "PASS"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.FAIL -> "FAIL"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.NOT_TESTED -> "تست‌نشده"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.NOT_APPLICABLE -> "نامرتبط"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.UNSUPPORTED -> "پشتیبانی‌نشده"
                                        com.siteguard.app.core.WebsiteCoverageStateV2.NEEDS_MANUAL_REVIEW -> "بازبینی دستی"
                                    }
                                    Text("${control.definition.family} • ${control.definition.title} • $stateLabel", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                                    Text(control.reason, color = Muted, fontSize = 9.sp)
                                }
                                if (websiteSpecialist.architectureNodes.isNotEmpty()) {
                                    Text("نقشه معماری و وابستگی‌های دارای مدرک", color = White, fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                                    websiteSpecialist.architectureNodes.take(12).forEach { node ->
                                        Text("${node.type}: ${node.label} • ${if (node.observed) "مشاهده‌شده" else "استنباطی"} • ${node.evidenceRef}", color = Muted, fontSize = 9.sp)
                                    }
                                    websiteSpecialist.architectureEdges.take(12).forEach { edge ->
                                        Text("${edge.relation}: ${edge.fromNodeId} → ${edge.toNodeId} • confidence ${edge.confidence} • ${if (edge.observed) "Observed" else "Inferred"}", color = Muted, fontSize = 9.sp)
                                    }
                                }
                                Text("طرح آزمون و معیار پوشش", color = White, fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                                websiteSpecialist.testPlans.take(10).forEach { plan ->
                                    Text("${plan.controlId} • ${plan.requiredTestClass} • ${plan.supportState} • ${plan.executionStatus}", color = Color(0xFFB8C0CC), fontSize = 9.sp)
                                    Text("روش: ${plan.method} پیش‌نیاز: ${plan.prerequisites} ریسک: ${plan.risk}", color = Muted, fontSize = 9.sp)
                                }
                                Text("شواهد دارای هش • ${websiteSpecialist.evidenceRecords.size} رکورد در گزارش جاری", color = White, fontWeight = FontWeight.SemiBold, fontSize = 11.sp)
                                websiteSpecialist.evidenceRecords.take(6).forEach { evidence ->
                                    Text("${evidence.evidenceId} • ${evidence.completeness} • SHA-256 ${evidence.integritySha256.take(16)}…", color = Color(0xFFB8C0CC), fontSize = 9.sp)
                                    Text("روش بازتولید: ${evidence.safeReproductionProcedure}", color = Muted, fontSize = 9.sp, maxLines = 2)
                                }
                                websiteSpecialist.limitations.take(8).forEach { limit -> Text("محدودیت متخصص: $limit", color = Muted, fontSize = 9.sp) }
                                Text("پوشش موتورهای تخصصی", color = White, fontWeight = FontWeight.Bold, fontSize = 12.sp)
                                project.domainCoverage.forEach { coverage ->
                                    Text("${coverage.domain} • ${coverage.state} • ${coverage.filesExamined} فایل • ${coverage.findings} یافته", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                                    Text(coverage.notes, color = Muted, fontSize = 9.sp)
                                }
                                if (project.defensiveTechniques.isNotEmpty()) {
                                    Text("راهنمای دفاعی MITRE ATT&CK (ارتباط احتمالی، نه مسیر حمله)", color = White, fontWeight = FontWeight.Bold, fontSize = 11.sp)
                                    project.defensiveTechniques.forEach { technique ->
                                        Text("${technique.techniqueId} • ${technique.name}", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                                        Text("شبیه‌سازی امن: ${technique.safeSimulation}", color = Muted, fontSize = 9.sp)
                                    }
                                }
                                if (project.dependencies.records.isNotEmpty()) {
                                    Text("فهرست وابستگی‌ها (بدون ادعای تطبیق CVE):", color = White, fontSize = 11.sp, fontWeight = FontWeight.Bold)
                                    project.dependencies.records.take(12).forEach { dep ->
                                        Text("${dep.ecosystem} • ${dep.name} • ${dep.declaredVersion}", color = Muted, fontSize = 10.sp)
                                    }
                                    TextButton(onClick = {
                                        val sbom = com.siteguard.app.core.JsonReportExporter.exportSbom(project.dependencies, project.archiveName)
                                        SafeShare.shareText(context, "application/vnd.cyclonedx+json", "SiteGuard SBOM", sbom, "خروجی SBOM CycloneDX", "siteguard-sbom.cdx.json")
                                    }) { Icon(Icons.Default.Share, null); Spacer(Modifier.width(4.dp)); Text("خروجی SBOM") }
                                }
                                project.rootCauseGroups.take(8).forEach { Text("گروه علت احتمالی: ${it.cwe} • ${it.count} نشانه", color = Color(0xFFB8C0CC), fontSize = 10.sp) }
                                }
                                project.skippedEntries.take(5).forEach { Text("ردشده: $it", color = Muted, fontSize = 10.sp) }
                                project.limitations.take(4).forEach { Text("محدودیت: $it", color = Muted, fontSize = 10.sp) }
                            }
                            codeAudit?.let { audit ->
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    MetricCard("خطوط", audit.linesScanned.toString(), Icons.Default.Subject, Modifier.weight(1f))
                                    MetricCard("نشانه‌ها", audit.findings.size.toString(), Icons.Default.BugReport, Modifier.weight(1f))
                                    MetricCard("زبان", audit.language, Icons.Default.Code, Modifier.weight(1f))
                                }
                                audit.rootCauseSummary.forEach { Text("تحلیل گروهی: $it", color = Color(0xFFB8C0CC), fontSize = 10.sp) }
                                Text("یافته‌های این تحلیل در بخش «نتایج یکپارچه و شواهد» نمایش داده می‌شوند.", color = Muted, fontSize = 10.sp)
                            }
                        }
                    }
                }
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(22.dp)) {
                        Column(Modifier.padding(18.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.LibraryBooks, tint = Red, contentDescription = null)
                                Spacer(Modifier.width(8.dp))
                                Text("پایگاه دانش امنیتی آفلاین", fontSize = 17.sp, fontWeight = FontWeight.Bold)
                            }
                            Text("جست‌وجوی محلی SQLite/FTS4 در رکوردهای مرجع و ضعف‌های CWE؛ بدون API و بدون اتصال اینترنت.", color = Muted, fontSize = 11.sp)
                            OutlinedTextField(
                                value = knowledgeQuery,
                                onValueChange = { knowledgeQuery = it },
                                modifier = Modifier.fillMaxWidth(),
                                singleLine = true,
                                label = { Text("عبارت یا شناسه مانند CWE-89") },
                                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Red, unfocusedBorderColor = Color(0xFF343843), focusedLabelColor = Red, cursorColor = Red)
                            )
                            Button(
                                enabled = !knowledgeSearchBusy && knowledgeQuery.isNotBlank(),
                                onClick = {
                                    knowledgeSearchBusy = true
                                    knowledgeSearchStatus = "در حال جست‌وجو در پایگاه محلی..."
                                    scope.launch {
                                        try {
                                            val hits = withContext(Dispatchers.IO) {
                                                val direct = localKnowledgeStore.lookupCwe(knowledgeQuery.trim())
                                                if (direct != null) listOf(direct) else localKnowledgeStore.search(knowledgeQuery.trim())
                                            }
                                            knowledgeResults = hits
                                            knowledgeSearchStatus = if (hits.isEmpty()) "رکوردی پیدا نشد؛ دامنه داده‌ها به بانک مرجع محلی محدود است." else "${hits.size} رکورد محلی پیدا شد."
                                        } catch (e: Exception) {
                                            knowledgeSearchStatus = "جست‌وجو انجام نشد: ${e.message ?: e.javaClass.simpleName}"
                                        } finally { knowledgeSearchBusy = false }
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                                colors = ButtonDefaults.buttonColors(containerColor = Red)
                            ) {
                                if (knowledgeSearchBusy) CircularProgressIndicator(Modifier.size(17.dp), color = White, strokeWidth = 2.dp) else Icon(Icons.Default.Search, null)
                                Spacer(Modifier.width(8.dp)); Text("جست‌وجوی دانش محلی")
                            }
                            Text(knowledgeSearchStatus, color = Muted, fontSize = 10.sp)
                            knowledgeResults.take(8).forEach { hit ->
                                Column(verticalArrangement = Arrangement.spacedBy(3.dp)) {
                                    Text(hit.title, color = White, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                                    Text(hit.body, color = Muted, fontSize = 10.sp)
                                    Text("منبع: ${hit.sourcePublisher} • ${hit.cwe} • ${hit.reviewStatus}", color = Color(0xFFB8C0CC), fontSize = 9.sp)
                                }
                            }
                            Text("این داده‌ها curated و آفلاین‌اند؛ منبع زنده، هشدار CVE جدید یا پوشش کامل آسیب‌پذیری ادعا نمی‌شود.", color = Muted, fontSize = 10.sp)
                        }
                    }
                }
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                            Text("پوشش مشخصات NEXUS 00 تا 23", fontSize = 13.sp, fontWeight = FontWeight.Bold)
                            Text("${specificationCoverage.presentDocuments}/${specificationCoverage.expectedDocuments} سند در رجیستری نسخه وجود دارد • ترتیب: ${if (specificationCoverage.sequenceValid) "صحیح" else "دارای خطا"}", color = Muted, fontSize = 10.sp)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                MetricCard("تکمیل‌شده کامل", specificationCoverage.implementedWholeDocuments.toString(), Icons.Default.CheckCircle, Modifier.weight(1f))
                                MetricCard("نیمه‌پشتیبانی", specificationCoverage.partiallySupportedDocuments.toString(), Icons.Default.Warning, Modifier.weight(1f))
                                MetricCard("کل سندهای تست‌شده", specificationCoverage.testedWholeDocuments.toString(), Icons.Default.Assessment, Modifier.weight(1f))
                            }
                            Text("هیچ سند کاملی صرفاً به دلیل وجود کد یا چند تست smoke، تأیید نهایی نشده است. جزئیات هر سند در گزارش JSON/HTML صادر می‌شود.", color = Muted, fontSize = 9.sp)
                        }
                    }
                }
                item {
                    Text("نمای کلی امنیت", fontSize = 17.sp, fontWeight = FontWeight.Bold)
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        MetricCard("کل یافته‌ها", allCurrentFindings.size.toString(), Icons.Default.BugReport, Modifier.weight(1f))
                        MetricCard("شدید/بالا", allCurrentFindings.count { it.severity == Severity.CRITICAL || it.severity == Severity.HIGH }.toString(), Icons.Default.Warning, Modifier.weight(1f))
                        MetricCard("HTTP", httpStatus?.toString() ?: "—", Icons.Default.Public, Modifier.weight(1f))
                    }
                }
                item {
                    Row(Modifier.bringIntoViewRequester(reportAnchor), verticalAlignment = Alignment.CenterVertically) {
                        Text("نتایج یکپارچه و شواهد", fontSize = 17.sp, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f))
                        if (allCurrentFindings.isNotEmpty() || codeAudit != null || projectAudit != null || scannedAt > 0L || dnsPosture != null) {
                            TextButton(onClick = { exportReport() }) { Icon(Icons.Default.Share, contentDescription = "خروجی گزارش"); Spacer(Modifier.width(4.dp)); Text("JSON") }
                            TextButton(onClick = { exportPdfReport() }) { Icon(Icons.Default.PictureAsPdf, contentDescription = "خروجی PDF"); Spacer(Modifier.width(4.dp)); Text("PDF") }
                        }
                    }
                    Text(
                        "وب: ${findings.size}  •  سورس: ${codeAudit?.findings?.size ?: 0}  •  پروژه: ${projectAudit?.findings?.size ?: 0}",
                        color = Muted, fontSize = 11.sp
                    )
                    OutlinedTextField(
                        value = findingSearchQuery,
                        onValueChange = { findingSearchQuery = it },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true,
                        placeholder = { Text("جست‌وجو در عنوان، شناسه، فایل یا CWE") },
                        leadingIcon = { Icon(Icons.Default.Search, contentDescription = "جست‌وجو") },
                        trailingIcon = if (findingSearchQuery.isNotEmpty()) ({
                            IconButton(onClick = { findingSearchQuery = "" }) {
                                Icon(Icons.Default.Close, contentDescription = "پاک‌کردن جست‌وجو")
                            }
                        }) else null,
                        colors = OutlinedTextFieldDefaults.colors(
                            focusedBorderColor = Red,
                            unfocusedBorderColor = Outline,
                            focusedLabelColor = Red,
                            cursorColor = Red
                        )
                    )
                    LazyRow(
                        horizontalArrangement = Arrangement.spacedBy(7.dp),
                        contentPadding = PaddingValues(horizontal = 2.dp)
                    ) {
                        items(listOf("ALL" to "همه", "HIGH" to "شدید", "MEDIUM" to "متوسط", "LOW" to "کم/اطلاعاتی"), key = { it.first }) { (key, label) ->
                            FilterChip(
                                selected = findingFilter == key,
                                onClick = { findingFilter = key },
                                label = { Text(label, fontSize = 10.sp) },
                                colors = FilterChipDefaults.filterChipColors(),
                                border = androidx.compose.foundation.BorderStroke(
                                    1.dp,
                                    if (findingFilter == key) Red.copy(alpha = .6f) else Outline
                                )
                            )
                        }
                    }
                    if (pdfExportStatus.isNotBlank()) Text(pdfExportStatus, color = Muted, fontSize = 10.sp)
                    Text("نمایش ${visibleFindings.size} از ${allCurrentFindings.size} یافته", color = Muted, fontSize = 10.sp)
                }
                if (visibleFindings.isEmpty()) {
                    item {
                        Surface(color = Panel, shape = RoundedCornerShape(18.dp), border = androidx.compose.foundation.BorderStroke(1.dp, Outline)) {
                            Row(Modifier.fillMaxWidth().padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
                                Icon(Icons.Default.Info, null, tint = Muted); Spacer(Modifier.width(10.dp))
                                Text(
                                    when {
                                        allCurrentFindings.isNotEmpty() -> "با فیلتر یا عبارت جست‌وجوی فعلی نتیجه‌ای پیدا نشد؛ فیلترها را تغییر دهید یا پاک کنید."
                                        scannedAt > 0L || codeAudit != null || projectAudit != null -> "در بررسی‌های فعلی یافته‌ای ثبت نشده است؛ این نتیجه به معنی امنیت کامل نیست و محدودیت‌های گزارش را ببینید."
                                        else -> "هنوز بررسی‌ای اجرا نشده است. از بخش اسکن، وب‌سایت یا فایل پروژه را بررسی کنید."
                                    },
                                    color = Muted, fontSize = 12.sp, lineHeight = 18.sp
                                )
                            }
                        }
                    }
                } else items(visibleFindings, key = { listOf(it.id, it.affectedAsset, it.exactLocation).joinToString("|") }) { finding -> FindingCard(finding, createRemediationPlan) }
                selectedRemediation?.let { plan ->
                    item {
                        Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(16.dp)) {
                            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
                                Text("برنامه اصلاح • ${plan.findingId}", fontWeight = FontWeight.Bold, fontSize = 14.sp)
                                Text("دارایی: ${plan.affectedAsset.ifBlank { "نامشخص" }} • نسخه: ${plan.affectedVersion}", color = Muted, fontSize = 10.sp)
                                Text("علت ریشه‌ای: ${plan.rootCause}", color = White, fontSize = 11.sp)
                                Text("محل دقیق: ${plan.exactLocation.ifBlank { "در شواهد موجود مشخص نیست" }}", color = Muted, fontSize = 10.sp)
                                Text("اصلاح پیشنهادی: ${plan.recommendedChange}", color = White, fontSize = 11.sp)
                                Text("پشتیبان: ${plan.backupPlan}", color = Muted, fontSize = 10.sp)
                                Text("بازگشت: ${plan.rollbackPlan}", color = Muted, fontSize = 10.sp)
                                Text("راستی‌آزمایی: ${plan.verification}", color = Muted, fontSize = 10.sp)
                                Text("Playbook ${plan.playbookSection} • ${plan.playbookTitle}", color = Color(0xFFFFC857), fontSize = 10.sp)
                                Text("الگوی علت ریشه‌ای (نیازمند تطبیق): ${plan.rootCausePattern}", color = Muted, fontSize = 10.sp)
                                Text("مهار فوری: ${plan.immediateContainment}", color = Muted, fontSize = 10.sp)
                                Text("اصلاح دائمی: ${plan.permanentFixPlan}", color = White, fontSize = 10.sp)
                                plan.regressionTests.forEachIndexed { index, test -> Text("Regression ${index + 1}: $test", color = Muted, fontSize = 9.sp) }
                                Text("اعتبارسنجی staging: ${plan.stagingValidation}", color = Muted, fontSize = 10.sp)
                                Text("ریسک downtime/سازگاری: ${plan.downtimeRisk}", color = Muted, fontSize = 10.sp)
                                Text("مالک اصلاح: ${plan.ownerRole}", color = Muted, fontSize = 10.sp)
                                Text("پایش پس از انتشار: ${plan.deploymentMonitoring}", color = Muted, fontSize = 10.sp)
                                Text("قابلیت Patch: ${plan.patchApplicability}", color = Color(0xFFFFC857), fontSize = 10.sp)
                                plan.acceptanceChecklist.forEach { check -> Text("□ $check", color = Muted, fontSize = 9.sp) }
                                Text("وضعیت: ${plan.lifecycle} • هیچ تغییری روی فایل یا production اعمال نشده است.", color = Color(0xFFFFC857), fontSize = 10.sp)
                                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                    TextButton(onClick = {
                                        val ticket = buildString {
                                            append("SiteGuard Developer Remediation Ticket\n")
                                            append("Finding: ${plan.findingId}\nAsset: ${plan.affectedAsset}\nVersion: ${plan.affectedVersion}\nLocation: ${plan.exactLocation}\n")
                                            append("Root cause observation: ${plan.rootCause}\nRoot cause pattern (verify): ${plan.rootCausePattern}\nPlaybook: ${plan.playbookSection} ${plan.playbookTitle}\n")
                                            append("Immediate containment: ${plan.immediateContainment}\nPermanent fix: ${plan.permanentFixPlan}\n")
                                            append("Regression tests:\n${plan.regressionTests.joinToString("\n- ", prefix = "- ")}\n")
                                            append("Staging: ${plan.stagingValidation}\nBackup: ${plan.backupPlan}\nRollback: ${plan.rollbackPlan}\n")
                                            append("Monitoring: ${plan.deploymentMonitoring}\nDowntime risk: ${plan.downtimeRisk}\nResidual risk: ${plan.residualRisk}\n")
                                            append("Acceptance: ${plan.acceptanceChecklist.joinToString("; ")}\n")
                                            append("Note: conceptual template unless exact source context is attached; no production change was applied.")
                                        }
                                        val share = Intent(Intent.ACTION_SEND).apply { type = "text/plain"; putExtra(Intent.EXTRA_SUBJECT, "SiteGuard remediation ${plan.findingId}"); putExtra(Intent.EXTRA_TEXT, ticket) }
                                        context.startActivity(Intent.createChooser(share, "اشتراک تیکت اصلاح"))
                                    }) { Text("خروجی تیکت توسعه‌دهنده") }
                                    TextButton(onClick = { selectedRemediation = null }) { Text("بستن برنامه اصلاح") }
                                }
                            }
                        }
                    }
                }
                item {
                    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(16.dp)) {
                        Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
                            Text("آخرین اسکن ذخیره‌شده", fontWeight = FontWeight.Bold, fontSize = 13.sp)
                            Text(previousSummary, color = Muted, fontSize = 11.sp)
                            Text("گزارش‌های وب، سورس، ZIP و DNS تا سقف ۳۰ مورد و baseline تغییرات تا ۵۰ دارایی با AES-GCM و Android Keystore ذخیره می‌شوند.", color = Muted, fontSize = 10.sp)
                            localHistory.getSummaries().take(5).forEachIndexed { index, summary ->
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Text("${index + 1}. $summary", color = Muted, fontSize = 10.sp, modifier = Modifier.weight(1f))
                                    TextButton(onClick = {
                                        val saved = localHistory.reportAt(index)
                                        if (saved != null) {
                                            SafeShare.shareText(context, "application/json", "SiteGuard saved report", saved, "خروجی گزارش ذخیره‌شده", "siteguard-saved-report.json")
                                        }
                                    }) { Text("گزارش") }
                                }
                            }
                            if (archivedAssessments.isNotEmpty()) {
                                Text("آرشیو تحلیل‌های تکمیلی", color = White, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
                                archivedAssessments.take(8).forEachIndexed { index, archived ->
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                            Text("${archived.kind.uppercase(Locale.ROOT)} • ${archived.title}", color = White, fontSize = 10.sp)
                                            Text("${archived.findingCount} یافته • ${SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.getDefault()).format(Date(archived.savedAtEpochMs))}", color = Muted, fontSize = 9.sp)
                                        }
                                        TextButton(onClick = {
                                            val saved = assessmentArchive.reportAt(index)
                                            if (saved != null) {
                                                SafeShare.shareText(context, "application/json", "SiteGuard archived assessment", saved, "خروجی آرشیو تحلیل", "siteguard-archived-assessment.json")
                                            }
                                        }) { Text("JSON") }
                                    }
                                }
                            }
                            TextButton(onClick = {
                                localHistory.clear()
                                assessmentArchive.clear()
                                assetDriftStore.clear()
                                archivedAssessments = emptyList()
                                lastAssetDrift = null
                                assetDriftSummary = "baseline تغییرات پاک شد."
                                prefs.edit().remove("last_summary").apply()
                                previousSummary = "تاریخچه و baseline محلی پاک شد."
                            }) { Icon(Icons.Default.Delete, null); Spacer(Modifier.width(4.dp)); Text("پاک‌کردن همه تاریخچه محلی") }
                        }
                    }
                }
                item {
                    Card(modifier = Modifier.bringIntoViewRequester(settingsAnchor), colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(18.dp)) {
                        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(9.dp)) {
                            Text("مرکز عملیات و هوشمندی دفاعی", fontSize = 16.sp, fontWeight = FontWeight.Bold)
                            Text("ابزارهای GitHub با بررسی provenance و مجوز؛ بدون دانلود یا اجرای خودکار repository.", color = Muted, fontSize = 11.sp)
                            Text("Attack Graph: ${evidenceGraph.nodes.size} گره و ${evidenceGraph.edges.size} رابطه مستند برای یافته‌های فعلی؛ observed و inferred جدا هستند و مسیر، بهره‌پذیری را اثبات نمی‌کند.", color = Muted, fontSize = 11.sp)
                            Text("اعتبار گراف شواهد: ${if (evidenceGraph.validate().valid) "ساختار معتبر" else "نیازمند بازبینی"} • گراف فقط از یافته‌های فعلی این نشست ساخته می‌شود.", color = Muted, fontSize = 10.sp)
                            Text("Remediation: برنامه اصلاح از هر کارت یافته قابل بازبینی است؛ Diff فقط برای snippet دقیق و یکتا، تأیید staging و ثبت rollback؛ اعمال production خودکار نیست.", color = Muted, fontSize = 11.sp)
                            Text("Threat Intel / Forensics: hash شواهد، chain of custody، timeline و تطبیق indicator؛ تطبیق شاخص اثبات compromise نیست.", color = Muted, fontSize = 11.sp)
                            Text("Automation: صف رمزگذاری‌شده؛ WorkManager اجرای پس‌زمینه را با زمان‌بندی شناور و محدودیت شبکه پیگیری می‌کند. مجوز پیش از هر اجرا دوباره بررسی می‌شود؛ اجرای دستی foreground نیز موجود است و اجرای دقیق در دقیقه تعیین‌شده تضمین نمی‌شود.", color = Muted, fontSize = 11.sp)
                            OutlinedTextField(
                                value = automationDelayMinutes,
                                onValueChange = { value -> automationDelayMinutes = value.filter(Char::isDigit).take(2) },
                                label = { Text("زمان اجرای بررسی (دقیقه؛ ۱ تا ۵۰)") },
                                singleLine = true, keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                                modifier = Modifier.fillMaxWidth(),
                                colors = OutlinedTextFieldDefaults.colors(focusedBorderColor = Red, unfocusedBorderColor = Outline, focusedLabelColor = Red)
                            )
                            Text("وضعیت صف: ${automationSnapshot.tasks.size} کار • ${automationSnapshot.tasks.count { it.status == com.siteguard.app.core.ScheduledAssessmentStatus.QUEUED }} در انتظار • ${if (automationSnapshot.emergencyStopped) "توقف اضطراری فعال" else "فعال"}", color = White, fontSize = 10.sp)
                            Text(automationStatus, color = Muted, fontSize = 10.sp)
                            automationSnapshot.tasks.takeLast(5).forEach { task ->
                                Text("${task.targetUrl} • ${task.status} • ${SimpleDateFormat("MM/dd HH:mm", Locale.getDefault()).format(Date(task.scheduledAtEpochMs))}", color = Color(0xFFB8C0CC), fontSize = 9.sp)
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                                Button(onClick = {
                                    // Keystore-backed queue persistence must not run on the UI thread; capture the
                                    // plain Compose inputs here, then move all queue/crypto work off main.
                                    val minutes = automationDelayMinutes.toIntOrNull()
                                    val manifest = if (authorized) com.siteguard.app.core.AuthorizationManifest.forSingleTarget(url, allowPrivate)?.copy(maxRequests = 2, requestsPerMinute = 2) else null
                                    val capturedUrl = url
                                    if (!authorized || manifest == null) {
                                        automationStatus = "برای زمان‌بندی، نشانی معتبر و تأیید مالکیت/مجوز الزامی است."
                                    } else if (minutes == null || minutes !in 1..50) {
                                        automationStatus = "زمان باید عددی بین ۱ تا ۵۰ دقیقه باشد."
                                    } else {
                                        scope.launch(Dispatchers.IO) {
                                            runCatching {
                                                val target = com.siteguard.app.core.normalizeUrl(capturedUrl) ?: error("نشانی معتبر نیست.")
                                                val task = com.siteguard.app.core.ScheduledAssessmentV1(
                                                    idempotencyKey = "$target:${System.currentTimeMillis() / 60_000L}:$minutes",
                                                    targetUrl = target, authorization = manifest,
                                                    scheduledAtEpochMs = System.currentTimeMillis() + minutes * 60_000L,
                                                    testClass = "PASSIVE_HTTP_GET", maxRetries = 1
                                                )
                                                val queued = automationQueue.enqueue(task)
                                                AssessmentQueueWorkSchedulerV1.enqueue(context, queued)
                                                automationSnapshot = automationQueue.snapshot()
                                                automationStatus = "بررسی برای حدود ${minutes} دقیقه دیگر ثبت شد. WorkManager اجرای پس‌زمینه را در فرصت مجاز سیستم پیگیری می‌کند؛ زمان دقیق تضمین‌شده نیست. اجرای دستی هم در دسترس است."
                                            }.onFailure { automationStatus = "ثبت کار انجام نشد: ${it.message ?: it.javaClass.simpleName}" }
                                        }
                                    }
                                }, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Red)) { Text("زمان‌بندی") }
                                OutlinedButton(onClick = {
                                    // Cancel the in-flight job and WorkManager requests immediately on the UI thread
                                    // (cheap); the encrypted queue write itself still moves off main.
                                    AssessmentQueueWorkSchedulerV1.cancelAll(context)
                                    activeAutomationJob?.cancel(CancellationException("توقف اضطراری توسط کاربر"))
                                    scope.launch(Dispatchers.IO) {
                                        automationQueue.emergencyStop()
                                        automationSnapshot = automationQueue.snapshot()
                                    }
                                    automationStatus = "توقف اضطراری فعال شد؛ کارهای صف‌شده claim نمی‌شوند و کارهای WorkManager لغو می‌شوند."
                                }, modifier = Modifier.weight(1f), colors = ButtonDefaults.outlinedButtonColors(contentColor = Color(0xFFFF8796))) { Text("توقف اضطراری") }
                            }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
                                Button(onClick = {
                                    if (!automationBusy) activeAutomationJob = scope.launch(Dispatchers.IO) {
                                        automationBusy = true
                                        try {
                                            val claimed = automationQueue.claimDue()
                                            automationSnapshot = automationQueue.snapshot()
                                            if (claimed.isEmpty()) {
                                                automationStatus = "کار سررسیدشده‌ای وجود ندارد یا مجوز یکی از کارها منقضی شده است."
                                            } else {
                                                var completed = 0
                                                claimed.forEach { task ->
                                                    try {
                                                        val result = withContext(Dispatchers.IO) {
                                                            com.siteguard.app.core.ScanEngine().scan(task.targetUrl, task.authorization.allowPrivateNetwork, task.authorization)
                                                        }
                                                        val success = result.httpStatus != null
                                                        automationQueue.complete(task.id, success, result.message)
                                                        if (success) {
                                                            runCatching { localHistory.add(result, task.authorization) }
                                                            runCatching { assessmentArchive.add("website", result.host, result.connectedAddress, result.findings.size, com.siteguard.app.core.JsonReportExporter.exportScan(result)) }
                                                            completed++
                                                        }
                                                    } catch (cancelled: CancellationException) {
                                                        runCatching { automationQueue.complete(task.id, false, "اجرای کار به درخواست کاربر متوقف شد.") }
                                                        throw cancelled
                                                    } catch (e: Exception) {
                                                        runCatching { automationQueue.complete(task.id, false, e.message ?: "خطای اجرای کار") }
                                                    }
                                                }
                                                archivedAssessments = assessmentArchive.entries()
                                                automationStatus = "$completed از ${claimed.size} کار در پیش‌زمینه اجرا شد؛ گزارش‌ها در تاریخچه ذخیره شدند."
                                            }
                                        } finally {
                                            automationSnapshot = automationQueue.snapshot()
                                            automationBusy = false
                                            activeAutomationJob = null
                                        }
                                    }
                                }, enabled = !automationBusy && !automationSnapshot.emergencyStopped, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = Red)) {
                                    if (automationBusy) CircularProgressIndicator(Modifier.size(16.dp), color = White, strokeWidth = 2.dp) else Icon(Icons.Default.PlayArrow, null)
                                    Spacer(Modifier.width(5.dp)); Text("اجرای کارهای سررسیدشده")
                                }
                                OutlinedButton(onClick = {
                                    scope.launch(Dispatchers.IO) {
                                        automationQueue.resetEmergencyStop()
                                        automationSnapshot = automationQueue.snapshot()
                                        automationSnapshot.tasks.filter { it.status == com.siteguard.app.core.ScheduledAssessmentStatus.QUEUED }
                                            .forEach { AssessmentQueueWorkSchedulerV1.enqueue(context, it) }
                                        automationStatus = "توقف اضطراری پس از بازبینی کاربر برداشته شد؛ کارهای مجاز دوباره به WorkManager سپرده شدند."
                                    }
                                }, modifier = Modifier.weight(1f), enabled = automationSnapshot.emergencyStopped) { Text("بازنشانی توقف") }
                            }
                            Text("Lab: سناریوهای synthetic و آفلاین؛ هیچ exploit یا هدف واقعی اجرا نمی‌شود.", color = Muted, fontSize = 11.sp)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(
                                    onClick = {
                                        if (!labBusy) {
                                            labBusy = true
                                            scope.launch {
                                                labStatus = "در حال اجرای fixtureهای مصنوعی آفلاین..."
                                                val results = withContext(Dispatchers.Default) { com.siteguard.app.core.LabSimulationEngineV1.runCatalogSmoke() }
                                                labResults = results
                                                labStatus = "${results.size} سناریو اجرا شد • ${results.count { it.findingIds.isNotEmpty() }} fixture آسیب‌پذیر شناسایی شد • ${results.count { it.passAfterFix }} نتیجه pass-after-fix"
                                                labBusy = false
                                            }
                                        }
                                    }, enabled = !labBusy, colors = ButtonDefaults.buttonColors(containerColor = Red)
                                ) { Text(if (labBusy) "در حال اجرا..." else "اجرای Lab آفلاین") }
                                OutlinedButton(onClick = { exportHtmlReport() }) { Text("گزارش HTML") }
                                OutlinedButton(onClick = { exportPdfReport() }) { Text("گزارش PDF") }
                            }
                            Text(labStatus, color = Muted, fontSize = 11.sp)
                            labResults.take(5).forEach { result ->
                                Text("${result.scenarioId} • ${if (result.passAfterFix) "PASS fixture امن" else "نشانه آسیب‌پذیری"} • ${result.findingIds.joinToString().ifBlank { "بدون یافته" }}", color = Color(0xFFB8C0CC), fontSize = 10.sp)
                            }
                        }
                    }
                }
                item {
                    Text("پوشش نسخه ${com.siteguard.app.core.SiteGuardBuildInfo.VERSION_NAME}", color = Muted, fontSize = 10.sp)
                    Text("قابلیت‌های نسخه ۰٫۱۳ حفظ شده‌اند. نسخه ۰٫۱۴ مرکز پیشرفتهٔ مستقل با استدلال محلی قاعده‌محور، CISA KEV و OSV، WordPress/WooCommerce REST فقط‌خواندنی، تحلیل Passive وب/API، AST/Taint تقریبی، Cloud/Network IaC، تحلیل باینری APK، Patch/Backup/Rollback محلی، گزارش مقایسه‌ای PDF/Markdown و WorkManager برای به‌روزرسانی روزانهٔ Threat Intelligence دارد. LLM محلی، DAST کامل، Cloud Runtime، parser کامپایلری، تأیید cryptographic امضای APK، decompilation/sandbox و اصلاح Remote Production هنوز محدودیت دارند.", color = Muted, fontSize = 11.sp)
                }
            }
            }
        }
    }
}

private fun applyResult(result: ScanResult, update: (String, List<Finding>, String, Int?, Long) -> Unit) {
    update(result.host, result.findings, result.message, result.httpStatus, result.scannedAt)
}

@Composable
private fun StatusPill(label: String, tint: Color) {
    Surface(
        color = tint.copy(alpha = .12f),
        shape = CircleShape,
        border = androidx.compose.foundation.BorderStroke(1.dp, tint.copy(alpha = .32f))
    ) {
        Text(label, color = tint, fontSize = 10.sp, fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp), maxLines = 1)
    }
}

@Composable
private fun MetricCard(title: String, value: String, icon: androidx.compose.ui.graphics.vector.ImageVector, modifier: Modifier = Modifier) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = PanelRaised),
        shape = RoundedCornerShape(18.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, Outline),
        elevation = CardDefaults.cardElevation(defaultElevation = 1.dp)
    ) {
        Column(Modifier.fillMaxWidth().padding(12.dp), verticalArrangement = Arrangement.spacedBy(7.dp)) {
            Surface(color = Red.copy(alpha = .12f), shape = RoundedCornerShape(10.dp)) {
                Icon(icon, contentDescription = title, tint = Red, modifier = Modifier.padding(7.dp).size(18.dp))
            }
            Text(value, fontSize = 22.sp, lineHeight = 25.sp, fontWeight = FontWeight.Bold, color = White, maxLines = 1)
            Text(title, fontSize = 10.sp, lineHeight = 14.sp, color = Muted, maxLines = 2)
        }
    }
}

@Composable
private fun FindingCard(f: Finding, onCreateRemediationPlan: (Finding) -> Unit = {}) {
    val color = when (f.severity) {
        Severity.CRITICAL -> Color(0xFFFF5269); Severity.HIGH -> Color(0xFFFF925C)
        Severity.MEDIUM -> Color(0xFFFFC857); Severity.LOW -> Color(0xFF67B7FF); Severity.INFO -> Color(0xFF9AA0AA)
    }
    Card(colors = CardDefaults.cardColors(containerColor = Panel), shape = RoundedCornerShape(16.dp)) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(f.title, modifier = Modifier.weight(1f), fontWeight = FontWeight.Bold, fontSize = 14.sp, lineHeight = 19.sp)
                StatusPill(f.severity.name, color)
            }
            Text(f.description, color = Muted, fontSize = 12.sp)
            if (f.affectedAsset.isNotBlank()) Text("دارایی: ${f.affectedAsset}", color = Muted, fontSize = 10.sp)
            if (f.exactLocation.isNotBlank()) Text("موقعیت دقیق: ${f.exactLocation}", color = Muted, fontSize = 10.sp)
            if (f.evidence.isNotBlank()) Text("شواهد: ${com.siteguard.app.core.EvidenceSanitizer.sanitize(f.evidence)}", color = Color(0xFFB8C0CC), fontSize = 10.sp)
            if (f.cwe.isNotBlank()) Text(f.cwe, color = Muted, fontSize = 10.sp)
            Text("راهنمای اصلاح: ${f.remediation}", color = White, fontSize = 11.sp)
            val statusLabel = when (f.status) {
                com.siteguard.app.core.FindingStatus.CONFIRMED -> "تأییدشده"
                com.siteguard.app.core.FindingStatus.PROBABLE -> "محتمل"
                com.siteguard.app.core.FindingStatus.UNVERIFIED -> "تأییدنشده"
                com.siteguard.app.core.FindingStatus.INFORMATIONAL -> "اطلاعاتی"
                com.siteguard.app.core.FindingStatus.FALSE_POSITIVE -> "مثبت کاذب"
            }
            val priority = com.siteguard.app.core.RiskEngine.prioritize(f)
            val evidenceQuality = com.siteguard.app.core.EvidenceConfidenceEngineV1.assess(f)
            Text("وضعیت: $statusLabel • اطمینان اولیه: ${f.confidence}", color = Muted, fontSize = 10.sp)
            Text("کیفیت شواهد: ${evidenceQuality.band} (${evidenceQuality.score}/100؛ شاخص داخلی، نه احتمال exploit)", color = Color(0xFFB8C0CC), fontSize = 10.sp)
            Text("اولویت داخلی: ${priority.band} (${priority.score}/100؛ CVSS نیست)", color = Muted, fontSize = 10.sp)
            Text("اعتبارسنجی ایمن: ${f.safeValidation}", color = Muted, fontSize = 10.sp)
            Text("آزمایش‌نشده: ${f.notTested}", color = Muted, fontSize = 10.sp)
            Text("بازآزمایی: ${f.verificationProcedure}", color = Muted, fontSize = 10.sp)
            TextButton(onClick = { onCreateRemediationPlan(f) }) {
                Icon(Icons.Default.Build, null, tint = Red)
                Spacer(Modifier.width(5.dp))
                Text("ساخت برنامه اصلاح", color = White)
            }
        }
    }
}
