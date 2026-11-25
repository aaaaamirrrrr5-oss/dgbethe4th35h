package com.siteguard.app

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.siteguard.app.advanced.*
import com.siteguard.app.core.Finding
import com.siteguard.app.core.LocalDataCipher
import com.siteguard.app.core.Severity
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.Base64

private data class HubTab(val id: String, val title: String, val icon: androidx.compose.ui.graphics.vector.ImageVector)

@Composable
fun AdvancedModulesHub(modifier: Modifier = Modifier, findings: List<Finding> = emptyList()) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val comparisonCipher = remember { LocalDataCipher("siteguard.comparison.snapshot.v1") }
    val tabs = remember {
        listOf(
            HubTab("ai", "هوش محلی", Icons.Default.Psychology),
            HubTab("intel", "تهدیدها", Icons.Default.TravelExplore),
            HubTab("wordpress", "WordPress", Icons.Default.Language),
            HubTab("web", "وب و API", Icons.Default.Public),
            HubTab("code", "AST / Taint", Icons.Default.Code),
            HubTab("cloud", "Cloud / Network", Icons.Default.Cloud),
            HubTab("apk", "Android Binary", Icons.Default.Android),
            HubTab("fix", "اصلاح و Rollback", Icons.Default.Build),
            HubTab("reports", "گزارش مقایسه‌ای", Icons.Default.Assessment),
            HubTab("automation", "اتوماسیون", Icons.Default.Schedule)
        )
    }
    var selectedTab by remember { mutableStateOf("ai") }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("مرکز پیشرفته آماده است. هر اتصال خارجی فقط پس از اقدام صریح شما اجرا می‌شود.") }

    var aiReport by remember { mutableStateOf<LocalReasoningReportV1?>(null) }
    var threatSnapshot by remember { mutableStateOf<ThreatIntelSnapshotV1?>(null) }
    var threatVersion by remember { mutableStateOf(context.getSharedPreferences("siteguard_threat_intel", 0).getString("last_catalog_version", "") ?: "") }
    var threatDate by remember { mutableStateOf(context.getSharedPreferences("siteguard_threat_intel", 0).getString("last_release_date", "") ?: "") }
    var osvEcosystem by remember { mutableStateOf("npm") }
    var osvPackage by remember { mutableStateOf("") }
    var osvVersion by remember { mutableStateOf("") }
    var osvReport by remember { mutableStateOf<OsvLookupReportV1?>(null) }

    var wpBase by remember { mutableStateOf("https://") }
    var wpUser by remember { mutableStateOf("") }
    var wpPassword by remember { mutableStateOf("") }
    var wpAllowPrivate by remember { mutableStateOf(false) }
    var wpAuthorized by remember { mutableStateOf(false) }
    var wpReport by remember { mutableStateOf<WordPressRuntimeReportV1?>(null) }

    var webOrigin by remember { mutableStateOf("https://") }
    var webAllowPrivate by remember { mutableStateOf(false) }
    var webAuthorized by remember { mutableStateOf(false) }
    var webReport by remember { mutableStateOf<WebSurfaceReportV1?>(null) }

    var sourceFileName by remember { mutableStateOf("sample.php") }
    var sourceText by remember { mutableStateOf("") }
    var astReport by remember { mutableStateOf<AstTaintReportV1?>(null) }

    var cloudFileName by remember { mutableStateOf("deployment.yaml") }
    var cloudText by remember { mutableStateOf("") }
    var cloudReport by remember { mutableStateOf<CloudNetworkReportV1?>(null) }

    var apkReport by remember { mutableStateOf<BinaryAndroidReportV1?>(null) }
    var apkPickerStatus by remember { mutableStateOf("یک APK امضاشده/آزمایشی را انتخاب کنید؛ فایل فقط خوانده می‌شود و اجرا نخواهد شد.") }

    LaunchedEffect(selectedTab) {
        if (selectedTab == "intel") {
            val saved = context.getSharedPreferences("siteguard_threat_intel", 0)
            threatVersion = saved.getString("last_catalog_version", "").orEmpty()
            threatDate = saved.getString("last_release_date", "").orEmpty()
        }
    }


    var patchSource by remember { mutableStateOf("") }
    var patchNeedle by remember { mutableStateOf("") }
    var patchReplacement by remember { mutableStateOf("") }
    var patchPreview by remember { mutableStateOf<LocalPatchPreviewV1?>(null) }
    var patchReceipt by remember { mutableStateOf<LocalPatchReceiptV1?>(null) }
    var patchWorkspaceText by remember { mutableStateOf("") }
    var exportText by remember { mutableStateOf("") }
    var exportPdfBytes by remember { mutableStateOf<ByteArray?>(null) }
    var comparison by remember { mutableStateOf<ComparativeReportV1?>(null) }

    val apkPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null) scope.launch {
            busy = true; apkPickerStatus = "در حال خواندن ZIP و AndroidManifest باینری..."
            try {
                val result = withContext(Dispatchers.IO) {
                    val bytes = context.contentResolver.openInputStream(uri)?.use { input ->
                        val output = java.io.ByteArrayOutputStream(); val buffer = ByteArray(16 * 1024); var total = 0
                        while (true) { val n = input.read(buffer); if (n < 0) break; total += n; require(total <= 120 * 1024 * 1024) { "حداکثر حجم فایل ۱۲۰ مگابایت است." }; output.write(buffer, 0, n) }
                        output.toByteArray()
                    } ?: error("فایل قابل خواندن نیست")
                    val name = context.contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { c -> if (c.moveToFirst()) c.getString(0) else null } ?: "selected.apk"
                    BinaryAndroidAnalyzerV1.analyze(name, bytes)
                }
                apkReport = result
                apkPickerStatus = "${result.packageName ?: "package نامشخص"} • ${result.dexFiles} DEX • ${result.findings.size} یافته • SHA-256 ${result.sha256.take(16)}…"
                status = "تحلیل باینری Android تکمیل شد. فایل اجرا یا نصب نشد."
            } catch (e: Exception) { apkPickerStatus = "تحلیل فایل ناموفق بود: ${e.message ?: e.javaClass.simpleName}" }
            // OutOfMemoryError is an Error, not an Exception: a very large APK/AAB read fully into memory would otherwise crash the app.
            catch (oom: OutOfMemoryError) { apkPickerStatus = "حافظه دستگاه برای تحلیل این فایل کافی نبود؛ فایل کوچک‌تر یا یک split APK را انتخاب کنید." }
            finally { busy = false }
        }
    }
    val exportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("text/plain")) { uri ->
        if (uri != null) scope.launch {
            runCatching {
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri)?.use { it.write(exportText.toByteArray(Charsets.UTF_8)) } ?: error("فایل مقصد قابل نوشتن نیست") }
            }.onSuccess { status = "فایل خروجی ذخیره شد." }.onFailure { status = "ذخیره فایل ناموفق بود: ${it.message}" }
        }
    }
    val pdfExportLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/pdf")) { uri ->
        if (uri != null) scope.launch {
            runCatching {
                val bytes = exportPdfBytes ?: error("محتوای PDF آماده نیست")
                withContext(Dispatchers.IO) { context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) } ?: error("فایل مقصد قابل نوشتن نیست") }
            }.onSuccess { status = "گزارش PDF ذخیره شد." }.onFailure { status = "ذخیره PDF ناموفق بود: ${it.message}" }
        }
    }

    Column(modifier.fillMaxSize().padding(horizontal = 14.dp, vertical = 10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF171B23)), shape = RoundedCornerShape(22.dp), border = BorderStroke(1.dp, Color(0xFF343B49))) {
            Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(Icons.Default.Security, null, tint = Color(0xFFFF536B), modifier = Modifier.size(32.dp))
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text("SITEGUARD • ADVANCED", color = Color.White, fontWeight = FontWeight.Black, fontSize = 17.sp)
                        Text("نسخه 0.14.0 • موتورهای مستقل و کنترل‌شده", color = Color(0xFF9DA7B8), fontSize = 10.sp)
                    }
                    if (busy) CircularProgressIndicator(Modifier.size(22.dp), strokeWidth = 2.dp, color = Color(0xFFFF536B))
                }
                Text("${findings.size} یافته در نشست جاری • اتصال خارجی خاموش تا اقدام دستی • اجرای exploit و تغییر خودکار production ممنوع", color = Color(0xFFB8C1CF), fontSize = 10.sp, lineHeight = 15.sp)
            }
        }
        Row(Modifier.horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(7.dp)) {
            tabs.forEach { tab ->
                FilterChip(selected = selectedTab == tab.id, onClick = { selectedTab = tab.id },
                    label = { Text(tab.title, fontSize = 11.sp) }, leadingIcon = { Icon(tab.icon, null, modifier = Modifier.size(16.dp)) })
            }
        }
        Text(status, color = Color(0xFFB8C1CF), fontSize = 10.sp, lineHeight = 15.sp)
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            when (selectedTab) {
                "ai" -> {
                    HubCard("موتور استدلال محلی و تصمیم‌یار", "تحلیل قطعی و شفاف؛ بدون API key و بدون ادعای مدل زبانی.") {
                        Button(onClick = {
                            val signals = findings.map { f -> LocalSecuritySignalV1(
                                f.id, f.title,
                                when (f.severity) { Severity.CRITICAL -> LocalRiskV1.CRITICAL; Severity.HIGH -> LocalRiskV1.HIGH; Severity.MEDIUM -> LocalRiskV1.MEDIUM; Severity.LOW -> LocalRiskV1.LOW; Severity.INFO -> LocalRiskV1.INFO },
                                when (f.confidence.lowercase()) { "high" -> 90; "medium" -> 65; "low" -> 35; else -> 50 },
                                f.cwe, f.affectedAsset, f.evidence, f.detectionMethod
                            ) }
                            aiReport = LocalReasoningEngineV1.reason(signals)
                            status = "تحلیل استدلالی محلی اجرا شد؛ امتیاز اولویت‌بندی به‌معنی احتمال نفوذ نیست."
                        }, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Default.Psychology, null); Spacer(Modifier.width(7.dp)); Text("تحلیل یافته‌های نشست") }
                        aiReport?.let { report ->
                            HubMetric("امتیاز اولویت", "${report.overallScore}/100 • ${report.priority}")
                            report.steps.forEach { HubBullet("${it.ruleId}: ${it.explanation}") }
                            report.actions.take(8).forEach { HubBullet("${it.priority}. ${it.title}\n${it.why}") }
                            report.limitations.forEach { HubMuted(it) }
                            OutlinedButton(onClick = { exportText = buildString { appendLine("SiteGuard Local Reasoning"); appendLine("Score: ${report.overallScore}"); report.steps.forEach { appendLine("${it.ruleId}: ${it.explanation}") }; report.actions.forEach { appendLine("${it.priority}. ${it.title}\n${it.why}") }; report.limitations.forEach { appendLine("LIMIT: $it") } }; exportLauncher.launch("siteguard-reasoning-v0.14.txt") }) { Text("ذخیره گزارش استدلال") }
                        }
                        HubMuted("مدل Generative / LLM محلی یا آموزش مدل در این نسخه ادعا نمی‌شود. موتور حاضر Rule-based و evidence-led است و پیشنهادها باید بازبینی شوند.")
                    }
                }
                "intel" -> {
                    HubCard("Threat Intelligence • CISA KEV", "بازیابی فهرست رسمی آسیب‌پذیری‌های شناخته‌شدهٔ مورد بهره‌برداری؛ داده فقط برای اولویت‌بندی است.") {
                        HubMetric("آخرین نسخه ذخیره‌شده", threatVersion.ifBlank { "دریافت نشده" })
                        HubMetric("تاریخ انتشار منبع", threatDate.ifBlank { "نامشخص" })
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(onClick = {
                                if (!busy) scope.launch {
                                    busy = true; status = "در حال دریافت CISA KEV از HTTPS..."
                                    try {
                                        threatSnapshot = withContext(Dispatchers.IO) { CisaKevFeedUpdaterV1().updateCache(context.filesDir.resolve("threat-intel/cisa-kev-v1.json")) }
                                        threatVersion = threatSnapshot!!.catalogVersion; threatDate = threatSnapshot!!.dateReleased
                                        context.getSharedPreferences("siteguard_threat_intel", 0).edit().putString("last_catalog_version", threatVersion).putString("last_release_date", threatDate).apply()
                                        status = "فهرست CISA KEV به‌روزرسانی شد: ${threatSnapshot!!.count} رکورد معتبر."
                                    } catch (e: Exception) { status = "به‌روزرسانی ناموفق بود: ${e.message ?: e.javaClass.simpleName}" }
                                    finally { busy = false }
                                }
                            }, modifier = Modifier.weight(1f), enabled = !busy) { Text("به‌روزرسانی دستی") }
                            OutlinedButton(onClick = { AdvancedThreatIntelSchedulerV1.scheduleDaily(context); status = "به‌روزرسانی روزانه CISA KEV با WorkManager زمان‌بندی شد." }, modifier = Modifier.weight(1f)) { Text("زمان‌بندی روزانه") }
                        }
                        OutlinedButton(onClick = { AdvancedThreatIntelSchedulerV1.cancel(context); status = "زمان‌بندی خودکار CISA KEV لغو شد." }, modifier = Modifier.fillMaxWidth()) { Text("لغو زمان‌بندی") }
                        threatSnapshot?.let { feed ->
                            HubMetric("رکورد معتبر", feed.count.toString())
                            HubMetric("SHA-256", feed.sha256.take(24) + "…")
                            feed.entries.take(15).forEach { HubBullet("${it.cveId} • ${it.vendor} ${it.product}\n${it.name}\nتاریخ اضافه‌شدن: ${it.dateAdded} • Ransomware: ${it.ransomwareKnown}") }
                        }
                        Divider(color = Color(0xFF303846))
                        Text("جست‌وجوی نسخه وابستگی در OSV.dev", color = Color.White, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                        OutlinedTextField(osvEcosystem, { osvEcosystem = it }, Modifier.fillMaxWidth(), label = { Text("Ecosystem: npm / PyPI / Maven / Go / NuGet / Packagist") }, singleLine = true)
                        OutlinedTextField(osvPackage, { osvPackage = it }, Modifier.fillMaxWidth(), label = { Text("نام پکیج") }, singleLine = true)
                        OutlinedTextField(osvVersion, { osvVersion = it }, Modifier.fillMaxWidth(), label = { Text("نسخه دقیق") }, singleLine = true)
                        OutlinedButton(onClick = {
                            if (!busy) scope.launch {
                                busy = true; status = "در حال بررسی advisoryهای نسخه در OSV.dev..."
                                try { osvReport = withContext(Dispatchers.IO) { OsvVulnerabilityLookupV1().query(osvEcosystem, osvPackage, osvVersion) }; status = "OSV query کامل شد: ${osvReport!!.vulnerabilities.size} advisory یافت شد." }
                                catch (e: Exception) { status = "OSV query ناموفق بود: ${e.message ?: e.javaClass.simpleName}" }
                                finally { busy = false }
                            }
                        }, modifier = Modifier.fillMaxWidth(), enabled = !busy && osvPackage.isNotBlank() && osvVersion.isNotBlank()) { Text("جست‌وجوی آسیب‌پذیری نسخه") }
                        osvReport?.let { report ->
                            HubMetric("نتیجه OSV", "${report.vulnerabilities.size} advisory")
                            report.vulnerabilities.forEach { v -> HubFinding("OSV", v.id, "${v.summary}\nAliases: ${v.aliases.joinToString().ifBlank { "ندارد" }}\nPublished: ${v.published} • Modified: ${v.modified}") }
                            report.limitations.forEach { HubMuted(it) }
                        }
                        HubMuted("به‌روزرسانی فقط از URL ثابت HTTPS رسمی CISA انجام می‌شود. داده با TLS دریافت، اندازه محدود و schema/date/CVE کنترل می‌شود؛ این فید امضای مستقل end-to-end ندارد و نباید تنها مرجع تصمیم اصلاح باشد.")
                    }
                }
                "wordpress" -> {
                    HubCard("WordPress / WooCommerce Runtime (Read-only)", "اتصال REST با Application Password؛ فقط GET و بدون تغییر تنظیمات یا سفارش.") {
                        OutlinedTextField(wpBase, { wpBase = it }, Modifier.fillMaxWidth(), label = { Text("آدرس سایت HTTPS") }, singleLine = true)
                        OutlinedTextField(wpUser, { wpUser = it }, Modifier.fillMaxWidth(), label = { Text("نام کاربری WordPress") }, singleLine = true)
                        OutlinedTextField(wpPassword, { wpPassword = it }, Modifier.fillMaxWidth(), label = { Text("Application Password") }, visualTransformation = PasswordVisualTransformation(), keyboardOptions = androidx.compose.foundation.text.KeyboardOptions(keyboardType = androidx.compose.ui.text.input.KeyboardType.Password), singleLine = true)
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(wpAuthorized, { wpAuthorized = it })
                            Text("مالک سایت هستم یا مجوز صریح بررسی فقط‌خواندنی دارم", color = Color.White, fontSize = 11.sp)
                        }
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Checkbox(wpAllowPrivate, { wpAllowPrivate = it })
                            Text("اجازه اتصال به IP خصوصی (فقط staging خودم)", color = Color(0xFFB8C1CF), fontSize = 11.sp)
                        }
                        Button(onClick = {
                            if (!wpAuthorized) { status = "برای اتصال، ابتدا مجوز را تأیید کنید." }
                            else if (!busy) scope.launch {
                                busy = true; status = "در حال اتصال HTTPS فقط‌خواندنی به WordPress..."
                                try { wpReport = withContext(Dispatchers.IO) { WordPressReadOnlyClientV1().inspect(wpBase, wpUser, wpPassword, wpAllowPrivate) }; status = "بررسی REST تمام شد؛ ${wpReport!!.endpoints.count { it.success }} از ${wpReport!!.endpoints.size} مسیر پاسخ موفق داشت." }
                                catch (e: Exception) { status = "اتصال WordPress انجام نشد: ${e.message ?: e.javaClass.simpleName}" }
                                finally { busy = false; wpPassword = "" }
                            }
                        }, modifier = Modifier.fillMaxWidth(), enabled = !busy && wpBase.isNotBlank() && wpUser.isNotBlank() && wpPassword.isNotBlank()) { Text("شروع بررسی REST امن") }
                        wpReport?.let { report ->
                            HubMetric("WordPress REST", if (report.isWordPressReachable) "قابل دسترس" else "تأیید نشد")
                            HubMetric("WooCommerce", if (report.isWooCommerceAvailable) "مسیر System Status پاسخ داد" else "پاسخ/مجوز تایید نشد")
                            report.endpoints.forEach { endpoint -> HubBullet("${endpoint.httpStatus ?: "ERR"} • ${endpoint.route}\n${endpoint.summary}" + (endpoint.itemCount?.let { " • $it مورد" } ?: "")) }
                            report.limitations.forEach { HubMuted(it) }
                            OutlinedButton(onClick = { exportText = buildString { appendLine("SiteGuard WordPress Runtime Report"); appendLine(report.baseUrl); report.endpoints.forEach { appendLine("${it.httpStatus} ${it.route}: ${it.summary}") }; report.limitations.forEach { appendLine("LIMIT: $it") } }; exportLauncher.launch("siteguard-wordpress-runtime.txt") }) { Text("ذخیره گزارش WordPress") }
                        }
                        HubMuted("برای امنیت، از یک Application Password مجزا با کمترین نقش لازم استفاده و پس از بررسی آن را لغو کنید. مسیرهای خصوصی و مقدارهای حساس در گزارش ذخیره نمی‌شوند. بعضی مسیرها به capability یا نصب نسخه خاص نیاز دارند.")
                    }
                }
                "web" -> {
                    HubCard("تحلیل سطح وب و API • Passive", "درخواست‌های محدود GET، فقط هم‌مبدأ؛ بدون brute-force، exploit، login یا تغییر داده.") {
                        OutlinedTextField(webOrigin, { webOrigin = it }, Modifier.fillMaxWidth(), label = { Text("Origin سایت (HTTPS)") }, singleLine = true)
                        Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(webAuthorized, { webAuthorized = it }); Text("مالک/دارای مجوز برای همین دامنه هستم", color = Color.White, fontSize = 11.sp) }
                        Row(verticalAlignment = Alignment.CenterVertically) { Checkbox(webAllowPrivate, { webAllowPrivate = it }); Text("staging روی شبکه خصوصی خودم", color = Color(0xFFB8C1CF), fontSize = 11.sp) }
                        Button(onClick = {
                            if (!webAuthorized) status = "مجوز دامنه را تأیید کنید."
                            else if (!busy) scope.launch {
                                busy = true; status = "در حال اجرای ۶ درخواست Passive GET..."
                                try { webReport = withContext(Dispatchers.IO) { WebSurfaceAnalyzerV1().assess(webOrigin, webAllowPrivate) }; status = "تحلیل وب تمام شد: ${webReport!!.pages.size} مسیر و ${webReport!!.controls.size} کنترل." }
                                catch (e: Exception) { status = "تحلیل وب متوقف شد: ${e.message ?: e.javaClass.simpleName}" }
                                finally { busy = false }
                            }
                        }, modifier = Modifier.fillMaxWidth(), enabled = !busy && webAuthorized) { Text("تحلیل وب‌سایت و مسیرهای API") }
                        webReport?.let { report ->
                            HubMetric("مسیرهای بررسی‌شده", report.pages.size.toString())
                            report.pages.forEach { HubBullet("${it.status} • ${it.path} • ${it.contentType} • ${it.bytesRead} byte") }
                            HubMetric("مسیرهای احتمالی OpenAPI", report.discoveredApiPaths.size.toString())
                            report.discoveredApiPaths.take(30).forEach { HubBullet(it) }
                            report.controls.forEach { HubFinding(it.severity, it.title, "${it.id} • ${it.evidence}") }
                            OutlinedButton(onClick = { exportText = buildString { appendLine("SiteGuard Web Surface Report"); report.pages.forEach { appendLine("${it.status} ${it.path}") }; report.controls.forEach { appendLine("${it.severity} ${it.id}: ${it.evidence}") }; report.discoveredApiPaths.forEach { appendLine("API $it") }; report.limitations.forEach { appendLine("LIMIT: $it") } }; exportLauncher.launch("siteguard-web-surface.txt") }) { Text("ذخیره گزارش وب") }
                            report.limitations.forEach { HubMuted(it) }
                        }
                    }
                }
                "code" -> {
                    HubCard("AST تقریبی + Taint Flow", "تحلیل token، statement، scope و انتقال ساده داده از source به sink؛ بدون اجرای سورس.") {
                        OutlinedTextField(sourceFileName, { sourceFileName = it }, Modifier.fillMaxWidth(), label = { Text("نام فایل و پسوند") }, singleLine = true)
                        OutlinedTextField(sourceText, { sourceText = it; astReport = null }, Modifier.fillMaxWidth().heightIn(min = 180.dp), label = { Text("کد منبع") }, minLines = 7)
                        Button(onClick = {
                            if (!busy) scope.launch {
                                busy = true; try { astReport = withContext(Dispatchers.Default) { CodeAstTaintAnalyzerV1.analyze(sourceFileName, sourceText) }; status = "تحلیل ساختار و taint تمام شد." }
                                catch (e: Exception) { status = "تحلیل کد انجام نشد: ${e.message}" } finally { busy = false }
                            }
                        }, modifier = Modifier.fillMaxWidth(), enabled = !busy && sourceText.isNotBlank()) { Text("اجرای AST / Taint Analysis") }
                        astReport?.let { report ->
                            HubMetric("توکن / statement / scope", "${report.tokenCount} / ${report.statementCount} / ${report.scopeCount}")
                            HubMetric("تعداد جریان‌های مشکوک", report.flows.size.toString())
                            report.flows.forEach { HubFinding(it.severity, "${it.cwe} • ${it.sink}", "${it.sourceVariable} در خط ${it.sourceLine} → sink در خط ${it.sinkLine}\n${it.evidence}\nConfidence ${it.confidence}%") }
                            report.limitations.forEach { HubMuted(it) }
                        }
                    }
                }
                "cloud" -> {
                    HubCard("Cloud / Network Security • Static posture", "بررسی پیکربندی Terraform، Kubernetes، Docker، Cloud و CI؛ بدون اتصال به حساب Cloud.") {
                        OutlinedTextField(cloudFileName, { cloudFileName = it }, Modifier.fillMaxWidth(), label = { Text("نام فایل (مثلاً main.tf / deployment.yaml)") }, singleLine = true)
                        OutlinedTextField(cloudText, { cloudText = it; cloudReport = null }, Modifier.fillMaxWidth().heightIn(min = 180.dp), label = { Text("محتوای فایل پیکربندی") }, minLines = 7)
                        Button(onClick = {
                            if (!busy) scope.launch {
                                busy = true; try { cloudReport = withContext(Dispatchers.Default) { CloudNetworkPostureAnalyzerV1.analyze(cloudFileName, cloudText) }; status = "تحلیل پیکربندی Cloud/Network پایان یافت." }
                                catch (e: Exception) { status = "تحلیل پیکربندی ناموفق: ${e.message}" } finally { busy = false }
                            }
                        }, modifier = Modifier.fillMaxWidth(), enabled = !busy && cloudText.isNotBlank()) { Text("تحلیل پیکربندی") }
                        cloudReport?.let { report ->
                            HubMetric("پلتفرم تشخیص‌داده‌شده", report.platform)
                            report.findings.forEach { HubFinding(it.severity, "${it.id} • خط ${it.line}: ${it.title}", "${it.evidence}\n${it.remediation}") }
                            report.limitations.forEach { HubMuted(it) }
                        }
                    }
                }
                "apk" -> {
                    HubCard("Android Binary Analysis", "فایل APK را به‌صورت باینری بازبینی می‌کند؛ نصب یا اجرا نمی‌شود.") {
                        Button(onClick = { apkPicker.launch(arrayOf("application/vnd.android.package-archive", "application/octet-stream", "*/*")) }, modifier = Modifier.fillMaxWidth(), enabled = !busy) { Icon(Icons.Default.FolderOpen, null); Spacer(Modifier.width(8.dp)); Text("انتخاب APK") }
                        HubMuted(apkPickerStatus)
                        apkReport?.let { report ->
                            HubMetric("Package", report.packageName ?: "نامشخص")
                            HubMetric("Min / Target SDK", "${report.minSdk ?: "?"} / ${report.targetSdk ?: "?"}")
                            HubMetric("DEX / Native / Entries", "${report.dexFiles} / ${report.nativeLibraries} / ${report.archiveEntries}")
                            HubMetric("SHA-256", report.sha256.take(32) + "…")
                            HubMetric("Permissionهای حساس", report.permissions.intersect(setOf("android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS", "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES")).size.toString())
                            report.findings.forEach { HubFinding(it.severity, it.title, "${it.id}\n${it.evidence}\n${it.recommendation}") }
                            report.components.take(40).forEach { HubBullet(it) }
                            report.limitations.forEach { HubMuted(it) }
                            OutlinedButton(onClick = { exportText = buildString { appendLine("SiteGuard Android Binary Report"); appendLine("File: ${report.fileName}"); appendLine("Package: ${report.packageName}"); appendLine("SHA-256: ${report.sha256}"); report.permissions.forEach { appendLine("Permission: $it") }; report.findings.forEach { appendLine("${it.severity} ${it.id}: ${it.evidence}") }; report.limitations.forEach { appendLine("LIMIT: $it") } }; exportLauncher.launch("siteguard-android-binary.txt") }) { Text("ذخیره گزارش APK") }
                        }
                    }
                }
                "fix" -> {
                    HubCard("Remediation Transaction + Rollback", "Patch دقیق، backup، کنترل SHA-256 و rollback؛ فقط روی workspace خصوصی برنامه.") {
                        OutlinedTextField(patchSource, { patchSource = it; patchPreview = null }, Modifier.fillMaxWidth().heightIn(min = 140.dp), label = { Text("متن فایل / نسخه اصلی") }, minLines = 5)
                        OutlinedTextField(patchNeedle, { patchNeedle = it; patchPreview = null }, Modifier.fillMaxWidth(), label = { Text("عبارت دقیق یکتا برای جایگزینی") }, minLines = 2)
                        OutlinedTextField(patchReplacement, { patchReplacement = it; patchPreview = null }, Modifier.fillMaxWidth(), label = { Text("متن جایگزین") }, minLines = 2)
                        Button(onClick = {
                            try { patchPreview = LocalPatchTransactionV1(File(context.filesDir, "remediation/workspace"), File(context.filesDir, "remediation/backups")).preview(patchSource, patchNeedle, patchReplacement); status = "Patch Preview ساخته شد؛ هنوز هیچ فایلی تغییر نکرده است." }
                            catch (e: Exception) { status = "ساخت Patch Preview ناموفق: ${e.message}" }
                        }, modifier = Modifier.fillMaxWidth(), enabled = patchNeedle.isNotBlank() && patchSource.isNotBlank()) { Text("ساخت Patch Preview") }
                        patchPreview?.let { preview ->
                            HubMetric("تطبیق یکتا", "${preview.occurrences} match • SHA قبل ${preview.beforeSha256.take(12)}… • بعد ${preview.afterSha256.take(12)}…")
                            HubBullet(preview.patchText)
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Button(onClick = {
                                    try {
                                        val root = File(context.filesDir, "remediation/workspace"); root.mkdirs()
                                        val file = File(root, "user-review.txt"); file.writeText(patchSource, Charsets.UTF_8)
                                        val tx = LocalPatchTransactionV1(root, File(context.filesDir, "remediation/backups"))
                                        patchReceipt = tx.apply("user-review.txt", preview.beforeSha256, preview)
                                        patchWorkspaceText = file.readText(Charsets.UTF_8)
                                        status = "Patch در workspace خصوصی اعمال شد؛ فایل اصلی خارج از برنامه دست‌نخورده است."
                                    } catch (e: Exception) { status = "اعمال Patch ناموفق: ${e.message}" }
                                }, modifier = Modifier.weight(1f), enabled = patchReceipt == null) { Text("اعمال در Workspace") }
                                OutlinedButton(onClick = {
                                    try {
                                        patchReceipt?.let { receipt ->
                                            val tx = LocalPatchTransactionV1(File(context.filesDir, "remediation/workspace"), File(context.filesDir, "remediation/backups"))
                                            tx.rollback(receipt); patchWorkspaceText = File(context.filesDir, "remediation/workspace/user-review.txt").readText(Charsets.UTF_8)
                                            status = "Rollback با بررسی SHA-256 انجام شد."; patchReceipt = null
                                        }
                                    } catch (e: Exception) { status = "Rollback رد شد: ${e.message}" }
                                }, modifier = Modifier.weight(1f), enabled = patchReceipt != null) { Text("Rollback") }
                            }
                        }
                        if (patchWorkspaceText.isNotBlank()) {
                            HubMetric("نسخه فعلی Workspace", "${patchWorkspaceText.length} character")
                            OutlinedButton(onClick = { exportText = patchWorkspaceText; exportLauncher.launch("siteguard-patched-workspace.txt") }) { Text("خروجی نسخه Workspace") }
                        }
                        HubMuted("هیچ درخواست تغییر به WordPress، Cloud یا Production ارسال نمی‌شود. این ماژول Patch محلی را اجرا و Rollback محلی را می‌آزماید؛ برای انتشار واقعی باید adapter جداگانه، staging، تأیید مالک و API محدود تعریف شود.")
                    }
                }
                "reports" -> {
                    HubCard("Comparative Reports", "مقایسه Snapshot قبلی و فعلی با تفکیک یافته جدید، تغییرکرده و غایب‌شده.") {
                        Button(onClick = {
                            val current = findings.map { f -> ReportSnapshotFindingV1(f.id, f.severity.name, f.affectedAsset, f.exactLocation, f.title, ComparativeReportEngineV1.evidenceFingerprint(f.evidence)) }
                            fun encodeField(value: String): String = Base64.getUrlEncoder().withoutPadding().encodeToString(value.toByteArray(Charsets.UTF_8))
                            fun decodeField(value: String): String = String(Base64.getUrlDecoder().decode(value), Charsets.UTF_8)
                            val previous = context.getSharedPreferences("siteguard_comparison", 0).getString("snapshot_enc", null)?.let { encrypted ->
                                comparisonCipher.decrypt(encrypted)?.let { raw -> runCatching {
                                    raw.lineSequence().filter { it.isNotBlank() }.map { line ->
                                        val p = line.split('\t')
                                        require(p.size == 6)
                                        ReportSnapshotFindingV1(decodeField(p[0]), decodeField(p[1]), decodeField(p[2]), decodeField(p[3]), decodeField(p[4]), decodeField(p[5]))
                                    }.toList()
                                }.getOrNull() }
                            }
                            val prefs = context.getSharedPreferences("siteguard_comparison", 0)
                            comparison = ComparativeReportEngineV1.compare(previous, current, prefs.getLong("snapshot_at", 0L).takeIf { it > 0 })
                            val encoded = current.joinToString("\n") { listOf(it.id, it.severity, it.asset, it.location, it.title, it.evidenceHash).joinToString("\t") { value -> encodeField(value) } }
                            prefs.edit().putString("snapshot_enc", comparisonCipher.encrypt(encoded)).putLong("snapshot_at", System.currentTimeMillis()).apply()
                            status = "Snapshot مقایسه شد و برای بررسی بعدی ذخیره شد."
                        }, modifier = Modifier.fillMaxWidth()) { Text("مقایسه با Snapshot قبلی و ذخیره جدید") }
                        comparison?.let { report ->
                            HubMetric("خلاصه تغییر", report.summary)
                            HubMetric("New / Resolved / Changed / Stable", "${report.newFindings} / ${report.resolvedFindings} / ${report.changedFindings} / ${report.unchangedFindings}")
                            report.changes.forEach { c -> HubBullet("${c.kind} • ${(c.after ?: c.before)?.id.orEmpty()} • ${(c.after ?: c.before)?.title.orEmpty()}") }
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                OutlinedButton(onClick = { exportText = ComparativeReportEngineV1.toMarkdown(report); exportLauncher.launch("siteguard-comparative-report.md") }, modifier = Modifier.weight(1f)) { Text("گزارش Markdown") }
                                OutlinedButton(onClick = { exportPdfBytes = PdfReportRenderer.render(ComparativeReportEngineV1.toMarkdown(report)); pdfExportLauncher.launch("siteguard-comparative-report.pdf") }, modifier = Modifier.weight(1f)) { Text("گزارش PDF فارسی") }
                            }
                            report.limitations.forEach { HubMuted(it) }
                        }
                    }
                }
                "automation" -> {
                    HubCard("اتوماسیون چندنوعی و مانیتورینگ", "Jobهای پشتیبانی‌شده با policy صریح؛ اطلاعات login یا فایل‌های شخصی برای اجرای پس‌زمینه ذخیره نمی‌شوند.") {
                        HubMetric("Passive Web", "از صف زمان‌بندی‌شده نسخه اصلی و AuthorizationManifest استفاده می‌کند")
                        HubMetric("Threat Intelligence", "به‌روزرسانی عمومی CISA KEV با زمان‌بندی روزانه")
                        HubMetric("WordPress / فایل / APK / Cloud", "اجرای تعاملی؛ تا وقتی ذخیره امن credential/URI تأیید نشده، زمان‌بندی پس‌زمینه بسته است")
                        Button(onClick = { AdvancedThreatIntelSchedulerV1.scheduleDaily(context); status = "زمان‌بندی روزانه Threat Intelligence فعال شد؛ زمان اجرا توسط Android مدیریت می‌شود." }, modifier = Modifier.fillMaxWidth()) { Text("فعال‌سازی پایش روزانه CISA") }
                        OutlinedButton(onClick = { AdvancedThreatIntelSchedulerV1.cancel(context); status = "پایش روزانه Threat Intelligence متوقف شد." }, modifier = Modifier.fillMaxWidth()) { Text("توقف پایش CISA") }
                        val prefs = context.getSharedPreferences("siteguard_threat_intel", 0)
                        HubMetric("آخرین وضعیت دریافت", prefs.getString("last_status", "هنوز اجرا نشده") ?: "نامشخص")
                        HubMetric("زمان آخرین دریافت", prefs.getLong("last_fetch_ms", 0L).takeIf { it > 0 }?.let { SimpleDateFormat("yyyy/MM/dd HH:mm", Locale.getDefault()).format(Date(it)) } ?: "ثبت نشده")
                        HubMuted("WorkManager زمان اجرای دقیق را تضمین نمی‌کند؛ شبکه، Battery Optimization و سیاست سیستم‌عامل بر اجرای آن اثر دارند. برای اجرای وب‌سایت، فقط اسکن Passive مجاز در صف قبلی موجود است.")
                        HubMuted("سیاست داخلی می‌تواند زمان‌بندی WORDPRESS_READ_ONLY با credential ذخیره‌شده را رد کند؛ فایل‌های انتخاب‌شده نیز تا تأمین دسترسی URI پایدار فقط دستی بررسی می‌شوند.")
                    }
                }
            }
            Spacer(Modifier.height(20.dp))
        }
    }
}

@Composable
private fun HubCard(title: String, subtitle: String, content: @Composable ColumnScope.() -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF171B23)), shape = RoundedCornerShape(20.dp), border = BorderStroke(1.dp, Color(0xFF303846))) {
        Column(Modifier.fillMaxWidth().padding(14.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text(title, color = Color.White, fontSize = 15.sp, fontWeight = FontWeight.Bold)
            Text(subtitle, color = Color(0xFF9DA7B8), fontSize = 10.sp, lineHeight = 15.sp)
            content()
        }
    }
}

@Composable private fun HubMetric(label: String, value: String) {
    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.Top) {
        Text(label, color = Color(0xFF9DA7B8), fontSize = 10.sp, modifier = Modifier.weight(.42f))
        Text(value, color = Color(0xFFF0F2F6), fontSize = 10.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(.58f))
    }
}
@Composable private fun HubBullet(value: String) { Row(verticalAlignment = Alignment.Top) { Text("•", color = Color(0xFFFF536B), fontSize = 13.sp); Spacer(Modifier.width(7.dp)); Text(value, color = Color(0xFFD1D6DF), fontSize = 10.sp, lineHeight = 15.sp) } }
@Composable private fun HubMuted(value: String) { Text(value, color = Color(0xFF8F9AAA), fontSize = 9.sp, lineHeight = 14.sp) }
@Composable private fun HubFinding(severity: String, title: String, detail: String) {
    val tint = when (severity.uppercase()) { "CRITICAL", "HIGH" -> Color(0xFFFF647C); "MEDIUM" -> Color(0xFFFFC857); else -> Color(0xFF8FB5FF) }
    Surface(color = Color(0xFF202632), shape = RoundedCornerShape(12.dp), border = BorderStroke(1.dp, tint.copy(alpha = .25f))) {
        Column(Modifier.fillMaxWidth().padding(10.dp), verticalArrangement = Arrangement.spacedBy(5.dp)) {
            Text("$severity • $title", color = tint, fontWeight = FontWeight.Bold, fontSize = 10.sp)
            Text(detail, color = Color(0xFFCAD1DC), fontSize = 9.sp, lineHeight = 14.sp)
        }
    }
}
