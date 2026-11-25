package com.siteguard.app.core

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.util.zip.ZipInputStream

data class ProjectAuditResult(
    val archiveName: String,
    val filesDiscovered: Int,
    val filesScanned: Int,
    val totalExpandedBytesRead: Long,
    val languages: Map<String, Int>,
    val findings: List<Finding>,
    val rootCauseGroups: List<RootCauseGroup>,
    val dependencies: DependencyInventory,
    val isWordPress: Boolean,
    val isWooCommerce: Boolean,
    val websiteComponents: List<WebsiteComponent>,
    val skippedEntries: List<String>,
    val limitations: List<String>,
    val domainCoverage: List<SpecialistDomainCoverage> = emptyList(),
    val defensiveTechniques: List<DefensiveTechniqueProfile> = emptyList(),
    val evidenceGraph: EvidenceGraphV1 = EvidenceGraphV1(emptyList(), emptyList(), emptyList())
)

object ArchivePathPolicy {
    fun isSafeEntryPath(path: String): Boolean {
        if (path.isBlank() || path.startsWith('/') || path.startsWith('\\') || path.contains('\\') || path.contains('\u0000')) return false
        if (Regex("^[A-Za-z]:").containsMatchIn(path)) return false
        // A single trailing slash only marks a directory entry (e.g. "src/"); it is not an empty path segment.
        val normalized = path.removeSuffix("/")
        if (normalized.isEmpty()) return false
        val parts = normalized.split('/')
        return parts.none { it == ".." || it == "." || it.isBlank() }
    }
}

/** ZIP is streamed in memory; nothing is extracted to disk. Hard limits prevent common archive-bomb abuse. */
class ProjectArchiveAnalyzer(
    private val maxCompressedBytes: Int = 25 * 1024 * 1024,
    private val maxEntryBytes: Int = 512 * 1024,
    private val maxTotalExpandedBytes: Int = 20 * 1024 * 1024,
    private val maxEntries: Int = 500,
    private val maxScannedFiles: Int = 200
) {
    private val supportedSourceExtensions = setOf(
        "php", "phtml", "js", "jsx", "mjs", "cjs", "ts", "tsx", "py", "java", "kt", "kts",
        "go", "rb", "cs", "html", "htm", "xml", "yaml", "yml", "toml", "ini", "conf", "cfg", "properties", "json", "tf", "tfvars", "sql", "sh", "dockerfile", "graphql", "graphqls", "gql", "wsdl"
    )
    private val manifestNames = setOf(
        "package.json", "composer.json", "requirements.txt", "pyproject.toml", "pom.xml",
        "build.gradle", "build.gradle.kts", "gradle.properties", "cargo.toml", "go.mod", "gemfile",
        "dockerfile", "docker-compose.yml", "docker-compose.yaml", "sshd_config", "kustomization.yaml"
    )

    fun analyze(input: InputStream, archiveName: String): ProjectAuditResult {
        val compressed = readBounded(input, maxCompressedBytes)
        require(compressed.size >= 4 && compressed[0] == 0x50.toByte() && compressed[1] == 0x4b.toByte()) {
            "فایل انتخاب‌شده ZIP معتبر نیست."
        }
        val textFiles = linkedMapOf<String, String>()
        val skipped = mutableListOf<String>()
        var discovered = 0
        var scanned = 0
        var expandedBytes = 0L
        var stoppedByLimit = false
        var binaryAndroidManifest = false
        var dexArtifacts = 0
        var androidSigningMetadata = false

        ZipInputStream(ByteArrayInputStream(compressed)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                discovered++
                if (discovered > maxEntries) {
                    discovered = maxEntries
                    skipped += "تعداد ورودی‌های ZIP از سقف $maxEntries بیشتر بود؛ ادامه متوقف شد."
                    stoppedByLimit = true
                    break
                }
                val safePath = ArchivePathPolicy.isSafeEntryPath(entry.name)
                if (!safePath) {
                    skipped += "مسیر ناامن یا غیرمجاز رد شد: ${entry.name.take(120)}"
                }
                val filename = entry.name.substringAfterLast('/').lowercase()
                val normalizedEntry = entry.name.lowercase()
                if (filename == "classes.dex" || Regex("classes[0-9]+\\.dex").matches(filename)) dexArtifacts++
                if (normalizedEntry.startsWith("meta-inf/") && (filename.endsWith(".rsa") || filename.endsWith(".dsa") || filename.endsWith(".ec") || filename.endsWith(".sf"))) androidSigningMetadata = true
                val extension = filename.substringAfterLast('.', "").lowercase()
                val supported = extension in supportedSourceExtensions || filename in manifestNames || isEnvFileName(filename)
                val duplicate = safePath && !entry.isDirectory && entry.name in textFiles
                if (duplicate) skipped += "ورودی تکراری با همان مسیر رد شد: ${entry.name.take(120)}"
                val capture = safePath && !entry.isDirectory && supported && !duplicate
                if (capture && scanned >= maxScannedFiles) {
                    skipped += "سقف $maxScannedFiles فایل قابل تحلیل تکمیل شد؛ ادامه متوقف شد."
                    stoppedByLimit = true
                    break
                }
                val remainingTotal = (maxTotalExpandedBytes - expandedBytes).coerceAtLeast(0).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                val entryRead = readEntryBounded(zip, maxEntryBytes, remainingTotal, capture)
                expandedBytes += entryRead.expandedBytes
                if (entryRead.exceededLimit) {
                    skipped += "حجم بازشده یکی از ورودی‌ها یا مجموع ZIP از سقف منابع عبور کرد؛ ادامه متوقف شد."
                    stoppedByLimit = true
                    break
                }
                if (entryRead.oversized && capture) {
                    skipped += "فایل بزرگ‌تر از سقف ${maxEntryBytes / 1024} کیلوبایت رد شد: ${entry.name.take(120)}"
                    zip.closeEntry()
                    continue
                }
                if (!capture) {
                    zip.closeEntry()
                    continue
                }
                val bytes = entryRead.bytes ?: ByteArray(0)
                if (bytes.any { it == 0.toByte() }) {
                    if (filename == "androidmanifest.xml") binaryAndroidManifest = true
                    skipped += "فایل باینری کنار گذاشته شد: ${entry.name.take(120)}"
                    zip.closeEntry()
                    continue
                }
                val content = bytes.toString(Charsets.UTF_8)
                textFiles[entry.name] = content
                scanned++
                zip.closeEntry()
            }
        }

        val sourceFiles = textFiles.filterKeys { key ->
            val name = key.substringAfterLast('/').lowercase()
            name !in manifestNames && (name.substringAfterLast('.', "") in supportedSourceExtensions || isEnvFileName(name))
        }
        val phpFiles = sourceFiles.filterKeys { it.substringAfterLast('.', "").lowercase() in setOf("php", "phtml") }
        val isWp = WordPressSecurityAnalyzer.looksLikeWordPress(textFiles)
        val isWoo = WordPressSecurityAnalyzer.looksLikeWooCommerce(textFiles)
        val sourceAnalyzer = SourceCodeAnalyzer()
        val allFindings = mutableListOf<Finding>()
        val languageCounts = linkedMapOf<String, Int>()
        sourceFiles.forEach { (path, source) ->
            val prefix = java.security.MessageDigest.getInstance("SHA-256").digest(path.toByteArray())
                .take(5).joinToString("") { "%02x".format(it) }
            val result = sourceAnalyzer.analyze(path.substringAfterLast('/'), source)
            if (result.language != "Unknown" && result.language != ENV_FILE_LANGUAGE) languageCounts[result.language] = (languageCounts[result.language] ?: 0) + 1
            allFindings += result.findings.map { finding ->
                val lineNumber = finding.id.substringAfterLast("-L").toIntOrNull()
                finding.copy(
                    id = "PRJ-$prefix-${finding.id}",
                    affectedAsset = path,
                    exactLocation = if (lineNumber != null) "$path:$lineNumber" else path
                )
            }
        }
        if (isWp) {
            phpFiles.forEach { (path, source) -> allFindings += WordPressSecurityAnalyzer.analyze(path, source, isWoo) }
        }
        val inventory = DependencyInventoryAnalyzer.analyze(textFiles)
        inventory.records.filterNot { it.versionPinned }.forEach { dependency ->
            allFindings += Finding(
                id = "SG-DEP-UNPINNED-${dependency.ecosystem}-${dependency.name}".replace(Regex("[^A-Za-z0-9_-]"), "_").take(100),
                title = "نسخه وابستگی به‌صورت دقیق pin نشده است",
                severity = Severity.INFO,
                description = "در ${dependency.manifestPath} وابستگی ${dependency.name} با نسخه ${dependency.declaredVersion} تعریف شده است؛ این موضوع به‌تنهایی آسیب‌پذیری نیست.",
                remediation = "نسخه امن و سازگار را بررسی و در صورت مناسب بودن lockfile تولید و commit کنید.",
                confidence = "High", evidence = "${dependency.ecosystem}:${dependency.name}:${dependency.declaredVersion}",
                cwe = "", status = FindingStatus.INFORMATIONAL, affectedAsset = dependency.manifestPath,
                exactLocation = dependency.manifestPath, detectionMethod = "Offline dependency manifest inventory",
                businessImpact = "نسخه‌های شناور می‌توانند بازتولید build و کنترل زنجیره تأمین را دشوار کنند.",
                exploitPrerequisites = "هیچ آسیب‌پذیری مشخصی از روی شناور بودن نسخه نتیجه نمی‌شود.",
                safeValidation = "manifest و lockfile متناظر را با مدیر بسته بررسی کنید.",
                notTested = "نسخه resolve شده، dependency transitive و CVE/OSV بررسی نشده است."
            )
        }
        // Specialist engines run locally on the same bounded, in-memory file set.
        // Their findings are hypotheses unless the individual rule has direct proof.
        val mobileFiles = textFiles.filterKeys { key ->
            val lower = key.lowercase()
            lower.endsWith("androidmanifest.xml") || lower.endsWith("network_security_config.xml") ||
                lower.endsWith("build.gradle") || lower.endsWith("build.gradle.kts") ||
                lower.endsWith(".kt") || lower.endsWith(".java")
        }
        val networkFiles = textFiles.filterKeys { key ->
            val lower = key.lowercase()
            lower.endsWith(".conf") || lower.endsWith(".cfg") || lower.endsWith(".ini") ||
                lower.endsWith(".zone") || lower.endsWith("sshd_config") || lower.endsWith(".tf") || lower.endsWith(".json")
        }
        val cloudFiles = textFiles.filterKeys { key ->
            val lower = key.lowercase()
            lower.substringAfterLast('/') == "dockerfile" || lower.endsWith(".dockerfile") ||
                lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".tf") ||
                lower.endsWith(".tfvars") || lower.endsWith(".json") || lower.contains(".github/workflows/")
        }
        val mobileFindings = MobileSecurityAnalyzer.analyze(mobileFiles).toMutableList()
        if (binaryAndroidManifest) {
            mobileFindings += Finding(
                id = "SG-MOB-APK-BINARY-AXML", title = "AndroidManifest باینری در artifact دیده شد؛ تحلیل آن پشتیبانی نمی‌شود",
                severity = Severity.INFO,
                description = "ورودی ZIP شامل AndroidManifest.xml باینری است که با parser متنی قابل تحلیل نیست.",
                remediation = "Manifest را با ابزار معتبر در محیط محلی به XML decoded تبدیل و خروجی را دوباره بررسی کنید؛ اصالت ابزار و نسخه آن را ثبت کنید.",
                confidence = "High", evidence = "Binary AndroidManifest entry detected; payload not retained", status = FindingStatus.INFORMATIONAL,
                affectedAsset = archiveName, exactLocation = "AndroidManifest.xml", detectionMethod = "APK/AAB archive container inspection",
                notTested = "کامپوننت‌های binary AXML، signing certificate، DEX bytecode و runtime موبایل بررسی نشده‌اند."
            )
        }
        if (dexArtifacts > 0) {
            mobileFindings += Finding(
                id = "SG-MOB-DEX-UNANALYZED", title = "فایل DEX در آرشیو وجود دارد اما bytecode تحلیل نشده است",
                severity = Severity.INFO, description = "$dexArtifacts فایل DEX شناسایی شد؛ وجود آن به‌تنهایی نشانه آسیب‌پذیری نیست.",
                remediation = "برای تحلیل bytecode از ابزار موبایل مستقل و بررسی‌شده با نسخه/هش مشخص در محیط ایزوله استفاده کنید.",
                confidence = "High", evidence = "DEX entry count=$dexArtifacts", status = FindingStatus.INFORMATIONAL,
                affectedAsset = archiveName, exactLocation = "classes*.dex", detectionMethod = "APK/AAB ZIP inventory",
                notTested = "DEX، JNI/native libraries، runtime behavior و exported components از manifest نهایی بررسی نشده‌اند."
            )
        }
        val networkFindings = NetworkEnterpriseSecurityAnalyzer.analyze(networkFiles)
        val cloudFindings = CloudConfigurationAnalyzer.analyze(cloudFiles)
        val apiSchemaFiles = textFiles.filterKeys { key ->
            val lower = key.lowercase()
            (lower.endsWith(".json") && (lower.substringAfterLast('/').contains("openapi") ||
                lower.substringAfterLast('/').contains("swagger") || lower.contains("/api/") || lower.startsWith("api/"))) ||
                lower.endsWith(".yaml") || lower.endsWith(".yml") || lower.endsWith(".graphql") || lower.endsWith(".graphqls") || lower.endsWith(".gql") || lower.endsWith(".wsdl")
        }
        val apiSchemaFindings = ApiSchemaAnalyzer.analyze(apiSchemaFiles) + GraphQlSoapSchemaAnalyzer.analyze(apiSchemaFiles)
        allFindings += mobileFindings
        allFindings += networkFindings
        allFindings += cloudFindings
        allFindings += apiSchemaFindings

        val finalFindings = allFindings.distinctBy { it.id }
        val defensiveProfiles = finalFindings.flatMap(DefensiveIntelligenceCatalog::forFinding)
            .distinctBy { it.techniqueId }
        val evidenceGraph = EvidenceGraphBuilder.fromFindings(finalFindings)
        val domainCoverage = listOf(
            SpecialistDomainCoverage("SOURCE", if (sourceFiles.isNotEmpty()) "ANALYZED" else "NOT_APPLICABLE", sourceFiles.size, finalFindings.count { it.detectionMethod.contains("Source", true) }, "تحلیل ایستای فایل‌های سورس؛ parser مبتنی بر قواعد."),
            SpecialistDomainCoverage("WORDPRESS_WOOCOMMERCE", if (isWp) "ANALYZED" else "NOT_APPLICABLE", if (isWp) textFiles.size else 0, finalFindings.count { it.id.startsWith("SG-WP-") }, "فقط سورس/فایل‌های داخل ZIP؛ runtime، کاربران، سفارش‌ها و درگاه پرداخت بررسی نشده‌اند."),
            SpecialistDomainCoverage("ANDROID_MOBILE", if (mobileFiles.isNotEmpty() || binaryAndroidManifest || dexArtifacts > 0) "PARTIAL_STATIC" else "NO_INPUT", mobileFiles.size + (if (binaryAndroidManifest) 1 else 0) + dexArtifacts, mobileFindings.size, "Manifest متنی، تنظیمات و source بررسی می‌شوند؛ وجود AXML/DEX باینری فقط شناسایی می‌شود، نه decode/bytecode analysis. Signatures present in META-INF=$androidSigningMetadata; signature validity is not verified."),
            SpecialistDomainCoverage("NETWORK_ENTERPRISE", if (networkFiles.isNotEmpty()) "ANALYZED" else "NO_INPUT", networkFiles.size, networkFindings.size, "بازبینی ایستای config؛ discovery/port scan به اجرای جداگانه با مجوز دقیق نیاز دارد."),
            SpecialistDomainCoverage("CLOUD_IDENTITY_CONTAINER_CICD", if (cloudFiles.isNotEmpty()) "ANALYZED" else "NO_INPUT", cloudFiles.size, cloudFindings.size, "فایل‌های Docker/Kubernetes/Terraform/CI؛ هیچ حساب ابری متصل یا تغییری اجرا نشده است."),
            SpecialistDomainCoverage("DEFENSIVE_RED_TEAM_INTELLIGENCE", "REFERENCE_ONLY", defensiveProfiles.size, 0, "کاتالوگ ATT&CK و طراحی purple-team فقط برای شبیه‌سازی بی‌خطر؛ هیچ exploit یا عملیات تهاجمی اجرا نمی‌شود."),
            SpecialistDomainCoverage("API_SECURITY", if (apiSchemaFiles.isNotEmpty()) "PARTIAL_STATIC_SCHEMA" else "NO_INPUT", apiSchemaFiles.size, apiSchemaFindings.size, "OpenAPI/Swagger JSON به‌علاوه بررسی ایستای محدود OpenAPI YAML، GraphQL SDL و SOAP WSDL؛ YAML anchor/${'$'}ref و resolver/runtime auth، DAST، tenant isolation و business logic تست نشده‌اند."),
            SpecialistDomainCoverage("CLOUD_IDENTITY_RUNTIME", "NOT_TESTED", 0, 0, "IAM/Entra/AD/Cloud فقط با exportهای read-only و دسترسی owner قابل ارزیابی کامل است.")
        )
        val limitations = buildList {
            add("تحلیل سورس و پیکربندی deterministic و line/rule-based است؛ AST، taint analysis و policy evaluation کامل نیستند.")
            add("فایل‌های بزرگ، باینری، فایل‌های ناشناخته و ورودی‌های خارج از سقف اسکن نمی‌شوند.")
            add("APK/AAB به‌عنوان ZIP inventory محدود می‌شود؛ AXML/DEX فقط شناسایی می‌شوند. Decode باینری، بررسی امضای APK/AAB، MobSF و runtime/device testing انجام نمی‌شود؛ Manifest متنی/decoded لازم است.")
            add("Cloud/IAM/AD/Kubernetes live با provider-native read-only role متصل نشده؛ فقط فایل‌های export شده تحلیل می‌شوند.")
            add("اسکن زنده شبکه، service/version fingerprinting، TLS handshake inventory و directory services در ZIP analyzer اجرا نمی‌شوند.")
            add("ATT&CKها فقط راهنمای دفاعی و فرضیه ارتباط‌اند؛ از آن‌ها مسیر exploit یا lateral movement نتیجه‌گیری نمی‌شود.")
            add("آسیب‌پذیری وابستگی‌ها با CVE/OSV تطبیق داده نشده؛ inventory به معنی vulnerable یا safe بودن نیست.")
            add("تحلیل runtime وردپرس، نقش‌ها، تنظیمات دیتابیس، افزونه‌های فعال، WooCommerce customer/order data و payment gateway انجام نشده است.")
            add("API شامل OpenAPI JSON و بررسی ایستای خط‌محور OpenAPI YAML، GraphQL SDL و SOAP WSDL است؛ schema review معادل DAST، resolver runtime، authentication، authorization یا tenant isolation نیست.")
            if (stoppedByLimit) add("اسکن آرشیو به سقف منابع برخورد کرد و ممکن است همه فایل‌ها بررسی نشده باشند.")
        }
        return ProjectAuditResult(
            archiveName = archiveName, filesDiscovered = discovered, filesScanned = scanned,
            totalExpandedBytesRead = expandedBytes, languages = languageCounts,
            findings = finalFindings, rootCauseGroups = RootCauseAnalyzer.group(finalFindings),
            dependencies = inventory, isWordPress = isWp, isWooCommerce = isWoo,
            websiteComponents = if (isWp) WordPressSecurityAnalyzer.inventory(textFiles) else emptyList(),
            skippedEntries = skipped, limitations = limitations,
            domainCoverage = domainCoverage, defensiveTechniques = defensiveProfiles, evidenceGraph = evidenceGraph
        )
    }

    private fun readBounded(input: InputStream, limit: Int): ByteArray {
        val output = ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        var total = 0
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            require(total <= limit) { "فایل ZIP فشرده از سقف ${limit / (1024 * 1024)} مگابایت عبور کرد." }
            output.write(buffer, 0, count)
        }
        return output.toByteArray()
    }

    private data class EntryRead(
        val bytes: ByteArray?,
        val expandedBytes: Long,
        /** Fatal: the archive-wide expanded-size budget was exhausted; the whole scan must stop. */
        val exceededLimit: Boolean,
        /** Non-fatal: this single entry is larger than the per-entry cap; it is skipped but the scan continues. */
        val oversized: Boolean = false
    )

    /**
     * Reads or drains every ZIP member through the same caps, including ignored/binary/unsafe entries.
     * An entry above [perEntryLimit] is drained without being kept (so one large image or minified bundle
     * no longer aborts the whole analysis); only the archive-wide [remainingTotalLimit] is fatal, which still bounds
     * the CPU/memory a decompression bomb can consume.
     */
    private fun readEntryBounded(input: InputStream, perEntryLimit: Int, remainingTotalLimit: Int, capture: Boolean): EntryRead {
        var output: ByteArrayOutputStream? = if (capture) ByteArrayOutputStream() else null
        val buffer = ByteArray(8192)
        var total = 0L
        var oversized = false
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            total += count
            if (total > remainingTotalLimit) return EntryRead(null, total, true, oversized)
            if (total > perEntryLimit && !oversized) {
                oversized = true
                output = null // release what was buffered; keep draining only to stay within the total budget
            }
            output?.write(buffer, 0, count)
        }
        return EntryRead(if (oversized) null else output?.toByteArray(), total, false, oversized)
    }
}
