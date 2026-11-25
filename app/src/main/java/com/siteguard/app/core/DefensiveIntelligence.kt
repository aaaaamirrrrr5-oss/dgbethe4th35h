package com.siteguard.app.core

/** Defensive-only ATT&CK reference profile. These are planning records, never executable attack instructions. */
data class DefensiveTechniqueProfile(
    val techniqueId: String,
    val name: String,
    val level: Int,
    val publicSource: String,
    val prerequisites: String,
    val defensiveIndicators: List<String>,
    val safeSimulation: String,
    val expectedTelemetry: List<String>,
    val detectionLogic: String,
    val mitigation: String,
    val validation: String
)

object DefensiveIntelligenceCatalog {
    val profiles: List<DefensiveTechniqueProfile> = listOf(
        DefensiveTechniqueProfile(
            "T1190", "Exploit Public-Facing Application", 3,
            "https://attack.mitre.org/techniques/T1190/",
            "یک برنامه آزمایشی آسیب‌پذیر در lab جدا، داده synthetic و محدوده شبکه ایزوله.",
            listOf("افزایش خطاهای 4xx/5xx", "درخواست‌های غیرعادی به endpointهای منتشرشده", "تغییرات غیرمنتظره در WAF/application logs"),
            "یک درخواست بی‌ضرر و از پیش تعریف‌شده به endpoint آزمایشی ارسال کنید؛ هیچ payload exploit یا دسترسی به داده واقعی استفاده نشود.",
            listOf("reverse proxy access log", "WAF decision", "application error log", "trace/request ID"),
            "endpoint، نرخ خطا، منبع درخواست و شناسه هم‌بسته را در پنجره زمانی واحد correlate کنید؛ برای رخدادهای synthetic alert آزمایشی بسازید.",
            "patch framework/component، محدودکردن سطح endpoint، اعتبارسنجی ورودی، WAF به‌عنوان لایه مکمل و logging امن.",
            "با یک درخواست مجاز synthetic، ثبت رخداد و alert را تأیید و سپس baseline عادی را با آن مقایسه کنید."
        ),
        DefensiveTechniqueProfile(
            "T1078", "Valid Accounts", 3,
            "https://attack.mitre.org/techniques/T1078/",
            "حساب تستی غیرممتاز، دسترسی read-only و ثبت رویداد در IdP/AD آزمایشگاهی.",
            listOf("ورود از مکان/دستگاه غیرمنتظره", "ورود موفق پس از چند شکست کنترل‌شده", "استفاده از حساب غیرفعال یا خارج از الگوی کاری"),
            "یک ورود عادی با حساب synthetic از دستگاه آزمایشگاهی انجام و eventها با برچسب TEST تولید شوند؛ هیچ credential واقعی یا تلاش حدس رمز اجرا نشود.",
            listOf("IdP sign-in log", "MFA result", "device posture", "conditional-access decision"),
            "ورود موفق/ناموفق، عامل MFA، شناسه کاربر تست و device ID را هم‌بسته و alertهای policy را بررسی کنید.",
            "MFA مقاوم، conditional access، least privilege، چرخه حذف حساب stale و بازبینی منظم مالکیت حساب.",
            "ورود synthetic از وضعیت مجاز و غیرمجاز باید نتیجه policy مورد انتظار را ثبت کند."
        ),
        DefensiveTechniqueProfile(
            "T1552", "Unsecured Credentials", 3,
            "https://attack.mitre.org/techniques/T1552/",
            "نمونه فایل حاوی placeholder ساختگی؛ هرگز secret واقعی در تمرین قرار ندهید.",
            listOf("secret-like value در repository/config", "credential در log/artifact", "استفاده از secret خارج از مخزن امن"),
            "یک مقدار کاملاً ساختگی با پیشوند TEST_ONLY در fixture قرار دهید و بررسی کنید secret scanner آن را با masking تشخیص دهد.",
            listOf("repository audit event", "secret-scanner finding", "CI job result", "rotation ticket"),
            "هشدار scanner را با path/commit و وضعیت false-positive مرور کنید؛ مقدار secret در alert یا log چاپ نشود.",
            "secret manager، حذف secret از سورس، rotation در صورت واقعی بودن افشا و محدودسازی token scope.",
            "مقدار ساختگی باید شناسایی و در خروجی redacted شود؛ هیچ مقدار واقعی در گزارش ذخیره نشود."
        ),
        DefensiveTechniqueProfile(
            "T1059", "Command and Scripting Interpreter", 3,
            "https://attack.mitre.org/techniques/T1059/",
            "ماشین آزمایشگاهی disposable، اسکریپت بی‌ضرر که فقط marker TEST_ONLY را در log چاپ کند.",
            listOf("فرآیند interpreter غیرمعمول", "والد/فرزند process نامتعارف", "اجرای script از مسیر writable توسط کاربر"),
            "یک اسکریپت بی‌اثر از پیش تأییدشده اجرا کنید که فقط یک شناسه تست را در خروجی محلی ثبت کند؛ هیچ فرمان شبکه/تغییر سیستمی اجرا نشود.",
            listOf("process creation event", "parent/child relationship", "script block log", "endpoint telemetry"),
            "نام فرآیند، parent، user، مسیر و شناسه synthetic را در event test correlate کنید.",
            "کنترل اجرای script، محدودسازی privilege، allowlisting، logging و محافظت از مسیرهای قابل‌نوشتن.",
            "event آزمایشی باید در collector و detection rule دیده شود؛ سیستم production لمس نشود."
        ),
        DefensiveTechniqueProfile(
            "T1610", "Deploy Container", 3,
            "https://attack.mitre.org/techniques/T1610/",
            "cluster محلی disposable، image غیرمخرب و namespace جدا با policy محدود.",
            listOf("image ناشناخته یا بدون digest", "container با privilege یا host namespace", "تغییر غیرمنتظره workload"),
            "یک workload benign با label تست در namespace محدود deploy و سپس حذف کنید؛ هیچ image ناشناس یا privileged استفاده نشود.",
            listOf("Kubernetes audit log", "admission decision", "image digest", "pod security context"),
            "هویت deployer، image digest، namespace و policy admission را با event آزمایش correlate کنید.",
            "image provenance، امضای image، non-root، seccomp، read-only root filesystem و کمینه‌سازی capability.",
            "policy باید workload سالم را مجاز و fixture نامنطبق را در مرحله admission رد کند."
        ),
        DefensiveTechniqueProfile(
            "T1098", "Account Manipulation", 3,
            "https://attack.mitre.org/techniques/T1098/",
            "فقط tenant/AD آزمایشگاهی و حساب synthetic با نقش محدود؛ مجوز تغییر جداگانه در lab.",
            listOf("تغییر عضویت گروه", "افزودن credential/factor", "تغییر role یا federation trust"),
            "به‌جای تغییر واقعی حساب، event مصنوعی ممیزی یا fixture log تولید کنید و alert مربوط به تغییر privilege را بسنجید.",
            listOf("directory audit log", "role assignment event", "MFA method change", "approval record"),
            "تغییر privilege را به actor، target account، approval و زمان متصل کنید؛ تغییر بدون change ticket را alert کنید.",
            "approval workflow، least privilege، dual control، بازبینی role assignment و هشدار روی تغییرات حساس.",
            "fixture مثبت/منفی باید alert درست بدهد؛ هیچ حساب production تغییر نکند."
        )
    )

    fun forFinding(finding: Finding): List<DefensiveTechniqueProfile> {
        val ids = when (finding.cwe) {
            "CWE-798", "CWE-522", "CWE-312", "CWE-256" -> setOf("T1552")
            "CWE-862", "CWE-306", "CWE-250", "CWE-269" -> setOf("T1078", "T1098")
            "CWE-78", "CWE-94", "CWE-95" -> setOf("T1059")
            "CWE-668", "CWE-732" -> setOf("T1610")
            "CWE-89", "CWE-79", "CWE-918", "CWE-352" -> setOf("T1190")
            else -> emptySet()
        }
        return profiles.filter { it.techniqueId in ids }
    }
}

data class EvidenceGraphNode(val id: String, val type: String, val label: String, val sourceReference: String)
data class EvidenceGraphEdge(val from: String, val to: String, val relationship: String, val evidenceReference: String)
data class EvidenceGraphV1(val nodes: List<EvidenceGraphNode>, val edges: List<EvidenceGraphEdge>, val limitations: List<String>)

/** Builds only directly evidenced same-asset links; it does not infer exploitability or lateral movement. */
object EvidenceGraphBuilder {
    fun fromFindings(findings: List<Finding>): EvidenceGraphV1 {
        val nodes = linkedMapOf<String, EvidenceGraphNode>()
        val edges = mutableListOf<EvidenceGraphEdge>()
        findings.forEach { finding ->
            val asset = finding.affectedAsset.ifBlank { "unknown-asset" }
            val assetId = "asset:${asset.hashCode()}"
            val findingId = "finding:${finding.id}"
            nodes.putIfAbsent(assetId, EvidenceGraphNode(assetId, "asset", asset, asset))
            nodes[findingId] = EvidenceGraphNode(findingId, "finding", finding.title, finding.id)
            edges += EvidenceGraphEdge(assetId, findingId, "HAS_OBSERVED_FINDING", finding.id)
        }
        val sameAssetPairs = findings.groupBy { it.affectedAsset }.filterKeys { it.isNotBlank() }
        sameAssetPairs.values.forEach { group ->
            if (group.size > 1) {
                val ids = group.map { "finding:${it.id}" }
                for (i in 0 until ids.size) for (j in i + 1 until ids.size) {
                    edges += EvidenceGraphEdge(ids[i], ids[j], "SAME_EXACT_ASSET", group[i].affectedAsset)
                }
            }
        }
        return EvidenceGraphV1(nodes.values.toList(), edges.distinct(), listOf(
            "رابطه‌ها فقط از affectedAsset یکسان و یافته ثبت‌شده ساخته شده‌اند.",
            "هیچ مسیر دسترسی، privilege escalation، lateral movement یا exploitability از روی هم‌مکانی استنتاج نشده است.",
            "ارتباط dependency و identity تا زمانی که شواهد versioned/owner-provided در دسترس نباشد ساخته نمی‌شود."
        ))
    }
}
