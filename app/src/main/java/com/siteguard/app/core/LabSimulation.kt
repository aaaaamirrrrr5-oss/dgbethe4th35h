package com.siteguard.app.core

/** Benign, deterministic configuration simulations; no payloads or target network traffic. */
data class LabScenarioV1(
    val id: String,
    val title: String,
    val domain: String,
    val setup: String,
    val expectedFindingId: String,
    val expectedEvidence: String,
    val safeTest: String,
    val expectedRemediation: String,
    val postFixPassCondition: String,
    val requiresDisposableTarget: Boolean = false
)

data class LabFixtureV1(
    val fixtureId: String,
    val observedControls: Map<String, Boolean>,
    val syntheticOnly: Boolean = true
)

data class LabSimulationResultV1(
    val scenarioId: String,
    val fixtureId: String,
    val findingIds: List<String>,
    val evidence: List<String>,
    val passAfterFix: Boolean,
    val reproducibleFingerprint: String,
    val notes: List<String>
)

object LabScenarioCatalogV1 {
    val scenarios = listOf(
        LabScenarioV1(
            "LAB-WEB-HEADERS", "هدرهای امنیتی وب", "Web configuration",
            "یک fixture محلی شامل تنظیمات پاسخ HTTP مصنوعی بسازید.", "LAB-WEB-CSP-MISSING",
            "fixture نشان می‌دهد contentSecurityPolicyConfigured=false.",
            "فقط وضعیت بولی تنظیمات مصنوعی را بررسی کنید؛ درخواست شبکه ارسال نمی‌شود.",
            "CSP را ابتدا در Report-Only و سپس با منابع مجاز محدود پیکربندی کنید.",
            "fixture پس از اصلاح contentSecurityPolicyConfigured=true باشد."
        ),
        LabScenarioV1(
            "LAB-MOBILE-MANIFEST", "Android exported component", "Android mobile",
            "Manifest متنی آزمایشی با exported component بدون permission بسازید.", "LAB-MOBILE-EXPORTED",
            "fixture نشان می‌دهد exportedComponentRestricted=false.",
            "تنظیم Manifest و permission در fixture را ایستا بررسی کنید.",
            "android:exported را حداقلی کنید و permission/intent validation اضافه کنید.",
            "همه componentهای exported دارای ضرورت و کنترل دسترسی مستند باشند."
        ),
        LabScenarioV1(
            "LAB-CLOUD-PRIVILEGE", "حداقل دسترسی IAM", "Cloud / identity",
            "یک policy JSON مصنوعی با wildcard permission بسازید.", "LAB-CLOUD-IAM-WILDCARD",
            "fixture نشان می‌دهد wildcardPermission=true.",
            "فقط policy نمونه را محلی parse کنید؛ هیچ حساب ابری متصل نمی‌شود.",
            "عملیات و منابع را به حداقل دسترسی موردنیاز محدود کنید.",
            "wildcard غیرضروری حذف و تست policy محلی موفق باشد."
        ),
        LabScenarioV1(
            "LAB-CONTAINER-PRIVILEGE", "کانتینر privileged", "Container",
            "Dockerfile یا manifest مصنوعی با privileged=true تهیه کنید.", "LAB-CONTAINER-PRIVILEGED",
            "fixture نشان می‌دهد privilegedContainer=true.",
            "پیکربندی محلی را بخوانید؛ کانتینری اجرا نمی‌شود.",
            "حالت privileged را حذف و capabilityها و filesystem را محدود کنید.",
            "fixture فاقد privileged mode و دارای دسترسی حداقلی باشد."
        ),
        LabScenarioV1(
            "LAB-FORENSICS-HASH", "یکپارچگی شواهد", "Forensics",
            "یک فایل متنی synthetic با مقدار ثابت ایجاد کنید.", "LAB-FORENSIC-HASH-MISMATCH",
            "هش SHA-256 فایل با مقدار ثبت‌شده مقایسه می‌شود.",
            "فقط hash محاسبه و مقایسه می‌شود؛ فایل اجرا یا بازنویسی نمی‌شود.",
            "نسخه اصلی حفظ و هر acquisition جدید به chain of custody افزوده شود.",
            "هش محاسبه‌شده دقیقاً با مقدار ثبت‌شده مطابقت داشته باشد."
        )
    )

    fun byId(id: String): LabScenarioV1? = scenarios.firstOrNull { it.id == id }
}

object LabSimulationEngineV1 {
    fun run(scenario: LabScenarioV1, fixture: LabFixtureV1): LabSimulationResultV1 {
        require(fixture.syntheticOnly) { "اجرای این runner فقط روی fixture مصنوعی مجاز است." }
        val signals = when (scenario.id) {
            "LAB-WEB-HEADERS" -> mapOf("LAB-WEB-CSP-MISSING" to (fixture.observedControls["contentSecurityPolicyConfigured"] == false))
            "LAB-MOBILE-MANIFEST" -> mapOf("LAB-MOBILE-EXPORTED" to (fixture.observedControls["exportedComponentRestricted"] == false))
            "LAB-CLOUD-PRIVILEGE" -> mapOf("LAB-CLOUD-IAM-WILDCARD" to (fixture.observedControls["wildcardPermission"] == true))
            "LAB-CONTAINER-PRIVILEGE" -> mapOf("LAB-CONTAINER-PRIVILEGED" to (fixture.observedControls["privilegedContainer"] == true))
            "LAB-FORENSICS-HASH" -> mapOf("LAB-FORENSIC-HASH-MISMATCH" to (fixture.observedControls["evidenceHashMatches"] == false))
            else -> emptyMap()
        }
        val findings = signals.filterValues { it }.keys.toList()
        val evidence = signals.filterValues { it }.keys.map { id -> "synthetic-fixture:${fixture.fixtureId}; signal=$id" }
        val fingerprint = java.security.MessageDigest.getInstance("SHA-256").digest(
            (scenario.id + "|" + fixture.fixtureId + "|" + fixture.observedControls.toSortedMap()).toByteArray(Charsets.UTF_8)
        ).joinToString("") { "%02x".format(it) }
        return LabSimulationResultV1(
            scenario.id, fixture.fixtureId, findings, evidence, findings.isEmpty(), fingerprint,
            listOf(
                "سناریو در محیط آزمایشگاهی محلی و با داده مصنوعی اجرا شد.",
                "هیچ درخواست شبکه، exploit، persistence یا تغییر هدف واقعی انجام نشد.",
                "نتیجه فقط صحت fixture و rule ساده را نشان می‌دهد؛ معیار پوشش واقعی محصول نیست."
            )
        )
    }

    fun runCatalogSmoke(): List<LabSimulationResultV1> = LabScenarioCatalogV1.scenarios.map { scenario ->
        val vulnerable = when (scenario.id) {
            "LAB-WEB-HEADERS" -> mapOf("contentSecurityPolicyConfigured" to false)
            "LAB-MOBILE-MANIFEST" -> mapOf("exportedComponentRestricted" to false)
            "LAB-CLOUD-PRIVILEGE" -> mapOf("wildcardPermission" to true)
            "LAB-CONTAINER-PRIVILEGE" -> mapOf("privilegedContainer" to true)
            else -> mapOf("evidenceHashMatches" to false)
        }
        run(scenario, LabFixtureV1("fixture-${scenario.id}", vulnerable))
    }
}
