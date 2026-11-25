package com.siteguard.app

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.siteguard.app.core.Finding
import com.siteguard.app.core.OwnershipChallengeV1
import com.siteguard.app.core.OwnershipProofResultV1
import com.siteguard.app.core.OwnershipProofStatusV1
import com.siteguard.app.core.OwnershipProofV1
import com.siteguard.app.core.PassiveHygieneChecksV1
import com.siteguard.app.core.PassiveHygieneReportV1
import com.siteguard.app.core.WebsiteAuthorizationProofV2
import com.siteguard.app.core.WebsiteEngagementManifestV2
import com.siteguard.app.core.WebsiteTestClassV2
import com.siteguard.app.core.canonicalHost
import com.siteguard.app.core.normalizeUrl
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val PanelBg = Color(0xFF1B1E26)
private val PanelMuted = Color(0xFF9AA0AA)
private val PanelText = Color(0xFFF4F5F7)

private fun panelManifest(host: String, proof: OwnershipProofResultV1?): WebsiteEngagementManifestV2 {
    val now = System.currentTimeMillis()
    val base = WebsiteEngagementManifestV2(
        projectId = "ui-$host",
        projectName = "Ownership and hygiene checks",
        assetOwner = "User declaration",
        authorizer = "User declaration",
        proofMethod = WebsiteAuthorizationProofV2.USER_DECLARATION,
        proofReference = "User confirmed authorization in the app",
        allowedHosts = setOf(host),
        excludedPaths = setOf("/wp-admin", "/wp-login.php", "/checkout", "/cart", "/my-account"),
        authorizedPorts = setOf(443, 80),
        allowedTestClasses = setOf(WebsiteTestClassV2.PASSIVE_REVIEW),
        environment = "production-passive",
        validFromEpochMs = now - 1_000,
        validUntilEpochMs = now + 15 * 60_000L,
        maxRequests = 6,
        requestsPerMinute = 60,
        maxConcurrency = 1,
        emergencyContact = "User controlled in-app cancellation",
        emergencyStopProcedure = "Leave the screen or cancel the running job"
    )
    return if (proof != null) OwnershipProofV1.applyTo(base, proof) else base
}

/** Technical ownership proof (well-known token) and passive hygiene checks (HTTP->HTTPS, robots.txt, sitemap). */
@Composable
internal fun OwnershipAndHygienePanel(
    url: String,
    authorized: Boolean,
    onFindings: (List<Finding>) -> Unit = {},
    onReport: (PassiveHygieneReportV1, OwnershipProofResultV1?) -> Unit = { _, _ -> }
) {
    val scope = rememberCoroutineScope()
    val host = remember(url) {
        normalizeUrl(url)?.let { runCatching { java.net.URI(it).host }.getOrNull() }?.let { canonicalHost(it) }
    }
    var challenge by remember(host) { mutableStateOf<OwnershipChallengeV1?>(null) }
    var proof by remember(host) { mutableStateOf<OwnershipProofResultV1?>(null) }
    var report by remember(host) { mutableStateOf<PassiveHygieneReportV1?>(null) }
    var busy by remember(host) { mutableStateOf(false) }
    var message by remember(host) { mutableStateOf("") }

    Surface(color = PanelBg, shape = RoundedCornerShape(14.dp), modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("اثبات مالکیت و بررسی‌های تکمیلی", fontSize = 13.sp, fontWeight = FontWeight.Bold, color = PanelText)
            Text(
                "اختیاری: اثبات فنی کنترل دامنه با فایل توکن، سپس بررسی redirect به HTTPS، robots.txt، sitemap و security.txt (حداکثر ۴ درخواست GET).",
                fontSize = 10.sp, color = PanelMuted
            )
            if (host == null) {
                Text("ابتدا یک آدرس معتبر وارد کنید.", fontSize = 11.sp, color = PanelMuted)
            } else {
                OutlinedButton(
                    onClick = {
                        val created = OwnershipProofV1.newChallenge(host)
                        challenge = created
                        proof = null
                        message = if (created == null) "برای IP یا نام بدون نقطه اثبات فایل ممکن نیست؛ نام دامنه لازم است." else ""
                    },
                    enabled = authorized && !busy, modifier = Modifier.fillMaxWidth()
                ) { Text("ساخت چالش مالکیت") }

                challenge?.let { c ->
                    Text(OwnershipProofV1.instructions(c), fontSize = 10.sp, color = PanelText)
                    OutlinedButton(
                        onClick = {
                            scope.launch {
                                busy = true
                                try {
                                    proof = withContext(Dispatchers.IO) { OwnershipProofV1.verify(c, panelManifest(host, null)) }
                                } catch (e: CancellationException) {
                                    throw e
                                } catch (e: Exception) {
                                    message = "تأیید ناموفق بود: ${e.javaClass.simpleName}"
                                } finally {
                                    busy = false
                                }
                            }
                        },
                        enabled = authorized && !busy, modifier = Modifier.fillMaxWidth()
                    ) { Text(if (busy) "در حال بررسی..." else "تأیید مالکیت") }
                }
                proof?.let { p ->
                    val label = when (p.status) {
                        OwnershipProofStatusV1.VERIFIED -> "تأیید شد"
                        OwnershipProofStatusV1.NOT_VERIFIED -> "تأیید نشد"
                        OwnershipProofStatusV1.EXPIRED -> "منقضی شد"
                        OwnershipProofStatusV1.ERROR -> "خطا"
                    }
                    Text("مالکیت: $label — ${p.reason}", fontSize = 10.sp, color = PanelText)
                }

                Spacer(Modifier.height(2.dp))
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            busy = true
                            message = ""
                            try {
                                val result = PassiveHygieneChecksV1.run(host, panelManifest(host, proof))
                                report = result
                                onFindings(result.findings)
                                onReport(result, proof)
                            } catch (e: CancellationException) {
                                throw e
                            } catch (e: Exception) {
                                message = "بررسی ناموفق بود: ${e.javaClass.simpleName}"
                            } finally {
                                busy = false
                            }
                        }
                    },
                    enabled = authorized && !busy, modifier = Modifier.fillMaxWidth()
                ) { Text(if (busy) "در حال بررسی..." else "بررسی HTTPS، robots.txt، sitemap و security.txt") }

                if (message.isNotBlank()) Text(message, fontSize = 10.sp, color = PanelMuted)
                report?.let { r ->
                    Text(
                        "${r.findings.size} یافته • ${r.requestsUsed} درخواست • sitemap: ${r.sitemapUrlCount} آدرس هم‌میزبان",
                        fontSize = 10.sp, color = PanelText
                    )
                    r.tls?.let { t ->
                        Text("TLS: ${t.protocol} • ${t.cipherSuite} • ${t.keyAlgorithm}/${t.keyBits}", fontSize = 9.sp, color = PanelMuted)
                    }
                    r.findings.forEach { f ->
                        Text("${f.severity.name} • ${f.title}", fontSize = 10.sp, fontWeight = FontWeight.Bold, color = PanelText)
                        Text(f.evidence, fontSize = 9.sp, color = PanelMuted)
                    }
                    r.events.filter { it.status != "FETCHED" }.take(5).forEach { e ->
                        Text("${e.status}: ${e.url}", fontSize = 9.sp, color = PanelMuted)
                    }
                    r.limitations.forEach { Text("• $it", fontSize = 9.sp, color = PanelMuted) }
                }
            }
        }
    }
}
