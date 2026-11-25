package com.siteguard.app.core

import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

class SpecialistArchiveIntegrationTest {
    @Test fun projectZipRunsMobileNetworkAndCloudModulesAndReportsCoverage() {
        val files = mapOf(
            "app/src/main/AndroidManifest.xml" to """<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-sdk android:targetSdkVersion="33"/><application android:debuggable="true" android:usesCleartextTraffic="true"/></manifest>""",
            "etc/ssh/sshd_config" to "PermitRootLogin yes\n",
            "Dockerfile" to "FROM alpine:latest\nUSER root\n",
            "k8s/deployment.yaml" to "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n",
            "api/openapi.json" to """{"openapi":"3.0.3","paths":{"/private":{"get":{"responses":{"200":{"description":"ok"}}}}}}"""
        )
        val zip = ByteArrayOutputStream().also { bytes ->
            ZipOutputStream(bytes).use { output ->
                files.forEach { (path, content) ->
                    output.putNextEntry(ZipEntry(path))
                    output.write(content.toByteArray())
                    output.closeEntry()
                }
            }
        }.toByteArray()
        val audit = ProjectArchiveAnalyzer().analyze(ByteArrayInputStream(zip), "multi-domain.zip")
        assertTrue(audit.findings.any { it.id.startsWith("SG-MOB-DEBUGGABLE") })
        assertTrue(audit.findings.any { it.id.startsWith("SG-NET-SSH-ROOT") })
        assertTrue(audit.findings.any { it.id.startsWith("SG-CLD-DOCKER-ROOT") })
        assertTrue(audit.findings.any { it.id.startsWith("SG-CLD-K8S-PRIVILEGED") })
        assertTrue(audit.domainCoverage.any { it.domain == "ANDROID_MOBILE" && it.state == "ANALYZED" })
        assertTrue(audit.domainCoverage.any { it.domain == "NETWORK_ENTERPRISE" && it.state == "ANALYZED" })
        assertTrue(audit.domainCoverage.any { it.domain == "CLOUD_IDENTITY_CONTAINER_CICD" && it.state == "ANALYZED" })
        assertTrue(audit.findings.any { it.id.startsWith("SG-API-OPENAPI-NO-SECURITY") })
        assertTrue(audit.domainCoverage.any { it.domain == "API_SECURITY" && it.state == "PARTIAL_STATIC_SCHEMA" })
        assertTrue(audit.evidenceGraph.nodes.isNotEmpty())
    }
}
