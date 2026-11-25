package com.siteguard.app.core

import org.junit.Assert.*
import org.junit.Test

class WebsiteSpecialistV2Test {
    private fun manifest(now: Long = 100_000L) = WebsiteEngagementManifestV2(
        projectId = "p-1", projectName = "Fixture website", assetOwner = "Example owner", authorizer = "Example authorizer",
        proofMethod = WebsiteAuthorizationProofV2.WRITTEN_CONTRACT, proofReference = "ticket/contract-123",
        allowedHosts = setOf("example.com"), excludedHosts = setOf("payments.example.net"),
        allowedPathPrefixes = setOf("/shop", "/wp-json"), excludedPaths = setOf("/shop/admin"),
        authorizedPorts = setOf(443), allowedTestClasses = setOf(WebsiteTestClassV2.PASSIVE_REVIEW, WebsiteTestClassV2.SOURCE_REVIEW),
        environment = "production", validFromEpochMs = now - 1000, validUntilEpochMs = now + 60_000,
        maxRequests = 10, requestsPerMinute = 2, maxConcurrency = 1,
        emergencyContact = "ops@example.com", emergencyStopProcedure = "Stop active job in app"
    )

    @Test fun engagementManifestValidatesAndHashesDeterministically() {
        val a = manifest()
        val b = a.copy(allowedHosts = linkedSetOf("example.com"), excludedPaths = linkedSetOf("/shop/admin"))
        assertTrue(a.validationErrors(100_000L).isEmpty())
        assertEquals(a.integritySha256(), b.integritySha256())
        assertEquals(64, a.integritySha256().length)
    }

    @Test fun websiteScopeGateRequiresExactHostPortPathAndAllowedTestClass() {
        val m = manifest()
        assertTrue(m.authorizeUrl("https://example.com/shop", WebsiteTestClassV2.PASSIVE_REVIEW, 0, 100_000L).allowed)
        assertFalse(m.authorizeUrl("https://sub.example.com/shop", WebsiteTestClassV2.PASSIVE_REVIEW, 0, 100_000L).allowed)
        assertFalse(m.authorizeUrl("https://example.com/shop/admin/orders", WebsiteTestClassV2.PASSIVE_REVIEW, 0, 100_000L).allowed)
        assertFalse(m.authorizeUrl("http://example.com/shop", WebsiteTestClassV2.PASSIVE_REVIEW, 0, 100_000L).allowed)
        assertFalse(m.authorizeUrl("https://payments.example.net/shop", WebsiteTestClassV2.PASSIVE_REVIEW, 0, 100_000L).allowed)
        assertFalse(m.authorizeUrl("https://example.com/shop", WebsiteTestClassV2.SAFE_ACTIVE, 0, 100_000L).allowed)
        assertFalse(m.authorizeUrl("https://example.com/shop", WebsiteTestClassV2.PASSIVE_REVIEW, 10, 100_000L).allowed)
    }

    @Test fun websiteScopeRejectsExpiredAndDangerousManifestConditions() {
        val m = manifest()
        assertFalse(m.authorizeUrl("https://example.com/shop", WebsiteTestClassV2.PASSIVE_REVIEW, 0, 1_000_000L).allowed)
        assertFalse(m.copy(allowedHosts = setOf("*.example.com")).validationErrors(100_000L).isEmpty())
        assertFalse(m.copy(explicitlyAuthorizedThirdPartyHosts = setOf("*.payments.example.net")).validationErrors(100_000L).isEmpty())
        assertFalse(m.copy(authorizedIpRanges = setOf("not-a-cidr")).validationErrors(100_000L).isEmpty())
        assertTrue(m.copy(authorizedIpRanges = setOf("203.0.113.0/24")).validationErrors(100_000L).isEmpty())
        assertFalse(m.copy(allowedHosts = setOf("example.com"), excludedHosts = setOf("example.com")).validationErrors(100_000L).isEmpty())
        assertFalse(m.copy(environment = "production", allowedTestClasses = setOf(WebsiteTestClassV2.DESTRUCTIVE_LAB)).validationErrors(100_000L).isEmpty())
        assertFalse(m.copy(allowedTestClasses = setOf(WebsiteTestClassV2.AUTHENTICATED_SYNTHETIC)).validationErrors(100_000L).isEmpty())
    }

    @Test fun websiteCoverageNeverTurnsMissingStaticFindingIntoPass() {
        val finding = Finding(
            id = "SG-WP-REST-PERM-L12", title = "WordPress REST permission callback review", severity = Severity.MEDIUM,
            description = "Review lead", remediation = "Add capability and object ownership authorization", cwe = "CWE-862",
            status = FindingStatus.PROBABLE, affectedAsset = "wp-content/plugins/demo/plugin.php", exactLocation = "wp-content/plugins/demo/plugin.php:12",
            evidence = "register_rest_route(...)", detectionMethod = "WordPress deterministic heuristic"
        )
        val project = ProjectAuditResult(
            archiveName = "wordpress-fixture.zip", filesDiscovered = 12, filesScanned = 8, totalExpandedBytesRead = 4096,
            languages = mapOf("PHP" to 4), findings = listOf(finding), rootCauseGroups = emptyList(),
            dependencies = DependencyInventory(emptyList(), emptyList(), emptyList()), isWordPress = true, isWooCommerce = true,
            websiteComponents = listOf(WebsiteComponent("plugin", "Demo plugin", "1.0.0", "wp-content/plugins/demo/plugin.php")),
            skippedEntries = emptyList(), limitations = emptyList(),
            domainCoverage = listOf(SpecialistDomainCoverage("WORDPRESS_WOOCOMMERCE", "ANALYZED", 8, 1, "static source only"))
        )
        val result = WebsiteSecuritySpecialistEngineV2.assess(project, 100_000L)
        assertEquals("2.0", result.specificationVersion)
        assertEquals(WebsiteCoverageStateV2.NEEDS_MANUAL_REVIEW, result.controls.single { it.definition.id == "WP-REST-AJAX" }.state)
        assertEquals(WebsiteCoverageStateV2.NOT_TESTED, result.controls.single { it.definition.id == "WEB-TLS-EDGE" }.state)
        assertEquals(0, result.passCount)
        assertTrue(result.architectureEdges.any { it.observed && it.evidenceRef.contains("plugin.php") })
        assertTrue(result.architectureEdges.none { it.relation.contains("PAYMENT") && it.observed })
        assertEquals(result.controls.size, result.testPlans.size)
        assertEquals(1, result.evidenceRecords.size)
        assertEquals(64, result.evidenceRecords.single().integritySha256.length)
        assertEquals(0, result.evidenceRecords.single().requestCount) // archive review is not a network request
    }

    @Test fun nonWordPressArchiveMarksWordPressControlsNotApplicable() {
        val project = ProjectAuditResult(
            archiveName = "generic.zip", filesDiscovered = 2, filesScanned = 1, totalExpandedBytesRead = 120,
            languages = mapOf("JavaScript" to 1), findings = emptyList(), rootCauseGroups = emptyList(),
            dependencies = DependencyInventory(emptyList(), emptyList(), emptyList()), isWordPress = false, isWooCommerce = false,
            websiteComponents = emptyList(), skippedEntries = emptyList(), limitations = emptyList()
        )
        val result = WebsiteSecuritySpecialistEngineV2.assess(project, 100_000L)
        assertEquals(WebsiteCoverageStateV2.NOT_APPLICABLE, result.controls.single { it.definition.id == "WP-COMPONENTS" }.state)
        assertEquals(WebsiteCoverageStateV2.NOT_APPLICABLE, result.controls.single { it.definition.id == "WP-WC-ORDERS" }.state)
        assertEquals(WebsiteCoverageStateV2.NOT_APPLICABLE, result.controls.single { it.definition.id == "WEB-COMMERCE" }.state)
        assertEquals(WebsiteCoverageStateV2.NOT_TESTED, result.controls.single { it.definition.id == "WEB-AUTHZ-TENANT" }.state)
    }

    @Test fun evidenceVaultSanitizesSecretsAndDoesNotInventNetworkTelemetry() {
        val finding = Finding(
            id = "F-SECRET", title = "Possible hardcoded token", severity = Severity.HIGH,
            description = "Credential-like value in local fixture", remediation = "Rotate and remove the secret",
            evidence = "access_token=\"super_secret_value_123456\"", exactLocation = "src/config.php:4"
        )
        val project = ProjectAuditResult(
            archiveName = "fixture.zip", filesDiscovered = 1, filesScanned = 1, totalExpandedBytesRead = 80,
            languages = mapOf("PHP" to 1), findings = listOf(finding), rootCauseGroups = emptyList(),
            dependencies = DependencyInventory(emptyList(), emptyList(), emptyList()), isWordPress = false, isWooCommerce = false,
            websiteComponents = emptyList(), skippedEntries = emptyList(), limitations = emptyList()
        )
        val record = WebsiteSecuritySpecialistEngineV2.assess(project, 100_000L).evidenceRecords.single()
        assertFalse(record.sanitizedEvidence.contains("super_secret_value_123456"))
        assertEquals(0, record.requestCount)
        assertEquals("UTC", record.timezone)
        assertTrue(record.integritySha256.matches(Regex("[a-f0-9]{64}")))
        assertTrue(record.completeness.startsWith("PARTIAL") || record.completeness.startsWith("INCOMPLETE"))
    }


    @Test fun confirmedStatusWithoutReproducibleEvidenceIsNotPublishedAsFail() {
        val finding = Finding(
            id = "SG-WP-REST-PERM-L12", title = "WordPress REST permission callback review", severity = Severity.MEDIUM,
            description = "Confirmation label without evidence", remediation = "Review capability and ownership",
            cwe = "CWE-862", status = FindingStatus.CONFIRMED, affectedAsset = "plugin.php",
            exactLocation = "plugin.php:12", evidence = "", detectionMethod = "fixture-rule"
        )
        val project = ProjectAuditResult(
            archiveName = "wp-fixture.zip", filesDiscovered = 4, filesScanned = 2, totalExpandedBytesRead = 1000,
            languages = mapOf("PHP" to 2), findings = listOf(finding), rootCauseGroups = emptyList(),
            dependencies = DependencyInventory(emptyList(), emptyList(), emptyList()), isWordPress = true, isWooCommerce = false,
            websiteComponents = emptyList(), skippedEntries = emptyList(), limitations = emptyList(),
            domainCoverage = listOf(SpecialistDomainCoverage("WORDPRESS_WOOCOMMERCE", "ANALYZED", 2, 1, "static fixture"))
        )
        val assessment = WebsiteSecuritySpecialistEngineV2.assess(project, 100_000L)
        assertEquals(WebsiteCoverageStateV2.NEEDS_MANUAL_REVIEW, assessment.controls.single { it.definition.id == "WP-REST-AJAX" }.state)
        assertEquals(0, assessment.failCount)
    }

    @Test fun passiveHttpCoverageDoesNotClaimAuthOrBusinessLogicWasTested() {
        val scan = ScanResult("example.com", emptyList(), "passive complete", httpStatus = 200, scannedAt = 100_000L)
        val coverage = WebsiteSecuritySpecialistEngineV2.assessPassiveWebScan(scan)
        assertEquals(WebsiteCoverageStateV2.NEEDS_MANUAL_REVIEW, coverage.single { it.definition.id == "WEB-HEADERS-COOKIE" }.state)
        assertEquals(WebsiteCoverageStateV2.NOT_TESTED, coverage.single { it.definition.id == "WEB-AUTHZ-TENANT" }.state)
        assertTrue(coverage.none { it.state == WebsiteCoverageStateV2.PASS })
    }

    @Test fun playbookMapsFindingToTechnologySpecificRemediationRecipe() {
        val sql = Finding("F-SQL", "SQL query", Severity.HIGH, "dynamic query", "bind parameters", cwe = "CWE-89")
        val wp = Finding("SG-WP-REST-PERM-L8", "WordPress REST route", Severity.MEDIUM, "REST callback", "capability", cwe = "CWE-862")
        val wc = Finding("SG-WC-WEBHOOK", "WooCommerce webhook", Severity.MEDIUM, "payment callback", "verify signature", cwe = "CWE-345")
        assertEquals("WP-02", WebsiteRemediationPlaybookV1.resolve(sql).sectionId)
        assertEquals("WP-10", WebsiteRemediationPlaybookV1.resolve(wp).sectionId)
        assertEquals("WP-11", WebsiteRemediationPlaybookV1.resolve(wc).sectionId)
        assertEquals(14, WebsiteRemediationPlaybookV1.recipes.size)
    }

    @Test fun generatedRemediationPlanContainsRollbackStagingRegressionAndOwner() {
        val finding = Finding("F-XSS", "XSS indicator", Severity.MEDIUM, "untrusted output", "encode output", cwe = "CWE-79")
        val plan = RemediationPatchEngineV1.createPlan(finding)
        assertEquals("WP-03", plan.playbookSection)
        assertTrue(plan.immediateContainment.isNotBlank())
        assertTrue(plan.permanentFixPlan.contains("encoding"))
        assertTrue(plan.regressionTests.isNotEmpty())
        assertTrue(plan.stagingValidation.isNotBlank())
        assertTrue(plan.rollbackPlan.isNotBlank())
        assertTrue(plan.ownerRole.isNotBlank())
        assertTrue(plan.patchApplicability.contains("الگو"))
    }

    @Test fun patchPreviewRejectsWindowsDriveAndBackslashTraversalPaths() {
        assertNull(RemediationPatchEngineV1.previewPatch("C:\\temp\\wp-config.php", "a=1", "a=1", "a=0").preview)
        assertNull(RemediationPatchEngineV1.previewPatch("src\\..\\wp-config.php", "a=1", "a=1", "a=0").preview)
    }
}
