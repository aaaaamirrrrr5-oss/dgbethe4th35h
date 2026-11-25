package com.siteguard.app.core

import android.content.Context
import java.io.InputStream

/** Website domain facade. It composes shared scanners and adds the v2 specialist intake/report model. */
class WebsiteSecuritySpecialist(private val context: Context) {
    val specificationVersion: String = WebsiteSecuritySpecialistEngineV2.SPECIFICATION_VERSION
    private val webScanner = ScanOrchestrator(context)
    private val projectAnalyzer = ProjectArchiveAnalyzer()

    suspend fun assessAuthorizedWebsite(request: ScannerRequestV1): ScanResult {
        val auth = request.authorization
        val hostManifest = WebsiteEngagementManifestV2(
            projectId = auth.authorizationId,
            projectName = request.target,
            assetOwner = auth.ownerDeclaration,
            authorizer = auth.ownerDeclaration,
            proofMethod = WebsiteAuthorizationProofV2.USER_DECLARATION,
            proofReference = auth.ownerDeclaration,
            allowedHosts = auth.authorizedHosts,
            excludedHosts = auth.excludedHosts,
            authorizedIpRanges = emptySet(),
            allowedPathPrefixes = auth.allowedPathPrefixes,
            excludedPaths = auth.excludedPaths,
            authorizedPorts = auth.allowedPorts,
            allowedTestClasses = setOf(WebsiteTestClassV2.PASSIVE_REVIEW),
            environment = "legacy-ui-declared-scope",
            validFromEpochMs = auth.validFromEpochMs,
            validUntilEpochMs = auth.validUntilEpochMs,
            maxRequests = auth.maxRequests,
            requestsPerMinute = auth.requestsPerMinute,
            maxConcurrency = 1,
            emergencyContact = "Not supplied by legacy UI; user must remain available to stop the scan",
            emergencyStopProcedure = auth.emergencyStopDescription
        )
        val scope = hostManifest.authorizeUrl(request.target, WebsiteTestClassV2.PASSIVE_REVIEW)
        if (!scope.allowed) {
            return ScanResult("", emptyList(), "Website Specialist Scope Gate: ${scope.reason}", authorizationId = auth.authorizationId)
        }
        return webScanner.scan(request)
    }

    fun assessWebsiteSourceArchive(input: InputStream, archiveName: String): ProjectAuditResult {
        val capability = DeviceCapabilityDetector.inspect(context)
        require(capability.canRunProjectAudit) {
            "تحلیل ZIP به RAM آزاد حداقل ۱۹۲ مگابایت، فضای آزاد ۸۰ مگابایت و وضعیت حرارتی مناسب نیاز دارد. RAM آزاد فعلی: ${capability.availableMemoryMb}MB؛ فضای آزاد فعلی: ${capability.availableStorageMb}MB."
        }
        return projectAnalyzer.analyze(input, archiveName)
    }

    fun assessWebsiteSpecialist(project: ProjectAuditResult): WebsiteSpecialistAssessmentV2 =
        WebsiteSecuritySpecialistEngineV2.assess(project)

    fun assessSingleSource(fileName: String, source: String): CodeAuditResult =
        SourceCodeAnalyzer().analyze(fileName, source)
}
