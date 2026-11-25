package com.siteguard.app.core

import kotlinx.coroutines.runBlocking
import org.junit.Assert.*
import org.junit.Test
import java.net.ConnectException
import java.net.ServerSocket
import java.net.SocketTimeoutException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import kotlin.concurrent.thread

class TlsFailureClassifierTest {
    private fun validatorFailure(reason: CertPathValidatorException.Reason, message: String = "validation failed") =
        CertPathValidatorException(message, null, null, -1, reason)

    @Test fun expiredCertificateIsDetectedFromValidatorReason() {
        val error = SSLHandshakeException("PKIX path validation failed").apply {
            initCause(validatorFailure(CertPathValidatorException.BasicReason.EXPIRED))
        }
        assertEquals(TlsFailureKind.CERTIFICATE_EXPIRED, TlsFailureClassifier.classify(error)?.kind)
    }

    @Test fun expiredCertificateIsDetectedFromExceptionType() {
        val error = SSLHandshakeException("handshake aborted").apply { initCause(CertificateExpiredException("NotAfter: Mon Jan 01 00:00:00 UTC 2024")) }
        assertEquals(TlsFailureKind.CERTIFICATE_EXPIRED, TlsFailureClassifier.classify(error)?.kind)
    }

    @Test fun notYetValidCertificateIsDetected() {
        val error = SSLHandshakeException("handshake aborted").apply { initCause(CertificateNotYetValidException("NotBefore: Fri Jan 01 00:00:00 UTC 2100")) }
        assertEquals(TlsFailureKind.CERTIFICATE_NOT_YET_VALID, TlsFailureClassifier.classify(error)?.kind)
    }

    @Test fun revokedAndWeakAlgorithmReasonsAreDetected() {
        val revoked = SSLHandshakeException("x").apply { initCause(validatorFailure(CertPathValidatorException.BasicReason.REVOKED)) }
        val weak = SSLHandshakeException("x").apply { initCause(validatorFailure(CertPathValidatorException.BasicReason.ALGORITHM_CONSTRAINED)) }
        assertEquals(TlsFailureKind.CERTIFICATE_REVOKED, TlsFailureClassifier.classify(revoked)?.kind)
        assertEquals(TlsFailureKind.WEAK_ALGORITHM, TlsFailureClassifier.classify(weak)?.kind)
    }

    @Test fun hostnameMismatchIsDetected() {
        assertEquals(TlsFailureKind.HOSTNAME_MISMATCH, TlsFailureClassifier.classify(SSLPeerUnverifiedException("Hostname example.test not verified"))?.kind)
        val wrapped = SSLHandshakeException("handshake").apply { initCause(java.security.cert.CertificateException("No subject alternative DNS name matching example.test found.")) }
        assertEquals(TlsFailureKind.HOSTNAME_MISMATCH, TlsFailureClassifier.classify(wrapped)?.kind)
    }

    @Test fun untrustedChainIsDetected() {
        val error = SSLHandshakeException("handshake").apply {
            initCause(validatorFailure(CertPathValidatorException.BasicReason.UNSPECIFIED, "Trust anchor for certification path not found."))
        }
        assertEquals(TlsFailureKind.UNTRUSTED_CHAIN, TlsFailureClassifier.classify(error)?.kind)
    }

    @Test fun nonTlsEndpointAndRejectedHandshakeAreDistinguished() {
        assertEquals(TlsFailureKind.NON_TLS_ENDPOINT, TlsFailureClassifier.classify(SSLException("Unsupported or unrecognized SSL message"))?.kind)
        assertEquals(TlsFailureKind.NON_TLS_ENDPOINT, TlsFailureClassifier.classify(SSLException("error:100000f7:SSL routines:OPENSSL_internal:WRONG_VERSION_NUMBER"))?.kind)
        assertEquals(TlsFailureKind.HANDSHAKE_REJECTED, TlsFailureClassifier.classify(SSLHandshakeException("Received fatal alert: handshake_failure"))?.kind)
        assertEquals(TlsFailureKind.HANDSHAKE_REJECTED, TlsFailureClassifier.classify(SSLException("some unknown TLS layer problem"))?.kind)
    }

    @Test fun ordinaryNetworkProblemsAreNotReportedAsTlsFindings() {
        assertNull(TlsFailureClassifier.classify(SocketTimeoutException("Read timed out")))
        assertNull(TlsFailureClassifier.classify(ConnectException("Connection refused")))
        assertNull(TlsFailureClassifier.classify(SSLHandshakeException("Connection closed by peer")))
        assertNull(TlsFailureClassifier.classify(SSLException("wrapper").apply { initCause(SocketTimeoutException("Read timed out")) }))
        assertNull(TlsFailureClassifier.classify(SSLHandshakeException("Remote host terminated the handshake").apply { initCause(java.io.EOFException("SSL peer shut down incorrectly")) }))
        assertNull(TlsFailureClassifier.classify(IllegalStateException("not tls")))
    }

    @Test fun cyclicCauseChainDoesNotHang() {
        val a = SSLException("a")
        val b = SSLException("b", a)
        a.initCause(b)
        assertNotNull(TlsFailureClassifier.classify(a))
    }

    @Test fun findingIsHonestAboutClientSideObservationAndSanitizesEvidence() {
        val error = SSLHandshakeException("password=hunter2hunter2 handshake failed").apply {
            initCause(validatorFailure(CertPathValidatorException.BasicReason.EXPIRED))
        }
        val failure = TlsFailureClassifier.classify(error)!!
        val finding = TlsFailureClassifier.toFinding("example.test", 443, failure)
        assertEquals("SG-TLS-VALIDATION-EXPIRED", finding.id)
        assertEquals(Severity.HIGH, finding.severity)
        assertEquals(FindingStatus.PROBABLE, finding.status)
        assertEquals("example.test:443", finding.affectedAsset)
        assertFalse(finding.evidence.contains("hunter2hunter2"))
        assertTrue(finding.evidence.contains("example.test:443"))
        assertTrue(finding.description.contains("دستگاه"))
        assertTrue(finding.notTested.isNotBlank())
        assertEquals(FindingStatus.UNVERIFIED, TlsFailureClassifier.toFinding("h", 443, TlsFailure(TlsFailureKind.HANDSHAKE_REJECTED, "SSLException", "x")).status)
    }

    @Test fun scanEngineReportsNonTlsEndpointInsteadOfAnonymousFailure() {
        val server = ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val acceptor = thread(isDaemon = true) {
            runCatching {
                server.accept().use { socket ->
                    socket.getOutputStream().apply { write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n".toByteArray()); flush() }
                    Thread.sleep(300)
                }
            }
        }
        try {
            val url = "https://127.0.0.1:${server.localPort}/"
            val manifest = AuthorizationManifest.forSingleTarget(url, allowPrivateNetwork = true)!!
            val result = runBlocking { ScanEngine().scan(url, allowPrivateNetwork = true, authorization = manifest) }
            assertTrue(result.findings.any { it.id == "SG-TLS-VALIDATION-NON-TLS-ENDPOINT" })
            assertNull(result.httpStatus)
            assertEquals("127.0.0.1", result.connectedAddress)
        } finally {
            server.close(); acceptor.join(2_000)
        }
    }

    @Test fun scanEngineDoesNotInventTlsFindingWhenPeerJustClosesConnection() {
        val server = ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"))
        val acceptor = thread(isDaemon = true) { runCatching { server.accept().close() } }
        try {
            val url = "https://127.0.0.1:${server.localPort}/"
            val manifest = AuthorizationManifest.forSingleTarget(url, allowPrivateNetwork = true)!!
            val result = runBlocking { ScanEngine().scan(url, allowPrivateNetwork = true, authorization = manifest) }
            assertTrue(result.findings.isEmpty())
            assertTrue(result.message.contains("ناموفق"))
        } finally {
            server.close(); acceptor.join(2_000)
        }
    }

    @Test fun passiveCoverageKeepsTlsFailureVisibleInsteadOfNotTested() {
        val failure = TlsFailureClassifier.classify(SSLHandshakeException("x").apply { initCause(CertificateExpiredException("NotAfter")) })!!
        val finding = TlsFailureClassifier.toFinding("example.test", 443, failure)
        val withFailure = WebsiteSecuritySpecialistEngineV2.assessPassiveWebScan(ScanResult("example.test", listOf(finding), "tls failed"))
        val tls = withFailure.first { it.definition.id == "WEB-TLS-EDGE" }
        assertEquals(WebsiteCoverageStateV2.NEEDS_MANUAL_REVIEW, tls.state)
        assertTrue(tls.findingIds.contains("SG-TLS-VALIDATION-EXPIRED"))
        assertEquals(WebsiteCoverageStateV2.NOT_TESTED, withFailure.first { it.definition.id == "WEB-HEADERS-COOKIE" }.state)

        val noResponse = WebsiteSecuritySpecialistEngineV2.assessPassiveWebScan(ScanResult("example.test", emptyList(), "failed"))
        assertEquals(WebsiteCoverageStateV2.NOT_TESTED, noResponse.first { it.definition.id == "WEB-TLS-EDGE" }.state)
    }
}
