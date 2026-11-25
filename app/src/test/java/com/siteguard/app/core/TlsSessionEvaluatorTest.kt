package com.siteguard.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsSessionEvaluatorTest {
    private val now = 1_800_000_000_000L
    private val day = 86_400_000L
    private fun info(
        protocol: String = "TLSv1.3",
        cipher: String = "TLS_AES_128_GCM_SHA256",
        keyAlg: String = "EC", bits: Int = 256, sig: String = "SHA256withECDSA",
        daysLeft: Long = 90
    ) = TlsSessionInfoV1(
        protocol, cipher, "CN=example.com", "CN=Example CA,O=Example", now - 30 * day, now + daysLeft * day,
        sig, keyAlg, bits, sanDnsCount = 2, chainLength = 3
    )
    private fun ids(i: TlsSessionInfoV1) = TlsSessionEvaluatorV1.evaluate("example.com", i, now).map { it.id }

    @Test fun healthyModernSessionOnlyProducesObservation() {
        assertEquals(listOf("SG-TLS-OBSERVED"), ids(info()))
    }

    @Test fun legacyProtocolIsFlagged() {
        assertTrue("SG-TLS-LEGACY-PROTOCOL" in ids(info(protocol = "TLSv1")))
        assertTrue("SG-TLS-LEGACY-PROTOCOL" in ids(info(protocol = "TLSv1.1")))
        assertFalse("SG-TLS-LEGACY-PROTOCOL" in ids(info(protocol = "TLSv1.2")))
    }

    @Test fun weakCipherMarkersAreFlaggedButGcmIsNot() {
        assertTrue("SG-TLS-WEAK-CIPHER" in ids(info(cipher = "TLS_RSA_WITH_3DES_EDE_CBC_SHA")))
        assertTrue("SG-TLS-WEAK-CIPHER" in ids(info(cipher = "TLS_RSA_WITH_RC4_128_SHA")))
        assertFalse("SG-TLS-WEAK-CIPHER" in ids(info(cipher = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")))
    }

    @Test fun shortKeysAndWeakSignaturesAreFlagged() {
        assertTrue("SG-TLS-WEAK-KEY" in ids(info(keyAlg = "RSA", bits = 1024)))
        assertFalse("SG-TLS-WEAK-KEY" in ids(info(keyAlg = "RSA", bits = 2048)))
        assertFalse("SG-TLS-WEAK-KEY" in ids(info(keyAlg = "EC", bits = 256)))
        assertFalse("SG-TLS-WEAK-KEY" in ids(info(keyAlg = "RSA", bits = 0))) // unknown size is not claimed weak
        assertTrue("SG-TLS-WEAK-SIGNATURE" in ids(info(sig = "SHA1withRSA")))
        assertTrue("SG-TLS-WEAK-SIGNATURE" in ids(info(sig = "MD5withRSA")))
        assertFalse("SG-TLS-WEAK-SIGNATURE" in ids(info(sig = "SHA256withRSA")))
    }

    @Test fun expiryWindowSeverityAndBoundaries() {
        val soon = TlsSessionEvaluatorV1.evaluate("example.com", info(daysLeft = 10), now).first { it.id == "SG-TLS-CERT-EXPIRING" }
        val later = TlsSessionEvaluatorV1.evaluate("example.com", info(daysLeft = 25), now).first { it.id == "SG-TLS-CERT-EXPIRING" }
        assertEquals(Severity.MEDIUM, soon.severity)
        assertEquals(Severity.LOW, later.severity)
        assertFalse("SG-TLS-CERT-EXPIRING" in ids(info(daysLeft = 45)))
        assertFalse("SG-TLS-CERT-EXPIRING" in ids(info(daysLeft = -3))) // already expired is a validation failure, reported elsewhere
    }

    @Test fun nothingIsEverReportedAsConfirmed() {
        val all = TlsSessionEvaluatorV1.evaluate("example.com", info(protocol = "TLSv1", cipher = "TLS_RSA_WITH_RC4_128_SHA", keyAlg = "RSA", bits = 1024, sig = "SHA1withRSA", daysLeft = 5), now)
        assertTrue(all.size >= 5)
        assertTrue(all.none { it.status == FindingStatus.CONFIRMED })
        assertTrue(all.all { it.notTested.isNotBlank() && it.affectedAsset == "example.com:443" })
    }
}
