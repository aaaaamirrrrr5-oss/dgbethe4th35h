package com.siteguard.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class WebsiteDiscoveryOptionsTest {
    @Test fun defaultDiscoveryDeadlineIsBounded() {
        assertEquals(60_000L, WebsiteDiscoveryOptionsV1().maxDurationMs)
        assertEquals(180_000L, WebsiteDiscoveryOptionsV1(maxDurationMs = 180_000L).maxDurationMs)
    }

    @Test fun rejectsDiscoveryDeadlinesOutsideSafeRange() {
        assertThrows(IllegalArgumentException::class.java) { WebsiteDiscoveryOptionsV1(maxDurationMs = 4_999L) }
        assertThrows(IllegalArgumentException::class.java) { WebsiteDiscoveryOptionsV1(maxDurationMs = 180_001L) }
    }
}
