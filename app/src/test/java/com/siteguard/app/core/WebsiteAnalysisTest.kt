package com.siteguard.app.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class WebsiteAnalysisTest {
    @Test fun detectsWordPressReviewSignalsAndComponents() {
        val files = mapOf(
            "wp-content/plugins/demo/demo.php" to """<?php
/*
Plugin Name: Demo Plugin
Version: 1.2.3
*/
register_rest_route('demo/v1', '/items', ['methods' => 'POST']);
""".trimIndent(),
            "wp-config.php" to "<?php define('WP_DEBUG', true);"
        )
        assertTrue(WordPressSecurityAnalyzer.looksLikeWordPress(files))
        val inventory = WordPressSecurityAnalyzer.inventory(files)
        assertTrue(inventory.any { it.type == "plugin" && it.name == "Demo Plugin" && it.version == "1.2.3" })
        val findings = WordPressSecurityAnalyzer.analyze("wp-content/plugins/demo/demo.php", files.values.first(), false)
        assertTrue(findings.any { it.id.startsWith("SG-WP-REST-PERM") })
    }

    @Test fun inventoriesDeclaredNpmAndComposerDependencies() {
        val result = DependencyInventoryAnalyzer.analyze(mapOf(
            "package.json" to """{"dependencies":{"express":"^4.18.0"}}""",
            "composer.json" to """{"require":{"vendor/package":"1.2.3"}}"""
        ))
        assertEquals(2, result.records.size)
        assertTrue(result.records.any { it.ecosystem == "npm" && it.name == "express" && !it.versionPinned })
        assertTrue(result.records.any { it.ecosystem == "composer" && it.name == "vendor/package" && it.versionPinned })
    }
}
