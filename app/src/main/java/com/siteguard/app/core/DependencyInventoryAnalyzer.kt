package com.siteguard.app.core

/** Offline inventory only. It does not claim to know whether a version is vulnerable. */
data class DependencyRecord(
    val ecosystem: String,
    val name: String,
    val declaredVersion: String,
    val manifestPath: String,
    val direct: Boolean = true,
    val versionPinned: Boolean = false
)

data class DependencyInventory(
    val records: List<DependencyRecord>,
    val manifestFiles: List<String>,
    val limitations: List<String>
)

object DependencyInventoryAnalyzer {
    private val versionPattern = Regex("(?i)(\\^|~|>=|<=|>|<|=|\\*)")
    private val packageLine = Regex("^\\s*[\"']?([A-Za-z0-9_.@/-]+)[\"']?\\s*[:= ]\\s*[\"']?([^\"',\\s}]+)")

    fun analyze(files: Map<String, String>): DependencyInventory {
        val records = mutableListOf<DependencyRecord>()
        val manifests = mutableListOf<String>()
        files.forEach { (path, content) ->
            val name = path.substringAfterLast('/').lowercase()
            when (name) {
                "package.json" -> {
                    manifests += path
                    val sections = listOf("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
                    sections.forEach { section ->
                        val sectionStart = Regex("\"$section\"\\s*:").find(content)?.range?.last ?: -1
                        if (sectionStart >= 0) {
                            val block = content.substring(sectionStart + 1).substringBefore('}')
                            val entries = Regex("""[\"']([^\"']+)[\"']\s*:\s*[\"']([^\"']+)[\"']""")
                            entries.findAll(block).forEach { match ->
                                val depName = match.groupValues[1]
                                val version = match.groupValues[2]
                                records += DependencyRecord("npm", depName, version, path, section != "devDependencies", isPinned(version))
                            }
                        }
                    }
                }
                "composer.json" -> {
                    manifests += path
                    listOf("require", "require-dev").forEach { section ->
                        val start = Regex("\"$section\"\\s*:").find(content)?.range?.last ?: -1
                        if (start >= 0) {
                            val block = content.substring(start + 1).substringBefore('}')
                            val entries = Regex("""[\"']([^\"']+)[\"']\s*:\s*[\"']([^\"']+)[\"']""")
                            entries.findAll(block).forEach { match ->
                                val depName = match.groupValues[1]
                                val version = match.groupValues[2]
                                if (depName.contains('/') && !depName.startsWith("ext-")) {
                                    records += DependencyRecord("composer", depName, version, path, section == "require", isPinned(version))
                                }
                            }
                        }
                    }
                }
                "requirements.txt" -> {
                    manifests += path
                    content.lineSequence().map(String::trim).filter { it.isNotBlank() && !it.startsWith('#') }.forEach lineLoop@{ line ->
                        val m = Regex("^([A-Za-z0-9_.-]+)\\s*(==|~=|>=|<=|>|<)?\\s*([^;#\\s]*)").find(line) ?: return@lineLoop
                        val op = m.groupValues[2]
                        val version = if (op.isBlank()) "UNPINNED" else op + m.groupValues[3]
                        records += DependencyRecord("pypi", m.groupValues[1], version, path, true, op == "==")
                    }
                }
                "pyproject.toml" -> {
                    manifests += path
                    content.lineSequence().forEach lineLoop@{ line ->
                        if (line.trimStart().startsWith("#") || !line.contains('=')) return@lineLoop
                        val m = Regex("^\\s*[\"']?([A-Za-z0-9_.-]+)[\"']?\\s*=\\s*[\"']([^\"']+)[\"']").find(line) ?: return@lineLoop
                        val nameValue = m.groupValues[1]
                        if (nameValue !in setOf("name", "version", "description", "requires-python", "build-backend")) {
                            records += DependencyRecord("pypi", nameValue, m.groupValues[2], path, true, isPinned(m.groupValues[2]))
                        }
                    }
                }
                "pom.xml" -> {
                    manifests += path
                    val blocks = Regex("<dependency>([\\s\\S]*?)</dependency>").findAll(content)
                    blocks.forEach { block ->
                        val group = Regex("<groupId>\\s*([^<]+)\\s*</groupId>").find(block.value)?.groupValues?.get(1)?.trim()
                        val artifact = Regex("<artifactId>\\s*([^<]+)\\s*</artifactId>").find(block.value)?.groupValues?.get(1)?.trim()
                        val version = Regex("<version>\\s*([^<]+)\\s*</version>").find(block.value)?.groupValues?.get(1)?.trim() ?: "MANAGED/UNSPECIFIED"
                        if (!group.isNullOrBlank() && !artifact.isNullOrBlank()) records += DependencyRecord("maven", "$group:$artifact", version, path, true, isPinned(version))
                    }
                }
            }
        }
        val unique = records.distinctBy { "${it.ecosystem}:${it.name}:${it.declaredVersion}:${it.manifestPath}" }
        return DependencyInventory(
            records = unique,
            manifestFiles = manifests.distinct(),
            limitations = listOf(
                "نسخه‌ها فقط از manifest استخراج شده‌اند؛ lockfile و نسخه واقعی resolve شده ممکن است متفاوت باشند.",
                "در این نسخه feed آسیب‌پذیری زنده یا تطبیق CVE/OSV انجام نمی‌شود.",
                "وابستگی‌های transitive و dependency confusion به‌طور کامل تحلیل نمی‌شوند."
            )
        )
    }

    private fun isPinned(version: String): Boolean = version.isNotBlank() &&
        !version.equals("UNPINNED", true) && !versionPattern.containsMatchIn(version) &&
        version !in setOf("*", "latest", "MANAGED/UNSPECIFIED")
}
