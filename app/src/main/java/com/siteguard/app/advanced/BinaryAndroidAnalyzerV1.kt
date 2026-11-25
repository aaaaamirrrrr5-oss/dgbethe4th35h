package com.siteguard.app.advanced

import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.zip.ZipInputStream

/** Read-only APK/AAB archive inspection with Android binary XML string-pool decoding. */
data class BinaryAndroidFindingV1(val id: String, val severity: String, val title: String, val evidence: String, val recommendation: String)
data class BinaryAndroidReportV1(
    val fileName: String, val packageName: String?, val minSdk: String?, val targetSdk: String?,
    val dexFiles: Int, val nativeLibraries: Int, val archiveEntries: Int, val sizeBytes: Long,
    val sha256: String, val permissions: List<String>, val components: List<String>,
    val signingMetadata: List<String>, val findings: List<BinaryAndroidFindingV1>, val limitations: List<String>
)

object BinaryAndroidAnalyzerV1 {
    private const val MAX_ARCHIVE_BYTES = 120L * 1024 * 1024
    private const val MAX_EXPANDED_BYTES = 240L * 1024 * 1024
    private const val MAX_ENTRIES = 20_000
    private const val MAX_MANIFEST_BYTES = 8 * 1024 * 1024
    private val sensitivePermissions = setOf(
        "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
        "android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CALL_LOG", "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.QUERY_ALL_PACKAGES"
    )

    fun analyze(fileName: String, bytes: ByteArray): BinaryAndroidReportV1 {
        require(bytes.size in 1..MAX_ARCHIVE_BYTES) { "APK/AAB archive must be between 1 byte and 120 MB" }
        val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        var manifest: ByteArray? = null; var dexFiles = 0; var nativeLibs = 0; var entryCount = 0
        var expanded = 0L; val signatures = mutableListOf<String>(); val interestingStrings = mutableSetOf<String>()
        ZipInputStream(ByteArrayInputStream(bytes)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entryCount++; require(entryCount <= MAX_ENTRIES) { "Archive contains too many entries" }
                val name = entry.name.replace('\\', '/')
                require(!name.startsWith('/') && !name.split('/').any { it == ".." } && !name.contains('\u0000')) { "Unsafe ZIP entry path" }
                var entryRead = 0
                val out = java.io.ByteArrayOutputStream()
                val buf = ByteArray(16 * 1024)
                while (true) {
                    val n = zip.read(buf); if (n < 0) break
                    entryRead += n; expanded += n
                    require(expanded <= MAX_EXPANDED_BYTES) { "Archive expanded size exceeds 240 MB" }
                    if (name == "AndroidManifest.xml" || name.endsWith("/AndroidManifest.xml")) {
                        require(entryRead <= MAX_MANIFEST_BYTES) { "AndroidManifest.xml exceeds size limit" }
                        out.write(buf, 0, n)
                    } else if (name.matches(Regex("classes(\\d*)\\.dex"))) {
                        // Search bounded DEX text literals for risk indicators without executing code.
                        require(entryRead <= 80 * 1024 * 1024) { "DEX file exceeds per-entry limit" }
                        out.write(buf, 0, n)
                    } else if (name.startsWith("META-INF/", true) && name.substringAfterLast('/').matches(Regex("(?i).+\\.(RSA|DSA|EC|SF|MF)"))) {
                        signatures += name.take(180)
                    }
                }
                if (name == "AndroidManifest.xml" || name.endsWith("/AndroidManifest.xml")) manifest = out.toByteArray()
                if (name.matches(Regex("classes(\\d*)\\.dex"))) {
                    dexFiles++
                    scanDexStrings(out.toByteArray(), interestingStrings)
                }
                if (name.startsWith("lib/") && name.endsWith(".so")) nativeLibs++
                zip.closeEntry()
            }
        }
        val manifestBytes = manifest ?: throw IllegalArgumentException("AndroidManifest.xml not found; selected file may not be an APK/AAB base module")
        val xml = runCatching { BinaryXmlReader.decode(manifestBytes) }.getOrElse {
            // APK manifest commonly uses binary AXML; fail clearly rather than silently report empty results.
            throw IllegalArgumentException("AndroidManifest.xml could not be decoded: ${it.message ?: "invalid AXML"}")
        }
        val packageName = xml.attribute("manifest", "package")
        val minSdk = xml.attribute("uses-sdk", "minSdkVersion")
        val targetSdk = xml.attribute("uses-sdk", "targetSdkVersion")
        val permissions = xml.elements.filter { it.name in setOf("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m") }
            .mapNotNull { it.attributes["name"] }.distinct().sorted()
        val components = xml.elements.filter { it.name in setOf("activity", "activity-alias", "service", "receiver", "provider") }
            .map { node -> "${node.name}:${node.attributes["name"].orEmpty()} exported=${node.attributes["exported"] ?: "implicit"}" }
            .take(300)
        val findings = mutableListOf<BinaryAndroidFindingV1>()
        sensitivePermissions.intersect(permissions.toSet()).forEach { permission ->
            findings += BinaryAndroidFindingV1("APK-PERM-${permission.substringAfterLast('.')}", "MEDIUM", "مجوز حساس درخواست شده است", permission,
                "نیاز واقعی مجوز، زمان درخواست و محافظت از داده مرتبط را بررسی کنید؛ وجود permission به‌تنهایی سوءاستفاده را ثابت نمی‌کند.")
        }
        if (xml.attribute("application", "debuggable").equals("true", true)) findings += BinaryAndroidFindingV1("APK-DEBUGGABLE", "HIGH", "برنامه با debuggable=true ساخته شده است", "application android:debuggable=true", "برای انتشار production مقدار debuggable را غیرفعال کنید.")
        if (xml.attribute("application", "allowBackup").equals("true", true)) findings += BinaryAndroidFindingV1("APK-ALLOW-BACKUP", "LOW", "پشتیبان‌گیری Android برای برنامه فعال است", "application android:allowBackup=true", "قابلیت backup و data extraction را با توجه به حساسیت داده بررسی کنید.")
        components.filter { it.endsWith("exported=true") }.forEach {
            findings += BinaryAndroidFindingV1("APK-EXPORTED-COMPONENT", "MEDIUM", "کامپوننت exported است و باید کنترل دسترسی آن بازبینی شود", it.take(180), "intent-filter، permission و اعتبارسنجی ورودی را بررسی کنید؛ exported بودن به‌تنهایی آسیب‌پذیری نیست.")
        }
        if (interestingStrings.any { it.startsWith("http://", true) }) findings += BinaryAndroidFindingV1("APK-CLEARTEXT-URL", "MEDIUM", "رشته HTTP cleartext در DEX مشاهده شد", "HTTP URL literal present; value omitted", "دامنه و کاربرد را بررسی و در صورت امکان HTTPS و cleartextTrafficPermitted=false استفاده کنید.")
        if (signatures.isEmpty()) findings += BinaryAndroidFindingV1("APK-SIGNATURE-METADATA", "INFO", "فایل امضای قدیمی META-INF در ZIP پیدا نشد", "No META-INF .RSA/.DSA/.EC entry", "امضای APK v2/v3/v4 را با apksigner verify در Android Build Tools بررسی کنید؛ این تحلیلگر امضا را cryptographically verify نمی‌کند.")
        return BinaryAndroidReportV1(
            fileName.take(200), packageName, minSdk, targetSdk, dexFiles, nativeLibs, entryCount, bytes.size.toLong(), hash,
            permissions, components, signatures, findings,
            listOf(
                "تحلیل باینری فقط فایل انتخاب‌شده را می‌خواند؛ APK اجرا یا نصب نمی‌شود.",
                "تأیید قطعی امضای APK v2/v3/v4 باید با apksigner و زنجیره گواهی جداگانه انجام شود.",
                "تحلیل DEX در این نسخه جست‌وجوی رشته و ساختار فایل است؛ decompilation، call graph، native code disassembly و runtime sandbox انجام نشده‌اند.",
                "برای AAB، ماژول انتخاب‌شده باید AndroidManifest.xml قابل‌خواندن داشته باشد؛ split/config moduleها به‌صورت یک bundle کامل بازسازی نمی‌شوند."
            )
        )
    }

    private fun scanDexStrings(bytes: ByteArray, output: MutableSet<String>) {
        val ascii = bytes.toString(Charsets.ISO_8859_1)
        Regex("https?://[^\\s\\u0000\"']{1,240}", RegexOption.IGNORE_CASE).findAll(ascii).take(100).forEach { output += it.value }
    }

    private data class Element(val name: String, val attributes: Map<String, String>)
    private data class DecodedManifest(val elements: List<Element>) {
        fun attribute(element: String, name: String) = elements.firstOrNull { it.name == element }?.attributes?.get(name)
    }

    private object BinaryXmlReader {
        private const val RES_XML = 0x0003
        private const val RES_STRING_POOL = 0x0001
        private const val RES_START_ELEMENT = 0x0102
        fun decode(bytes: ByteArray): DecodedManifest {
            require(bytes.size >= 8)
            val b = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            require(u16(b, 0) == RES_XML) { "Not Android binary XML" }
            val declaredSize = u32(b, 4).toInt(); require(declaredSize in 8..bytes.size)
            var offset = u16(b, 2)
            var strings = emptyList<String>()
            val elements = mutableListOf<Element>()
            while (offset + 8 <= declaredSize) {
                val type = u16(b, offset); val headerSize = u16(b, offset + 2); val size = u32(b, offset + 4).toInt()
                require(size >= 8 && offset + size <= declaredSize && headerSize >= 8) { "Invalid AXML chunk size" }
                when (type) {
                    RES_STRING_POOL -> strings = readStringPool(b, offset, size)
                    RES_START_ELEMENT -> {
                        require(headerSize >= 16 && size >= 36) { "Invalid start-element chunk" }
                        val nameIndex = u32(b, offset + 20).toInt()
                        val name = strings.getOrNull(nameIndex).orEmpty()
                        val attributeStart = u16(b, offset + 24)
                        val attributeSize = u16(b, offset + 26)
                        val attributeCount = u16(b, offset + 28)
                        require(attributeSize >= 20 && attributeCount <= 512) { "Invalid AXML attribute table" }
                        val attrsAt = offset + 16 + attributeStart
                        val attrs = linkedMapOf<String, String>()
                        repeat(attributeCount) { index ->
                            val at = attrsAt + index * attributeSize
                            require(at + 20 <= offset + size) { "AXML attribute out of bounds" }
                            val attrNameIndex = u32(b, at + 4).toInt()
                            val rawValueIndex = u32(b, at + 8).toInt()
                            val valueType = b.get(at + 15).toInt() and 0xff
                            val valueData = u32(b, at + 16).toInt()
                            val attrName = strings.getOrNull(attrNameIndex).orEmpty()
                            val value = if (rawValueIndex >= 0) strings.getOrNull(rawValueIndex) else null
                                ?: if (valueType == 3) strings.getOrNull(valueData) else when (valueType) {
                                    0x12 -> (valueData != 0).toString()
                                    0x10 -> valueData.toString()
                                    else -> if (valueData >= 0) valueData.toString() else ""
                                }
                            if (attrName.isNotBlank()) attrs[attrName] = value.orEmpty()
                        }
                        elements += Element(name, attrs)
                    }
                }
                offset += size
            }
            return DecodedManifest(elements)
        }

        private fun readStringPool(b: ByteBuffer, start: Int, size: Int): List<String> {
            val count = u32(b, start + 8).toInt(); val flags = u32(b, start + 16).toInt(); val stringsStart = u32(b, start + 20).toInt()
            require(count in 0..100_000 && stringsStart in 28..size)
            val utf8 = (flags and 0x100) != 0
            val result = ArrayList<String>(count)
            repeat(count) { index ->
                val relative = u32(b, start + 28 + index * 4).toInt()
                var p = start + stringsStart + relative
                require(p >= start && p < start + size)
                if (utf8) {
                    val first = len8(b, p); p = first.second
                    val second = len8(b, p); p = second.second
                    val byteLength = second.first
                    require(byteLength in 0..(start + size - p))
                    val data = ByteArray(byteLength); for (n in 0 until byteLength) data[n] = b.get(p + n)
                    result += data.toString(Charsets.UTF_8)
                } else {
                    val first = len16(b, p); p = first.second
                    val charLength = first.first
                    require(charLength in 0..(start + size - p) / 2)
                    val data = CharArray(charLength) { n -> b.getShort(p + n * 2).toInt().toChar() }
                    result += String(data)
                }
            }
            return result
        }

        private fun len8(b: ByteBuffer, offset: Int): Pair<Int, Int> {
            val first = b.get(offset).toInt() and 0xff
            return if (first and 0x80 == 0) first to (offset + 1) else (((first and 0x7f) shl 8) or (b.get(offset + 1).toInt() and 0xff)) to (offset + 2)
        }
        private fun len16(b: ByteBuffer, offset: Int): Pair<Int, Int> {
            val first = u16(b, offset)
            return if (first and 0x8000 == 0) first to (offset + 2) else (((first and 0x7fff) shl 16) or u16(b, offset + 2)) to (offset + 4)
        }
        private fun u16(b: ByteBuffer, p: Int) = b.getShort(p).toInt() and 0xffff
        private fun u32(b: ByteBuffer, p: Int) = b.getInt(p).toLong() and 0xffffffffL
    }
}
