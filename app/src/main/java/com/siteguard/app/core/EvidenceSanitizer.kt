package com.siteguard.app.core

/** Redacts common credential formats before evidence enters reports, UI snippets or local history. */
object EvidenceSanitizer {
    private val quotedAssignment = Regex(
        """(?i)((?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token|private[_-]?key|refresh[_-]?token)\s*[:=]\s*)(["'])([^"'\r\n]{4,})(["'])"""
    )
    private val jsonQuotedAssignment = Regex(
        """(?i)(["'](?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token|private[_-]?key|refresh[_-]?token)["']\s*:\s*)(["'])([^"'\r\n]{4,})(["'])"""
    )
    private val unquotedAssignment = Regex(
        """(?i)((?:api[_-]?key|secret[_-]?key|client[_-]?secret|password|passwd|access[_-]?token|auth[_-]?token|private[_-]?key|refresh[_-]?token)\s*[:=]\s*)([-A-Za-z0-9_./+=]{8,})"""
    )
    private val authorizationHeader = Regex("""(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[-A-Za-z0-9_./+=]+""")
    private val pemPrivateKey = Regex("""(?is)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----""")
    private val githubToken = Regex("""\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b""")
    private val awsAccessKey = Regex("""\bAKIA[0-9A-Z]{16}\b""")
    private val jwt = Regex("""\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b""")
    private val credentialUrl = Regex("""(?i)(https?://[^:/@\s]+:)[^@/\s]+@""")

    fun sanitize(text: String): String {
        if (text.isEmpty()) return text
        var safe = pemPrivateKey.replace(text, "[PRIVATE KEY REDACTED]")
        safe = jsonQuotedAssignment.replace(safe) { match ->
            match.groupValues[1] + match.groupValues[2] + "[REDACTED]" + match.groupValues[4]
        }
        safe = quotedAssignment.replace(safe) { match ->
            match.groupValues[1] + match.groupValues[2] + "[REDACTED]" + match.groupValues[4]
        }
        safe = unquotedAssignment.replace(safe) { match -> match.groupValues[1] + "[REDACTED]" }
        safe = authorizationHeader.replace(safe) { match -> match.groupValues[1] + "[REDACTED]" }
        safe = credentialUrl.replace(safe) { match -> match.groupValues[1] + "[REDACTED]@" }
        safe = githubToken.replace(safe, "[TOKEN REDACTED]")
        safe = awsAccessKey.replace(safe, "[TOKEN REDACTED]")
        safe = jwt.replace(safe, "[JWT REDACTED]")
        return safe
    }
}
