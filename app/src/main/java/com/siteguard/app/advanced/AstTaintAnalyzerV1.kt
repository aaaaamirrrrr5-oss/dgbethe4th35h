package com.siteguard.app.advanced

/** Lexical syntax tree approximation with statement, scope and token nodes (not a compiler-grade AST). */
data class AstTokenV1(val value: String, val kind: String, val line: Int)
data class AstStatementV1(val index: Int, val lineStart: Int, val lineEnd: Int, val tokens: List<AstTokenV1>, val scopeId: Int)
data class TaintFlowV1(
    val sourceVariable: String,
    val sourceLine: Int,
    val sink: String,
    val sinkLine: Int,
    val severity: String,
    val cwe: String,
    val evidence: String,
    val confidence: Int
)
data class AstTaintReportV1(
    val language: String,
    val tokenCount: Int,
    val statementCount: Int,
    val scopeCount: Int,
    val flows: List<TaintFlowV1>,
    val limitations: List<String>
)

object CodeAstTaintAnalyzerV1 {
    private val sourcePatterns = listOf(
        Regex("(?i)\\\$_(GET|POST|REQUEST|COOKIE|FILES)"),
        Regex("(?i)req\\s*\\.\\s*(query|body|params|cookies)"),
        Regex("(?i)request\\s*\\.\\s*(args|form|values|query|data|cookies)"),
        Regex("(?i)request\\s*\\.\\s*getParameter\\s*\\("),
        Regex("(?i)\\b(input|raw_input)\\s*\\(")
    )
    private val sanitizerPatterns = listOf(
        Regex("(?i)\\b(htmlspecialchars|esc_html|esc_attr|textContent|intval|absint|filter_var|parameterized|prepare)\\s*\\("),
        Regex("(?i)\\b(parseInt|Number|encodeURIComponent)\\s*\\(")
    )
    private val sinkPatterns = listOf(
        SinkRule("echo|print|innerHTML|document\\.write", "XSS/output", "CWE-79", "MEDIUM"),
        SinkRule("eval|Function|exec|shell_exec|system|passthru|ProcessBuilder|subprocess", "dynamic-execution/command", "CWE-78", "HIGH"),
        SinkRule("query|execute|rawQuery|mysqli_query|mysql_query", "database-query", "CWE-89", "HIGH"),
        SinkRule("include|require|readFile|sendFile", "path/file-operation", "CWE-22", "MEDIUM")
    )

    fun analyze(fileName: String, source: String): AstTaintReportV1 {
        require(source.length <= 2_000_000) { "Source exceeds 2 MB limit" }
        val language = when (fileName.substringAfterLast('.', "").lowercase()) {
            "php", "phtml" -> "PHP"; "js", "jsx", "ts", "tsx", "mjs" -> "JavaScript/TypeScript"
            "py" -> "Python"; "java", "kt", "kts" -> "JVM"; "cs" -> ".NET"; "go" -> "Go"
            else -> "Generic"
        }
        val tokens = lex(source)
        val statements = buildStatements(tokens)
        val tainted = linkedMapOf<String, Pair<Int, Int>>() // variable -> (source line, scope)
        val flows = mutableListOf<TaintFlowV1>()
        for (statement in statements) {
            val values = statement.tokens.map { it.value }
            val joined = values.joinToString(" ")
            val line = statement.lineStart
            val hasSource = sourcePatterns.any { it.containsMatchIn(joined) }
            val assignment = Regex("(?:\\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_$][A-Za-z0-9_$]*)\\s*=").find(joined)
                ?.value?.substringBefore('=')?.trim()
            val variables = Regex("(?:\\$[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_$][A-Za-z0-9_$]*)")
                .findAll(joined).map { it.value }.toSet()
            if (assignment != null) {
                val rhs = joined.substringAfter('=')
                val sourceLine = statement.tokens.firstOrNull { token -> sourcePatterns.any { it.containsMatchIn(token.value) } }?.line ?: line
                val sourceVar = variables.firstOrNull { it != assignment && it in tainted && tainted[it]?.second == statement.scopeId }
                if ((hasSource || sourceVar != null) && sanitizerPatterns.none { it.containsMatchIn(rhs) }) {
                    tainted[assignment] = (if (hasSource) sourceLine else tainted[sourceVar]?.first ?: line) to statement.scopeId
                } else if (sanitizerPatterns.any { it.containsMatchIn(rhs) }) {
                    tainted.remove(assignment)
                }
            }
            val used = variables.filter { it in tainted && tainted[it]?.second == statement.scopeId }
            val containsSink = sinkPatterns.firstOrNull { rule -> Regex("(?i)\\b(${rule.pattern})\\b").containsMatchIn(joined) }
            if (containsSink != null && (hasSource || used.isNotEmpty())) {
                val sourceVar = used.firstOrNull()
                val sourceLine = sourceVar?.let { tainted[it]?.first } ?: line
                val rule = containsSink
                val sanitized = sanitizerPatterns.any { it.containsMatchIn(joined) }
                if (!sanitized) flows += TaintFlowV1(
                    sourceVariable = sourceVar ?: "unassigned request/input source",
                    sourceLine = sourceLine,
                    sink = rule.name,
                    sinkLine = line,
                    severity = rule.severity,
                    cwe = rule.cwe,
                    evidence = joined.take(220),
                    confidence = if (sourceVar != null && sourceLine != line) 78 else if (hasSource) 64 else 45
                )
            }
        }
        return AstTaintReportV1(language, tokens.size, statements.size, statements.map { it.scopeId }.distinct().size,
            flows.distinctBy { listOf(it.sourceVariable, it.sourceLine, it.sink, it.sinkLine).joinToString(":") }.take(200),
            listOf(
                "ساختار تولیدی، lexical/statement AST تقریبی است و جایگزین parser رسمی زبان، type resolution یا control-flow graph نیست.",
                "Taint tracking محدود به انتساب‌های قابل مشاهده در scope ساده است؛ alias، callback، interprocedural flow و reflection کامل پوشش داده نمی‌شوند.",
                "sanitizerهای شناخته‌شده فقط heuristic هستند؛ ترتیب context و صحت استفاده باید دستی بررسی شود.",
                "کد اجرا نمی‌شود و نتیجه نشانهٔ نیازمند بازبینی است، نه اثبات exploitability."
            ))
    }

    private data class SinkRule(val pattern: String, val name: String, val cwe: String, val severity: String)

    private fun lex(source: String): List<AstTokenV1> {
        val out = mutableListOf<AstTokenV1>(); var i = 0; var line = 1
        while (i < source.length) {
            val c = source[i]
            if (c == '\n') { line++; i++; continue }
            if (c.isWhitespace()) { i++; continue }
            if (source.startsWith("//", i) || source.startsWith("#", i)) {
                while (i < source.length && source[i] != '\n') i++
                continue
            }
            if (source.startsWith("/*", i)) {
                i += 2
                while (i < source.length && !source.startsWith("*/", i)) { if (source[i] == '\n') line++; i++ }
                if (i < source.length) i += 2
                continue
            }
            if (c == '\'' || c == '"' || c == '`') {
                val quote = c; val startLine = line; val start = i++
                while (i < source.length) {
                    if (source[i] == '\n') line++
                    if (source[i] == '\\') { i = (i + 2).coerceAtMost(source.length); continue }
                    if (source[i++] == quote) break
                }
                out += AstTokenV1(source.substring(start, i).take(512), "STRING", startLine); continue
            }
            if (c.isLetterOrDigit() || c == '_' || c == '$') {
                val start = i++
                while (i < source.length && (source[i].isLetterOrDigit() || source[i] == '_' || source[i] == '$')) i++
                out += AstTokenV1(source.substring(start, i), if (c.isDigit()) "NUMBER" else "IDENT", line); continue
            }
            out += AstTokenV1(c.toString(), "SYMBOL", line); i++
        }
        return out
    }

    private fun buildStatements(tokens: List<AstTokenV1>): List<AstStatementV1> {
        val output = mutableListOf<AstStatementV1>(); var bucket = mutableListOf<AstTokenV1>(); var scope = 0; var nextScope = 1
        fun flush() {
            if (bucket.isNotEmpty()) {
                output += AstStatementV1(output.size, bucket.first().line, bucket.last().line, bucket.toList(), scope)
                bucket = mutableListOf()
            }
        }
        tokens.forEach { token ->
            if (token.value == "}") { flush(); scope = (scope - 1).coerceAtLeast(0) }
            bucket += token
            if (token.value == "{") { flush(); scope = nextScope++ }
            else if (token.value == ";") flush()
        }
        flush()
        return output
    }
}
