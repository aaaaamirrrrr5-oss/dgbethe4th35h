package com.siteguard.app.advanced

/** Small bounded JSON reader for trusted/public feeds; rejects duplicate keys and malformed input. */
object MiniJsonV1 {
    fun parse(source: String, maxChars: Int = 2_000_000, maxDepth: Int = 32): Any? {
        require(source.length <= maxChars) { "JSON exceeds the $maxChars character limit" }
        val parser = Parser(source, maxDepth)
        val value = parser.value(0)
        parser.space()
        require(parser.atEnd()) { "Trailing data after JSON document" }
        return value
    }

    @Suppress("UNCHECKED_CAST")
    fun objectValue(value: Any?): Map<String, Any?> = value as? Map<String, Any?>
        ?: throw IllegalArgumentException("Expected JSON object")

    @Suppress("UNCHECKED_CAST")
    fun arrayValue(value: Any?): List<Any?> = value as? List<Any?>
        ?: throw IllegalArgumentException("Expected JSON array")

    private class Parser(private val s: String, private val maxDepth: Int) {
        private var i = 0
        fun atEnd() = i == s.length
        fun space() { while (i < s.length && s[i] in " \t\r\n") i++ }

        fun value(depth: Int): Any? {
            require(depth <= maxDepth) { "JSON nesting is too deep" }
            space(); require(i < s.length) { "Unexpected end of JSON" }
            return when (s[i]) {
                '{' -> obj(depth + 1)
                '[' -> array(depth + 1)
                '"' -> string()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                '-', in '0'..'9' -> number()
                else -> throw IllegalArgumentException("Unexpected JSON token at offset $i")
            }
        }

        private fun obj(depth: Int): Map<String, Any?> {
            i++; space(); val result = linkedMapOf<String, Any?>()
            if (take('}')) return result
            while (true) {
                space(); require(i < s.length && s[i] == '"') { "Object key must be a string" }
                val key = string(); require(!result.containsKey(key)) { "Duplicate JSON key: $key" }
                space(); require(take(':')) { "Expected ':' after object key" }
                result[key] = value(depth)
                space(); if (take('}')) return result
                require(take(',')) { "Expected ',' between object members" }
            }
        }

        private fun array(depth: Int): List<Any?> {
            i++; space(); val result = mutableListOf<Any?>()
            if (take(']')) return result
            while (true) {
                result += value(depth)
                space(); if (take(']')) return result
                require(take(',')) { "Expected ',' between array values" }
                require(result.size <= 100_000) { "JSON array is too large" }
            }
        }

        private fun string(): String {
            require(take('"'))
            val out = StringBuilder()
            while (i < s.length) {
                val c = s[i++]
                when (c) {
                    '"' -> return out.toString()
                    '\\' -> {
                        require(i < s.length) { "Incomplete JSON escape" }
                        when (val e = s[i++]) {
                            '"', '\\', '/' -> out.append(e)
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000c')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                require(i + 4 <= s.length) { "Incomplete unicode escape" }
                                val code = s.substring(i, i + 4).toIntOrNull(16)
                                    ?: throw IllegalArgumentException("Invalid unicode escape")
                                out.append(code.toChar()); i += 4
                            }
                            else -> throw IllegalArgumentException("Invalid JSON escape")
                        }
                    }
                    else -> {
                        require(c.code >= 0x20) { "Control character in JSON string" }
                        out.append(c)
                    }
                }
                require(out.length <= 1_000_000) { "JSON string is too long" }
            }
            throw IllegalArgumentException("Unterminated JSON string")
        }

        private fun number(): Number {
            val start = i
            if (take('-')) require(i < s.length)
            if (take('0')) {
                require(i >= s.length || s[i] !in '0'..'9') { "Leading zero in JSON number" }
            } else {
                require(i < s.length && s[i] in '1'..'9') { "Invalid JSON number" }
                while (i < s.length && s[i] in '0'..'9') i++
            }
            var decimal = false
            if (take('.')) {
                decimal = true
                require(i < s.length && s[i] in '0'..'9')
                while (i < s.length && s[i] in '0'..'9') i++
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                decimal = true; i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                require(i < s.length && s[i] in '0'..'9')
                while (i < s.length && s[i] in '0'..'9') i++
            }
            val raw = s.substring(start, i)
            return if (decimal) raw.toDoubleOrNull() ?: throw IllegalArgumentException("Invalid JSON number")
            else raw.toLongOrNull() ?: throw IllegalArgumentException("JSON integer overflow")
        }

        private fun <T> literal(token: String, result: T): T {
            require(s.regionMatches(i, token, 0, token.length)) { "Invalid JSON literal" }
            i += token.length; return result
        }

        private fun take(c: Char): Boolean {
            if (i < s.length && s[i] == c) { i++; return true }
            return false
        }
    }
}
