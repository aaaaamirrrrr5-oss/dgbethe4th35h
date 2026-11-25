#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$ROOT/app/src/main"
PATTERN='api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.gemini\.google\.com'
if grep -R -n -E -i "$PATTERN" "$SOURCE"; then
  echo "Hosted AI inference endpoint reference found in application source." >&2
  exit 1
fi
echo "PASS: no configured hosted AI inference endpoint found in app/src/main."
