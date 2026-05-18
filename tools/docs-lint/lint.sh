#!/bin/bash
#
# Documentation linter for Talos notes and plans
#
# Checks:
# 1. YAML frontmatter with required fields (date, reason)
# 2. File length warnings (>500 lines)
# 3. No placeholder text patterns
#
# Note: Emoji check removed - grep -P behavior differs between macOS and Linux,
# causing false positives. Status symbols (✅ ✓ ❌) are legitimate in docs.
#
# Usage: ./tools/docs-lint/lint.sh [directory]
# Default: docs/notes and docs/plans
#
# Exit codes:
# 0 - All checks passed
# 1 - Errors found (missing frontmatter, placeholders)
# 2 - Warnings only (file length)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Colors for output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Counters
errors=0
warnings=0

# Directories to lint
DIRS=("$ROOT_DIR/docs/notes" "$ROOT_DIR/docs/plans")

# Override with argument if provided
if [ $# -gt 0 ]; then
    DIRS=("$1")
fi

log_error() {
    echo -e "${RED}ERROR${NC}: $1" >&2
    errors=$((errors + 1))
}

log_warning() {
    echo -e "${YELLOW}WARNING${NC}: $1" >&2
    warnings=$((warnings + 1))
}

log_ok() {
    if [ "${VERBOSE:-}" = "1" ]; then
        echo -e "${GREEN}OK${NC}: $1"
    fi
}

# Check a single file
lint_file() {
    local file="$1"
    local relpath="${file#$ROOT_DIR/}"
    local has_error=0

    # Skip archive directory
    if [[ "$relpath" == *"/archive/"* ]]; then
        return 0
    fi

    # Check 1: YAML frontmatter
    if ! head -1 "$file" | grep -q "^---"; then
        log_error "$relpath: Missing YAML frontmatter"
        has_error=1
    else
        # Check for required fields
        local frontmatter
        frontmatter=$(sed -n '1,/^---$/p' "$file" | tail -n +2)

        if ! echo "$frontmatter" | grep -q "^date:"; then
            log_error "$relpath: Frontmatter missing 'date' field"
            has_error=1
        fi

        if ! echo "$frontmatter" | grep -q "^reason:"; then
            log_error "$relpath: Frontmatter missing 'reason' field"
            has_error=1
        fi
    fi

    # Check 2: File length
    local lines
    lines=$(wc -l < "$file" | tr -d ' ')
    if [ "$lines" -gt 1000 ]; then
        log_warning "$relpath: File has $lines lines (>1000, consider splitting)"
    elif [ "$lines" -gt 500 ]; then
        log_warning "$relpath: File has $lines lines (>500)"
    fi

    # Check 3: Placeholder text patterns (only unfinished content indicators)
    # Note: "placeholder" alone is allowed (used in SQL/code discussions)
    # Only flag phrases that indicate unfinished documentation
    if grep -qiE 'will be populated|to be added|this section will|content pending|TBD\s*$|TBD[^a-zA-Z]' "$file"; then
        log_error "$relpath: Contains placeholder text"
        has_error=1
    fi

    if [ $has_error -eq 0 ]; then
        log_ok "$relpath"
    fi
}

# Main
echo "Documentation linter"
echo "===================="
echo ""

total=0
for dir in "${DIRS[@]}"; do
    if [ ! -d "$dir" ]; then
        echo "Directory not found: $dir"
        continue
    fi

    while IFS= read -r file; do
        lint_file "$file"
        total=$((total + 1))
    done < <(find "$dir" -name "*.md" -type f)
done

echo ""
echo "===================="
echo "Checked: $total files"
echo "Errors:  $errors"
echo "Warnings: $warnings"

if [ $errors -gt 0 ]; then
    echo ""
    echo "Documentation lint failed with $errors errors"
    exit 1
elif [ $warnings -gt 0 ]; then
    echo ""
    echo "Documentation lint passed with $warnings warnings"
    exit 0
else
    echo ""
    echo "Documentation lint passed"
    exit 0
fi
