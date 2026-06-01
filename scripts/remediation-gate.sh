#!/usr/bin/env bash
# remediation-gate.sh — run from repo root before every commit.
# Fails (exit 1) if any forbidden pattern is found in the codebase.
set -e
FAIL=0

echo "=== B-class: untagged active_case primary reads ==="
# Exclusions:
#   test_ / # Legacy CLI fallback / # legacy  — explicitly tagged or test code
#   active_case_file / active_case_dir        — already-correct variable names
#   _ACTIVE_CASE_FILE                         — module-level constant
#   _get_active_case / _require_active_case   — function/method names (not reads)
if grep -rn "active_case\b" packages/ --include="*.py" \
   | grep -v "test_\|# Legacy CLI fallback\|# legacy\|active_case_file\|active_case_dir\|_ACTIVE_CASE_FILE\|_get_active_case\|_require_active_case"; then
    echo "FAIL: untagged active_case reads found"
    FAIL=1
fi

echo
echo "=== B10/B11: legacy workflow strings in LLM-visible text ==="
if grep -rn "agentir case activate\|agentir case init\|~/.sift/active_case" \
   packages/ --include="*.py" | grep -v "test_\|#"; then
    echo "FAIL: legacy CLI workflow strings in tool descriptions/errors"
    FAIL=1
fi

echo
echo "=== sys.exit in sift-core ==="
if grep -rn "sys\.exit" packages/sift-core/ --include="*.py"; then
    echo "FAIL: sys.exit in sift-core (raise exceptions instead)"
    FAIL=1
fi

echo
echo "=== shell=True outside sift-mcp ==="
if grep -rn "shell=True" packages/ --include="*.py" \
   | grep -v "packages/sift-mcp\|test_"; then
    echo "FAIL: shell=True outside sift-mcp"
    FAIL=1
fi

echo
echo "=== vhir namespace ==="
# Exclude vhir. (dot after) — these are OpenSearch field names like vhir.source_file
if grep -rn "vhir\|VHIR" packages/ --include="*.py" | grep -v "vhir\."; then
    echo "FAIL: vhir namespace leak"
    FAIL=1
fi

echo
echo "=== Tool responses: bare string errors (WARN only — fails after R4) ==="
if grep -rn 'return ".*[Ee]rror\|return f".*[Ee]rror' packages/*/src/ --include="*.py" \
   | grep -v "test_\|#"; then
    echo "WARN: bare string error returns (should be dicts) — will be FAIL after R4"
fi

if [ "$FAIL" -eq 0 ]; then
    echo
    echo "=== Gate PASSED ==="
else
    echo
    echo "=== Gate FAILED ($FAIL check(s)) ==="
fi

exit $FAIL
