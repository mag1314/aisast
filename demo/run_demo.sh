#!/usr/bin/env bash
# End-to-end AI-SAST demo: detect -> AI triage/deep scan -> AI fixes -> validation -> apply + git -> verify -> reports.
# Usage: ./demo/run_demo.sh [--no-ai] [--model qwen2.5-coder:7b] [--workdir /tmp/aisast-demo]
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
WORK="/tmp/aisast-demo"
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --workdir) WORK="$2"; shift 2 ;;
    --model|--fix-model|--ollama-url) EXTRA+=("$1" "$2"); shift 2 ;;
    --no-ai) EXTRA+=("--no-ai"); shift ;;
    *) echo "unknown option $1"; exit 1 ;;
  esac
done

AISAST=(python3 -m aisast)
command -v aisast >/dev/null 2>&1 && AISAST=(aisast)
step() { printf '\n\033[1;36m━━ %s\033[0m\n' "$*"; }

step "0. Prepare a fresh copy of the vulnerable app in $WORK (git repo)"
rm -rf "$WORK" && mkdir -p "$WORK"
cp -r "$HERE/vulnerable-app/." "$WORK/"
rm -rf "$WORK/.aisast"
cd "$WORK"
python3 -m pip install -q -r requirements.txt 2>/dev/null || echo "(could not pip install demo requirements; tests may be skipped)"
git init -q && git add -A && git -c user.name=demo -c user.email=demo@localhost commit -qm "AcmeShop (vulnerable)"
python3 -m pytest -q tests -p no:cacheprovider >/dev/null 2>&1 && echo "functional tests: PASS on vulnerable code" || echo "functional tests: not runnable"

step "1. Environment check (Ollama + model)"
(cd "$REPO" && "${AISAST[@]}" doctor "${EXTRA[@]}") || echo "→ Ollama not ready: the demo continues with the deterministic engine + fix templates."

step "2. Scan: taint analysis + AI triage + AI deep scan"
(cd "$REPO" && "${AISAST[@]}" scan "$WORK" --deep "${EXTRA[@]}")

step "3. Ask the AI about the top finding"
TOP=$(python3 -c "import json;print(json.load(open('$WORK/.aisast/last-scan.json'))['findings'][0]['id'])")
(cd "$REPO" && "${AISAST[@]}" explain "$TOP" -p "$WORK" -Q "How would an attacker exploit this and how do I test the fix?" "${EXTRA[@]}") || true

step "4. Remediate: AI patches → syntax → re-scan → AI review → tests → apply → git branch"
(cd "$REPO" && "${AISAST[@]}" fix "$WORK" --test-cmd "python3 -m pytest -q tests -p no:cacheprovider" --apply --git "${EXTRA[@]}")

step "5. Validate: functional tests on the fixed code"
python3 -m pytest -q tests -p no:cacheprovider | tail -1

step "6. Verify: re-scan marks fixed findings as verified"
(cd "$REPO" && "${AISAST[@]}" verify "$WORK" "${EXTRA[@]}") | tail -4

step "7. Remediation status"
(cd "$REPO" && "${AISAST[@]}" status "$WORK") | head -12

step "8. Results"
git --no-pager log --oneline -3
echo
echo "HTML report      : $WORK/.aisast/reports/aisast-report.html"
echo "SARIF            : $WORK/.aisast/reports/aisast-report.sarif"
echo "Combined patch   : $WORK/.aisast/fixes/aisast-fixes.patch"
echo "PR description   : $WORK/.aisast/fixes/PR_DESCRIPTION.md"
echo "Branch to push   : $(git branch --show-current)"
