#!/usr/bin/env bash
#
# probar-gate.sh — runs the gate against sample SARIF files, without scanners.
#
# Shows the three decisions the gate takes: block, tolerate through an active
# exception, and fail because of an expired exception.

set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

command -v python3 >/dev/null || { echo "python3 is required"; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo "pip install pyyaml"; exit 1; }

run() {   # run <title> <contents of .security-baseline.yml>
  local title="$1" policy="$2"
  local ws; ws="$(mktemp -d)"
  mkdir -p "$ws/reports"
  cp "$ROOT"/examples/sarif/*.sarif "$ws/reports/"
  printf '%s\n' "$policy" > "$ws/.security-baseline.yml"

  printf '\n\033[1m=== %s ===\033[0m\n' "$title"
  ( cd "$ws" && python3 "$ROOT/actions/gate/gate.py" \
      --reports reports --config .security-baseline.yml \
      --severity-map "$ROOT/policy/severity-map.yml" --repo . )
  local rc=$?
  if [ $rc -eq 0 ]; then printf '\033[32mgate: PASSES (exit 0)\033[0m\n'
  else printf '\033[31mgate: BLOCKS (exit %s)\033[0m\n' "$rc"; fi
  sed -n '1,14p' "$ws/reports/gate-summary.md"
}

VIGENTE="$(python3 -c 'import datetime;print((datetime.date.today()+datetime.timedelta(days=60)).isoformat())')"
VENCIDA="$(python3 -c 'import datetime;print((datetime.date.today()-datetime.timedelta(days=1)).isoformat())')"

run "1 · No exceptions: must block" \
"version: 1
gate:
  severity: high"

run "2 · With active exceptions: must pass" \
"version: 1
gate:
  severity: high
exceptions:
  - id: CVE-2018-18074
    scope: 'requirements.txt'
    reason: 'demo'
    owner: '@yo'
    expires: '${VIGENTE}'
  - id: CVE-2020-1747
    scope: 'requirements.txt'
    reason: 'demo'
    owner: '@yo'
    expires: '${VIGENTE}'
  - id: generic-api-key
    scope: 'src/**'
    reason: 'demo'
    owner: '@yo'
    expires: '${VIGENTE}'"

run "3 · Expired exception: must fail even though it was covered" \
"version: 1
gate:
  severity: high
exceptions:
  - id: CVE-2018-18074
    owner: '@yo'
    expires: '${VENCIDA}'"

printf '\n\033[1mExpected summary:\033[0m 1 blocks · 2 passes · 3 fails on configuration\n'
