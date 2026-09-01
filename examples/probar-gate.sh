#!/usr/bin/env bash
#
# probar-gate.sh — ejecuta el gate contra SARIF de ejemplo, sin escáneres.
#
# Enseña las tres decisiones que toma el gate: bloquear, tolerar por excepción
# vigente y fallar por excepción vencida.

set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

command -v python3 >/dev/null || { echo "hace falta python3"; exit 1; }
python3 -c 'import yaml' 2>/dev/null || { echo "pip install pyyaml"; exit 1; }

run() {   # run <titulo> <contenido de .security-baseline.yml>
  local titulo="$1" policy="$2"
  local ws; ws="$(mktemp -d)"
  mkdir -p "$ws/reports"
  cp "$ROOT"/examples/sarif/*.sarif "$ws/reports/"
  printf '%s\n' "$policy" > "$ws/.security-baseline.yml"

  printf '\n\033[1m=== %s ===\033[0m\n' "$titulo"
  ( cd "$ws" && python3 "$ROOT/actions/gate/gate.py" \
      --reports reports --config .security-baseline.yml \
      --severity-map "$ROOT/policy/severity-map.yml" --repo . )
  local rc=$?
  if [ $rc -eq 0 ]; then printf '\033[32mgate: PASA (exit 0)\033[0m\n'
  else printf '\033[31mgate: BLOQUEA (exit %s)\033[0m\n' "$rc"; fi
  sed -n '1,14p' "$ws/reports/gate-summary.md"
}

VIGENTE="$(python3 -c 'import datetime;print((datetime.date.today()+datetime.timedelta(days=60)).isoformat())')"
VENCIDA="$(python3 -c 'import datetime;print((datetime.date.today()-datetime.timedelta(days=1)).isoformat())')"

run "1 · Sin excepciones: debe bloquear" \
"version: 1
gate:
  severity: high"

run "2 · Con excepciones vigentes: debe pasar" \
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

run "3 · Excepción vencida: debe fallar aunque estuviera cubierta" \
"version: 1
gate:
  severity: high
exceptions:
  - id: CVE-2018-18074
    owner: '@yo'
    expires: '${VENCIDA}'"

printf '\n\033[1mResumen esperado:\033[0m 1 bloquea · 2 pasa · 3 falla por configuración\n'
