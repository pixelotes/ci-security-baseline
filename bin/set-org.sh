#!/usr/bin/env bash
#
# set-org.sh — estampa tu organización de GitHub en las referencias `uses:`.
#
# GitHub no admite expresiones en `uses:`, así que la org tiene que aparecer
# literal en cada reusable workflow y en cada composite action. Este script
# sustituye el marcador __ORG__ por la tuya.
#
#   ./bin/set-org.sh mi-usuario
#   ./bin/set-org.sh              # intenta deducirla de `gh`

set -euo pipefail
cd "$(dirname "$0")/.."

ORG="${1:-}"
if [ -z "$ORG" ] && command -v gh >/dev/null 2>&1; then
  ORG="$(gh api user --jq .login 2>/dev/null || true)"
  [ -n "$ORG" ] && echo "Deducida de gh: $ORG"
fi
[ -n "$ORG" ] || { echo "Uso: $0 <org-o-usuario>" >&2; exit 1; }

case "$ORG" in
  *[!a-zA-Z0-9._-]*) echo "Nombre de organización no válido: $ORG" >&2; exit 1 ;;
esac

count=0
while IFS= read -r f; do
  grep -q '__ORG__' "$f" || continue
  # -i '' para el sed de macOS, -i para el de GNU
  if sed --version >/dev/null 2>&1; then
    sed -i "s|__ORG__|${ORG}|g" "$f"
  else
    sed -i '' "s|__ORG__|${ORG}|g" "$f"
  fi
  echo "  $f"
  count=$((count + 1))
done < <(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')

echo "Estampada la organización '${ORG}' en ${count} fichero(s)."
echo
echo "Comprueba que no queda ninguno:"
echo "  grep -rn __ORG__ . || echo limpio"
