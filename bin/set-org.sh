#!/usr/bin/env bash
#
# set-org.sh — estampa tu organización y el nombre de este repositorio en las
# referencias `uses:`.
#
# GitHub no admite expresiones en `uses:`, así que ambos tienen que aparecer
# literales en cada reusable workflow y en cada composite action. Este script
# sustituye los marcadores __ORG__ y __REPO__.
#
#   ./bin/set-org.sh pixelotes composite-actions
#   ./bin/set-org.sh pixelotes                    # repo = security-baseline
#   ./bin/set-org.sh                              # org deducida de `gh`
#
# Es idempotente solo la primera vez: una vez estampado ya no quedan
# marcadores. Para cambiarlo después, `git checkout` y volver a ejecutarlo.

set -euo pipefail
cd "$(dirname "$0")/.."

ORG="${1:-}"
REPO="${2:-security-baseline}"

if [ -z "$ORG" ] && command -v gh >/dev/null 2>&1; then
  ORG="$(gh api user --jq .login 2>/dev/null || true)"
  [ -n "$ORG" ] && echo "Organización deducida de gh: $ORG"
fi
[ -n "$ORG" ] || { echo "Uso: $0 <org-o-usuario> [nombre-del-repo]" >&2; exit 1; }

for v in "$ORG" "$REPO"; do
  case "$v" in
    *[!a-zA-Z0-9._-]*) echo "Nombre no válido: $v" >&2; exit 1 ;;
  esac
done

# sed de GNU frente al de macOS
sed_i() {
  if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

count=0
while IFS= read -r f; do
  grep -q '__ORG__\|__REPO__' "$f" || continue
  sed_i "s|__ORG__|${ORG}|g; s|__REPO__|${REPO}|g" "$f"
  echo "  $f"
  count=$((count + 1))
done < <(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')

echo
echo "Estampado ${ORG}/${REPO} en ${count} fichero(s)."
if grep -rq '__ORG__\|__REPO__' . 2>/dev/null; then
  echo "AVISO: todavía quedan marcadores sin sustituir:" >&2
  grep -rn '__ORG__\|__REPO__' . >&2
  exit 1
fi
echo "No quedan marcadores."
