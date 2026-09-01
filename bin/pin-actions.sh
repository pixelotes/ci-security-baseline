#!/usr/bin/env bash
#
# pin-actions.sh — resuelve los tags de las actions de terceros a SHA completo.
#
# Un tag es mutable: un compromiso de la cuenta upstream se propaga a todos los
# repos en el siguiente build. Este script deja el tag como comentario para que
# Dependabot siga sabiendo qué versión es.
#
# Requiere `gh` autenticado.   Uso: ./bin/pin-actions.sh [--check]

set -euo pipefail
cd "$(dirname "$0")/.."

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1
pending=0

command -v gh >/dev/null || { echo "hace falta gh"; exit 1; }

# actions propias y del repo se dejan por tag a propósito: son el canal de
# actualización del baseline.
while IFS= read -r line; do
  file="${line%%:*}"; rest="${line#*:}"
  ref="$(printf '%s' "$rest" | sed -E 's/.*uses:[[:space:]]+([^[:space:]]+).*/\1/')"
  repo="${ref%@*}"; tag="${ref#*@}"
  case "$repo" in actions/*|__ORG__/*|./*) continue ;; esac
  case "$tag" in [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*) continue ;; esac

  sha="$(gh api "repos/${repo}/commits/${tag}" --jq .sha 2>/dev/null || true)"
  [ -n "$sha" ] || { echo "no resuelto: $ref"; continue; }

  if [ "$CHECK" = "1" ]; then
    echo "sin fijar: $file  $ref  →  $sha"
    pending=$((pending + 1))
  else
    perl -pi -e "s|\Q${ref}\E|${repo}\@${sha} # ${tag}|g" "$file"
    echo "fijado: $repo@$tag → ${sha:0:12}"
  fi
done < <(grep -rn 'uses:' .github/workflows actions --include='*.yml' || true)

[ "$CHECK" = "1" ] && [ "$pending" -gt 0 ] && exit 1
exit 0
