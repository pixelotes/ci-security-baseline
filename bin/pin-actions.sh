#!/usr/bin/env bash
#
# pin-actions.sh — resolves third-party action tags to a full SHA.
#
# A tag is mutable: a compromise of the upstream account propagates to every
# repo on the next build. This script leaves the tag as a comment so that
# Dependabot still knows which version it is.
#
# Requires an authenticated `gh`.   Usage: ./bin/pin-actions.sh [--check]

set -euo pipefail
cd "$(dirname "$0")/.."

CHECK=0
[ "${1:-}" = "--check" ] && CHECK=1
pending=0

command -v gh >/dev/null || { echo "gh is required"; exit 1; }

# This baseline's actions (pixelotes/*) and local ones (./*) are left on a tag
# on purpose: they are the update channel. Everything else, including the
# official `actions/*` ones, is pinned by SHA.
while IFS= read -r line; do
  file="${line%%:*}"; rest="${line#*:}"
  ref="$(printf '%s' "$rest" | sed -E 's/.*uses:[[:space:]]+([^[:space:]]+).*/\1/')"
  repo="${ref%@*}"; tag="${ref#*@}"
  # github/codeql-action/init -> github/codeql-action (subpath is not part of the repo)
  slug="$(printf %s "$repo" | cut -d/ -f1-2)"
  case "$repo" in pixelotes/*|./*) continue ;; esac
  # already pinned: exactly 40 hex chars (a tag like "0.28.0" must not be mistaken for a SHA)
  case "$tag" in *[!0-9a-f]*) ;; *) [ "${#tag}" -eq 40 ] && continue ;; esac

  # Resolve via refs/tags (not /commits/<tag>, which fails with numeric tags)
  # and dereference the annotated tag down to the commit.
  sha="" ; type=""
  read -r type sha < <(gh api "repos/${slug}/git/ref/tags/${tag}" \
    --jq '[.object.type,.object.sha]|@tsv' 2>/dev/null || true) || true
  if [ "$type" = "tag" ] && [ -n "$sha" ]; then
    sha="$(gh api "repos/${slug}/git/tags/${sha}" --jq .object.sha 2>/dev/null || true)"
  fi
  [ -n "$sha" ] || { echo "unresolved: $ref"; continue; }

  if [ "$CHECK" = "1" ]; then
    echo "unpinned: $file  $ref  →  $sha"
    pending=$((pending + 1))
  else
    perl -pi -e "s|\Q${ref}\E|${repo}\@${sha} # ${tag}|g" "$file"
    echo "pinned: $repo@$tag → ${sha:0:12}"
  fi
done < <(grep -rn 'uses:' .github/workflows actions --include='*.yml' || true)

[ "$CHECK" = "1" ] && [ "$pending" -gt 0 ] && exit 1
exit 0
