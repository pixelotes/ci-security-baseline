#!/usr/bin/env bash
#
# set-org.sh — repoint the `uses:` references to your own copy of this repo.
#
# GitHub does not allow expressions in `uses:`, so the owner and the repository
# name must appear literally in every reusable workflow and composite action.
# This repository ships stamped as `pixelotes/ci-security-baseline`; if you
# fork it under another owner or name, run this script once to rewrite them.
#
#   ./bin/set-org.sh my-org                      # repo = ci-security-baseline
#   ./bin/set-org.sh my-org my-baseline-repo
#   ./bin/set-org.sh                             # owner taken from `gh`
#
# It is idempotent: it rewrites whatever owner/repo is currently stamped
# (detected from the files), so it can be run again after a rename.
#
# It does not touch CODEOWNERS, nor the `pixelotes/` exclusions in
# policy/semgrep/baseline.yml and bin/pin-actions.sh: review those by hand.

set -euo pipefail
cd "$(dirname "$0")/.."

DEFAULT_REPO="ci-security-baseline"
ORG="${1:-}"
REPO="${2:-$DEFAULT_REPO}"

if [ -z "$ORG" ] && command -v gh >/dev/null 2>&1; then
  ORG="$(gh api user --jq .login 2>/dev/null || true)"
  [ -n "$ORG" ] && echo "Owner taken from gh: $ORG"
fi
[ -n "$ORG" ] || { echo "Usage: $0 <owner> [repo-name]" >&2; exit 1; }

for v in "$ORG" "$REPO"; do
  case "$v" in
    *[!a-zA-Z0-9._-]*) echo "Invalid name: $v" >&2; exit 1 ;;
  esac
done

# Detect what is stamped right now from the first reference we find.
CURRENT="$(grep -rhoE '[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/actions/gate@' .github actions 2>/dev/null \
  | head -1 | sed -E 's|/actions/gate@||')"
[ -n "$CURRENT" ] || { echo "No stamped reference found (…/actions/gate@…)." >&2; exit 1; }
NEW="${ORG}/${REPO}"

if [ "$CURRENT" = "$NEW" ]; then
  echo "Already stamped as ${NEW}. Nothing to do."
  exit 0
fi

# GNU sed vs macOS sed
sed_i() {
  if sed --version >/dev/null 2>&1; then sed -i "$@"; else sed -i '' "$@"; fi
}

# escape the regex metacharacters of the current value for the sed pattern
CUR_RE="$(printf '%s' "$CURRENT" | sed 's/[.[\*^$|]/\\&/g')"

count=0
while IFS= read -r f; do
  [ "$f" = "bin/set-org.sh" ] && continue
  grep -qF "$CURRENT" "$f" || continue
  sed_i "s|${CUR_RE}|${NEW}|g" "$f"
  echo "  $f"
  count=$((count + 1))
done < <(git ls-files 2>/dev/null || find . -type f -not -path './.git/*')

echo
echo "Rewrote ${CURRENT} -> ${NEW} in ${count} file(s)."
echo "Remember to publish the tag the references point to (default: v1)."
