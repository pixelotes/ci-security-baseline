#!/usr/bin/env bash
#
# new-repo.sh — generates a repository already hooked into the security baseline,
# or hooks an existing one.
#
# Writes only two baseline files into the target repo:
#   .github/workflows/ci.yml   (caller of ~15 lines)
#   .security-baseline.yml     (threshold, cutoff date and exceptions)
#
# The pipeline logic is NOT copied: it lives in pixelotes/ci-security-baseline and
# is referenced by tag. So a baseline improvement reaches every repo by moving
# the tag, without opening a PR per repository.
#
#   ./new-repo.sh                      interactive mode, new repo
#   ./new-repo.sh --adopt ../my-repo   adds the baseline to an existing repo
#   ./new-repo.sh --dry-run            shows what it would do and writes nothing
#   ./new-repo.sh --help
#
# Compatible with bash 3.2 (the one on macOS).

set -euo pipefail

# ------------------------------------------------------------------ style

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$'\033[1m'; DIM=$'\033[2m'; R=$'\033[0m'
  CY=$'\033[36m'; GR=$'\033[32m'; YE=$'\033[33m'; RD=$'\033[31m'
else
  B=""; DIM=""; R=""; CY=""; GR=""; YE=""; RD=""
fi

say()  { printf '%s\n' "$*"; }
head1(){ printf '\n%s%s%s\n' "$B$CY" "$*" "$R"; }
ok()   { printf '%s✓%s %s\n' "$GR" "$R" "$*"; }
warn() { printf '%s!%s %s\n' "$YE" "$R" "$*"; }
die()  { printf '%s✗ %s%s\n' "$RD" "$*" "$R" >&2; exit 1; }

# ------------------------------------------------------------------ config

# The org is not hardwired: it comes from baseline.conf, the environment, or gh.
[ -f "$(dirname "$0")/baseline.conf" ] && . "$(dirname "$0")/baseline.conf"
BASELINE_ORG="${BASELINE_ORG:-pixelotes}"
BASELINE_REPO="${BASELINE_REPO:-ci-security-baseline}"
BASELINE_REF="${BASELINE_REF:-v1}"
DTRACK_URL_DEFAULT="${DTRACK_URL:-https://dependency-track.example.internal}"
REGISTRY_DEFAULT="${ACR_REGISTRY:-myorg.azurecr.io}"
KEYVAULT_DEFAULT="${AZURE_KEYVAULT:-kv-cicd}"

DRY_RUN=0
ADOPT_PATH=""
OUT_DIR="."

# ------------------------------------------------------------------ prompts

# ask VAR "Question" "default"
ask() {
  local __var="$1" __prompt="$2" __default="${3:-}" __reply=""
  if [ -n "$__default" ]; then
    printf '%s %s[%s]%s ' "$__prompt" "$DIM" "$__default" "$R"
  else
    printf '%s ' "$__prompt"
  fi
  read -r __reply || true
  [ -z "$__reply" ] && __reply="$__default"
  eval "$__var=\$__reply"
}

# confirm "Question" "y|n"  -> 0 if yes
confirm() {
  local prompt="$1" default="${2:-n}" reply=""
  local hint="y/N"; [ "$default" = "y" ] && hint="Y/n"
  printf '%s %s[%s]%s ' "$prompt" "$DIM" "$hint" "$R"
  read -r reply || true
  [ -z "$reply" ] && reply="$default"
  case "$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')" in
    s|si|sí|y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

# choose VAR "Question" "opt1 opt2 opt3" "default"
choose() {
  local __var="$1" __prompt="$2" __opts="$3" __default="$4"
  local o i=1 reply=""
  say ""
  say "$__prompt"
  for o in $__opts; do
    if [ "$o" = "$__default" ]; then
      printf '  %s%d)%s %s %s(default)%s\n' "$B" "$i" "$R" "$o" "$DIM" "$R"
    else
      printf '  %s%d)%s %s\n' "$B" "$i" "$R" "$o"
    fi
    i=$((i + 1))
  done
  printf 'Choose [%s]: ' "$__default"
  read -r reply || true
  if [ -z "$reply" ]; then
    eval "$__var=\$__default"; return
  fi
  case "$reply" in
    ''|*[!0-9]*)
      # they typed the name: only accepted if it is among the options,
      # so that a shifted answer does not slip through as a valid value
      for o in $__opts; do
        [ "$o" = "$reply" ] && { eval "$__var=\$o"; return; }
      done
      warn "\"$reply\" is not a valid option; using $__default"
      eval "$__var=\$__default"
      ;;
    *)
      i=1
      for o in $__opts; do
        [ "$i" = "$reply" ] && { eval "$__var=\$o"; return; }
        i=$((i + 1))
      done
      eval "$__var=\$__default"
      ;;
  esac
}

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# writes a file, honouring --dry-run
emit() {
  local path="$1"
  if [ "$DRY_RUN" = "1" ]; then
    printf '\n%s--- %s %s---%s\n' "$DIM" "$path" "$DIM" "$R"
    cat
    return
  fi
  mkdir -p "$(dirname "$path")"
  cat > "$path"
  ok "$path"
}

# ------------------------------------------------------------------ detection

# Detects stacks in an existing repo. Echoes a space-separated list.
detect_stacks() {
  local dir="$1" found=""
  _has() { [ -n "$(find "$dir" -maxdepth 3 -not -path '*/.git/*' -name "$1" -print 2>/dev/null | head -1)" ]; }

  _has 'pom.xml'        && found="$found jvm-maven"
  _has 'build.gradle*'  && found="$found jvm-gradle"
  _has 'package.json'   && found="$found node"
  { _has 'requirements*.txt' || _has 'pyproject.toml' || _has 'setup.py'; } && found="$found python"
  _has 'go.mod'         && found="$found go"
  _has 'Dockerfile*'    && found="$found container"
  { _has '*.tf' || _has 'Chart.yaml' || [ -d "$dir/k8s" ]; } && found="$found iac"
  { _has '*.sh' || _has '*.ps1'; } && found="$found scripts"

  printf '%s' "${found# }"
}

# ------------------------------------------------------------------ arguments

usage() {
  sed -n '3,22p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [ $# -gt 0 ]; do
  case "$1" in
    --adopt)   ADOPT_PATH="${2:-}"; shift 2 ;;
    --out|-o)  OUT_DIR="${2:-.}"; shift 2 ;;
    --ref)     BASELINE_REF="${2:-v1}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage ;;
    *) die "Unknown option: $1  (use --help)" ;;
  esac
done

# ------------------------------------------------------------------ 1. identity

cat <<BANNER

${B}security baseline · repository generator${R}
${DIM}platform and security${R}

This script writes only the caller and the policy configuration.
The pipeline logic lives in ${BASELINE_ORG}/${BASELINE_REPO}@${BASELINE_REF}.
BANNER

[ "$DRY_RUN" = "1" ] && warn "--dry-run mode: no files will be written."

MODE="new"
if [ -n "$ADOPT_PATH" ]; then
  [ -d "$ADOPT_PATH" ] || die "Directory does not exist: $ADOPT_PATH"
  MODE="adopt"
  TARGET="$ADOPT_PATH"
  REPO_NAME="$(basename "$(cd "$ADOPT_PATH" && pwd)")"
  head1 "1 · Existing repository"
  say "Adopting: ${B}${TARGET}${R}"
else
  head1 "1 · Repository identity"
  ask REPO_NAME "Repository name:" ""
  [ -n "$REPO_NAME" ] || die "The name is required."
  case "$REPO_NAME" in
    *[!a-zA-Z0-9._-]*) die "Invalid name: use only letters, numbers, dot, hyphen and underscore." ;;
  esac
  TARGET="$OUT_DIR/$REPO_NAME"
  [ -e "$TARGET" ] && die "Already exists: $TARGET"
fi

ask GH_ORG "GitHub organization:" "$BASELINE_ORG"
ask OWNER  "Owning team (CODEOWNERS):" "@${GH_ORG}/$(lower "${REPO_NAME%%-*}")"

# ------------------------------------------------------------------ 2. stack

head1 "2 · Stack"

PRIMARY=""
if [ "$MODE" = "adopt" ]; then
  DETECTED="$(detect_stacks "$TARGET")"
  if [ -n "$DETECTED" ]; then
    say "Signals found: ${B}${DETECTED}${R}"
    for s in $DETECTED; do
      case "$s" in
        jvm-maven|jvm-gradle|node|python|go) [ -z "$PRIMARY" ] && PRIMARY="$s" ;;
      esac
    done
  else
    warn "No recognizable build signals. This repo needs manual review."
  fi
fi

choose PRIMARY "What is the primary stack?" \
  "jvm-maven jvm-gradle node python go scripts" "${PRIMARY:-jvm-maven}"

case "$PRIMARY" in
  jvm-maven|jvm-gradle) ask LANG_VERSION "Java version:"   "21" ;;
  node)                 ask LANG_VERSION "Node version:"   "22" ;;
  python)               ask LANG_VERSION "Python version:" "3.12" ;;
  go)                   ask LANG_VERSION "Go version:"     "1.23" ;;
  *)                    LANG_VERSION="" ;;
esac

HAS_CONTAINER=false
HAS_IAC=false
case " ${DETECTED:-} " in *" container "*) HAS_CONTAINER=true ;; esac
case " ${DETECTED:-} " in *" iac "*) HAS_IAC=true ;; esac

confirm "Does the repo build a container image?" "$([ "$HAS_CONTAINER" = true ] && echo y || echo n)" \
  && HAS_CONTAINER=true || HAS_CONTAINER=false
confirm "Does it contain Terraform, Helm or Kubernetes manifests?" "$([ "$HAS_IAC" = true ] && echo y || echo n)" \
  && HAS_IAC=true || HAS_IAC=false

# ------------------------------------------------------------------ 3. policy

head1 "3 · Gate policy"
say "${DIM}The gate is the only required check. Scanners only report.${R}"

choose SEVERITY "From which severity is the merge blocked?" \
  "critical high medium" "high"

say ""
say "${DIM}The cutoff date downgrades to warnings anything introduced before it.${R}"
say "${DIM}Without it, applying the gate to a repo with existing debt blocks every PR${R}"
say "${DIM}in the first week and someone ends up disabling the required check.${R}"
DEFAULT_CUTOFF="$(date +%Y-%m-01)"
if [ "$MODE" = "adopt" ]; then
  ask CUTOFF "Cutoff date (YYYY-MM-DD, or '-' for none):" "$DEFAULT_CUTOFF"
else
  # a new repo has no prior debt: it needs no cutoff
  ask CUTOFF "Cutoff date (YYYY-MM-DD, empty = no cutoff):" ""
fi
# with a proposed default, an empty answer cannot mean "none":
# an explicit way to say so is needed
case "$(printf '%s' "$CUTOFF" | tr '[:upper:]' '[:lower:]')" in
  -|none|ninguna|no) CUTOFF="" ;;
esac
if [ -n "$CUTOFF" ]; then
  case "$CUTOFF" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) : ;;
    *) die "Invalid cutoff date: $CUTOFF (format YYYY-MM-DD)" ;;
  esac
fi

# ------------------------------------------------------------------ 4. delivery

head1 "4 · Publishing"

WANT_CD=false
if confirm "Does this repo publish artifacts (CD)?" "$([ "$MODE" = new ] && echo y || echo n)"; then
  WANT_CD=true
  ask ENVIRONMENT "GitHub environment for production:" "prod"
  ask DTRACK_URL  "Dependency-Track URL:" "$DTRACK_URL_DEFAULT"
  ask KEYVAULT    "Key Vault with the CI secrets:" "$KEYVAULT_DEFAULT"
  if [ "$HAS_CONTAINER" = true ]; then
    ask REGISTRY "Azure Container Registry:" "$REGISTRY_DEFAULT"
    choose SIGN_METHOD "Image signing method" "cosign-kms notation" "cosign-kms"
    if [ "$SIGN_METHOD" = "cosign-kms" ]; then
      ask COSIGN_KEY "Key URI in Key Vault:" "azurekms://${KEYVAULT}.vault.azure.net/cosign-signing-key"
    else
      COSIGN_KEY=""
    fi
  else
    REGISTRY=""; SIGN_METHOD="cosign-kms"; COSIGN_KEY=""
  fi
  say ""
  say "${DIM}Remember: the Entra federated credential must be scoped to${R}"
  say "${DIM}  repo:${GH_ORG}/${REPO_NAME}:environment:${ENVIRONMENT}${R}"
  say "${DIM}A wildcard subject lets a PR obtain a production token.${R}"
fi

# ------------------------------------------------------------------ 5. summary

WORKFLOW="ci-${PRIMARY}.yml"
[ "$PRIMARY" = "scripts" ] && WORKFLOW="ci-scripts.yml"

head1 "5 · Summary"
cat <<SUMMARY
  Mode             ${MODE}
  Target           ${TARGET}
  Organization     ${GH_ORG}
  Owner            ${OWNER}
  Primary stack    ${PRIMARY}${LANG_VERSION:+ (${LANG_VERSION})}
  Extra modules    $([ "$HAS_CONTAINER" = true ] && printf 'container ')$([ "$HAS_IAC" = true ] && printf 'iac ')$([ "$HAS_CONTAINER" = false ] && [ "$HAS_IAC" = false ] && printf 'none')
  Gate             blocks ${SEVERITY} and above
  Cutoff date      ${CUTOFF:-no cutoff}
  CD               $([ "$WANT_CD" = true ] && printf 'yes → %s' "${ENVIRONMENT}" || printf 'no')
  Baseline         ${GH_ORG}/${BASELINE_REPO}@${BASELINE_REF}
SUMMARY

say ""
confirm "Generate?" "y" || { warn "Cancelled."; exit 0; }

# ------------------------------------------------------------------ 6. generate

head1 "6 · Writing"

# The inputs block is built beforehand: command substitution inside a heredoc
# eats the trailing newlines and glues the keys together.
CI_INPUTS=""
case "$PRIMARY" in
  jvm-maven|jvm-gradle) CI_INPUTS="      java-version: '${LANG_VERSION}'" ;;
  node)                 CI_INPUTS="      node-version: '${LANG_VERSION}'" ;;
  python)               CI_INPUTS="      python-version: '${LANG_VERSION}'" ;;
  go)                   CI_INPUTS="      go-version: '${LANG_VERSION}'" ;;
esac
[ -n "$CI_INPUTS" ] && CI_INPUTS="${CI_INPUTS}
"
CI_INPUTS="${CI_INPUTS}      severity-gate: '${SEVERITY}'
      cutoff-date: '${CUTOFF}'"
[ "$HAS_CONTAINER" = true ] && CI_INPUTS="${CI_INPUTS}
      run-container: true"
[ "$HAS_IAC" = true ] && CI_INPUTS="${CI_INPUTS}
      run-iac: true"

emit "$TARGET/.github/workflows/ci.yml" <<CIEOF
# Generated by ci-security-baseline/new-repo.sh
#
# This file must not grow. Everything variable goes in the inputs below or in
# .security-baseline.yml. If a baseline change forces you to touch this
# file, it is the baseline that is badly designed.
name: CI

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

concurrency:
  group: ci-\${{ github.ref }}
  cancel-in-progress: true

jobs:
  baseline:
    uses: ${GH_ORG}/${BASELINE_REPO}/.github/workflows/${WORKFLOW}@${BASELINE_REF}
    with:
${CI_INPUTS}
    secrets: inherit
CIEOF

emit "$TARGET/.security-baseline.yml" <<POLEOF
# Security baseline policy for ${REPO_NAME}.
#
# Every exception carries an owner and an expiry date. Without expiry, in six
# months this file is a graveyard and the gate blocks nothing; with it, each
# exception comes back to the table with a named owner.
version: 1

# Stages to run (optional). Without this key they all run.
# Valid names: build, lint, sast, secret-scan, sca, container-scan,
# iac-scan, quality, all.
# stages:
#   - lint
#   - secret-scan

gate:
  severity: ${SEVERITY}
$([ -n "$CUTOFF" ] && printf "  cutoff: '%s'\n" "$CUTOFF" || printf "  # cutoff: '2026-10-01'   # new repo: no prior debt to tolerate\n")
exceptions: []
  # - id: CVE-2025-48795
  #   tool: trivy
  #   scope: 'pom.xml'
  #   reason: 'Not exploitable: the parser receives no external input'
  #   owner: '${OWNER}'
  #   expires: '2026-12-15'     # MANDATORY
POLEOF

if [ "$WANT_CD" = true ]; then
  emit "$TARGET/.github/workflows/cd.yml" <<CDEOF
# Generated by ci-security-baseline/new-repo.sh
name: CD

on:
  push:
    tags: ['v*']

permissions:
  contents: read
  id-token: write     # OIDC hacia Entra ID — only in CD, never in CI
  attestations: write

jobs:
  publish:
    uses: ${GH_ORG}/${BASELINE_REPO}/.github/workflows/cd-publish.yml@${BASELINE_REF}
    with:
      stack: '$([ "$HAS_CONTAINER" = true ] && echo container || echo "$PRIMARY")'
      artifact-name: '${REPO_NAME}'
      version: \${{ github.ref_name }}
      environment: '${ENVIRONMENT}'
      registry: '${REGISTRY:-}'
      dtrack-url: '${DTRACK_URL}'
      keyvault: '${KEYVAULT}'
      sign-method: '${SIGN_METHOD:-cosign-kms}'
      cosign-key-uri: '${COSIGN_KEY:-}'
    secrets: inherit
CDEOF
fi

emit "$TARGET/CODEOWNERS" <<COEOF
# Repository owner
*                        ${OWNER}

# Security configuration is always reviewed by the security team:
# an unreviewed exception is the quietest way to disable the gate.
/.security-baseline.yml  ${OWNER} @${GH_ORG}/security
/.github/workflows/      ${OWNER} @${GH_ORG}/security
COEOF

emit "$TARGET/.pre-commit-config.yaml" <<PCEOF
# The Team plan does not include push protection on private repos: this hook is
# the only barrier before a secret reaches the server.
#
#   pip install pre-commit && pre-commit install
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.28.0
    hooks:
      - id: gitleaks
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v5.0.0
    hooks:
      - id: check-merge-conflict
      - id: detect-private-key
      - id: end-of-file-fixer
      - id: trailing-whitespace
PCEOF

if [ "$MODE" = "new" ]; then
  emit "$TARGET/README.md" <<RMEOF
# ${REPO_NAME}

## Security

This repository uses the organization's
[security baseline](https://github.com/${GH_ORG}/${BASELINE_REPO}).

- The **\`gate\`** check is required to merge. It blocks from severity
  \`${SEVERITY}\` upwards.
- Findings are posted as a comment on the pull request.
- Exceptions are declared in \`.security-baseline.yml\` and **always expire**.
- Before the first commit: \`pip install pre-commit && pre-commit install\`.

See [the onboarding guide](https://github.com/${GH_ORG}/${BASELINE_REPO}/blob/main/docs/onboarding.md).
RMEOF

  emit "$TARGET/.gitignore" <<GIEOF
reports/
*.sarif
.env
.venv/
node_modules/
target/
build/
dist/
__pycache__/
.terraform/
*.tfstate*
GIEOF
fi

# ------------------------------------------------------------------ 7. git

if [ "$DRY_RUN" = "0" ] && [ "$MODE" = "new" ]; then
  head1 "7 · Git"
  if confirm "Initialize the git repository?" "y"; then
    (
      cd "$TARGET"
      git init -q -b main
      git add -A
      git -c user.useConfigOnly=false commit -q -m "chore: adopt the security baseline

Generates the baseline caller and the gate policy.
Baseline: ${GH_ORG}/${BASELINE_REPO}@${BASELINE_REF}" || warn "Commit not made (configure git user.name/user.email)"
    )
    ok "git initialized in $TARGET"
  fi

  if command -v gh >/dev/null 2>&1; then
    if confirm "Create the repository on GitHub with gh?" "n"; then
      (cd "$TARGET" && gh repo create "${GH_ORG}/${REPO_NAME}" --private --source=. --push) \
        && ok "Created on GitHub" || warn "Could not create the remote repository"
    fi
  fi
fi

# ------------------------------------------------------------------ 8. wrap-up

head1 "Done"
if [ "$DRY_RUN" = "1" ]; then
  warn "Nothing was written (--dry-run)."
  exit 0
fi

cat <<NEXT
Next:

  1. Review ${TARGET}/.github/workflows/ci.yml
  2. Mark the ${B}gate${R} check as required in the main branch ruleset
NEXT

if [ "$WANT_CD" = true ]; then
  cat <<CDNEXT
  3. Create the '${ENVIRONMENT}' environment with required reviewers
  4. Add the federated credential in Entra with exactly this subject:
       ${B}repo:${GH_ORG}/${REPO_NAME}:environment:${ENVIRONMENT}${R}
     ${DIM}Never with a wildcard: a broad subject lets a PR obtain a production token.${R}
CDNEXT
fi
