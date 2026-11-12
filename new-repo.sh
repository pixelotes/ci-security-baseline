#!/usr/bin/env bash
#
# new-repo.sh — genera un repositorio ya enganchado al security baseline,
# o engancha uno que ya existe.
#
# Escribe únicamente dos ficheros de baseline en el repo destino:
#   .github/workflows/ci.yml   (llamador de ~15 líneas)
#   .security-baseline.yml     (umbral, fecha de corte y excepciones)
#
# La lógica del pipeline NO se copia: vive en pixelotes/ci-security-baseline y se
# referencia por tag. Por eso una mejora del baseline llega a todos los repos
# moviendo el tag, sin abrir un PR por repositorio.
#
#   ./new-repo.sh                      modo interactivo, repo nuevo
#   ./new-repo.sh --adopt ../mi-repo   añade el baseline a un repo existente
#   ./new-repo.sh --dry-run            muestra lo que haría y no escribe nada
#   ./new-repo.sh --help
#
# Compatible con bash 3.2 (el de macOS).

set -euo pipefail

# ------------------------------------------------------------------ estilo

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

# La org no viene cableada: se toma de baseline.conf, del entorno, o de gh.
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

# ask VAR "Pregunta" "por-defecto"
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

# confirm "Pregunta" "s|n"  -> 0 si sí
confirm() {
  local prompt="$1" default="${2:-n}" reply=""
  local hint="s/N"; [ "$default" = "s" ] && hint="S/n"
  printf '%s %s[%s]%s ' "$prompt" "$DIM" "$hint" "$R"
  read -r reply || true
  [ -z "$reply" ] && reply="$default"
  case "$(printf '%s' "$reply" | tr '[:upper:]' '[:lower:]')" in
    s|si|sí|y|yes) return 0 ;;
    *) return 1 ;;
  esac
}

# choose VAR "Pregunta" "opt1 opt2 opt3" "por-defecto"
choose() {
  local __var="$1" __prompt="$2" __opts="$3" __default="$4"
  local o i=1 reply=""
  say ""
  say "$__prompt"
  for o in $__opts; do
    if [ "$o" = "$__default" ]; then
      printf '  %s%d)%s %s %s(por defecto)%s\n' "$B" "$i" "$R" "$o" "$DIM" "$R"
    else
      printf '  %s%d)%s %s\n' "$B" "$i" "$R" "$o"
    fi
    i=$((i + 1))
  done
  printf 'Elige [%s]: ' "$__default"
  read -r reply || true
  if [ -z "$reply" ]; then
    eval "$__var=\$__default"; return
  fi
  case "$reply" in
    ''|*[!0-9]*)
      # han escrito el nombre: solo se acepta si está entre las opciones,
      # para que una respuesta desplazada no se cuele como valor válido
      for o in $__opts; do
        [ "$o" = "$reply" ] && { eval "$__var=\$o"; return; }
      done
      warn "\"$reply\" no es una opción válida; se usa $__default"
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

# escribe un fichero respetando --dry-run
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

# ------------------------------------------------------------------ detección

# Detecta stacks en un repo existente. Ecoa una lista separada por espacios.
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

# ------------------------------------------------------------------ argumentos

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
    *) die "Opción desconocida: $1  (usa --help)" ;;
  esac
done

# ------------------------------------------------------------------ 1. identidad

cat <<BANNER

${B}security baseline · generador de repositorio${R}
${DIM}plataforma y seguridad${R}

Este script escribe solo el llamador y la configuración de política.
La lógica del pipeline vive en ${BASELINE_ORG}/${BASELINE_REPO}@${BASELINE_REF}.
BANNER

[ "$DRY_RUN" = "1" ] && warn "Modo --dry-run: no se escribirá ningún fichero."

MODE="nuevo"
if [ -n "$ADOPT_PATH" ]; then
  [ -d "$ADOPT_PATH" ] || die "No existe el directorio: $ADOPT_PATH"
  MODE="adopcion"
  TARGET="$ADOPT_PATH"
  REPO_NAME="$(basename "$(cd "$ADOPT_PATH" && pwd)")"
  head1 "1 · Repositorio existente"
  say "Adoptando: ${B}${TARGET}${R}"
else
  head1 "1 · Identidad del repositorio"
  ask REPO_NAME "Nombre del repositorio:" ""
  [ -n "$REPO_NAME" ] || die "El nombre es obligatorio."
  case "$REPO_NAME" in
    *[!a-zA-Z0-9._-]*) die "Nombre no válido: usa solo letras, números, punto, guion y guion bajo." ;;
  esac
  TARGET="$OUT_DIR/$REPO_NAME"
  [ -e "$TARGET" ] && die "Ya existe: $TARGET"
fi

ask GH_ORG "Organización en GitHub:" "$BASELINE_ORG"
ask OWNER  "Equipo propietario (CODEOWNERS):" "@${GH_ORG}/$(lower "${REPO_NAME%%-*}")"

# ------------------------------------------------------------------ 2. stack

head1 "2 · Stack"

PRIMARY=""
if [ "$MODE" = "adopcion" ]; then
  DETECTED="$(detect_stacks "$TARGET")"
  if [ -n "$DETECTED" ]; then
    say "Señales encontradas: ${B}${DETECTED}${R}"
    for s in $DETECTED; do
      case "$s" in
        jvm-maven|jvm-gradle|node|python|go) [ -z "$PRIMARY" ] && PRIMARY="$s" ;;
      esac
    done
  else
    warn "Sin señales de build reconocibles. Este repo necesita revisión manual."
  fi
fi

choose PRIMARY "¿Cuál es el stack principal?" \
  "jvm-maven jvm-gradle node python go scripts" "${PRIMARY:-jvm-maven}"

case "$PRIMARY" in
  jvm-maven|jvm-gradle) ask LANG_VERSION "Versión de Java:"   "21" ;;
  node)                 ask LANG_VERSION "Versión de Node:"   "22" ;;
  python)               ask LANG_VERSION "Versión de Python:" "3.12" ;;
  go)                   ask LANG_VERSION "Versión de Go:"     "1.23" ;;
  *)                    LANG_VERSION="" ;;
esac

HAS_CONTAINER=false
HAS_IAC=false
case " ${DETECTED:-} " in *" container "*) HAS_CONTAINER=true ;; esac
case " ${DETECTED:-} " in *" iac "*) HAS_IAC=true ;; esac

confirm "¿El repo construye una imagen de contenedor?" "$([ "$HAS_CONTAINER" = true ] && echo s || echo n)" \
  && HAS_CONTAINER=true || HAS_CONTAINER=false
confirm "¿Contiene Terraform, Helm o manifests de Kubernetes?" "$([ "$HAS_IAC" = true ] && echo s || echo n)" \
  && HAS_IAC=true || HAS_IAC=false

# ------------------------------------------------------------------ 3. política

head1 "3 · Política del gate"
say "${DIM}El gate es el único check obligatorio. Los escáneres solo reportan.${R}"

choose SEVERITY "¿A partir de qué severidad se bloquea el merge?" \
  "critical high medium" "high"

say ""
say "${DIM}La fecha de corte degrada a aviso lo introducido antes de ella.${R}"
say "${DIM}Sin ella, aplicar el gate sobre un repo con deuda bloquea todos los PRs${R}"
say "${DIM}la primera semana y alguien acaba desactivando el required check.${R}"
DEFAULT_CUTOFF="$(date +%Y-%m-01)"
if [ "$MODE" = "adopcion" ]; then
  ask CUTOFF "Fecha de corte (YYYY-MM-DD, o '-' para ninguna):" "$DEFAULT_CUTOFF"
else
  # un repo nuevo no tiene deuda previa: no necesita corte
  ask CUTOFF "Fecha de corte (YYYY-MM-DD, vacío = sin corte):" ""
fi
# con un default propuesto, una respuesta vacía no puede significar "ninguna":
# hace falta una forma explícita de decirlo
case "$(printf '%s' "$CUTOFF" | tr '[:upper:]' '[:lower:]')" in
  -|none|ninguna|no) CUTOFF="" ;;
esac
if [ -n "$CUTOFF" ]; then
  case "$CUTOFF" in
    [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) : ;;
    *) die "Fecha de corte no válida: $CUTOFF (formato YYYY-MM-DD)" ;;
  esac
fi

# ------------------------------------------------------------------ 4. entrega

head1 "4 · Publicación"

WANT_CD=false
if confirm "¿Este repo publica artefactos (CD)?" "$([ "$MODE" = nuevo ] && echo s || echo n)"; then
  WANT_CD=true
  ask ENVIRONMENT "Environment de GitHub para producción:" "prod"
  ask DTRACK_URL  "URL de Dependency-Track:" "$DTRACK_URL_DEFAULT"
  ask KEYVAULT    "Key Vault con los secretos de CI:" "$KEYVAULT_DEFAULT"
  if [ "$HAS_CONTAINER" = true ]; then
    ask REGISTRY "Azure Container Registry:" "$REGISTRY_DEFAULT"
    choose SIGN_METHOD "Método de firma de imagen" "cosign-kms notation" "cosign-kms"
    if [ "$SIGN_METHOD" = "cosign-kms" ]; then
      ask COSIGN_KEY "URI de la clave en Key Vault:" "azurekms://${KEYVAULT}.vault.azure.net/cosign-signing-key"
    else
      COSIGN_KEY=""
    fi
  else
    REGISTRY=""; SIGN_METHOD="cosign-kms"; COSIGN_KEY=""
  fi
  say ""
  say "${DIM}Recuerda: la federated credential de Entra debe acotarse a${R}"
  say "${DIM}  repo:${GH_ORG}/${REPO_NAME}:environment:${ENVIRONMENT}${R}"
  say "${DIM}Un subject con comodín permite que un PR obtenga token de producción.${R}"
fi

# ------------------------------------------------------------------ 5. resumen

WORKFLOW="ci-${PRIMARY}.yml"
[ "$PRIMARY" = "scripts" ] && WORKFLOW="ci-scripts.yml"

head1 "5 · Resumen"
cat <<SUMMARY
  Modo             ${MODE}
  Destino          ${TARGET}
  Organización     ${GH_ORG}
  Propietario      ${OWNER}
  Stack principal  ${PRIMARY}${LANG_VERSION:+ (${LANG_VERSION})}
  Módulos extra    $([ "$HAS_CONTAINER" = true ] && printf 'container ')$([ "$HAS_IAC" = true ] && printf 'iac ')$([ "$HAS_CONTAINER" = false ] && [ "$HAS_IAC" = false ] && printf 'ninguno')
  Gate             bloquea ${SEVERITY} y superior
  Fecha de corte   ${CUTOFF:-sin corte}
  CD               $([ "$WANT_CD" = true ] && printf 'sí → %s' "${ENVIRONMENT}" || printf 'no')
  Baseline         ${GH_ORG}/${BASELINE_REPO}@${BASELINE_REF}
SUMMARY

say ""
confirm "¿Generar?" "s" || { warn "Cancelado."; exit 0; }

# ------------------------------------------------------------------ 6. generar

head1 "6 · Escribiendo"

# El bloque de inputs se construye antes: la sustitución de comandos dentro
# de un heredoc se come los saltos de línea finales y pega las claves entre sí.
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
# Generado por ci-security-baseline/new-repo.sh
#
# Este fichero no debe crecer. Todo lo variable va en los inputs de abajo o en
# .security-baseline.yml. Si un cambio del baseline obliga a tocar este
# fichero, es el baseline el que está mal diseñado.
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
# Política del security baseline para ${REPO_NAME}.
#
# Toda excepción lleva owner y fecha de caducidad. Sin caducidad, en seis meses
# este fichero es un cementerio y el gate no bloquea nada; con ella, cada
# excepción vuelve a la mesa con un responsable con nombre.
version: 1

gate:
  severity: ${SEVERITY}
$([ -n "$CUTOFF" ] && printf "  cutoff: '%s'\n" "$CUTOFF" || printf "  # cutoff: '2026-10-01'   # repo nuevo: sin deuda previa que tolerar\n")
exceptions: []
  # - id: CVE-2025-48795
  #   tool: trivy
  #   scope: 'pom.xml'
  #   reason: 'No explotable: el parser no recibe entrada externa'
  #   owner: '${OWNER}'
  #   expires: '2026-12-15'     # OBLIGATORIO
POLEOF

if [ "$WANT_CD" = true ]; then
  emit "$TARGET/.github/workflows/cd.yml" <<CDEOF
# Generado por ci-security-baseline/new-repo.sh
name: CD

on:
  push:
    tags: ['v*']

permissions:
  contents: read
  id-token: write     # OIDC hacia Entra ID — solo en CD, nunca en CI
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
# Propietario del repositorio
*                        ${OWNER}

# La configuración de seguridad la revisa siempre el equipo de seguridad:
# una excepción sin revisar es la forma más silenciosa de desactivar el gate.
/.security-baseline.yml  ${OWNER} @${GH_ORG}/security
/.github/workflows/      ${OWNER} @${GH_ORG}/security
COEOF

emit "$TARGET/.pre-commit-config.yaml" <<PCEOF
# El plan Team no incluye push protection en repos privados: este hook es la
# única barrera antes de que un secreto llegue al servidor.
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

if [ "$MODE" = "nuevo" ]; then
  emit "$TARGET/README.md" <<RMEOF
# ${REPO_NAME}

## Seguridad

Este repositorio usa el [security baseline](https://github.com/${GH_ORG}/${BASELINE_REPO})
de la organización.

- El check **\`gate\`** es obligatorio para hacer merge. Bloquea a partir de
  severidad \`${SEVERITY}\`.
- Los hallazgos se publican como comentario en el pull request.
- Las excepciones se declaran en \`.security-baseline.yml\` y **caducan siempre**.
- Antes del primer commit: \`pip install pre-commit && pre-commit install\`.

Ver [la guía de onboarding](https://github.com/${GH_ORG}/${BASELINE_REPO}/blob/main/docs/onboarding.md).
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

if [ "$DRY_RUN" = "0" ] && [ "$MODE" = "nuevo" ]; then
  head1 "7 · Git"
  if confirm "¿Inicializar el repositorio git?" "s"; then
    (
      cd "$TARGET"
      git init -q -b main
      git add -A
      git -c user.useConfigOnly=false commit -q -m "chore: adoptar el security baseline

Genera el llamador del baseline y la política del gate.
Baseline: ${GH_ORG}/${BASELINE_REPO}@${BASELINE_REF}" || warn "Commit no realizado (configura git user.name/user.email)"
    )
    ok "git inicializado en $TARGET"
  fi

  if command -v gh >/dev/null 2>&1; then
    if confirm "¿Crear el repositorio en GitHub con gh?" "n"; then
      (cd "$TARGET" && gh repo create "${GH_ORG}/${REPO_NAME}" --private --source=. --push) \
        && ok "Creado en GitHub" || warn "No se pudo crear el repositorio remoto"
    fi
  fi
fi

# ------------------------------------------------------------------ 8. cierre

head1 "Hecho"
if [ "$DRY_RUN" = "1" ]; then
  warn "No se ha escrito nada (--dry-run)."
  exit 0
fi

cat <<NEXT
Siguiente:

  1. Revisa ${TARGET}/.github/workflows/ci.yml
  2. Marca el check ${B}gate${R} como required en el ruleset de la rama main
NEXT

if [ "$WANT_CD" = true ]; then
  cat <<CDNEXT
  3. Crea el environment '${ENVIRONMENT}' con required reviewers
  4. Añade la federated credential en Entra con subject exactamente:
       ${B}repo:${GH_ORG}/${REPO_NAME}:environment:${ENVIRONMENT}${R}
     ${DIM}Nunca con comodín: un subject amplio deja que un PR obtenga token de producción.${R}
CDNEXT
fi
