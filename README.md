# security-baseline

Pipeline modular de seguridad para GitHub Actions. Se ensambla según el stack
de cada repositorio y aporta un gate bloqueante común a toda la organización.

> **Diseñado para GitHub sin Advanced Security.** En los planes Team no hay
> Code Scanning ni upload de SARIF en repositorios privados, así que el
> agregador de hallazgos es propio y vive en `actions/gate`. Si tienes GHAS,
> este baseline sigue valiendo: puedes sustituir el gate por el Security tab.

## La idea en una frase

El repositorio de producto solo contiene una referencia de ~15 líneas. La
lógica vive aquí y se versiona por tag, así que **una mejora del baseline llega
a todos los repos moviendo el tag `v1`, sin abrir un PR por repositorio**.

```
repos de producto   .github/workflows/ci.yml    ← generado una vez (15 líneas)
                    .security-baseline.yml      ← umbral, corte y excepciones
        ↓ uses @v1
security-baseline   .github/workflows/ci-*.yml  ← reusable workflows por stack
        ↓ uses
                    actions/*                   ← composite actions atómicas
```

## Instalación

```bash
git clone https://github.com/TU-ORG/security-baseline
cd security-baseline
./bin/set-org.sh TU-ORG          # estampa la org en las referencias uses:
cp baseline.conf.example baseline.conf   # opcional: destinos de publicación
```

`set-org.sh` es necesario porque GitHub **no admite expresiones en `uses:`**:
la organización tiene que aparecer literal en cada referencia.

## Uso

```bash
./new-repo.sh                      # repo nuevo, modo interactivo
./new-repo.sh --adopt ../mi-repo   # añade el baseline a un repo existente
./new-repo.sh --dry-run            # enseña lo que haría, sin escribir
```

El script pregunta stack, versión, umbral del gate, fecha de corte y destino de
publicación, y escribe **solo dos ficheros** en el repo destino. No copia
lógica: si un cambio del baseline obliga a tocar el fichero generado, es el
baseline el que está mal diseñado.

## Probarlo sin tocar nada real

```bash
pip install pyyaml pytest
python -m pytest tests/ -q        # 15 tests del gate

./examples/probar-gate.sh          # el gate contra SARIF de ejemplo
./new-repo.sh --adopt examples/demo-python --dry-run
```

`examples/demo-python` es un repo mínimo con hallazgos plantados a propósito:
sirve para ver el gate bloquear de verdad antes de apuntarlo a nada tuyo.

## Contrato del pipeline

| | |
|---|---|
| Los escáneres | emiten SARIF y **nunca fallan** (`continue-on-error: true`) |
| El `gate` | agrega, normaliza severidad, aplica excepciones y **decide** |
| Required check | solo `gate`. Cambiar la política no toca ningún escáner |
| Presupuesto de CI | < 10 min. Lo pesado va a `nightly-deep-scan.yml` |

## Módulos

| Workflow | Herramientas |
|---|---|
| `ci-jvm-maven.yml`  | checkstyle · pmd · spotless · semgrep · gitleaks · trivy |
| `ci-jvm-gradle.yml` | detekt · ktlint · semgrep · gitleaks · trivy |
| `ci-node.yml`       | eslint · tsc · semgrep · gitleaks · trivy |
| `ci-python.yml`     | ruff · mypy · semgrep · gitleaks · trivy |
| `ci-go.yml`         | golangci-lint · semgrep · gitleaks · trivy |
| `ci-container.yml`  | hadolint · trivy image |
| `ci-iac.yml`        | tflint · ansible-lint · helm lint · checkov · trivy |
| `ci-scripts.yml`    | shellcheck · PSScriptAnalyzer |
| `cd-publish.yml`    | syft · Dependency-Track · cosign/notation · registry |
| `nightly-deep-scan.yml` | trufflehog verificado · re-scan del registry |

`container`, `iac` y `scripts` **no** son alternativas a los módulos de
lenguaje: son aditivos. Un repo Java con Dockerfile y charts llama a los tres y
el `gate` corre una sola vez al final.

## Decisiones que conviene conocer antes de tocar nada

- **El gate necesita una fecha de corte.** Aplicarlo de golpe sobre un parque
  con años de deuda bloquea todos los PRs la primera semana, y el resultado
  previsible es que alguien desactive el required check. El corte degrada a
  aviso lo introducido antes de una fecha.
- **Las excepciones caducan siempre.** Sin `expires`, el gate falla. Sin esa
  regla, en seis meses el fichero es un cementerio y el gate no bloquea nada.
- **Dos herramientas de secretos, dos momentos.** Gitleaks informa sobre el
  diff del PR; TruffleHog `--only-verified` bloquea en la nocturna, porque un
  secreto verificado contra el proveedor es cierto por definición.
- **Cosign keyless, opcional.** Publica la identidad del repositorio en el log
  público de Rekor. En repos privados con nombres sensibles, se firma con clave
  en KMS/Key Vault o con Notation.
- **`id-token: write` solo en CD.** Sin ese permiso no hay token OIDC posible,
  aunque el proveedor de identidad esté mal configurado. Es la defensa en
  profundidad que protege el almacén de secretos.

## Por qué Dependency-Track

Un feed de artefactos (Azure Artifacts, GitHub Packages) no escanea, no evalúa
licencias y no reevalúa lo ya publicado. Un artefacto publicado en enero
afectado por una CVE de marzo deja de generar señal.
`actions/dtrack-upload` repone esa capacidad y aporta el histórico de SBOM que
sirve como evidencia de auditoría. Es opcional: sin `dtrack-url`, el CD
funciona igual pero pierde el escaneo continuo.

## Requisitos de organización

- **Actions access policy** de este repositorio abierta a la org, o ningún repo
  privado podrá llamar a sus reusable workflows.
- Ruleset en `main` con `gate` como required check.
- Environments con required reviewers para producción.
- Federated credentials acotadas por environment:
  `repo:ORG/REPO:environment:prod`. **Nunca con comodín**: un subject amplio
  deja que un workflow de pull request obtenga token de producción.

## Configuración local que NO se versiona

- `baseline.conf` — destinos de publicación de tu organización.
- `policy/gitleaks.local.toml` — patrones internos (prefijos de token propios,
  dominios de simulación de phishing). Publicarlos en un repo documentaría en
  claro justo lo que no interesa que se encuentre.

## Desarrollo

```bash
python -m pytest tests/ -q     # tests del gate
bash -n new-repo.sh            # sintaxis del generador
./bin/pin-actions.sh --check   # comprueba que las actions van por SHA
```

`selfcheck.yml` aplica el baseline a este mismo repositorio: si el gate no pasa
aquí, no está listo para nadie más.
