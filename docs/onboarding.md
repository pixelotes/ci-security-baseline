# Adoptar el security baseline

## Qué va a pasar en tu repositorio

Se añaden dos ficheros:

- `.github/workflows/ci.yml` — llama al baseline. No debe crecer.
- `.security-baseline.yml` — umbral del gate, fecha de corte y excepciones.

Y aparece un check nuevo llamado **`gate`** en tus pull requests. Es el único
required check que añade el baseline.

## Qué hace el gate

Los escáneres (semgrep, gitleaks, trivy, checkov, hadolint) **nunca fallan**.
Emiten SARIF y siguen. El `gate` los agrega, normaliza la severidad entre
herramientas, aplica tus excepciones y la fecha de corte, y decide.

Si bloquea, verás en el PR un comentario con la tabla de hallazgos, la
ubicación exacta y la regla. Ese comentario se actualiza en cada push; no se
acumulan comentarios.

## Qué NO bloquea

- El **lint** (checkstyle, ruff, eslint, tflint…) señala calidad, no riesgo.
  Corre con `continue-on-error` y anota, pero no impide el merge. Mezclarlo con
  el gate haría que un `prettier` mal configurado bloqueara un hotfix.
- Los hallazgos **por debajo del umbral** de tu repo (por defecto, todo lo que
  no sea `high` o `critical`).
- Los hallazgos **anteriores a la fecha de corte**, durante 90 días.

## La fecha de corte

Cuando adoptas el baseline en un repo con historia, `cutoff` degrada a aviso
todo lo introducido antes de esa fecha. Lo que toques a partir de ahí sí
bloquea.

```yaml
gate:
  severity: high
  cutoff: '2026-10-01'
```

No es una amnistía indefinida: esos hallazgos aparecen en el comentario del PR
dentro de un desplegable y hay que drenarlos. Pero permite que el gate entre
en vigor sin parar al equipo el primer día.

## Antes del primer commit

```bash
pip install pre-commit
pre-commit install
```

El plan Team no incluye push protection en repos privados. Este hook es la
única barrera antes de que un secreto llegue al servidor.

## Si el gate te bloquea

1. **Arréglalo.** Es lo correcto en la mayoría de los casos.
2. **Si es un falso positivo o no es explotable**, declara una excepción en
   `.security-baseline.yml`. Ver [exceptions.md](exceptions.md).
3. **Si crees que la regla está mal**, abre un issue en `ci-security-baseline`:
   arreglar la regla ahí beneficia a todos los repos. Ver
   [runbook-falsos-positivos.md](runbook-falsos-positivos.md).

Lo que no vale es desactivar el check.
