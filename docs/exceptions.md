# Excepciones

## Formato

```yaml
exceptions:
  - id: CVE-2025-48795          # ruleId o CVE
    tool: trivy                 # opcional: acota a una herramienta
    scope: 'pom.xml'            # opcional: glob sobre la ruta
    reason: 'No explotable: el parser XML no recibe entrada externa'
    owner: '@__ORG__/team-alpha'
    expires: '2026-12-15'       # OBLIGATORIO
```

## `expires` es obligatorio

Una excepción sin fecha de caducidad hace **fallar el gate**, aunque no haya
ningún hallazgo bloqueante. No es un descuido del diseño: es el diseño.

Sin caducidad, el fichero de excepciones crece de forma monótona y en seis
meses el gate no bloquea nada, mientras el dashboard sigue en verde. Con
caducidad, cada excepción vuelve a la mesa con un responsable con nombre.

Al vencer, el gate falla y el mensaje dice cuál venció. Renovarla es explícito
y queda en el historial de git: quién, cuándo y por qué.

## `reason` se lee

Escribe por qué **este** hallazgo no aplica, no qué es la vulnerabilidad.

- Mal: `'CVE en la librería XML'`
- Bien: `'El parser solo procesa ficheros del propio repositorio; no hay
  entrada externa que pueda contener una entidad maliciosa'`

Quien revise la renovación dentro de tres meses no tiene tu contexto de hoy.

## Buenas prácticas de `scope`

Acota siempre que puedas. Una excepción sin `scope` aplica a todo el repo, así
que una vulnerabilidad idéntica en un módulo nuevo pasa sin que nadie la vea.

```yaml
scope: 'src/test/resources/fixtures/**'   # bien
scope: '**'                               # equivale a no ponerlo
```

## Lo que NO se excepciona

- **Secretos verificados por TruffleHog.** Están confirmados contra el
  proveedor. Se rotan, no se excepcionan.
- **Exposición pública de recursos en IaC** (`CKV_*_public_*`). Si de verdad
  tiene que ser público, va por una decisión de arquitectura documentada, no
  por una línea en un YAML.

## Revisión

`CODEOWNERS` pone a `@__ORG__/security` como revisor obligatorio de
`.security-baseline.yml`. Una excepción sin revisar es la forma más silenciosa
de desactivar el gate.
