# Runbook: falsos positivos

Un baseline que grita se acaba ignorando. El objetivo no es cero hallazgos,
es que **cada hallazgo que bloquea merezca la interrupción**.

## Árbol de decisión

```
¿El hallazgo es real en este contexto?
├─ Sí  → arreglar
└─ No
   ├─ ¿Fallaría igual en otros repos?
   │  ├─ Sí → arreglar la REGLA en security-baseline (beneficia a todos)
   │  └─ No → excepción local con scope, reason, owner y expires
   └─ ¿Es ruido sistemático de la herramienta?
      └─ ajustar policy/severity-map.yml o el allowlist de policy/
```

La pregunta que importa es la segunda: si el mismo falso positivo va a
aparecer en veinte repos, veinte excepciones locales son veinte sitios donde
mantener lo mismo.

## Dónde se arregla cada cosa

| Síntoma | Sitio |
|---|---|
| Regla de semgrep con demasiado ruido | `policy/semgrep/` o el `config` del módulo |
| Gitleaks marca ficheros de test | `policy/gitleaks.toml` → `allowlist.paths` |
| Severidad desproporcionada de una herramienta | `policy/severity-map.yml` → `overrides` |
| Checkov con checks no aplicables a la org | `policy/checkov/` |
| Solo afecta a un repositorio | `.security-baseline.yml` de ese repo |

## Señales de que el umbral está mal, no los equipos

Cada ola de despliegue tiene criterio de salida. Vigila:

- **Tasa de excepciones nuevas por semana.** Si crece ola tras ola, el problema
  es la política, no la disciplina de los equipos.
- **Tiempo mediano de PR.** Si sube de forma sostenida tras activar el gate, o
  bien el pipeline es lento (mirar caché) o bien bloquea demasiado.
- **Excepciones renovadas sin cambio de `reason`.** Señal de que la regla no
  aplica a ese contexto y hay que arreglarla arriba.

## Escalado

1. Issue en `security-baseline` con la etiqueta `false-positive`, adjuntando el
   SARIF del job.
2. Si bloquea una entrega, excepción local con `expires` corto (30 días) y el
   issue enlazado en `reason`.
3. `@__ORG__/security` decide si la regla se ajusta, se reclasifica o se
   mantiene.
