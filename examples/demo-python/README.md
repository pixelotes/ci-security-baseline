# demo-python

Repositorio de ejemplo con hallazgos **plantados a propósito** para comprobar
que el gate bloquea de verdad.

```bash
../../new-repo.sh --adopt . --dry-run
```

Hallazgos esperados: un secreto embebido, un hash MD5, un `shell=True` y dos
dependencias con CVE conocido.
