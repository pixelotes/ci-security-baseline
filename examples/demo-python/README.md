# demo-python

Example repository with findings **planted on purpose** to check that the gate
really blocks.

```bash
../../new-repo.sh --adopt . --dry-run
```

Expected findings: an embedded secret, an MD5 hash, a `shell=True` and two
dependencies with known CVEs.
