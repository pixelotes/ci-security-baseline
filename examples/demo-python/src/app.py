"""Repo de demostración: contiene hallazgos plantados a propósito.

NO copiar nada de aquí a código real.
"""
import hashlib
import os
import subprocess

# hallazgo esperado: secreto embebido (gitleaks / semgrep)
API_TOKEN = "acme_sk_0123456789abcdef0123456789abcdef"

# hallazgo esperado: hash débil (semgrep p/python)
def huella(dato: str) -> str:
    return hashlib.md5(dato.encode()).hexdigest()

# hallazgo esperado: shell=True con entrada variable (semgrep p/python)
def listar(ruta: str) -> str:
    return subprocess.check_output(f"ls {ruta}", shell=True).decode()

def main() -> None:
    print(huella(os.environ.get("USER", "nadie")))

if __name__ == "__main__":
    main()
