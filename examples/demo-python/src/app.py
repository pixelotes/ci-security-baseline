"""Demo repo: contains findings planted on purpose.

Do NOT copy anything from here into real code.
"""
import hashlib
import os
import subprocess

# expected finding: embedded secret (gitleaks / semgrep)
API_TOKEN = "acme_sk_0123456789abcdef0123456789abcdef"

# expected finding: weak hash (semgrep p/python)
def huella(dato: str) -> str:
    return hashlib.md5(dato.encode()).hexdigest()

# expected finding: shell=True with variable input (semgrep p/python)
def listar(ruta: str) -> str:
    return subprocess.check_output(f"ls {ruta}", shell=True).decode()

def main() -> None:
    print(huella(os.environ.get("USER", "nadie")))

if __name__ == "__main__":
    main()
