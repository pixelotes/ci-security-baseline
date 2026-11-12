# ci-security-baseline

A modular security pipeline for GitHub Actions. It is assembled per repository
according to its stack and gives the whole organization one common, blocking
gate.

> **Designed for GitHub without Advanced Security.** On Team plans there is no
> Code Scanning and no SARIF upload for private repositories, so the findings
> aggregator is our own and lives in `actions/gate`. If you do have GHAS this
> baseline is still useful: you can replace the gate with the Security tab.

## The idea in one sentence

A product repository only contains a ~15-line reference. The logic lives here
and is versioned by tag, so **an improvement to the baseline reaches every
repository by moving the `v1` tag, without opening a PR per repository**.

```
product repos        .github/workflows/ci.yml   ← generated once (15 lines)
                     .security-baseline.yml     ← threshold, cutoff, exceptions
        ↓ uses @v1
ci-security-baseline .github/workflows/ci-*.yml ← reusable workflows per stack
        ↓ uses
                     actions/*                  ← atomic composite actions
```

## Installation

To use it as is, reference it from your repositories:

```yaml
jobs:
  baseline:
    uses: pixelotes/ci-security-baseline/.github/workflows/ci-python.yml@v1
```

or let `new-repo.sh` generate the caller for you (see [Usage](#usage)).

To run your own copy, fork it and repoint the references:

```bash
git clone https://github.com/YOUR-ORG/YOUR-REPO
cd YOUR-REPO
./bin/set-org.sh YOUR-ORG YOUR-REPO      # rewrites the owner/repo in every uses:
cp baseline.conf.example baseline.conf   # optional: publishing destinations
```

`set-org.sh` is needed because GitHub **does not allow expressions in
`uses:`**: the owner and the repository name have to appear literally in every
reference. The repository ships stamped as `pixelotes/ci-security-baseline`;
the script rewrites whatever is currently stamped, so it can be run again after
a rename. Then publish the `v1` tag in your copy (the references point to it).

## Usage

```bash
./new-repo.sh                      # new repo, interactive mode
./new-repo.sh --adopt ../my-repo   # add the baseline to an existing repo
./new-repo.sh --dry-run            # show what it would do, write nothing
```

The script asks for the stack, version, gate threshold, cutoff date and
publishing target, and writes **only two files** into the target repository. It
copies no logic: if a baseline change forces you to touch the generated file,
the baseline is badly designed.

## Try it without touching anything real

```bash
pip install pyyaml pytest
python -m pytest tests/ -q        # 15 gate tests

./examples/probar-gate.sh          # the gate against sample SARIF files
./new-repo.sh --adopt examples/demo-python --dry-run
```

`examples/demo-python` is a minimal repo with deliberately planted findings:
use it to watch the gate actually block before pointing it at anything of
yours.

## Pipeline contract

| | |
|---|---|
| Scanners | emit SARIF and **never fail** (`continue-on-error: true`) |
| The `gate` | aggregates, normalizes severity, applies exceptions and **decides** |
| Required check | `gate` only. Changing the policy never touches a scanner |
| CI budget | < 10 min. Anything heavy goes to `nightly-deep-scan.yml` |

## Choosing which stages run

By default every module runs all its stages. To run only some, list them in
`.security-baseline.yml`; no workflow needs to change:

```yaml
version: 1
stages:
  - lint
  - secret-scan
  - sast
gate:
  severity: high
```

| Stage | What runs |
|---|---|
| `build` | build and tests |
| `lint` | linters and formatters |
| `sast` | Opengrep |
| `secret-scan` | Gitleaks on the PR diff |
| `sca` | OSV-Scanner (plus govulncheck for Go) |
| `container-scan` | image build and Trivy image scan |
| `iac-scan` | Checkov and Trivy config |
| `quality` | complexity and duplication report as a PR comment (informational) |

- `all` is accepted as a shortcut for every stage.
- Without a `stages:` key, every stage runs.
- An unknown name **fails** the run: a typo must never silently turn a
  security stage off. When the plan fails, the `gate` fails too, so the
  required check cannot go green.
- The `gate` always runs, whatever the selection. A stage that is switched off
  produces no findings, so the gate only judges what you left on. Each run
  prints the plan (enabled and skipped stages) in its job summary.
- Narrowing `stages:` weakens the pipeline, so the file is covered by
  `CODEOWNERS`: review changes to it like you would review an exception.

## Modules and tools

Each row is a reusable workflow; each column is a CI step; each cell lists the
tools that run in that step. `–` means the step does not apply to that module.

| Module (`ci-*.yml`) | Build & test | Lint & format | SAST | Secrets (PR diff) | Dependencies / SCA | Quality (informational) | Image & IaC scan |
|---|---|---|---|---|---|---|---|
| **Java · Maven** (`jvm-maven`) | `mvn verify` · JaCoCo report | Checkstyle · PMD · Spotless | Opengrep | Gitleaks | OSV-Scanner | lizard · jscpd | via `container` / `iac` |
| **Kotlin · Gradle** (`jvm-gradle`) | `gradle build` · JaCoCo report | detekt · ktlint | Opengrep | Gitleaks | OSV-Scanner | lizard · jscpd | via `container` / `iac` |
| **Node / TypeScript** (`node`) | `npm ci` · `npm test` | ESLint · `tsc --noEmit` · format check | Opengrep | Gitleaks | OSV-Scanner | lizard · jscpd | via `container` / `iac` |
| **Python** (`python`) | `pip install` · pytest | Ruff · mypy | Opengrep | Gitleaks | OSV-Scanner | lizard · jscpd | via `container` / `iac` |
| **Go** (`go`) | `go build` · `go test -race` | golangci-lint | Opengrep | Gitleaks | OSV-Scanner · govulncheck | lizard · jscpd | via `container` / `iac` |
| **Container** (`container`) | `docker buildx` (no push) | hadolint | – | – | – | – | Trivy image (vuln · secret · misconfig) |
| **IaC** (`iac`) | – | terraform fmt/validate · tflint · ansible-lint · helm lint · kubeconform | Checkov | – | – | – | Trivy config (misconfig · secret) |
| **Scripts** (`scripts`) | – | ShellCheck · PSScriptAnalyzer | – | Gitleaks | – | – | – |

Notes on the tool choices, picked for being light and fast (mostly single
binaries pinned by checksum):

- **Opengrep** replaces Semgrep: same rule format and same results on the
  rulesets we ran (identical finding counts), a ~45 MB binary instead of a
  ~300 MB Python install, and no telemetry. Rulesets such as `p/ci` come from
  the Semgrep registry and are covered by the *Semgrep Rules License v1.0*,
  which allows internal use but not offering them as a service.
- **OSV-Scanner** replaces Trivy for dependency vulnerabilities. It needs no
  database to download or cache and finds more advisories (it merges GHSA,
  PYSEC and others). It queries the osv.dev API with package names and
  versions, never your code; set `offline: true` in `scan-osv` if even that is
  too much.
- **govulncheck** (Go only) reports whether your code actually *calls* the
  vulnerable function: reachable findings come out as high, unreachable ones as
  low.
- **lizard and jscpd** (MIT) give the code-smell view you would get from
  SonarQube without running a server: functions above a cyclomatic-complexity
  threshold and duplicated blocks, posted as one PR comment that is updated on
  every push. It is informational: it never fails and the gate ignores it.
  Tests, vendored and generated code are excluded by default (`exclude` input).
  Ruff and golangci-lint also enable their complexity and simplification rules
  (`C90`, `SIM`, `gocyclo`, `gocognit`, `dupl`, `gocritic`), which
  show up as non-blocking lint warnings.
- **Trivy** stays where nothing else covers it: IaC misconfiguration, image
  scanning and the nightly full scan (including licenses).

Every module ends in the same `gate`, which runs once. `container`, `iac` and
`scripts` are **additive**, not alternatives to the language modules: a Java
repo with a Dockerfile and Helm charts calls all three, and the gate runs a
single time at the end. From any language module, switch them on with
`run-container: true` and `run-iac: true`; the gate waits for both.

Beyond the per-PR modules:

| Workflow | When | Build & publish | Supply chain | Secrets | Dependencies / SCA |
|---|---|---|---|---|---|
| `cd-publish.yml` | release | registry push (ACR) | Syft SBOM · Dependency-Track · cosign / Notation signing | – | Dependency-Track (continuous) |
| `nightly-deep-scan.yml` | nightly | – | re-scan of published images (Trivy image) | TruffleHog, history, `--only-verified` | Trivy fs (vuln · secret · license · misconfig) |

## Decisions worth knowing before you touch anything

- **The gate needs a cutoff date.** Applying it all at once to an estate with
  years of debt blocks every PR in the first week, and the predictable outcome
  is that someone disables the required check. The cutoff downgrades to a
  warning whatever was introduced before a given date.
- **Exceptions always expire.** Without `expires`, the gate fails. Without that
  rule, six months from now the file is a graveyard and the gate blocks
  nothing.
- **Two secret scanners, two moments.** Gitleaks reports on the PR diff;
  TruffleHog `--only-verified` blocks in the nightly, because a secret verified
  against the provider is real by definition.
- **Keyless cosign is optional.** It publishes the repository identity to the
  public Rekor log. For private repos with sensitive names, sign with a key in
  KMS/Key Vault or with Notation.
- **`id-token: write` only in CD.** Without that permission no OIDC token is
  possible, even if the identity provider is misconfigured. It is the
  defense in depth that protects the secret store.
- **Third-party actions are pinned by SHA**, `actions/*` included, with the
  release tag kept as a trailing comment so Dependabot still knows the version.
  `./bin/pin-actions.sh` does it and `--check` verifies it.

## Licensing: free to run on private repositories

Everything the baseline runs is open source and free to use on private
repositories; nothing needs GitHub Advanced Security or a paid scanner. That is
a design constraint, which is why CodeQL (free only for public repositories) is
not part of it.

| Tool | License |
|---|---|
| Opengrep | LGPL-2.1 |
| OSV-Scanner · govulncheck · Trivy · Checkov · Syft · cosign · Notation · Dependency-Track | Apache-2.0 / BSD-3 |
| Gitleaks · PSScriptAnalyzer · lizard · jscpd | MIT |
| TruffleHog | AGPL-3.0 |
| hadolint · ShellCheck · ansible-lint · golangci-lint | GPL-3.0 |
| tflint | MPL-2.0 |

The GPL and AGPL tools are only *run* in CI, never modified or redistributed,
so their copyleft does not reach your code. Two caveats:

- The rulesets Opengrep loads from the Semgrep registry (`p/ci`, `p/python`...)
  are under the *Semgrep Rules License v1.0*: fine for internal use, not for
  reselling them as a service. If that matters to you, pass your own rules
  through the `config` input and keep `policy/semgrep/`, which is ours.
- `terraform fmt/validate` runs the Terraform CLI (BUSL-1.1), which allows
  internal use. Swap it for OpenTofu (MPL-2.0) if you want a fully open stack.

GitHub's own free-tier limits still apply to private repositories (Actions
minutes and artifact storage). SARIF artifacts are kept for one day to stay
well under the storage quota.

## Why Dependency-Track

An artifact feed (Azure Artifacts, GitHub Packages) does not scan, does not
evaluate licenses and does not re-evaluate what was already published. An
artifact published in January and affected by a CVE from March stops producing
signal. `actions/dtrack-upload` restores that capability and provides the SBOM
history that serves as audit evidence. It is optional: without `dtrack-url`,
CD works the same but loses continuous scanning.

## Organization requirements

- If you run this from a **private** repository, its **Actions access policy**
  must be open to the organization, or no private repo will be able to call
  its reusable workflows. (A public repository needs nothing.)
- A ruleset on `main` with `gate` as a required check.
- Environments with required reviewers for production.
- Federated credentials scoped per environment:
  `repo:ORG/REPO:environment:prod`. **Never with a wildcard**: a broad subject
  lets a pull-request workflow obtain a production token.

## Local configuration that is NOT versioned

- `baseline.conf` — your organization's publishing destinations.
- `policy/gitleaks.local.toml` — internal patterns (own token prefixes,
  phishing-simulation domains). Publishing them in a repo would document in the
  clear exactly what you do not want found.

## Development

```bash
python -m pytest tests/ -q     # gate tests
bash -n new-repo.sh            # generator syntax
./bin/pin-actions.sh --check   # verify that actions are pinned by SHA
```

`selfcheck.yml` applies the baseline to this very repository: if the gate does
not pass here, it is not ready for anyone else.

## License

MIT — see [LICENSE](LICENSE).
