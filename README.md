# sast-scan

`sast-scan` is a Python CLI that orchestrates containerized OpenGrep and Trivy scans, normalizes findings into one model, applies policy, and generates console, JSON, HTML, and SARIF reports.

It does not replace OpenGrep or Trivy. OpenGrep performs source-code SAST. Trivy performs dependency vulnerability, secret, and misconfiguration scanning.

OpenGrep is configured to use the cloned community rule packs under `rules\opengrep\community\` plus project-specific gap rules under `rules\opengrep\custom\`. Trivy uses its own vulnerability database, secret rules, and misconfiguration rules.

## Quick Start

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .[dev]
docker build -t sast-scan/opengrep:latest .\docker\opengrep
sast-scan doctor
sast-scan scan .\examples\vulnerable --output-dir reports
```

Open `reports/scan.html` for the full report. Machine-readable output is written to `reports/scan.json` and `reports/scan.sarif`.

## One Command Scan Workflow

Use the same command for a file, folder, local repository, or public GitHub repository:

```powershell
sast-scan scan <target>
```

Examples:

```powershell
sast-scan scan .\examples\vulnerable
sast-scan scan .\examples\vulnerable\app.py
sast-scan scan C:\path\to\your\project
sast-scan scan https://github.com/octocat/Hello-World
```

By default this prints a terminal summary and writes complete reports to `reports\`:

- `reports\scan.html` for human review
- `reports\scan.json` for automation
- `reports\scan.sarif` for code-scanning integrations

The report includes target, status, scanner versions, files scanned, lines scanned, language/file-type coverage, severity counts, category counts, detailed findings, remediation guidance, references, and scanner errors if any scanner fails.

Each scanner section in `scan.json` includes `raw_finding_count`, `parsed_finding_count`, and `dropped_finding_count`. A zero dropped count means every raw scanner finding was carried into the normalized report.

## Scan Targets

```powershell
sast-scan scan .\app.py
sast-scan scan .\project
sast-scan scan .\local-git-repository
sast-scan scan https://github.com/OWASP/NodeGoat
```

Public GitHub repositories are cloned into a temporary workspace and deleted after the scan.

## Configuration

Default configuration lives in `configs/scanner.yaml`.

Important options:

- `scanners.opengrep.enabled`
- `scanners.opengrep.image`
- `scanners.opengrep.config`
- `scanners.trivy.enabled`
- `scanners.trivy.scanners`
- `scan.timeout_seconds`
- `scan.exclude`
- `policy.fail_on`
- `report.formats`

## Rule Coverage

OpenGrep community rules are stored locally in:

```text
rules\opengrep\community
```

They were cloned from:

```text
https://github.com/opengrep/opengrep-rules
```

Custom gap rules live in:

```text
rules\opengrep\custom\security.yaml
```

The default config enables community language rule directories plus the custom gap rules. `auto_select_rule_sources: true` keeps scans practical by loading only rule directories relevant to the detected file types, plus generic/problem-based/custom rules.

To update community rules later:

```powershell
git -C .\rules\opengrep\community pull --ff-only
```

## Security Model

- Scanned source is mounted read-only into scanner containers.
- The Docker socket is never mounted.
- Commands are executed as argument lists, not through shell concatenation.
- Scanner containers run with dropped Linux capabilities and `no-new-privileges`.
- OpenGrep runs without network access.
- Trivy network access is configurable because vulnerability DB updates may require it.
- Secret evidence is redacted before normalized reports are generated.

## Development Tests

```powershell
pytest
```

These tests validate configuration, parsing, normalization, deduplication, policy, reporting, and workspace behavior without requiring Docker.
