# Ubuntu CIS Compliance Auditing Framework (Bash)

<<<<<<< codex/enhance-engine-to-professional-standards-vyyhh5
Modular, Bash-based Ubuntu CIS auditing framework with deterministic checks and structured multi-format reporting.

## Architecture

- `core/` framework engine helpers and reporting backends
- `checks/` atomic CIS checks as standardized `check_*` functions
- `modules/` logical CIS group execution
- `reports/` generated TXT/CSV/JSON artifacts
- `ubuntu_cis_audit.sh` main execution entrypoint

## Check schema

Each check function defines:

- `SECTION`
- `SUBSECTION`
- `CONTROL`
- `CHECK_ID`
- `CHECK_NAME`
- `DESCRIPTION`
- `RATIONALE`
- `AUDIT`
- `RECOMMENDATION`
- `REMEDIATION`

## Reporting

The framework writes three report formats per run:

- Structured TXT (`.txt`)
- Group-ready CSV (`.csv`)
- Machine-readable JSON (`.json`)
=======
Bash-based CIS-style compliance auditing engine for Ubuntu.

## What changed

This version introduces a **structured classification model** for checks:

- `TOPIC`
- `SUBTOPIC`

Runtime output now uses:

- `TOPIC -> SUBTOPIC -> CHECK`

Example output label:

- `[PASS] [Filesystem/Core] Ensure mounting of cramfs filesystems is disabled`

## Why this matters

- Better organization for large rule sets
- More searchable output artifacts
- Prepares the engine for future filtering (e.g. `--topic`, `--subtopic`)
- Backward-compatible scoring and summaries
>>>>>>> main

## Run

```bash
<<<<<<< codex/enhance-engine-to-professional-standards-vyyhh5
bash ubuntu_cis_audit.sh
```

Reports are written to `reports/` with UTC timestamps.
=======
sudo bash ubuntu_cis_audit.sh
```

## Options

```bash
bash ubuntu_cis_audit.sh --help
bash ubuntu_cis_audit.sh --output ./my-audit.log
bash ubuntu_cis_audit.sh --quiet
```
>>>>>>> main
