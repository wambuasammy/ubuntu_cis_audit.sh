# Ubuntu CIS Compliance Auditing Framework (Bash)

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

## Run

```bash
bash ubuntu_cis_audit.sh
```

Reports are written to `reports/` with UTC timestamps.
