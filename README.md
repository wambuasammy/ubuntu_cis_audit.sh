# Ubuntu CIS Compliance Auditing Framework (Bash)

Modular, Bash-based Ubuntu CIS auditing framework with deterministic checks and structured multi-format reporting.

## Architecture

- `core/` framework engine helpers, reporting backends, and scoring engine
- `checks/` atomic CIS checks as standardized `check_*` functions
- `modules/` top-level CIS section runners (`initial_setup.sh` for Section 1 and `services.sh` for Section 2)
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

## Implemented checks

The framework currently implements the pasted initial setup checklist through `1.10` and the services checklist through `2.4`, including inetd services, time synchronization, special-purpose server package removal checks, local-only MTA validation, service client removal checks, and nonessential service review.

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


## Scoring engine

`core/scoring.sh` computes weighted compliance and qualitative score banding.

- PASS = 1.0
- WARNING = 0.5
- MANUAL = 0.5
- FAIL = 0.0
