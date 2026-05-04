# Ubuntu CIS Audit

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

## Run

```bash
sudo bash ubuntu_cis_audit.sh
```

## Options

```bash
bash ubuntu_cis_audit.sh --help
bash ubuntu_cis_audit.sh --output ./my-audit.log
bash ubuntu_cis_audit.sh --quiet
```
