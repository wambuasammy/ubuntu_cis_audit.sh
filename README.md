# Ubuntu CIS Audit

Lightweight Bash-based security audit tool for Ubuntu systems.  
Validates system configuration against **CIS-style Linux hardening controls** and reports **PASS / FAIL / MANUAL** results with a final compliance score.

**Author:** Sammy Wambua

---

## What it checks

- Patch management
- System services
- Network configuration
- Logging and auditing
- SSH configuration
- Authentication & PAM policies
- User account security
- System file permissions

---

## Supported systems

- Ubuntu 20.04
- Ubuntu 22.04
- Ubuntu 24.04

---

## Run

```bash
git clone https://github.com/wambuasammy/ubuntu_cis_audit.sh.git
cd ubuntu_cis_audit.sh
sudo bash ubuntu_cis_audit.sh
