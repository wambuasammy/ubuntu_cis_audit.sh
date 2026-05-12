#!/bin/bash

set_file_integrity_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.4 Filesystem Integrity Checking"
  CONTROL="1.4 Filesystem Integrity Checking"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_4_1() {
  set_file_integrity_check_metadata "1.4.1" "Ensure AIDE is installed" "AIDE snapshots filesystem state including modification times, permissions, and file hashes for later comparison." "Filesystem-state monitoring can detect compromised or modified files." "dpkg -s aide; dpkg -s aide-common" "Install and initialize AIDE with apt install aide aide-common, aideinit, and move the generated database into place."
  if audit_package_installed "aide" && audit_package_installed "aide-common"; then record_result PASS; else record_result FAIL; fi
}

check_1_4_2() {
  set_file_integrity_check_metadata "1.4.2" "Ensure filesystem integrity is regularly checked" "Periodic filesystem integrity checking is needed to detect filesystem changes." "Scheduled integrity checks allow administrators to identify unauthorized changes to critical files." "Check root cron, /etc/cron.*, /etc/crontab, or aidecheck.timer/service for scheduled AIDE checks." "Schedule AIDE via root cron or configure aidecheck.service and aidecheck.timer according to site policy."
  if audit_aide_regularly_checked; then record_result PASS; else record_result FAIL; fi
}
