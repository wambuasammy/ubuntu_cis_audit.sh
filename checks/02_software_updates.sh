#!/bin/bash

set_software_update_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.2 Configure Software Updates"
  CONTROL="1.2 Configure Software Updates"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_2_1() {
  set_software_update_check_metadata "1.2.1" "Ensure package manager repositories are configured" "Systems need package manager repositories configured to receive patches and updates." "Misconfigured repositories may prevent patch identification or allow a rogue repository to introduce compromised software." "apt-cache policy" "Configure package manager repositories according to site policy."
  if audit_apt_repositories_configured; then record_result PASS; else record_result FAIL; fi
}

check_1_2_2() {
  set_software_update_check_metadata "1.2.2" "Ensure GPG keys are configured" "Most package managers implement GPG key signing to verify package integrity during installation." "Updates must come from valid sources to protect against spoofing and inadvertent malware installation." "apt-key list" "Update package manager GPG keys in accordance with site policy."
  if audit_apt_gpg_keys_configured; then record_result PASS; else record_result FAIL; fi
}
