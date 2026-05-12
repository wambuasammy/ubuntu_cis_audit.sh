#!/bin/bash

set_sudo_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.3 Configure sudo"
  CONTROL="1.3 Configure sudo"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_3_1() {
  set_sudo_check_metadata "1.3.1" "Ensure sudo is installed" "sudo allows a permitted user to execute commands as the superuser or another user according to policy." "sudo provides policy-controlled privilege escalation and supports security policy and I/O logging plugins." "dpkg -s sudo OR dpkg -s sudo-ldap" "Install sudo with apt install sudo or sudo-ldap according to site policy."
  if audit_any_package_installed "sudo" "sudo-ldap"; then record_result PASS; else record_result FAIL; fi
}

check_1_3_2() {
  set_sudo_check_metadata "1.3.2" "Ensure sudo commands use pty" "sudo can be configured to run commands only from a pseudo-terminal." "Requiring a pseudo-terminal helps prevent malicious sudo-launched processes from persisting in the background." "grep for Defaults use_pty in /etc/sudoers and /etc/sudoers.d/*" "Edit sudoers with visudo and add: Defaults use_pty."
  if audit_sudo_uses_pty; then record_result PASS; else record_result FAIL; fi
}

check_1_3_3() {
  set_sudo_check_metadata "1.3.3" "Ensure sudo log file exists" "sudo can use a custom log file." "A dedicated sudo log file simplifies auditing of sudo commands." "grep for Defaults logfile in /etc/sudoers and /etc/sudoers.d/*" "Edit sudoers with visudo and add a custom logfile, for example: Defaults logfile=\"/var/log/sudo.log\"."
  if audit_sudo_logfile_configured; then record_result PASS; else record_result FAIL; fi
}
