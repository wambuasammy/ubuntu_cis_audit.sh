#!/bin/bash

set_process_hardening_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.6 Additional Process Hardening"
  CONTROL="1.6 Additional Process Hardening"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_6_1() {
  set_process_hardening_check_metadata "1.6.1" "Ensure XD/NX support is enabled" "XD/NX support prevents code execution on a per-memory-page basis on supported processors." "NX/XD mitigates exploitation of buffer overflow vulnerabilities." "journalctl | grep 'protection: active' or inspect /proc/cmdline and /proc/cpuinfo" "Enable NX/XD in BIOS/firmware and use a PAE-capable kernel on 32-bit systems if required."
  if audit_nx_enabled; then record_result PASS; else record_result FAIL; fi
}

check_1_6_2() {
  set_process_hardening_check_metadata "1.6.2" "Ensure address space layout randomization (ASLR) is enabled" "ASLR randomly arranges key process address-space regions." "Random virtual-memory placement makes memory-page exploits more difficult." "sysctl kernel.randomize_va_space and sysctl configuration files" "Set kernel.randomize_va_space = 2 in sysctl configuration and run sysctl -w kernel.randomize_va_space=2."
  if audit_sysctl_equals "kernel.randomize_va_space" "2" && audit_sysctl_configured "kernel.randomize_va_space" "2"; then record_result PASS; else record_result FAIL; fi
}

check_1_6_3() {
  set_process_hardening_check_metadata "1.6.3" "Ensure prelink is disabled" "prelink modifies ELF libraries and dynamically linked binaries to reduce relocation time." "prelink can interfere with AIDE and increase risk if common libraries are compromised." "dpkg -s prelink" "Restore binaries with prelink -ua if needed, then purge prelink."
  if audit_prelink_disabled; then record_result PASS; else record_result FAIL; fi
}

check_1_6_4() {
  set_process_hardening_check_metadata "1.6.4" "Ensure core dumps are restricted" "Core dumps contain process memory and can expose confidential information." "Hard core limits and fs.suid_dumpable=0 prevent users and setuid programs from dumping sensitive memory." "Check hard core limits, fs.suid_dumpable, sysctl config, and systemd-coredump settings if installed." "Set '* hard core 0', configure fs.suid_dumpable = 0, and if systemd-coredump is installed set Storage=none and ProcessSizeMax=0."
  if audit_core_dumps_restricted; then record_result PASS; else record_result FAIL; fi
}
