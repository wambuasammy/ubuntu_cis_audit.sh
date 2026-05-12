#!/bin/bash

set_apparmor_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.7 Mandatory Access Control"
  CONTROL="1.7.1 Configure AppArmor"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_7_1_1() {
  set_apparmor_check_metadata "1.7.1.1" "Ensure AppArmor is installed" "AppArmor provides Mandatory Access Controls." "Without MAC, only default discretionary access controls are available." "dpkg -s apparmor" "Install AppArmor with apt install apparmor."
  if audit_package_installed "apparmor"; then record_result PASS; else record_result FAIL; fi
}

check_1_7_1_2() {
  set_apparmor_check_metadata "1.7.1.2" "Ensure AppArmor is enabled in the bootloader configuration" "AppArmor must be enabled at boot and not overridden by bootloader parameters." "Bootloader-level enablement ensures AppArmor controls are active at startup." "Verify all linux lines in /boot/grub/grub.cfg include apparmor=1 and security=apparmor." "Add apparmor=1 security=apparmor to GRUB_CMDLINE_LINUX and run update-grub."
  if audit_apparmor_bootloader_enabled; then record_result PASS; else record_result FAIL; fi
}

check_1_7_1_3() {
  set_apparmor_check_metadata "1.7.1.3" "Ensure all AppArmor Profiles are in enforce or complain mode" "AppArmor profiles define what resources applications can access." "Loaded profiles must be activated to enforce or test policy coverage." "apparmor_status profiles and processes output" "Set profiles to enforce with aa-enforce or complain with aa-complain, then address unconfined processes."
  if audit_apparmor_profiles_active; then record_result PASS; else record_result FAIL; fi
}

check_1_7_1_4() {
  set_apparmor_check_metadata "1.7.1.4" "Ensure all AppArmor Profiles are enforcing" "AppArmor profiles define what resources applications can access." "Enforcing mode applies the strictest profile behavior for loaded policies." "apparmor_status profiles and processes output" "Set profiles to enforce with aa-enforce and restart or profile unconfined processes."
  if audit_apparmor_profiles_enforcing; then record_result PASS; else record_result FAIL; fi
}
