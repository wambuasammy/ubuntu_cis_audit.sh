#!/bin/bash

set_updates_gdm_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="$1"
  CONTROL="$2"
  CHECK_ID="$3"
  CHECK_NAME="$4"
  DESCRIPTION="$5"
  RATIONALE="$6"
  AUDIT="$7"
  REMEDIATION="$8"
  RECOMMENDATION="$8"
}

check_1_9() {
  set_updates_gdm_check_metadata "1.9 Updates, Patches, and Additional Security Software" "1.9 Updates, Patches, and Additional Security Software" "1.9" "Ensure updates, patches, and additional security software are installed" "Security and functionality patches are periodically released for installed software." "Current patches may contain important security enhancements unavailable in older package versions." "apt -s upgrade should show no packages to install" "Use apt upgrade or apt dist-upgrade according to site policy."
  if audit_no_pending_apt_upgrades; then record_result PASS; else record_result FAIL; fi
}

check_1_10() {
  set_updates_gdm_check_metadata "1.10 GDM Login Configuration" "1.10 GDM Login Configuration" "1.10" "Ensure GDM is removed or login is configured" "GDM handles graphical login for GNOME-based systems." "If graphical login is not required it should be removed; otherwise last-user display should be disabled and a warning banner configured." "If gdm3 is installed, verify greeter.dconf-defaults enables a banner and disables user list." "Remove gdm3 if unused, or configure /etc/gdm3/greeter.dconf-defaults with banner-message-enable=true, banner-message-text, and disable-user-list=true."
  if audit_gdm_removed_or_configured; then record_result PASS; else record_result FAIL; fi
}
