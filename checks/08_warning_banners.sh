#!/bin/bash

set_banner_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.8 Warning Banners"
  CONTROL="1.8.1 Command Line Warning Banners"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_8_1_1() {
  set_banner_check_metadata "1.8.1.1" "Ensure message of the day is configured properly" "/etc/motd is displayed after login as the message of the day." "Warning banners should not disclose OS or patch details to attackers." "cat /etc/motd and grep for OS disclosure escapes or OS ID" "Edit /etc/motd according to site policy and remove OS information, or remove the file if unused."
  if audit_banner_has_no_os_info "/etc/motd"; then record_result PASS; else record_result FAIL; fi
}

check_1_8_1_2() {
  set_banner_check_metadata "1.8.1.2" "Ensure local login warning banner is configured properly" "/etc/issue is displayed before local terminal login." "Warning banners should define legal status and avoid detailed platform disclosure." "cat /etc/issue and grep for OS disclosure escapes or OS ID" "Edit /etc/issue according to site policy and remove OS information."
  if audit_banner_has_no_os_info "/etc/issue"; then record_result PASS; else record_result FAIL; fi
}

check_1_8_1_3() {
  set_banner_check_metadata "1.8.1.3" "Ensure remote login warning banner is configured properly" "/etc/issue.net is displayed before remote login by configured services." "Remote warning banners should define legal status and avoid platform disclosure." "cat /etc/issue.net and grep for OS disclosure escapes or OS ID" "Edit /etc/issue.net according to site policy and remove OS information."
  if audit_banner_has_no_os_info "/etc/issue.net"; then record_result PASS; else record_result FAIL; fi
}

check_1_8_1_4() {
  set_banner_check_metadata "1.8.1.4" "Ensure permissions on /etc/motd are configured" "/etc/motd content can be modified if ownership or permissions are weak." "Incorrect ownership can allow unauthorized users to alter login messages." "stat /etc/motd" "Set root:root ownership and chmod u-x,go-wx /etc/motd, or remove /etc/motd if unused."
  if audit_file_root_owned_not_more_permissive_than_0644 "/etc/motd"; then record_result PASS; else record_result FAIL; fi
}

check_1_8_1_5() {
  set_banner_check_metadata "1.8.1.5" "Ensure permissions on /etc/issue are configured" "/etc/issue content can be modified if ownership or permissions are weak." "Incorrect ownership can allow unauthorized users to alter local login warnings." "stat /etc/issue" "Set root:root ownership and chmod u-x,go-wx /etc/issue."
  if audit_file_root_owned_not_more_permissive_than_0644 "/etc/issue"; then record_result PASS; else record_result FAIL; fi
}

check_1_8_1_6() {
  set_banner_check_metadata "1.8.1.6" "Ensure permissions on /etc/issue.net are configured" "/etc/issue.net content can be modified if ownership or permissions are weak." "Incorrect ownership can allow unauthorized users to alter remote login warnings." "stat /etc/issue.net" "Set root:root ownership and chmod u-x,go-wx /etc/issue.net."
  if audit_file_root_owned_not_more_permissive_than_0644 "/etc/issue.net"; then record_result PASS; else record_result FAIL; fi
}
