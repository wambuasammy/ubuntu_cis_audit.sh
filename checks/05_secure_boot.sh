#!/bin/bash

set_secure_boot_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.5 Secure Boot Settings"
  CONTROL="1.5 Secure Boot Settings"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

check_1_5_1() {
  set_secure_boot_check_metadata "1.5.1" "Ensure bootloader password is set" "Setting the bootloader password requires authentication before changing boot command-line parameters." "A boot password prevents unauthorized users from weakening security through boot parameters." "grep '^set superusers' /boot/grub/grub.cfg; grep '^password' /boot/grub/grub.cfg" "Create a PBKDF2 password with grub-mkpasswd-pbkdf2, add set superusers and password_pbkdf2 to a custom GRUB config, then run update-grub."
  if audit_grub_password_set; then record_result PASS; else record_result FAIL; fi
}

check_1_5_2() {
  set_secure_boot_check_metadata "1.5.2" "Ensure permissions on bootloader config are configured" "The GRUB configuration contains boot settings and passwords for boot option unlocks." "Root-only permissions prevent non-root users from reading boot parameters or changing them." "stat /boot/grub/grub.cfg" "Run chown root:root /boot/grub/grub.cfg and chmod og-rwx /boot/grub/grub.cfg."
  if audit_file_root_owned_group_other_restricted "/boot/grub/grub.cfg"; then record_result PASS; else record_result FAIL; fi
}

check_1_5_3() {
  set_secure_boot_check_metadata "1.5.3" "Ensure authentication required for single user mode" "Single-user mode is used for recovery during boot issues or manual bootloader selection." "Authentication prevents unauthorized users from rebooting into single-user mode for root access." "grep '^root:[*!]:' /etc/shadow should return no results" "Set a root password with passwd root."
  if audit_root_password_set; then record_result PASS; else record_result FAIL; fi
}
