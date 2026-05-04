#!/bin/bash

check_1_1_1_1() {
SECTION="1 Initial Setup"
SUBSECTION="1.1 Filesystem Configuration"
CONTROL="1.1.1 Disable unused filesystems"
CHECK_ID="1.1.1.1"
CHECK_NAME="Ensure mounting of cramfs filesystems is disabled"
DESCRIPTION="The cramfs module should be disabled unless required."
RATIONALE="Unused filesystems increase attack surface."
AUDIT="modprobe -n -v cramfs"
RECOMMENDATION="Disable cramfs module."
REMEDIATION="Add install cramfs /bin/true in modprobe config."

if audit_modprobe_disabled "cramfs"; then record_result PASS; else record_result FAIL; fi
}

check_1_1_1_2() {
SECTION="1 Initial Setup"
SUBSECTION="1.1 Filesystem Configuration"
CONTROL="1.1.1 Disable unused filesystems"
CHECK_ID="1.1.1.2"
CHECK_NAME="Ensure mounting of freevxfs filesystems is disabled"
DESCRIPTION="The freevxfs module should be disabled unless required."
RATIONALE="Unused filesystems increase attack surface."
AUDIT="modprobe -n -v freevxfs"
RECOMMENDATION="Disable freevxfs module."
REMEDIATION="Add install freevxfs /bin/true in modprobe config."

if audit_modprobe_disabled "freevxfs"; then record_result PASS; else record_result FAIL; fi
}

check_1_1_2() {
SECTION="1 Initial Setup"
SUBSECTION="1.1 Filesystem Configuration"
CONTROL="1.1.2 Configure /tmp"
CHECK_ID="1.1.2"
CHECK_NAME="Ensure /tmp is configured"
DESCRIPTION="/tmp should be separately mounted or securely configured."
RATIONALE="Separating /tmp improves containment."
AUDIT="mount | grep /tmp"
RECOMMENDATION="Configure secure /tmp mount."
REMEDIATION="Create and mount /tmp with secure options."

if audit_mount_exists "/tmp"; then record_result PASS; else record_result FAIL; fi
}

check_1_1_3() {
SECTION="1 Initial Setup"
SUBSECTION="1.1 Filesystem Configuration"
CONTROL="1.1.2 Configure /tmp"
CHECK_ID="1.1.3"
CHECK_NAME="Ensure nodev option set on /tmp partition"
DESCRIPTION="nodev prevents device files on /tmp."
RATIONALE="Reduces abuse of special device files."
AUDIT="mount | grep /tmp | grep nodev"
RECOMMENDATION="Set nodev on /tmp."
REMEDIATION="Update fstab and remount /tmp with nodev."

if audit_mount_option "/tmp" "nodev"; then record_result PASS; else record_result FAIL; fi
}
