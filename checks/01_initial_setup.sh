#!/bin/bash

set_filesystem_check_metadata() {
  SECTION="1 Initial Setup"
  SUBSECTION="1.1 Filesystem Configuration"
  CHECK_ID="$1"
  CHECK_NAME="$2"
  DESCRIPTION="$3"
  RATIONALE="$4"
  AUDIT="$5"
  REMEDIATION="$6"
  RECOMMENDATION="$6"
}

record_mount_exists_check() {
  local mountpoint="$1"
  if audit_mount_exists "$mountpoint"; then record_result PASS; else record_result FAIL; fi
}

record_mount_option_check() {
  local mountpoint="$1" option="$2"
  if audit_mount_option "$mountpoint" "$option"; then record_result PASS; else record_result FAIL; fi
}

record_module_disabled_check() {
  local module="$1"
  if audit_kernel_module_disabled "$module"; then record_result PASS; else record_result FAIL; fi
}

check_1_1_1_1() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.1" "Ensure mounting of cramfs filesystems is disabled" "The cramfs filesystem type is a compressed read-only Linux filesystem embedded in small footprint systems." "Removing support for unneeded filesystem types reduces the local attack surface of the server." "modprobe -n -v cramfs; lsmod | grep cramfs" "Add 'install cramfs /bin/true' to a file under /etc/modprobe.d/ and unload cramfs."
  record_module_disabled_check "cramfs"
}

check_1_1_1_2() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.2" "Ensure mounting of freevxfs filesystems is disabled" "The freevxfs filesystem type is a free version of the Veritas filesystem used by HP-UX." "Removing support for unneeded filesystem types reduces the local attack surface of the system." "modprobe -n -v freevxfs; lsmod | grep freevxfs" "Add 'install freevxfs /bin/true' to a file under /etc/modprobe.d/ and unload freevxfs."
  record_module_disabled_check "freevxfs"
}

check_1_1_1_3() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.3" "Ensure mounting of jffs2 filesystems is disabled" "The jffs2 filesystem type is a log-structured filesystem used in flash memory devices." "Removing support for unneeded filesystem types reduces the local attack surface of the system." "modprobe -n -v jffs2; lsmod | grep jffs2" "Add 'install jffs2 /bin/true' to a file under /etc/modprobe.d/ and unload jffs2."
  record_module_disabled_check "jffs2"
}

check_1_1_1_4() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.4" "Ensure mounting of hfs filesystems is disabled" "The hfs filesystem type allows mounting Mac OS filesystems." "Removing support for unneeded filesystem types reduces the local attack surface of the system." "modprobe -n -v hfs; lsmod | grep hfs" "Add 'install hfs /bin/true' to a file under /etc/modprobe.d/ and unload hfs."
  record_module_disabled_check "hfs"
}

check_1_1_1_5() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.5" "Ensure mounting of hfsplus filesystems is disabled" "The hfsplus filesystem type allows mounting Mac OS filesystems." "Removing support for unneeded filesystem types reduces the local attack surface of the system." "modprobe -n -v hfsplus; lsmod | grep hfsplus" "Add 'install hfsplus /bin/true' to a file under /etc/modprobe.d/ and unload hfsplus."
  record_module_disabled_check "hfsplus"
}

check_1_1_1_6() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.6" "Ensure mounting of udf filesystems is disabled" "The udf filesystem type is used for ISO/IEC 13346 and ECMA-167 optical media formats." "Removing support for unneeded filesystem types reduces the local attack surface of the system." "modprobe -n -v udf; lsmod | grep udf" "Add 'install udf /bin/true' to a file under /etc/modprobe.d/ and unload udf."
  record_module_disabled_check "udf"
}

check_1_1_1_7() {
  CONTROL="1.1.1 Disable unused filesystems"
  set_filesystem_check_metadata "1.1.1.7" "Ensure mounting of FAT filesystems is limited" "The FAT filesystem format is commonly used by older Windows systems and removable media through the vfat module." "Removing or limiting support for unneeded filesystem types reduces the local attack surface of the system." "Review vfat entries in /etc/fstab; if not required, verify vfat is disabled with modprobe and lsmod." "If FAT is not required, add 'install vfat /bin/true' under /etc/modprobe.d/ and unload vfat; if UEFI requires FAT, restrict it to appropriate mounts."
  if audit_kernel_module_disabled "vfat"; then record_result PASS; else record_result MANUAL; fi
}

check_1_1_2() {
  CONTROL="1.1.2 Configure /tmp"
  set_filesystem_check_metadata "1.1.2" "Ensure /tmp is configured" "The /tmp directory is a world-writable directory used for temporary storage by all users and some applications." "Making /tmp its own filesystem allows administrators to apply restrictive mount options." "findmnt --kernel --mountpoint /tmp" "Configure /tmp in /etc/fstab or enable systemd tmp.mount with secure options."
  record_mount_exists_check "/tmp"
}

check_1_1_3() {
  CONTROL="1.1.2 Configure /tmp"
  set_filesystem_check_metadata "1.1.3" "Ensure nodev option set on /tmp partition" "The nodev mount option specifies that the filesystem cannot contain special devices." "The /tmp filesystem is not intended to support device files." "findmnt --kernel --mountpoint /tmp --options nodev" "Add nodev to the /tmp mount options and remount /tmp."
  record_mount_option_check "/tmp" "nodev"
}

check_1_1_4() {
  CONTROL="1.1.2 Configure /tmp"
  set_filesystem_check_metadata "1.1.4" "Ensure nosuid option set on /tmp partition" "The nosuid mount option specifies that the filesystem cannot contain setuid files." "The /tmp filesystem is intended for temporary file storage, not privileged executables." "findmnt --kernel --mountpoint /tmp --options nosuid" "Add nosuid to the /tmp mount options and remount /tmp."
  record_mount_option_check "/tmp" "nosuid"
}

check_1_1_5() {
  CONTROL="1.1.2 Configure /tmp"
  set_filesystem_check_metadata "1.1.5" "Ensure noexec option set on /tmp partition" "The noexec mount option specifies that the filesystem cannot contain executable binaries." "The /tmp filesystem is intended for temporary file storage, not executable content." "findmnt --kernel --mountpoint /tmp --options noexec" "Add noexec to the /tmp mount options and remount /tmp."
  record_mount_option_check "/tmp" "noexec"
}

check_1_1_6() {
  CONTROL="1.1.6 Configure /dev/shm"
  set_filesystem_check_metadata "1.1.6" "Ensure /dev/shm is configured" "/dev/shm provides shared memory and is mounted as tmpfs by systemd." "Configuring /dev/shm allows restrictive mount options to reduce executable shared-memory abuse." "findmnt --kernel --mountpoint /dev/shm" "Add or edit /dev/shm in /etc/fstab with noexec,nodev,nosuid and remount /dev/shm."
  record_mount_exists_check "/dev/shm"
}

check_1_1_7() {
  CONTROL="1.1.6 Configure /dev/shm"
  set_filesystem_check_metadata "1.1.7" "Ensure nodev option set on /dev/shm partition" "The nodev mount option specifies that the filesystem cannot contain special devices." "The /dev/shm filesystem is not intended to support device files." "findmnt --kernel --mountpoint /dev/shm --options nodev" "Add nodev to /dev/shm mount options and remount /dev/shm."
  record_mount_option_check "/dev/shm" "nodev"
}

check_1_1_8() {
  CONTROL="1.1.6 Configure /dev/shm"
  set_filesystem_check_metadata "1.1.8" "Ensure nosuid option set on /dev/shm partition" "The nosuid mount option specifies that the filesystem cannot contain setuid files." "This prevents users from introducing privileged programs onto shared memory." "findmnt --kernel --mountpoint /dev/shm --options nosuid" "Add nosuid to /dev/shm mount options and remount /dev/shm."
  record_mount_option_check "/dev/shm" "nosuid"
}

check_1_1_9() {
  CONTROL="1.1.6 Configure /dev/shm"
  set_filesystem_check_metadata "1.1.9" "Ensure noexec option set on /dev/shm partition" "The noexec mount option specifies that the filesystem cannot contain executable binaries." "This prevents users from executing programs from shared memory." "findmnt --kernel --mountpoint /dev/shm --options noexec" "Add noexec to /dev/shm mount options and remount /dev/shm."
  record_mount_option_check "/dev/shm" "noexec"
}

check_1_1_10() {
  CONTROL="1.1.10 Configure /var"
  set_filesystem_check_metadata "1.1.10" "Ensure separate partition exists for /var" "The /var directory is used by daemons and services to store dynamic data." "A separate /var partition helps reduce resource exhaustion risk from world-writable or growing data." "findmnt --kernel --mountpoint /var" "Create a separate partition for /var and configure /etc/fstab as appropriate."
  record_mount_exists_check "/var"
}

check_1_1_11() {
  CONTROL="1.1.11 Configure /var/tmp"
  set_filesystem_check_metadata "1.1.11" "Ensure separate partition exists for /var/tmp" "/var/tmp is a world-writable directory used for temporary storage by users and applications." "A separate /var/tmp partition supports restrictive mount options and resource containment." "findmnt --kernel --mountpoint /var/tmp" "Create a separate partition for /var/tmp and configure /etc/fstab as appropriate."
  record_mount_exists_check "/var/tmp"
}

check_1_1_12() {
  CONTROL="1.1.11 Configure /var/tmp"
  set_filesystem_check_metadata "1.1.12" "Ensure nodev option set on /var/tmp partition" "The nodev mount option specifies that the filesystem cannot contain special devices." "/var/tmp is not intended to support device files." "findmnt --kernel --mountpoint /var/tmp --options nodev" "Add nodev to /var/tmp mount options and remount /var/tmp."
  record_mount_option_check "/var/tmp" "nodev"
}

check_1_1_13() {
  CONTROL="1.1.11 Configure /var/tmp"
  set_filesystem_check_metadata "1.1.13" "Ensure nosuid option set on /var/tmp partition" "The nosuid mount option specifies that the filesystem cannot contain setuid files." "/var/tmp is intended for temporary file storage, not privileged executables." "findmnt --kernel --mountpoint /var/tmp --options nosuid" "Add nosuid to /var/tmp mount options and remount /var/tmp."
  record_mount_option_check "/var/tmp" "nosuid"
}

check_1_1_14() {
  CONTROL="1.1.11 Configure /var/tmp"
  set_filesystem_check_metadata "1.1.14" "Ensure noexec option set on /var/tmp partition" "The noexec mount option specifies that the filesystem cannot contain executable binaries." "/var/tmp is intended for temporary file storage, not executable content." "findmnt --kernel --mountpoint /var/tmp --options noexec" "Add noexec to /var/tmp mount options and remount /var/tmp."
  record_mount_option_check "/var/tmp" "noexec"
}

check_1_1_15() {
  CONTROL="1.1.15 Configure /var/log"
  set_filesystem_check_metadata "1.1.15" "Ensure separate partition exists for /var/log" "/var/log is used by system services to store log data." "A separate /var/log partition protects against resource exhaustion and helps protect log data." "findmnt --kernel --mountpoint /var/log" "Create a separate partition for /var/log and configure /etc/fstab as appropriate."
  record_mount_exists_check "/var/log"
}

check_1_1_16() {
  CONTROL="1.1.16 Configure /var/log/audit"
  set_filesystem_check_metadata "1.1.16" "Ensure separate partition exists for /var/log/audit" "auditd stores audit log data in /var/log/audit." "A separate audit log partition protects audit data and reduces resource exhaustion risk." "findmnt --kernel --mountpoint /var/log/audit" "Create a separate partition for /var/log/audit and configure /etc/fstab as appropriate."
  record_mount_exists_check "/var/log/audit"
}

check_1_1_17() {
  CONTROL="1.1.17 Configure /home"
  set_filesystem_check_metadata "1.1.17" "Ensure separate partition exists for /home" "/home supports disk storage needs of local users." "A separate /home partition protects against resource exhaustion and restricts user-stored files." "findmnt --kernel --mountpoint /home" "Create a separate partition for /home and configure /etc/fstab as appropriate."
  record_mount_exists_check "/home"
}

check_1_1_18() {
  CONTROL="1.1.17 Configure /home"
  set_filesystem_check_metadata "1.1.18" "Ensure nodev option set on /home partition" "The nodev mount option specifies that the filesystem cannot contain special devices." "User partitions are not intended to support device files." "findmnt --kernel --mountpoint /home --options nodev" "Add nodev to /home mount options and remount /home."
  record_mount_option_check "/home" "nodev"
}

check_1_1_19() {
  CONTROL="1.1.19 Configure removable media"
  set_filesystem_check_metadata "1.1.19" "Ensure nodev option set on removable media partitions" "The nodev mount option specifies that the filesystem cannot contain special devices." "Removable media with device files could be used to circumvent security controls." "Review mount output for removable media and verify nodev is set." "Add nodev to removable-media mount entries in /etc/fstab."
  record_result MANUAL
}

check_1_1_20() {
  CONTROL="1.1.19 Configure removable media"
  set_filesystem_check_metadata "1.1.20" "Ensure nosuid option set on removable media partitions" "The nosuid mount option specifies that the filesystem cannot contain setuid files." "This prevents users from introducing privileged programs from removable media." "Review mount output for removable media and verify nosuid is set." "Add nosuid to removable-media mount entries in /etc/fstab."
  record_result MANUAL
}

check_1_1_21() {
  CONTROL="1.1.19 Configure removable media"
  set_filesystem_check_metadata "1.1.21" "Ensure noexec option set on removable media partitions" "The noexec mount option specifies that the filesystem cannot contain executable binaries." "This prevents execution of potentially malicious software from removable media." "Review mount output for removable media and verify noexec is set." "Add noexec to removable-media mount entries in /etc/fstab."
  record_result MANUAL
}

check_1_1_22() {
  CONTROL="1.1.22 Configure world-writable directories"
  set_filesystem_check_metadata "1.1.22" "Ensure sticky bit is set on all world-writable directories" "The sticky bit on world-writable directories prevents users from deleting or renaming files they do not own." "This prevents deletion or renaming of another user's files in world-writable directories." "Find world-writable directories without the sticky bit across local filesystems." "Set the sticky bit on all world-writable directories using chmod a+t."
  if audit_world_writable_sticky_dirs; then record_result PASS; else record_result FAIL; fi
}

check_1_1_23() {
  CONTROL="1.1.23 Disable automounting"
  set_filesystem_check_metadata "1.1.23" "Disable Automounting" "autofs allows automatic mounting of devices such as CD/DVDs and USB drives." "Automounting can make attached media available to users without explicit mount permissions." "systemctl is-enabled autofs; dpkg -s autofs" "Mask autofs with systemctl --now mask autofs or remove it with apt purge autofs."
  if audit_service_not_enabled_or_not_installed "autofs" "autofs"; then record_result PASS; else record_result FAIL; fi
}

check_1_1_24() {
  CONTROL="1.1.24 Disable USB storage"
  set_filesystem_check_metadata "1.1.24" "Disable USB Storage" "USB storage provides a way to transfer and persist files outside network controls." "Restricting USB storage decreases physical attack surface and malware-introduction vectors." "modprobe -n -v usb-storage; lsmod | grep usb-storage" "Add 'install usb-storage /bin/true' to a file under /etc/modprobe.d/ and unload usb-storage."
  record_module_disabled_check "usb-storage"
}
