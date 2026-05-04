#!/bin/bash

set -u

############################################################
# Ubuntu CIS Security Audit Script
############################################################

PASS=0
FAIL=0
MANUAL=0

SCRIPT_NAME=$(basename "$0")
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
REPORT_DIR="./reports"
REPORT_FILE=""
QUIET=0

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [options]

Options:
  -o, --output <file>   Write full audit output to a specific file
  -q, --quiet           Suppress terminal output and write to report only
  -h, --help            Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -o|--output)
            REPORT_FILE="${2:-}"
            [[ -n "$REPORT_FILE" ]] || { echo "[ERROR] Missing file path for $1" >&2; exit 1; }
            shift 2
            ;;
        -q|--quiet)
            QUIET=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "[ERROR] Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

mkdir -p "$REPORT_DIR"
if [[ -z "$REPORT_FILE" ]]; then
    REPORT_FILE="$REPORT_DIR/cis-audit-$TIMESTAMP.log"
fi

if [[ "$QUIET" -eq 1 ]]; then
    exec >"$REPORT_FILE" 2>&1
else
    exec > >(tee "$REPORT_FILE") 2>&1
fi

if [[ "$EUID" -ne 0 ]]; then
    report_manual "Running without root may reduce audit coverage"
fi

TOPIC="General"
SUBTOPIC="General"

set_context() { TOPIC="$1"; SUBTOPIC="$2"; }
report_pass() { echo "[PASS] [$TOPIC/$SUBTOPIC] $1"; ((PASS++)); }
report_fail() { echo "[FAIL] [$TOPIC/$SUBTOPIC] $1"; ((FAIL++)); }
report_manual() { echo "[MANUAL] [$TOPIC/$SUBTOPIC] $1"; ((MANUAL++)); }

echo "Audit started (UTC): $(date -u +'%Y-%m-%d %H:%M:%S')"
echo "Report file        : $REPORT_FILE"
echo
echo "=================================================="
set_context "Filesystem" "Core"
echo "SECTION A: FILESYSTEM CONFIGURATION"
echo "=================================================="

# 1.1.1.1 Ensure mounting of cramfs filesystems is disabled
if modprobe -n -v cramfs 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of cramfs filesystems is disabled"
else
    report_fail "Ensure mounting of cramfs filesystems is disabled"
fi

# 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled
if modprobe -n -v freevxfs 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of freevxfs filesystems is disabled"
else
    report_fail "Ensure mounting of freevxfs filesystems is disabled"
fi

# 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled
if modprobe -n -v jffs2 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of jffs2 filesystems is disabled"
else
    report_fail "Ensure mounting of jffs2 filesystems is disabled"
fi

# 1.1.1.4 Ensure mounting of hfs filesystems is disabled
if modprobe -n -v hfs 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of hfs filesystems is disabled"
else
    report_fail "Ensure mounting of hfs filesystems is disabled"
fi

# 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled
if modprobe -n -v hfsplus 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of hfsplus filesystems is disabled"
else
    report_fail "Ensure mounting of hfsplus filesystems is disabled"
fi

# 1.1.1.6 Ensure mounting of udf filesystems is disabled
if modprobe -n -v udf 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of udf filesystems is disabled"
else
    report_fail "Ensure mounting of udf filesystems is disabled"
fi

# 1.1.1.7 Ensure mounting of FAT filesystems is limited
if modprobe -n -v vfat 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure mounting of FAT filesystems is limited"
else
    report_manual "Ensure mounting of FAT filesystems is limited"
fi

# 1.1.2 Ensure /tmp is configured
if mount | grep -E '\s/tmp\s' >/dev/null; then
    report_pass "Ensure /tmp is configured"
else
    report_fail "Ensure /tmp is configured"
fi

# 1.1.3 Ensure nodev option set on /tmp partition
if mount | grep -E '\s/tmp\s' | grep -q nodev; then
    report_pass "Ensure nodev option set on /tmp partition"
else
    report_fail "Ensure nodev option set on /tmp partition"
fi

# 1.1.4 Ensure nosuid option set on /tmp partition
if mount | grep -E '\s/tmp\s' | grep -q nosuid; then
    report_pass "Ensure nosuid option set on /tmp partition"
else
    report_fail "Ensure nosuid option set on /tmp partition"
fi

# 1.1.5 Ensure noexec option set on /tmp partition
if mount | grep -E '\s/tmp\s' | grep -q noexec; then
    report_pass "Ensure noexec option set on /tmp partition"
else
    report_fail "Ensure noexec option set on /tmp partition"
fi

# 1.1.6 Ensure /dev/shm is configured
if mount | grep -E '\s/dev/shm\s' >/dev/null; then
    report_pass "Ensure /dev/shm is configured"
else
    report_fail "Ensure /dev/shm is configured"
fi

# 1.1.7 Ensure nodev option set on /dev/shm partition
if mount | grep -E '\s/dev/shm\s' | grep -q nodev; then
    report_pass "Ensure nodev option set on /dev/shm partition"
else
    report_fail "Ensure nodev option set on /dev/shm partition"
fi

# 1.1.8 Ensure nosuid option set on /dev/shm partition
if mount | grep -E '\s/dev/shm\s' | grep -q nosuid; then
    report_pass "Ensure nosuid option set on /dev/shm partition"
else
    report_fail "Ensure nosuid option set on /dev/shm partition"
fi

# 1.1.9 Ensure noexec option set on /dev/shm partition
if mount | grep -E '\s/dev/shm\s' | grep -q noexec; then
    report_pass "Ensure noexec option set on /dev/shm partition"
else
    report_fail "Ensure noexec option set on /dev/shm partition"
fi

# 1.1.10 Ensure separate partition exists for /var
if mount | grep -E '\s/var\s' >/dev/null; then
    report_pass "Ensure separate partition exists for /var"
else
    report_manual "Ensure separate partition exists for /var"
fi

# 1.1.11 Ensure separate partition exists for /var/tmp
if mount | grep -E '\s/var/tmp\s' >/dev/null; then
    report_pass "Ensure separate partition exists for /var/tmp"
else
    report_manual "Ensure separate partition exists for /var/tmp"
fi

# 1.1.12 Ensure nodev option set on /var/tmp partition
if mount | grep -E '\s/var/tmp\s' | grep -q nodev; then
    report_pass "Ensure nodev option set on /var/tmp partition"
else
    report_fail "Ensure nodev option set on /var/tmp partition"
fi

# 1.1.13 Ensure nosuid option set on /var/tmp partition
if mount | grep -E '\s/var/tmp\s' | grep -q nosuid; then
    report_pass "Ensure nosuid option set on /var/tmp partition"
else
    report_fail "Ensure nosuid option set on /var/tmp partition"
fi

# 1.1.14 Ensure noexec option set on /var/tmp partition
if mount | grep -E '\s/var/tmp\s' | grep -q noexec; then
    report_pass "Ensure noexec option set on /var/tmp partition"
else
    report_fail "Ensure noexec option set on /var/tmp partition"
fi

# 1.1.15 Ensure separate partition exists for /var/log
if mount | grep -E '\s/var/log\s' >/dev/null; then
    report_pass "Ensure separate partition exists for /var/log"
else
    report_manual "Ensure separate partition exists for /var/log"
fi

# 1.1.16 Ensure separate partition exists for /var/log/audit
if mount | grep -E '\s/var/log/audit\s' >/dev/null; then
    report_pass "Ensure separate partition exists for /var/log/audit"
else
    report_manual "Ensure separate partition exists for /var/log/audit"
fi

# 1.1.17 Ensure separate partition exists for /home
if mount | grep -E '\s/home\s' >/dev/null; then
    report_pass "Ensure separate partition exists for /home"
else
    report_manual "Ensure separate partition exists for /home"
fi

# 1.1.18 Ensure nodev option set on /home partition
if mount | grep -E '\s/home\s' | grep -q nodev; then
    report_pass "Ensure nodev option set on /home partition"
else
    report_fail "Ensure nodev option set on /home partition"
fi

# 1.1.19 Ensure nodev option set on removable media partitions
report_manual "Ensure nodev option set on removable media partitions"

# 1.1.20 Ensure nosuid option set on removable media partitions
report_manual "Ensure nosuid option set on removable media partitions"

# 1.1.21 Ensure noexec option set on removable media partitions
report_manual "Ensure noexec option set on removable media partitions"

# 1.1.22 Ensure sticky bit is set on all world-writable directories
if df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | grep -q .; then
    report_fail "Ensure sticky bit is set on all world-writable directories"
else
    report_pass "Ensure sticky bit is set on all world-writable directories"
fi

# 1.1.23 Disable Automounting
if systemctl is-enabled autofs 2>/dev/null | grep -q enabled; then
    report_fail "Disable Automounting"
else
    report_pass "Disable Automounting"
fi

# 1.1.24 Disable USB storage
if modprobe -n -v usb-storage 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Disable USB storage"
else
    report_fail "Disable USB storage"
fi
echo
echo "=================================================="
set_context "Software Updates" "APT"
echo "CONFIGURE SOFTWARE UPDATES"
echo "=================================================="

# 1.2.1 Ensure package manager repositories are configured
if apt-cache policy 2>/dev/null | grep -q "http"; then
    report_pass "Ensure package manager repositories are configured"
else
    report_fail "Ensure package manager repositories are configured"
fi

# 1.2.2 Ensure GPG keys are configured
if apt-key list 2>/dev/null | grep -q "pub"; then
    report_pass "Ensure GPG keys are configured"
else
    report_fail "Ensure GPG keys are configured"
fi
echo
echo "=================================================="
set_context "Privilege Escalation" "sudo"
echo "CONFIGURE SUDO"
echo "=================================================="

# 1.3.1 Ensure sudo is installed
if dpkg -s sudo >/dev/null 2>&1 || dpkg -s sudo-ldap >/dev/null 2>&1; then
    report_pass "Ensure sudo is installed"
else
    report_fail "Ensure sudo is installed"
fi

# 1.3.2 Ensure sudo commands use pty
if grep -Ei '^\s*Defaults\s+([^#]+,\s*)?use_pty(,\s+\S+\s*)*(\s+#.*)?$' /etc/sudoers /etc/sudoers.d/* >/dev/null 2>&1; then
    report_pass "Ensure sudo commands use pty"
else
    report_fail "Ensure sudo commands use pty"
fi

# 1.3.3 Ensure sudo log file exists
if grep -Ei '^\s*Defaults\s+logfile=\S+' /etc/sudoers /etc/sudoers.d/* >/dev/null 2>&1; then
    report_pass "Ensure sudo log file exists"
else
    report_fail "Ensure sudo log file exists"
fi
echo
echo "=================================================="
set_context "File Integrity" "AIDE"
echo "FILESYSTEM INTEGRITY CHECKING"
echo "=================================================="

# 1.4.1 Ensure AIDE is installed
if dpkg -s aide 2>/dev/null | grep -q "Status: install ok installed" && \
   dpkg -s aide-common 2>/dev/null | grep -q "Status: install ok installed"; then
    report_pass "Ensure AIDE is installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure AIDE is installed"
    FAIL=$((FAIL+1))
fi

# 1.4.2 Ensure filesystem integrity is regularly checked
if crontab -u root -l 2>/dev/null | grep -q aide || \
   find /etc/cron.* /etc/crontab -type f -name "*aide*" 2>/dev/null | grep -q aide || \
   systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q enabled; then
    report_pass "Ensure filesystem integrity is regularly checked"
    PASS=$((PASS+1))
else
    report_fail "Ensure filesystem integrity is regularly checked"
    FAIL=$((FAIL+1))
fi


echo
echo "=================================================="
echo "SECURE BOOT SETTINGS"
echo "=================================================="

# 1.5.1 Ensure bootloader password is set
if grep -q "^set superusers" /boot/grub/grub.cfg 2>/dev/null && \
   grep -q "^password_pbkdf2" /boot/grub/grub.cfg 2>/dev/null; then
    report_pass "Ensure bootloader password is set"
    PASS=$((PASS+1))
else
    report_fail "Ensure bootloader password is set"
    FAIL=$((FAIL+1))
fi

# 1.5.2 Ensure permissions on bootloader config are configured
perm=$(stat -c "%a" /boot/grub/grub.cfg 2>/dev/null)
owner=$(stat -c "%U" /boot/grub/grub.cfg 2>/dev/null)

if [[ "$perm" -le 400 && "$owner" == "root" ]]; then
    report_pass "Ensure permissions on bootloader config are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on bootloader config are configured"
    FAIL=$((FAIL+1))
fi

# 1.5.3 Ensure authentication required for single user mode
if grep '^root:' /etc/shadow | grep -vq '^[^:]*:[!*]'; then
    report_pass "Ensure authentication required for single user mode"
    PASS=$((PASS+1))
else
    report_fail "Ensure authentication required for single user mode"
    FAIL=$((FAIL+1))
fi


echo
echo "=================================================="
echo "ADDITIONAL PROCESS HARDENING"
echo "=================================================="

# 1.6.1 Ensure XD/NX support is enabled
if journalctl 2>/dev/null | grep -q "NX (Execute Disable) protection: active"; then
    report_pass "Ensure XD/NX support is enabled"
    PASS=$((PASS+1))
else
    report_manual "Ensure XD/NX support is enabled"
    MANUAL=$((MANUAL+1))
fi

# 1.6.2 Ensure address space layout randomization (ASLR) is enabled
if sysctl kernel.randomize_va_space 2>/dev/null | grep -q "2"; then
    report_pass "Ensure address space layout randomization (ASLR) is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure address space layout randomization (ASLR) is enabled"
    FAIL=$((FAIL+1))
fi

# 1.6.3 Ensure prelink is disabled
if ! dpkg -s prelink >/dev/null 2>&1; then
    report_pass "Ensure prelink is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure prelink is disabled"
    FAIL=$((FAIL+1))
fi

# 1.6.4 Ensure core dumps are restricted
if grep -Eq "^\* hard core 0" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null && \
   sysctl fs.suid_dumpable 2>/dev/null | grep -q "0"; then
    report_pass "Ensure core dumps are restricted"
    PASS=$((PASS+1))
else
    report_fail "Ensure core dumps are restricted"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
echo "MANDATORY ACCESS CONTROL"
echo "=================================================="

# Ensure AppArmor is installed
if dpkg -s apparmor 2>/dev/null | grep -q "Status: install ok installed"; then
    report_pass "Ensure AppArmor is installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure AppArmor is installed"
    FAIL=$((FAIL+1))
fi

# Ensure AppArmor is enabled in the bootloader configuration
if grep "^\s*linux" /boot/grub/grub.cfg | grep -q "apparmor=1" && \
   grep "^\s*linux" /boot/grub/grub.cfg | grep -q "security=apparmor"; then
    report_pass "Ensure AppArmor is enabled in the bootloader configuration"
    PASS=$((PASS+1))
else
    report_fail "Ensure AppArmor is enabled in the bootloader configuration"
    FAIL=$((FAIL+1))
fi

# Ensure all AppArmor Profiles are in enforce or complain mode
if apparmor_status 2>/dev/null | grep -q "profiles are loaded"; then
    report_pass "Ensure all AppArmor Profiles are in enforce or complain mode"
    PASS=$((PASS+1))
else
    report_manual "Ensure all AppArmor Profiles are in enforce or complain mode"
    MANUAL=$((MANUAL+1))
fi

# Ensure all AppArmor Profiles are enforcing
if apparmor_status 2>/dev/null | grep -q "profiles are in enforce mode"; then
    report_pass "Ensure all AppArmor Profiles are enforcing"
    PASS=$((PASS+1))
else
    report_fail "Ensure all AppArmor Profiles are enforcing"
    FAIL=$((FAIL+1))
fi


echo
echo "=================================================="
echo "WARNING BANNERS"
echo "=================================================="

# Ensure message of the day is configured properly
if [ -f /etc/motd ] && ! grep -Ei "(\\\v|\\\r|\\\m|\\\s)" /etc/motd >/dev/null; then
    report_pass "Ensure message of the day is configured properly"
    PASS=$((PASS+1))
else
    report_fail "Ensure message of the day is configured properly"
    FAIL=$((FAIL+1))
fi

# Ensure local login warning banner is configured properly
if [ -f /etc/issue ] && ! grep -Ei "(\\\v|\\\r|\\\m|\\\s)" /etc/issue >/dev/null; then
    report_pass "Ensure local login warning banner is configured properly"
    PASS=$((PASS+1))
else
    report_fail "Ensure local login warning banner is configured properly"
    FAIL=$((FAIL+1))
fi

# Ensure remote login warning banner is configured properly
if [ -f /etc/issue.net ] && ! grep -Ei "(\\\v|\\\r|\\\m|\\\s)" /etc/issue.net >/dev/null; then
    report_pass "Ensure remote login warning banner is configured properly"
    PASS=$((PASS+1))
else
    report_fail "Ensure remote login warning banner is configured properly"
    FAIL=$((FAIL+1))
fi

# Ensure permissions on /etc/motd are configured
if [ ! -f /etc/motd ] || stat -c "%a %U %G" /etc/motd | grep -q "644 root root"; then
    report_pass "Ensure permissions on /etc/motd are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/motd are configured"
    FAIL=$((FAIL+1))
fi

# Ensure permissions on /etc/issue are configured
if stat -c "%a %U %G" /etc/issue | grep -q "644 root root"; then
    report_pass "Ensure permissions on /etc/issue are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/issue are configured"
    FAIL=$((FAIL+1))
fi

# Ensure permissions on /etc/issue.net are configured
if stat -c "%a %U %G" /etc/issue.net | grep -q "644 root root"; then
    report_pass "Ensure permissions on /etc/issue.net are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/issue.net are configured"
    FAIL=$((FAIL+1))
fi


echo
echo "=================================================="
echo "PATCH MANAGEMENT"
echo "=================================================="

# Ensure updates, patches, and additional security software are installed
if apt-get -s upgrade | grep -q "0 upgraded"; then
    report_pass "Ensure updates, patches, and additional security software are installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure updates, patches, and additional security software are installed"
    FAIL=$((FAIL+1))
fi


echo
echo "=================================================="
echo "GDM CONFIGURATION"
echo "=================================================="

# Ensure GDM is removed or login is configured
if ! dpkg -s gdm3 >/dev/null 2>&1; then
    report_pass "Ensure GDM is removed or login is configured"
    PASS=$((PASS+1))
else
    if grep -q "disable-user-list=true" /etc/gdm3/greeter.dconf-defaults 2>/dev/null; then
    report_pass "Ensure GDM is removed or login is configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure GDM is removed or login is configured"
        FAIL=$((FAIL+1))
    fi
fi
echo
echo "=================================================="
echo "SECTION B: SERVICES"
echo "=================================================="

echo
echo "---------------- INETD SERVICES ----------------"

# Ensure xinetd is not installed
if ! dpkg -s xinetd >/dev/null 2>&1; then
    report_pass "Ensure xinetd is not installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure xinetd is not installed"
    FAIL=$((FAIL+1))
fi

# Ensure openbsd-inetd is not installed
if ! dpkg -s openbsd-inetd >/dev/null 2>&1; then
    report_pass "Ensure openbsd-inetd is not installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure openbsd-inetd is not installed"
    FAIL=$((FAIL+1))
fi


echo
echo "------------- TIME SYNCHRONIZATION -------------"

# Ensure time synchronization is in use
if systemctl is-enabled systemd-timesyncd >/dev/null 2>&1 || \
   dpkg -s chrony >/dev/null 2>&1 || \
   dpkg -s ntp >/dev/null 2>&1; then
    report_pass "Ensure time synchronization is in use"
    PASS=$((PASS+1))
else
    report_fail "Ensure time synchronization is in use"
    FAIL=$((FAIL+1))
fi


echo
echo "----------- SPECIAL PURPOSE SERVICES -----------"

check_pkg_absent () {
    pkg=$1
    desc=$2

    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
    report_pass "$desc"
        PASS=$((PASS+1))
    else
    report_fail "$desc"
        FAIL=$((FAIL+1))
    fi
}

check_pkg_absent xserver-xorg "Ensure X Window System is not installed"
check_pkg_absent avahi-daemon "Ensure Avahi Server is not installed"
check_pkg_absent cups "Ensure CUPS is not installed"
check_pkg_absent isc-dhcp-server "Ensure DHCP Server is not installed"
check_pkg_absent slapd "Ensure LDAP server is not installed"
check_pkg_absent nfs-kernel-server "Ensure NFS is not installed"
check_pkg_absent bind9 "Ensure DNS Server is not installed"
check_pkg_absent vsftpd "Ensure FTP Server is not installed"
check_pkg_absent apache2 "Ensure HTTP server is not installed"
check_pkg_absent dovecot-imapd "Ensure IMAP server is not installed"
check_pkg_absent dovecot-pop3d "Ensure POP3 server is not installed"
check_pkg_absent samba "Ensure Samba is not installed"
check_pkg_absent squid "Ensure HTTP Proxy Server is not installed"
check_pkg_absent snmpd "Ensure SNMP Server is not installed"
check_pkg_absent rsync "Ensure rsync service is not installed"
check_pkg_absent nis "Ensure NIS Server is not installed"


echo
echo "--------------- SERVICE CLIENTS ----------------"

check_pkg_absent nis "Ensure NIS Client is not installed"
check_pkg_absent rsh-client "Ensure rsh client is not installed"
check_pkg_absent talk "Ensure talk client is not installed"
check_pkg_absent telnet "Ensure telnet client is not installed"
check_pkg_absent ldap-utils "Ensure LDAP client is not installed"
check_pkg_absent rpcbind "Ensure RPC is not installed"


echo
echo "------------- MAIL TRANSFER AGENT --------------"

if ss -lntu | grep ':25 ' | grep -vE '(127.0.0.1|::1)' >/dev/null; then
    report_fail "Ensure mail transfer agent is configured for local-only mode"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure mail transfer agent is configured for local-only mode"
    PASS=$((PASS+1))
fi


echo "----------- NONESSENTIAL SERVICES REVIEW --------"
report_manual "Ensure nonessential services are removed or masked"
echo

ss -tulnp | awk 'NR>1 {split($5,a,":"); split($7,b,"\""); printf "%-6s %s\n", a[length(a)], b[2]}' | sort -u
echo
echo "=================================================="
set_context "Networking" "Core"
echo "SECTION C: NETWORK CONFIGURATION"
echo "=================================================="

echo
echo "------------ DISABLE UNUSED NETWORK PROTOCOLS ------------"

# Disable IPv6
if grep -E "ipv6.disable=1" /boot/grub/grub.cfg >/dev/null 2>&1; then
    report_pass "Disable IPv6"
    PASS=$((PASS+1))
else
    report_fail "Disable IPv6"
    FAIL=$((FAIL+1))
fi


# Ensure wireless interfaces are disabled
if command -v nmcli >/dev/null 2>&1; then
    if nmcli radio all | grep -q "disabled"; then
    report_pass "Ensure wireless interfaces are disabled"
        PASS=$((PASS+1))
    else
    report_fail "Ensure wireless interfaces are disabled"
        FAIL=$((FAIL+1))
    fi
else
    report_manual "Ensure wireless interfaces are disabled (NetworkManager not installed)"
    MANUAL=$((MANUAL+1))
fi


echo
echo "------------ NETWORK PARAMETERS (HOST ONLY) ------------"

# Ensure packet redirect sending is disabled
if sysctl net.ipv4.conf.all.send_redirects | grep -q "= 0" && \
   sysctl net.ipv4.conf.default.send_redirects | grep -q "= 0"; then
    report_pass "Ensure packet redirect sending is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure packet redirect sending is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure IP forwarding is disabled
if sysctl net.ipv4.ip_forward | grep -q "= 0"; then
    report_pass "Ensure IP forwarding is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure IP forwarding is disabled"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ NETWORK PARAMETERS (HOST AND ROUTER) ------------"

# Ensure source routed packets are not accepted
if sysctl net.ipv4.conf.all.accept_source_route | grep -q "= 0" && \
   sysctl net.ipv4.conf.default.accept_source_route | grep -q "= 0"; then
    report_pass "Ensure source routed packets are not accepted"
    PASS=$((PASS+1))
else
    report_fail "Ensure source routed packets are not accepted"
    FAIL=$((FAIL+1))
fi


# Ensure ICMP redirects are not accepted
if sysctl net.ipv4.conf.all.accept_redirects | grep -q "= 0" && \
   sysctl net.ipv4.conf.default.accept_redirects | grep -q "= 0"; then
    report_pass "Ensure ICMP redirects are not accepted"
    PASS=$((PASS+1))
else
    report_fail "Ensure ICMP redirects are not accepted"
    FAIL=$((FAIL+1))
fi


# Ensure secure ICMP redirects are not accepted
if sysctl net.ipv4.conf.all.secure_redirects | grep -q "= 0" && \
   sysctl net.ipv4.conf.default.secure_redirects | grep -q "= 0"; then
    report_pass "Ensure secure ICMP redirects are not accepted"
    PASS=$((PASS+1))
else
    report_fail "Ensure secure ICMP redirects are not accepted"
    FAIL=$((FAIL+1))
fi


# Ensure suspicious packets are logged
if sysctl net.ipv4.conf.all.log_martians | grep -q "= 1" && \
   sysctl net.ipv4.conf.default.log_martians | grep -q "= 1"; then
    report_pass "Ensure suspicious packets are logged"
    PASS=$((PASS+1))
else
    report_fail "Ensure suspicious packets are logged"
    FAIL=$((FAIL+1))
fi


# Ensure broadcast ICMP requests are ignored
if sysctl net.ipv4.icmp_echo_ignore_broadcasts | grep -q "= 1"; then
    report_pass "Ensure broadcast ICMP requests are ignored"
    PASS=$((PASS+1))
else
    report_fail "Ensure broadcast ICMP requests are ignored"
    FAIL=$((FAIL+1))
fi


# Ensure bogus ICMP responses are ignored
if sysctl net.ipv4.icmp_ignore_bogus_error_responses | grep -q "= 1"; then
    report_pass "Ensure bogus ICMP responses are ignored"
    PASS=$((PASS+1))
else
    report_fail "Ensure bogus ICMP responses are ignored"
    FAIL=$((FAIL+1))
fi


# Ensure Reverse Path Filtering is enabled
if sysctl net.ipv4.conf.all.rp_filter | grep -q "= 1" && \
   sysctl net.ipv4.conf.default.rp_filter | grep -q "= 1"; then
    report_pass "Ensure Reverse Path Filtering is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure Reverse Path Filtering is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure TCP SYN Cookies is enabled
if sysctl net.ipv4.tcp_syncookies | grep -q "= 1"; then
    report_pass "Ensure TCP SYN Cookies is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure TCP SYN Cookies is enabled"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ UNCOMMON NETWORK PROTOCOLS ------------"

# Ensure DCCP is disabled
if modprobe -n -v dccp 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure DCCP is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure DCCP is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SCTP is disabled
if modprobe -n -v sctp 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure SCTP is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SCTP is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure RDS is disabled
if modprobe -n -v rds 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure RDS is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure RDS is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure TIPC is disabled
if modprobe -n -v tipc 2>/dev/null | grep -q "install /bin/true"; then
    report_pass "Ensure TIPC is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure TIPC is disabled"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
set_context "Firewall" "UFW"
echo "FIREWALL CONFIGURATION"
echo "=================================================="

echo
echo "------------ UFW CONFIGURATION ------------"

# Ensure Uncomplicated Firewall is installed
if dpkg -s ufw 2>/dev/null | grep -q "Status: install ok installed"; then
    report_pass "Ensure Uncomplicated Firewall is installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure Uncomplicated Firewall is installed"
    FAIL=$((FAIL+1))
fi


# Ensure iptables-persistent is not installed
if dpkg-query -s iptables-persistent 2>&1 | grep -q "is not installed"; then
    report_pass "Ensure iptables-persistent is not installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure iptables-persistent is not installed"
    FAIL=$((FAIL+1))
fi


# Ensure ufw service is enabled
if systemctl is-enabled ufw 2>/dev/null | grep -q enabled; then
    report_pass "Ensure ufw service is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure ufw service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure loopback traffic is configured
if ufw status verbose | grep -q "Anywhere on lo"; then
    report_pass "Ensure loopback traffic is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure loopback traffic is configured"
    FAIL=$((FAIL+1))
fi


# Ensure outbound connections are configured
if ufw status numbered >/dev/null 2>&1; then
    report_pass "Ensure outbound connections are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure outbound connections are configured"
    FAIL=$((FAIL+1))
fi


# Ensure firewall rules exist for all open ports
OPEN_PORTS=$(ss -4tuln | awk 'NR>1 {print $5}' | grep -v "127.0.0.1" | wc -l)

if [ "$OPEN_PORTS" -ge 0 ]; then
    report_pass "Ensure firewall rules exist for all open ports"
    PASS=$((PASS+1))
else
    report_fail "Ensure firewall rules exist for all open ports"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ NFTABLES CONFIGURATION ------------"

# Ensure nftables is installed
if dpkg-query -s nftables 2>/dev/null | grep -q "install ok installed"; then
    report_pass "Ensure nftables is installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables is installed"
    FAIL=$((FAIL+1))
fi


# Ensure UFW is not installed or disabled
if ! dpkg-query -s ufw >/dev/null 2>&1 || ufw status | grep -q inactive; then
    report_pass "Ensure UFW is not installed or disabled (nftables)"
    PASS=$((PASS+1))
else
    report_fail "Ensure UFW is not installed or disabled (nftables)"
    FAIL=$((FAIL+1))
fi


# Ensure iptables are flushed
if iptables -L | grep -q "Chain"; then
    report_pass "Ensure iptables are flushed"
    PASS=$((PASS+1))
else
    report_fail "Ensure iptables are flushed"
    FAIL=$((FAIL+1))
fi


# Ensure a table exists
if nft list tables 2>/dev/null | grep -q table; then
    report_pass "Ensure nftables table exists"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables table exists"
    FAIL=$((FAIL+1))
fi


# Ensure base chains exist
if nft list ruleset 2>/dev/null | grep -q "hook input"; then
    report_pass "Ensure nftables base chains exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables base chains exist"
    FAIL=$((FAIL+1))
fi


# Ensure loopback traffic is configured
if nft list ruleset 2>/dev/null | grep -q 'iif "lo" accept'; then
    report_pass "Ensure nftables loopback traffic configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables loopback traffic configured"
    FAIL=$((FAIL+1))
fi


# Ensure outbound and established connections configured
if nft list ruleset 2>/dev/null | grep -q "ct state"; then
    report_pass "Ensure outbound and established connections configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure outbound and established connections configured"
    FAIL=$((FAIL+1))
fi


# Ensure default deny firewall policy
if nft list ruleset 2>/dev/null | grep -q "policy drop"; then
    report_pass "Ensure default deny firewall policy"
    PASS=$((PASS+1))
else
    report_fail "Ensure default deny firewall policy"
    FAIL=$((FAIL+1))
fi


# Ensure nftables service is enabled
if systemctl is-enabled nftables 2>/dev/null | grep -q enabled; then
    report_pass "Ensure nftables service is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure nftables rules are permanent
if grep -q include /etc/nftables.conf 2>/dev/null; then
    report_pass "Ensure nftables rules are permanent"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables rules are permanent"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ IPTABLES CONFIGURATION ------------"

# Ensure iptables packages are installed
if apt list iptables 2>/dev/null | grep -q installed; then
    report_pass "Ensure iptables packages are installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure iptables packages are installed"
    FAIL=$((FAIL+1))
fi


# Ensure nftables is not installed
if dpkg -s nftables 2>&1 | grep -q "is not installed"; then
    report_pass "Ensure nftables is not installed (iptables mode)"
    PASS=$((PASS+1))
else
    report_fail "Ensure nftables is not installed (iptables mode)"
    FAIL=$((FAIL+1))
fi


# Ensure UFW is not installed or disabled
if ! dpkg-query -s ufw >/dev/null 2>&1 || ufw status | grep -q inactive; then
    report_pass "Ensure UFW is not installed or disabled (iptables)"
    PASS=$((PASS+1))
else
    report_fail "Ensure UFW is not installed or disabled (iptables)"
    FAIL=$((FAIL+1))
fi


# Ensure default deny firewall policy
if iptables -L | grep -q "policy DROP"; then
    report_pass "Ensure IPv4 default deny firewall policy"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv4 default deny firewall policy"
    FAIL=$((FAIL+1))
fi


# Ensure loopback traffic configured
if iptables -L INPUT -v -n | grep -q "lo"; then
    report_pass "Ensure IPv4 loopback traffic configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv4 loopback traffic configured"
    FAIL=$((FAIL+1))
fi


# Ensure outbound and established connections configured
if iptables -L -v -n | grep -q ESTABLISHED; then
    report_pass "Ensure outbound and established connections configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure outbound and established connections configured"
    FAIL=$((FAIL+1))
fi


# Ensure firewall rules exist for all open ports
if ss -4tuln >/dev/null; then
    report_pass "Ensure IPv4 firewall rules exist for all open ports"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv4 firewall rules exist for all open ports"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ IPV6 IPTABLES CONFIGURATION ------------"

# Ensure IPv6 default deny firewall policy
if ip6tables -L | grep -q "policy DROP"; then
    report_pass "Ensure IPv6 default deny firewall policy"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv6 default deny firewall policy"
    FAIL=$((FAIL+1))
fi


# Ensure IPv6 loopback traffic configured
if ip6tables -L | grep -q lo; then
    report_pass "Ensure IPv6 loopback traffic configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv6 loopback traffic configured"
    FAIL=$((FAIL+1))
fi


# Ensure outbound and established connections configured
if ip6tables -L -v -n | grep -q ESTABLISHED; then
    report_pass "Ensure IPv6 outbound and established connections configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv6 outbound and established connections configured"
    FAIL=$((FAIL+1))
fi


# Ensure IPv6 firewall rules exist for open ports
if ss -6tuln >/dev/null; then
    report_pass "Ensure IPv6 firewall rules exist for all open ports"
    PASS=$((PASS+1))
else
    report_fail "Ensure IPv6 firewall rules exist for all open ports"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
echo "Section B: LOGGING AND AUDITING"
echo "=================================================="

echo
echo "------------ AUDITD CONFIGURATION ------------"

# Ensure auditd is installed
if dpkg -s auditd audispd-plugins 2>/dev/null | grep -q "install ok installed"; then
    report_pass "Ensure auditd is installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure auditd is installed"
    FAIL=$((FAIL+1))
fi


# Ensure auditd service is enabled
if systemctl is-enabled auditd 2>/dev/null | grep -q enabled; then
    report_pass "Ensure auditd service is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure auditd service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure auditing for processes that start prior to auditd is enabled
if grep "^\s*linux" /boot/grub/grub.cfg 2>/dev/null | grep -q "audit=1"; then
    report_pass "Ensure auditing for processes prior to auditd is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure auditing for processes prior to auditd is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure audit_backlog_limit is sufficient
if grep "audit_backlog_limit=" /boot/grub/grub.cfg 2>/dev/null | grep -E "8192|16384|32768"; then
    report_pass "Ensure audit backlog limit configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure audit backlog limit configured"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ AUDIT LOG CONFIGURATION ------------"

# Ensure audit log storage size configured
if grep -q "max_log_file" /etc/audit/auditd.conf 2>/dev/null; then
    report_pass "Ensure audit log storage size configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure audit log storage size configured"
    FAIL=$((FAIL+1))
fi


# Ensure audit logs are not automatically deleted
if grep -q "max_log_file_action = keep_logs" /etc/audit/auditd.conf 2>/dev/null; then
    report_pass "Ensure audit logs are not automatically deleted"
    PASS=$((PASS+1))
else
    report_fail "Ensure audit logs are not automatically deleted"
    FAIL=$((FAIL+1))
fi


# Ensure system is disabled when audit logs are full
if grep -q "admin_space_left_action = halt" /etc/audit/auditd.conf 2>/dev/null; then
    report_pass "Ensure system disabled when audit logs are full"
    PASS=$((PASS+1))
else
    report_fail "Ensure system disabled when audit logs are full"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ AUDIT RULES CHECKS ------------"

# Ensure time-change events collected
if grep -q "time-change" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure time change events are collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure time change events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure identity events collected
if grep -q "identity" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure user/group modification events are collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure user/group modification events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure system-locale events collected
if grep -q "system-locale" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure network environment changes are collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure network environment changes are collected"
    FAIL=$((FAIL+1))
fi


# Ensure MAC policy changes collected
if grep -q "MAC-policy" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure MAC policy changes are collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure MAC policy changes are collected"
    FAIL=$((FAIL+1))
fi


# Ensure login events collected
if grep -q "logins" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure login events are collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure login events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure session events collected
if grep -q "session" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure session initiation events are collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure session initiation events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure permission modification events collected
if grep -q "perm_mod" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure permission modification events collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure permission modification events collected"
    FAIL=$((FAIL+1))
fi


# Ensure unauthorized file access attempts collected
if grep -q "access" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure unauthorized file access attempts collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure unauthorized file access attempts collected"
    FAIL=$((FAIL+1))
fi


# Ensure file deletion events collected
if grep -q "delete" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure file deletion events collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure file deletion events collected"
    FAIL=$((FAIL+1))
fi


# Ensure sudo scope changes collected
if grep -q "scope" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure sudo scope changes collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure sudo scope changes collected"
    FAIL=$((FAIL+1))
fi


# Ensure sudo command executions collected
if grep -q "actions" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure sudo command executions collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure sudo command executions collected"
    FAIL=$((FAIL+1))
fi


# Ensure kernel module events collected
if grep -q "modules" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure kernel module loading events collected"
    PASS=$((PASS+1))
else
    report_fail "Ensure kernel module loading events collected"
    FAIL=$((FAIL+1))
fi


# Ensure audit configuration immutable
if grep -q "^-e 2" /etc/audit/rules.d/*.rules 2>/dev/null; then
    report_pass "Ensure audit configuration is immutable"
    PASS=$((PASS+1))
else
    report_fail "Ensure audit configuration is immutable"
    FAIL=$((FAIL+1))
fi
echo
echo "------------ RSYSLOG CONFIGURATION ------------"

# Ensure rsyslog is installed
if dpkg -s rsyslog 2>/dev/null | grep -q "install ok installed"; then
    report_pass "Ensure rsyslog is installed"
    PASS=$((PASS+1))
else
    report_fail "Ensure rsyslog is installed"
    FAIL=$((FAIL+1))
fi


# Ensure rsyslog service is enabled
if systemctl is-enabled rsyslog 2>/dev/null | grep -q enabled; then
    report_pass "Ensure rsyslog service is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure rsyslog service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure logging is configured
if ls /var/log 2>/dev/null | grep -q auth.log; then
    report_pass "Ensure logging is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure logging is configured"
    FAIL=$((FAIL+1))
fi


# Ensure rsyslog default file permissions configured
if grep -E "^\s*\$FileCreateMode\s+0640" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    report_pass "Ensure rsyslog default file permissions configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure rsyslog default file permissions configured"
    FAIL=$((FAIL+1))
fi


# Ensure rsyslog configured to send logs to remote host
if grep -E "^[^#].*@@" /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null; then
    report_pass "Ensure rsyslog configured to send logs to remote host"
    PASS=$((PASS+1))
else
    report_fail "Ensure rsyslog configured to send logs to remote host"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ JOURNALD CONFIGURATION ------------"

# Ensure journald forwards logs to rsyslog
if grep -q "ForwardToSyslog=yes" /etc/systemd/journald.conf 2>/dev/null; then
    report_pass "Ensure journald forwards logs to rsyslog"
    PASS=$((PASS+1))
else
    report_fail "Ensure journald forwards logs to rsyslog"
    FAIL=$((FAIL+1))
fi


# Ensure journald compresses large log files
if grep -q "Compress=yes" /etc/systemd/journald.conf 2>/dev/null; then
    report_pass "Ensure journald compresses large log files"
    PASS=$((PASS+1))
else
    report_fail "Ensure journald compresses large log files"
    FAIL=$((FAIL+1))
fi


# Ensure journald logs persist to disk
if grep -q "Storage=persistent" /etc/systemd/journald.conf 2>/dev/null; then
    report_pass "Ensure journald logs persist to disk"
    PASS=$((PASS+1))
else
    report_fail "Ensure journald logs persist to disk"
    FAIL=$((FAIL+1))
fi


echo
echo "------------ LOG FILE SECURITY ------------"

# Ensure permissions on log files are restricted
if find /var/log -type f -perm /027 2>/dev/null | grep -q .; then
    report_fail "Ensure permissions on log files are restricted"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure permissions on log files are restricted"
    PASS=$((PASS+1))
fi


echo
echo "------------ LOGROTATE CONFIGURATION ------------"

# Ensure logrotate is configured
if [ -f /etc/logrotate.conf ]; then
    report_pass "Ensure logrotate is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure logrotate is configured"
    FAIL=$((FAIL+1))
fi


# Ensure logrotate assigns appropriate permissions
if grep -E "create\s+0640" /etc/logrotate.conf 2>/dev/null; then
    report_pass "Ensure logrotate assigns appropriate permissions"
    PASS=$((PASS+1))
else
    report_fail "Ensure logrotate assigns appropriate permissions"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
echo "SECTION E: ACCESS, AUTHENTICATION AND AUTHORIZATION"
echo "TIME-BASED JOB SCHEDULERS"
echo "=================================================="

# Ensure cron daemon is enabled and running
if systemctl is-enabled cron 2>/dev/null | grep -q enabled && \
   systemctl is-active cron 2>/dev/null | grep -q active; then
    report_pass "Ensure cron daemon is enabled and running"
    PASS=$((PASS+1))
else
    report_fail "Ensure cron daemon is enabled and running"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/crontab are configured
perm=$(stat -c "%a" /etc/crontab 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/crontab 2>/dev/null)

if [ "$perm" = "600" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/crontab are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/crontab are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.hourly are configured
perm=$(stat -c "%a" /etc/cron.hourly 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/cron.hourly 2>/dev/null)

if [ "$perm" = "700" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/cron.hourly are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/cron.hourly are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.daily are configured
perm=$(stat -c "%a" /etc/cron.daily 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/cron.daily 2>/dev/null)

if [ "$perm" = "700" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/cron.daily are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/cron.daily are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.weekly are configured
perm=$(stat -c "%a" /etc/cron.weekly 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/cron.weekly 2>/dev/null)

if [ "$perm" = "700" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/cron.weekly are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/cron.weekly are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.monthly are configured
perm=$(stat -c "%a" /etc/cron.monthly 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/cron.monthly 2>/dev/null)

if [ "$perm" = "700" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/cron.monthly are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/cron.monthly are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.d are configured
perm=$(stat -c "%a" /etc/cron.d 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/cron.d 2>/dev/null)

if [ "$perm" = "700" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/cron.d are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/cron.d are configured"
    FAIL=$((FAIL+1))
fi


# Ensure cron is restricted to authorized users
if [ -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ]; then
    report_pass "Ensure cron is restricted to authorized users"
    PASS=$((PASS+1))
else
    report_fail "Ensure cron is restricted to authorized users"
    FAIL=$((FAIL+1))
fi


# Ensure at is restricted to authorized users
if [ -f /etc/at.allow ] && [ ! -f /etc/at.deny ] && [ "$(stat -c %a /etc/at.allow)" -le 640 ]; then
    report_pass "Ensure at is restricted to authorized users"
    PASS=$((PASS+1))
else
    report_fail "Ensure at is restricted to authorized users"
    FAIL=$((FAIL+1))
fi
echo "=================================================="
echo "SSH SERVER CONFIGURATION"
echo "=================================================="

# Ensure permissions on /etc/ssh/sshd_config are configured
perm=$(stat -c "%a" /etc/ssh/sshd_config 2>/dev/null)
owner=$(stat -c "%U:%G" /etc/ssh/sshd_config 2>/dev/null)

if [ "$perm" = "600" ] && [ "$owner" = "root:root" ]; then
    report_pass "Ensure permissions on /etc/ssh/sshd_config are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/ssh/sshd_config are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on SSH private host key files are configured
if find /etc/ssh -xdev -type f -name "ssh_host_*_key" -perm /177 2>/dev/null | grep -q .; then
    report_fail "Ensure permissions on SSH private host key files are configured"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure permissions on SSH private host key files are configured"
    PASS=$((PASS+1))
fi


# Ensure permissions on SSH public host key files are configured
if find /etc/ssh -xdev -type f -name "ssh_host_*_key.pub" -perm /022 2>/dev/null | grep -q .; then
    report_fail "Ensure permissions on SSH public host key files are configured"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure permissions on SSH public host key files are configured"
    PASS=$((PASS+1))
fi


# Ensure SSH LogLevel is appropriate
if sshd -T 2>/dev/null | grep -Ei "loglevel (INFO|VERBOSE)"; then
    report_pass "Ensure SSH LogLevel is appropriate"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH LogLevel is appropriate"
    FAIL=$((FAIL+1))
fi


# Ensure SSH X11 forwarding is disabled
if sshd -T | grep -q "x11forwarding no"; then
    report_pass "Ensure SSH X11 forwarding is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH X11 forwarding is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH MaxAuthTries is set to 4 or less
val=$(sshd -T | grep maxauthtries | awk '{print $2}')
if [ "$val" -le 4 ]; then
    report_pass "Ensure SSH MaxAuthTries is set to 4 or less"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH MaxAuthTries is set to 4 or less"
    FAIL=$((FAIL+1))
fi


# Ensure SSH IgnoreRhosts is enabled
if sshd -T | grep -q "ignorerhosts yes"; then
    report_pass "Ensure SSH IgnoreRhosts is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH IgnoreRhosts is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH HostbasedAuthentication is disabled
if sshd -T | grep -q "hostbasedauthentication no"; then
    report_pass "Ensure SSH HostbasedAuthentication is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH HostbasedAuthentication is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH root login is disabled
if sshd -T | grep -q "permitrootlogin no"; then
    report_pass "Ensure SSH root login is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH root login is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH PermitEmptyPasswords is disabled
if sshd -T | grep -q "permitemptypasswords no"; then
    report_pass "Ensure SSH PermitEmptyPasswords is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH PermitEmptyPasswords is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH PermitUserEnvironment is disabled
if sshd -T | grep -q "permituserenvironment no"; then
    report_pass "Ensure SSH PermitUserEnvironment is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH PermitUserEnvironment is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure only strong Ciphers are used
if sshd -T 2>/dev/null | grep -E "^ciphers" | grep -q "cbc"; then
    report_fail "Ensure only strong Ciphers are used"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure only strong Ciphers are used"
    PASS=$((PASS+1))
fi


# Ensure only strong MAC algorithms are used
if sshd -T 2>/dev/null | grep -E "^macs" | grep -Eq "hmac-sha1(,|$)|umac-64@"; then
    report_fail "Ensure only strong MAC algorithms are used"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure only strong MAC algorithms are used"
    PASS=$((PASS+1))
fi


# Ensure only strong Key Exchange algorithms are used
if sshd -T | grep -i kexalgorithms | grep -E "sha1"; then
    report_fail "Ensure only strong Key Exchange algorithms are used"
    FAIL=$((FAIL+1))
else
    report_pass "Ensure only strong Key Exchange algorithms are used"
    PASS=$((PASS+1))
fi


# Ensure SSH Idle Timeout Interval is configured
interval=$(sshd -T | grep clientaliveinterval | awk '{print $2}')
count=$(sshd -T | grep clientalivecountmax | awk '{print $2}')

if [ "$interval" -le 300 ] && [ "$count" -le 3 ]; then
    report_pass "Ensure SSH Idle Timeout Interval is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH Idle Timeout Interval is configured"
    FAIL=$((FAIL+1))
fi


# Ensure SSH LoginGraceTime is set to one minute or less
grace=$(sshd -T | grep logingracetime | awk '{print $2}')
if [ "$grace" -le 60 ]; then
    report_pass "Ensure SSH LoginGraceTime is set to one minute or less"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH LoginGraceTime is set to one minute or less"
    FAIL=$((FAIL+1))
fi


# Ensure SSH access is limited
if sshd -T | grep -E "allowusers|allowgroups|denyusers|denygroups" >/dev/null; then
    report_pass "Ensure SSH access is limited"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH access is limited"
    FAIL=$((FAIL+1))
fi


# Ensure SSH warning banner is configured
if sshd -T | grep -q "banner /etc/issue.net"; then
    report_pass "Ensure SSH warning banner is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH warning banner is configured"
    FAIL=$((FAIL+1))
fi


# Ensure SSH PAM is enabled
if sshd -T | grep -iq "usepam yes"; then
    report_pass "Ensure SSH PAM is enabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH PAM is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH AllowTcpForwarding is disabled
if sshd -T | grep -iq "allowtcpforwarding no"; then
    report_pass "Ensure SSH AllowTcpForwarding is disabled"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH AllowTcpForwarding is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH MaxStartups is configured
if sshd -T | grep -iq "maxstartups"; then
    report_pass "Ensure SSH MaxStartups is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH MaxStartups is configured"
    FAIL=$((FAIL+1))
fi


# Ensure SSH MaxSessions is limited
sessions=$(sshd -T | grep maxsessions | awk '{print $2}')
if [ "$sessions" -le 10 ]; then
    report_pass "Ensure SSH MaxSessions is limited"
    PASS=$((PASS+1))
else
    report_fail "Ensure SSH MaxSessions is limited"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
echo "CONFIGURE PAM"
echo "=================================================="

# Ensure password creation requirements are configured
minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/* 2>/dev/null | awk '{print $3}' | head -1)
minclass=$(grep -E '^\s*minclass' /etc/security/pwquality.conf /etc/security/pwquality.conf.d/* 2>/dev/null | awk '{print $3}' | head -1)

minlen=${minlen:-0}
minclass=${minclass:-0}

if [[ "$minlen" =~ ^[0-9]+$ ]] && [[ "$minclass" =~ ^[0-9]+$ ]] && [ "$minlen" -ge 14 ] && [ "$minclass" -ge 4 ]; then
    report_pass "Ensure password creation requirements are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure password creation requirements are configured"
    FAIL=$((FAIL+1))
fi

# Ensure lockout for failed password attempts is configured
if grep -q "pam_tally2" /etc/pam.d/common-auth 2>/dev/null; then
    report_pass "Ensure lockout for failed password attempts is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure lockout for failed password attempts is configured"
    FAIL=$((FAIL+1))
fi


# Ensure password reuse is limited
if grep -E "pam_pwhistory\.so.*remember=([5-9]|[1-9][0-9]+)" /etc/pam.d/common-password 2>/dev/null; then
    report_pass "Ensure password reuse is limited"
    PASS=$((PASS+1))
else
    report_fail "Ensure password reuse is limited"
    FAIL=$((FAIL+1))
fi


# Ensure password hashing algorithm is SHA-512
if grep -E "pam_unix\.so.*sha512" /etc/pam.d/common-password 2>/dev/null; then
    report_pass "Ensure password hashing algorithm is SHA-512"
    PASS=$((PASS+1))
else
    report_fail "Ensure password hashing algorithm is SHA-512"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
echo "USER ACCOUNTS AND ENVIRONMENT"
echo "=================================================="

# Ensure password expiration is 365 days or less
maxdays=$(awk '/^\s*PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs)

if [[ "$maxdays" =~ ^[0-9]+$ ]] && [ "$maxdays" -le 365 ]; then
    report_pass "Ensure password expiration is 365 days or less"
    PASS=$((PASS+1))
else
    report_fail "Ensure password expiration is 365 days or less"
    FAIL=$((FAIL+1))
fi


# Ensure minimum days between password changes is configured
mindays=$(awk '/^\s*PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs)

if [[ "$mindays" =~ ^[0-9]+$ ]] && [ "$mindays" -ge 1 ]; then
    report_pass "Ensure minimum days between password changes is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure minimum days between password changes is configured"
    FAIL=$((FAIL+1))
fi


# Ensure password expiration warning days is 7 or more
warndays=$(awk '/^\s*PASS_WARN_AGE/{print $2; exit}' /etc/login.defs)

if [[ "$warndays" =~ ^[0-9]+$ ]] && [ "$warndays" -ge 7 ]; then
    report_pass "Ensure password expiration warning days is 7 or more"
    PASS=$((PASS+1))
else
    report_fail "Ensure password expiration warning days is 7 or more"
    FAIL=$((FAIL+1))
fi


# Ensure inactive password lock is 30 days or less
inactive=$(useradd -D | awk -F= '/INACTIVE/{print $2}')

if [[ "$inactive" =~ ^[0-9]+$ ]] && [ "$inactive" -le 30 ]; then
    report_pass "Ensure inactive password lock is 30 days or less"
    PASS=$((PASS+1))
else
    report_fail "Ensure inactive password lock is 30 days or less"
    FAIL=$((FAIL+1))
fi


# Ensure all users last password change date is in the past
report_manual "Ensure all users last password change date is in the past"
MANUAL=$((MANUAL+1))

# Ensure system accounts are non-login
nonlogin=$(awk -F: '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7!="/usr/sbin/nologin" && $7!="/sbin/nologin" && $7!="/bin/false") {print}' /etc/passwd)

if [ -z "$nonlogin" ]; then
    report_pass "Ensure system accounts are non-login"
    PASS=$((PASS+1))
else
    report_fail "Ensure system accounts are non-login"
    FAIL=$((FAIL+1))
fi

# Ensure default group for the root account is GID 0
root_gid=$(grep "^root:" /etc/passwd | cut -d: -f4)

if [ "$root_gid" -eq 0 ]; then
    report_pass "Ensure default group for the root account is GID 0"
    PASS=$((PASS+1))
else
    report_fail "Ensure default group for the root account is GID 0"
    FAIL=$((FAIL+1))
fi

# Ensure default user umask is 027 or more restrictive
umask_value=$(grep -R "umask" /etc/profile /etc/bash.bashrc /etc/profile.d/* 2>/dev/null | grep -Eo "umask [0-9]+" | awk '{print $2}' | head -1)

if [[ "$umask_value" =~ ^[0-9]+$ ]] && [ "$umask_value" -le 027 ]; then
    report_pass "Ensure default user umask is 027 or more restrictive"
    PASS=$((PASS+1))
else
    report_fail "Ensure default user umask is 027 or more restrictive"
    FAIL=$((FAIL+1))
fi

# Ensure access to the su command is restricted
if grep -Eq "pam_wheel.so.*use_uid" /etc/pam.d/su 2>/dev/null; then
    report_pass "Ensure access to the su command is restricted"
    PASS=$((PASS+1))
else
    report_fail "Ensure access to the su command is restricted"
    FAIL=$((FAIL+1))
fi

echo
echo "=================================================="
echo "SYSTEM MAINTENANCE"
echo "=================================================="

# Ensure permissions on /etc/passwd are configured
perm=$(stat -c "%a %u %g" /etc/passwd)
if [ "$perm" = "644 0 0" ]; then
    report_pass "Ensure permissions on /etc/passwd are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/passwd are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/shadow are configured
perm=$(stat -c "%a %u" /etc/shadow)
if [ "$(stat -c %a /etc/shadow)" -le 640 ] && [ "$(stat -c %u /etc/shadow)" -eq 0 ]; then
    report_pass "Ensure permissions on /etc/shadow are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/shadow are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/group are configured
perm=$(stat -c "%a %u %g" /etc/group)
if [ "$perm" = "644 0 0" ]; then
    report_pass "Ensure permissions on /etc/group are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/group are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/gshadow are configured
if [ "$(stat -c %a /etc/gshadow)" -le 640 ]; then
    report_pass "Ensure permissions on /etc/gshadow are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/gshadow are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/passwd- are configured
if [ -f /etc/passwd- ]; then
    if [ "$(stat -c %a /etc/passwd-)" -le 644 ]; then
    report_pass "Ensure permissions on /etc/passwd- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/passwd- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure permissions on /etc/shadow- are configured
if [ -f /etc/shadow- ]; then
    if [ "$(stat -c %a /etc/shadow-)" -le 640 ]; then
    report_pass "Ensure permissions on /etc/shadow- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/shadow- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure permissions on /etc/group- are configured
if [ -f /etc/group- ]; then
    if [ "$(stat -c %a /etc/group-)" -le 644 ]; then
    report_pass "Ensure permissions on /etc/group- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/group- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure permissions on /etc/gshadow- are configured
if [ -f /etc/gshadow- ]; then
    if [ "$(stat -c %a /etc/gshadow-)" -le 640 ]; then
    report_pass "Ensure permissions on /etc/gshadow- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/gshadow- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure no world writable files exist
if [ -z "$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)" ]; then
    report_pass "Ensure no world writable files exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure no world writable files exist"
    FAIL=$((FAIL+1))
fi


# Ensure no unowned files exist
if [ -z "$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)" ]; then
    report_pass "Ensure no unowned files or directories exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure no unowned files or directories exist"
    FAIL=$((FAIL+1))
fi


# Ensure no ungrouped files exist
if [ -z "$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)" ]; then
    report_pass "Ensure no ungrouped files or directories exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure no ungrouped files or directories exist"
    FAIL=$((FAIL+1))
    fi
    
echo
echo "=================================================="
echo "USER AND GROUP SETTINGS"
echo "=================================================="

# Ensure password fields are not empty
if [ -z "$(awk -F: '($2 == "") {print $1}' /etc/shadow)" ]; then
    report_pass "Ensure password fields are not empty"
    PASS=$((PASS+1))
else
    report_fail "Ensure password fields are not empty"
    FAIL=$((FAIL+1))
fi


# Ensure no legacy '+' entries exist in /etc/passwd
if ! grep -q '^\+:' /etc/passwd; then
    report_pass "Ensure no legacy '+' entries exist in /etc/passwd"
    PASS=$((PASS+1))
else
    report_fail "Ensure no legacy '+' entries exist in /etc/passwd"
    FAIL=$((FAIL+1))
fi


# Ensure no legacy '+' entries exist in /etc/shadow
if ! grep -q '^\+:' /etc/shadow; then
    report_pass "Ensure no legacy '+' entries exist in /etc/shadow"
    PASS=$((PASS+1))
else
    report_fail "Ensure no legacy '+' entries exist in /etc/shadow"
    FAIL=$((FAIL+1))
fi


# Ensure no legacy '+' entries exist in /etc/group
if ! grep -q '^\+:' /etc/group; then
    report_pass "Ensure no legacy '+' entries exist in /etc/group"
    PASS=$((PASS+1))
else
    report_fail "Ensure no legacy '+' entries exist in /etc/group"
    FAIL=$((FAIL+1))
fi


# Ensure root is the only UID 0 account
if [ "$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)" -eq 1 ]; then
    report_pass "Ensure root is the only UID 0 account"
    PASS=$((PASS+1))
else
    report_fail "Ensure root is the only UID 0 account"
    FAIL=$((FAIL+1))
fi


# Ensure root PATH Integrity
badpath=0

echo $PATH | grep "::" >/dev/null && badpath=1
echo $PATH | grep ":$" >/dev/null && badpath=1

for dir in $(echo $PATH | tr ":" " "); do
    [ "$dir" = "." ] && badpath=1
done

if [ "$badpath" -eq 0 ]; then
    report_pass "Ensure root PATH Integrity"
    PASS=$((PASS+1))
else
    report_fail "Ensure root PATH Integrity"
    FAIL=$((FAIL+1))
fifi
echo
echo "=================================================="
echo "USER ACCOUNTS AND ENVIRONMENT"
echo "=================================================="

# Ensure password expiration is 365 days or less
maxdays=$(awk '/^\s*PASS_MAX_DAYS/{print $2; exit}' /etc/login.defs)

if [[ "$maxdays" =~ ^[0-9]+$ ]] && [ "$maxdays" -le 365 ]; then
    report_pass "Ensure password expiration is 365 days or less"
    PASS=$((PASS+1))
else
    report_fail "Ensure password expiration is 365 days or less"
    FAIL=$((FAIL+1))
fi


# Ensure minimum days between password changes is configured
mindays=$(awk '/^\s*PASS_MIN_DAYS/{print $2; exit}' /etc/login.defs)

if [[ "$mindays" =~ ^[0-9]+$ ]] && [ "$mindays" -ge 1 ]; then
    report_pass "Ensure minimum days between password changes is configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure minimum days between password changes is configured"
    FAIL=$((FAIL+1))
fi


# Ensure password expiration warning days is 7 or more
warndays=$(awk '/^\s*PASS_WARN_AGE/{print $2; exit}' /etc/login.defs)

if [[ "$warndays" =~ ^[0-9]+$ ]] && [ "$warndays" -ge 7 ]; then
    report_pass "Ensure password expiration warning days is 7 or more"
    PASS=$((PASS+1))
else
    report_fail "Ensure password expiration warning days is 7 or more"
    FAIL=$((FAIL+1))
fi


# Ensure inactive password lock is 30 days or less
inactive=$(useradd -D | awk -F= '/INACTIVE/{print $2}')

if [[ "$inactive" =~ ^[0-9]+$ ]] && [ "$inactive" -le 30 ]; then
    report_pass "Ensure inactive password lock is 30 days or less"
    PASS=$((PASS+1))
else
    report_fail "Ensure inactive password lock is 30 days or less"
    FAIL=$((FAIL+1))
fi


# Ensure all users last password change date is in the past
report_manual "Ensure all users last password change date is in the past"
MANUAL=$((MANUAL+1))
    fi

report_manual "Ensure all users last password change date is in the past"
MANUAL=$((MANUAL+1))
echo
echo "=================================================="
echo "SYSTEM MAINTENANCE"
echo "=================================================="

# Ensure permissions on /etc/passwd are configured
perm=$(stat -c "%a %u %g" /etc/passwd)
if [ "$perm" = "644 0 0" ]; then
    report_pass "Ensure permissions on /etc/passwd are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/passwd are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/shadow are configured
perm=$(stat -c "%a %u" /etc/shadow)
if [ "$(stat -c %a /etc/shadow)" -le 640 ] && [ "$(stat -c %u /etc/shadow)" -eq 0 ]; then
    report_pass "Ensure permissions on /etc/shadow are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/shadow are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/group are configured
perm=$(stat -c "%a %u %g" /etc/group)
if [ "$perm" = "644 0 0" ]; then
    report_pass "Ensure permissions on /etc/group are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/group are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/gshadow are configured
if [ "$(stat -c %a /etc/gshadow)" -le 640 ]; then
    report_pass "Ensure permissions on /etc/gshadow are configured"
    PASS=$((PASS+1))
else
    report_fail "Ensure permissions on /etc/gshadow are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/passwd- are configured
if [ -f /etc/passwd- ]; then
    if [ "$(stat -c %a /etc/passwd-)" -le 644 ]; then
    report_pass "Ensure permissions on /etc/passwd- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/passwd- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure permissions on /etc/shadow- are configured
if [ -f /etc/shadow- ]; then
    if [ "$(stat -c %a /etc/shadow-)" -le 640 ]; then
    report_pass "Ensure permissions on /etc/shadow- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/shadow- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure permissions on /etc/group- are configured
if [ -f /etc/group- ]; then
    if [ "$(stat -c %a /etc/group-)" -le 644 ]; then
    report_pass "Ensure permissions on /etc/group- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/group- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure permissions on /etc/gshadow- are configured
if [ -f /etc/gshadow- ]; then
    if [ "$(stat -c %a /etc/gshadow-)" -le 640 ]; then
    report_pass "Ensure permissions on /etc/gshadow- are configured"
        PASS=$((PASS+1))
    else
    report_fail "Ensure permissions on /etc/gshadow- are configured"
        FAIL=$((FAIL+1))
    fi
fi


# Ensure no world writable files exist
if [ -z "$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)" ]; then
    report_pass "Ensure no world writable files exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure no world writable files exist"
    FAIL=$((FAIL+1))
fi


# Ensure no unowned files exist
if [ -z "$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)" ]; then
    report_pass "Ensure no unowned files or directories exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure no unowned files or directories exist"
    FAIL=$((FAIL+1))
fi


# Ensure no ungrouped files exist
if [ -z "$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)" ]; then
    report_pass "Ensure no ungrouped files or directories exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure no ungrouped files or directories exist"
    FAIL=$((FAIL+1))
    fi
    
echo
echo "=================================================="
echo "USER AND GROUP SETTINGS"
echo "=================================================="

# Ensure password fields are not empty
if [ -z "$(awk -F: '($2 == "") {print $1}' /etc/shadow)" ]; then
    report_pass "Ensure password fields are not empty"
    PASS=$((PASS+1))
else
    report_fail "Ensure password fields are not empty"
    FAIL=$((FAIL+1))
fi


# Ensure no legacy '+' entries exist in /etc/passwd
if ! grep -q '^\+:' /etc/passwd; then
    report_pass "Ensure no legacy '+' entries exist in /etc/passwd"
    PASS=$((PASS+1))
else
    report_fail "Ensure no legacy '+' entries exist in /etc/passwd"
    FAIL=$((FAIL+1))
fi


# Ensure no legacy '+' entries exist in /etc/shadow
if ! grep -q '^\+:' /etc/shadow; then
    report_pass "Ensure no legacy '+' entries exist in /etc/shadow"
    PASS=$((PASS+1))
else
    report_fail "Ensure no legacy '+' entries exist in /etc/shadow"
    FAIL=$((FAIL+1))
fi


# Ensure no legacy '+' entries exist in /etc/group
if ! grep -q '^\+:' /etc/group; then
    report_pass "Ensure no legacy '+' entries exist in /etc/group"
    PASS=$((PASS+1))
else
    report_fail "Ensure no legacy '+' entries exist in /etc/group"
    FAIL=$((FAIL+1))
fi


# Ensure root is the only UID 0 account
if [ "$(awk -F: '($3 == 0) {print $1}' /etc/passwd | wc -l)" -eq 1 ]; then
    report_pass "Ensure root is the only UID 0 account"
    PASS=$((PASS+1))
else
    report_fail "Ensure root is the only UID 0 account"
    FAIL=$((FAIL+1))
fi


# Ensure root PATH Integrity
badpath=0

echo $PATH | grep "::" >/dev/null && badpath=1
echo $PATH | grep ":$" >/dev/null && badpath=1

for dir in $(echo $PATH | tr ":" " "); do
    [ "$dir" = "." ] && badpath=1
done

if [ "$badpath" -eq 0 ]; then
    report_pass "Ensure root PATH Integrity"
    PASS=$((PASS+1))
else
    report_fail "Ensure root PATH Integrity"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
echo "USER AND GROUP SETTINGS (HOME DIRECTORY CONTROLS)"
echo "=================================================="

# Ensure all users' home directories exist
missing_home=0

while IFS=: read -r user x uid gid home shell; do
    if [ "$uid" -ge 1000 ] && [ "$shell" != "/usr/sbin/nologin" ] && [ "$shell" != "/bin/false" ]; then
        if [ ! -d "$home" ]; then
            missing_home=1
        fi
    fi
done < /etc/passwd

if [ "$missing_home" -eq 0 ]; then
    report_pass "Ensure all users' home directories exist"
    PASS=$((PASS+1))
else
    report_fail "Ensure all users' home directories exist"
    FAIL=$((FAIL+1))
fi


# Ensure users' home directories permissions are 750 or more restrictive
badperm=0

for dir in $(awk -F: '$3>=1000 && $7!="/usr/sbin/nologin" && $7!="/bin/false" {print $6}' /etc/passwd); do
    if [ -d "$dir" ]; then
        perm=$(stat -c "%a" "$dir")
        if [ "$perm" -gt 750 ]; then
            badperm=1
        fi
    fi
done

if [ "$badperm" -eq 0 ]; then
    report_pass "Ensure users' home directories permissions are 750 or more restrictive"
    PASS=$((PASS+1))
else
    report_fail "Ensure users' home directories permissions are 750 or more restrictive"
    FAIL=$((FAIL+1))
fi


# Ensure users own their home directories
badowner=0

while IFS=: read -r user x uid gid home shell; do
    if [ "$uid" -ge 1000 ] && [ -d "$home" ]; then
        owner=$(stat -c "%U" "$home")
        if [ "$owner" != "$user" ]; then
            badowner=1
        fi
    fi
done < /etc/passwd

if [ "$badowner" -eq 0 ]; then
    report_pass "Ensure users own their home directories"
    PASS=$((PASS+1))
else
    report_fail "Ensure users own their home directories"
    FAIL=$((FAIL+1))
fi


# Ensure users' dot files are not group or world writable
dot_issue=0

for dir in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
    if [ -d "$dir" ]; then
        for file in "$dir"/.[A-Za-z0-9]*; do
            [ -f "$file" ] || continue
            perm=$(stat -c "%a" "$file")
            if [ $((perm % 10)) -ge 2 ]; then
                dot_issue=1
            fi
        done
    fi
done

if [ "$dot_issue" -eq 0 ]; then
    report_pass "Ensure users' dot files are not group or world writable"
    PASS=$((PASS+1))
else
    report_fail "Ensure users' dot files are not group or world writable"
    FAIL=$((FAIL+1))
fi


# Ensure no users have .forward files
forward_found=0

for dir in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
    if [ -f "$dir/.forward" ]; then
        forward_found=1
    fi
done

if [ "$forward_found" -eq 0 ]; then
    report_pass "Ensure no users have .forward files"
    PASS=$((PASS+1))
else
    report_fail "Ensure no users have .forward files"
    FAIL=$((FAIL+1))
fi


# Ensure no users have .netrc files
netrc_found=0

for dir in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
    if [ -f "$dir/.netrc" ]; then
        netrc_found=1
    fi
done

if [ "$netrc_found" -eq 0 ]; then
    report_pass "Ensure no users have .netrc files"
    PASS=$((PASS+1))
else
    report_fail "Ensure no users have .netrc files"
    FAIL=$((FAIL+1))
fi


# Ensure users' .netrc files are not group or world accessible
netrc_perm_issue=0

for dir in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
    if [ -f "$dir/.netrc" ]; then
        perm=$(stat -c "%a" "$dir/.netrc")
        if [ "$perm" -gt 600 ]; then
            netrc_perm_issue=1
        fi
    fi
done

if [ "$netrc_perm_issue" -eq 0 ]; then
    report_pass "Ensure users' .netrc files are not group or world accessible"
    PASS=$((PASS+1))
else
    report_fail "Ensure users' .netrc files are not group or world accessible"
    FAIL=$((FAIL+1))
fi


# Ensure no users have .rhosts files
rhosts_found=0

for dir in $(awk -F: '$3>=1000 {print $6}' /etc/passwd); do
    if [ -f "$dir/.rhosts" ]; then
        rhosts_found=1
    fi
done

if [ "$rhosts_found" -eq 0 ]; then
    report_pass "Ensure no users have .rhosts files"
    PASS=$((PASS+1))
else
    report_fail "Ensure no users have .rhosts files"
    FAIL=$((FAIL+1))
fi
echo
echo "=================================================="
set_context "Summary" "Results"
echo "FINAL AUDIT SUMMARY"
echo "=================================================="

# Ensure counters exist (in case earlier sections didn't initialize them)
PASS=${PASS:-0}
FAIL=${FAIL:-0}
MANUAL=${MANUAL:-0}

TOTAL=$((PASS + FAIL + MANUAL))

if [ "$TOTAL" -gt 0 ]; then
    COMPLIANCE=$(awk "BEGIN {printf \"%.2f\", ($PASS/$TOTAL)*100}")
else
    COMPLIANCE="0.00"
fi

echo "Total Checks      : $TOTAL"
echo "Passed Checks     : $PASS"
echo "Failed Checks     : $FAIL"
echo "Manual Checks     : $MANUAL"
echo "Compliance Score  : $COMPLIANCE %"
echo "Topic model      : TOPIC -> SUBTOPIC -> CHECK"

echo "Report saved to: $REPORT_FILE"
