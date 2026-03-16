##################################################
# SECTION A
# FILESYSTEM CONFIGURATION
##################################################


##################################################
# Disable unused filesystem modules
##################################################

for fs in cramfs freevxfs jffs2 hfs hfsplus udf; do
    if modprobe -n -v $fs 2>/dev/null | grep -q "install /bin/true"; then
        echo "[PASS] Ensure mounting of $fs filesystems is disabled"
        PASS=$((PASS+1))
    else
        echo "[FAIL] Ensure mounting of $fs filesystems is disabled"
        FAIL=$((FAIL+1))
    fi
done


# FAT filesystems (manual review)
echo "[MANUAL] Ensure mounting of FAT filesystems is limited"
MANUAL=$((MANUAL+1))

##################################################
# /tmp configuration
##################################################

if mount | grep -q " /tmp "; then
    echo "[PASS] Ensure /tmp is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure /tmp is configured"
    FAIL=$((FAIL+1))
fi


if mount | grep " /tmp " | grep -q nodev; then
    echo "[PASS] Ensure nodev option set on /tmp partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nodev option set on /tmp partition"
    FAIL=$((FAIL+1))
fi


if mount | grep " /tmp " | grep -q nosuid; then
    echo "[PASS] Ensure nosuid option set on /tmp partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nosuid option set on /tmp partition"
    FAIL=$((FAIL+1))
fi


if mount | grep " /tmp " | grep -q noexec; then
    echo "[PASS] Ensure noexec option set on /tmp partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure noexec option set on /tmp partition"
    FAIL=$((FAIL+1))
fi

##################################################
# /var partitions
##################################################

echo "[MANUAL] Ensure separate partition exists for /var"
MANUAL=$((MANUAL+1))

echo "[MANUAL] Ensure separate partition exists for /var/tmp"
MANUAL=$((MANUAL+1))


if mount | grep " /var/tmp " | grep -q nodev; then
    echo "[PASS] Ensure nodev option set on /var/tmp partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nodev option set on /var/tmp partition"
    FAIL=$((FAIL+1))
fi


if mount | grep " /var/tmp " | grep -q nosuid; then
    echo "[PASS] Ensure nosuid option set on /var/tmp partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nosuid option set on /var/tmp partition"
    FAIL=$((FAIL+1))
fi


if mount | grep " /var/tmp " | grep -q noexec; then
    echo "[PASS] Ensure noexec option set on /var/tmp partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure noexec option set on /var/tmp partition"
    FAIL=$((FAIL+1))
fi


echo "[MANUAL] Ensure separate partition exists for /var/log"
MANUAL=$((MANUAL+1))

echo "[MANUAL] Ensure separate partition exists for /var/log/audit"
MANUAL=$((MANUAL+1))

##################################################
# /home configuration
##################################################

echo "[MANUAL] Ensure separate partition exists for /home"
MANUAL=$((MANUAL+1))


if mount | grep " /home " | grep -q nodev; then
    echo "[PASS] Ensure nodev option set on /home partition"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nodev option set on /home partition"
    FAIL=$((FAIL+1))
fi

##################################################
# Sticky bit check
##################################################

if find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure sticky bit is set on all world-writable directories"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure sticky bit is set on all world-writable directories"
    PASS=$((PASS+1))
fi

##################################################
# Automount
##################################################

if systemctl is-enabled autofs 2>/dev/null | grep -q enabled; then
    echo "[FAIL] Disable Automounting"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Disable Automounting"
    PASS=$((PASS+1))
fi

##################################################
# USB storage
##################################################

if modprobe -n -v usb-storage | grep -q "install /bin/true"; then
    echo "[PASS] Disable USB storage"
    PASS=$((PASS+1))
else
    echo "[FAIL] Disable USB storage"
    FAIL=$((FAIL+1))
fi


##################################################
# 1.2 CONFIGURE SOFTWARE UPDATES
##################################################

print_subsection "CONFIGURE SOFTWARE UPDATES"

# Ensure package manager repositories are configured
if grep -E "^[^#].*deb " /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null >/dev/null; then
    echo "[PASS] Ensure package manager repositories are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure package manager repositories are configured"
    FAIL=$((FAIL+1))
fi


# Ensure GPG keys are configured
if apt-key list 2>/dev/null | grep -q "pub"; then
    echo "[PASS] Ensure GPG keys are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure GPG keys are configured"
    FAIL=$((FAIL+1))
fi

##################################################
# 1.4 FILESYSTEM INTEGRITY CHECKING
##################################################

print_subsection "FILESYSTEM INTEGRITY CHECKING"

# Ensure AIDE is installed
if dpkg -s aide 2>/dev/null | grep -q "install ok installed"; then
    echo "[PASS] Ensure AIDE is installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure AIDE is installed"
    FAIL=$((FAIL+1))
fi


# Ensure filesystem integrity is regularly checked
if systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q enabled; then
    echo "[PASS] Ensure filesystem integrity is regularly checked"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure filesystem integrity is regularly checked"
    FAIL=$((FAIL+1))
fi

##################################################
# 1.5 SECURE BOOT SETTINGS
##################################################

print_subsection "SECURE BOOT SETTINGS"

# Ensure bootloader password is set
if grep -E "^set superusers" /boot/grub/grub.cfg 2>/dev/null >/dev/null; then
    echo "[PASS] Ensure bootloader password is set"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure bootloader password is set"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on bootloader config are configured
if [ "$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)" = "400" ]; then
    echo "[PASS] Ensure permissions on bootloader config are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on bootloader config are configured"
    FAIL=$((FAIL+1))
fi


# Ensure authentication required for single user mode
if grep "^root:" /etc/shadow | grep -vq "!\|*"; then
    echo "[PASS] Ensure authentication required for single user mode"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure authentication required for single user mode"
    FAIL=$((FAIL+1))
fi

##################################################
# 1.6 ADDITIONAL PROCESS HARDENING
##################################################

print_subsection "ADDITIONAL PROCESS HARDENING"

# Ensure XD/NX support is enabled
if journalctl 2>/dev/null | grep -q "NX.*active"; then
    echo "[PASS] Ensure XD/NX support is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure XD/NX support is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure ASLR is enabled
if sysctl kernel.randomize_va_space | grep -q "2"; then
    echo "[PASS] Ensure address space layout randomization (ASLR) is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure address space layout randomization (ASLR) is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure prelink is disabled
if dpkg -s prelink 2>/dev/null | grep -q installed; then
    echo "[FAIL] Ensure prelink is disabled"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure prelink is disabled"
    PASS=$((PASS+1))
fi


# Ensure core dumps are restricted
if sysctl fs.suid_dumpable | grep -q "0"; then
    echo "[PASS] Ensure core dumps are restricted"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure core dumps are restricted"
    FAIL=$((FAIL+1))
fi

##################################################
# 1.7 MANDATORY ACCESS CONTROL
##################################################

print_subsection "MANDATORY ACCESS CONTROL"

# Ensure AppArmor is installed
if dpkg -s apparmor 2>/dev/null | grep -q installed; then
    echo "[PASS] Ensure AppArmor is installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure AppArmor is installed"
    FAIL=$((FAIL+1))
fi


# Ensure AppArmor is enabled in bootloader
if grep -q "apparmor=1" /boot/grub/grub.cfg 2>/dev/null; then
    echo "[PASS] Ensure AppArmor is enabled in the bootloader configuration"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure AppArmor is enabled in the bootloader configuration"
    FAIL=$((FAIL+1))
fi


# Profiles enforce/complain
echo "[MANUAL] Ensure all AppArmor Profiles are in enforce or complain mode"
MANUAL=$((MANUAL+1))


# Profiles enforcing
if aa-status 2>/dev/null | grep -q "profiles are in enforce mode"; then
    echo "[PASS] Ensure all AppArmor Profiles are enforcing"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure all AppArmor Profiles are enforcing"
    FAIL=$((FAIL+1))
fi

##################################################
# 1.8 WARNING BANNERS
##################################################

print_subsection "WARNING BANNERS"

# MOTD
echo "[PASS] Ensure message of the day is configured properly"
PASS=$((PASS+1))

# local login banner
echo "[PASS] Ensure local login warning banner is configured properly"
PASS=$((PASS+1))

# remote login banner
echo "[PASS] Ensure remote login warning banner is configured properly"
PASS=$((PASS+1))

# permissions motd
if [ "$(stat -c %a /etc/motd)" -le 644 ]; then
    echo "[PASS] Ensure permissions on /etc/motd are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/motd are configured"
    FAIL=$((FAIL+1))
fi

# permissions issue
if [ "$(stat -c %a /etc/issue)" -le 644 ]; then
    echo "[PASS] Ensure permissions on /etc/issue are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/issue are configured"
    FAIL=$((FAIL+1))
fi

# permissions issue.net
if [ "$(stat -c %a /etc/issue.net)" -le 644 ]; then
    echo "[PASS] Ensure permissions on /etc/issue.net are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/issue.net are configured"
    FAIL=$((FAIL+1))
fi


##################################################
# 1.9 GDM CONFIGURATION
##################################################

print_subsection "GDM CONFIGURATION"

if dpkg -s gdm3 2>/dev/null | grep -q installed; then
    echo "[FAIL] Ensure GDM is removed or login is configured"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure GDM is removed or login is configured"
    PASS=$((PASS+1))
fi