# ==================================================
# SECURE BOOT SETTINGS
# ==================================================

# Ensure bootloader password is set
if grep -Eq "^set superusers|password_pbkdf2" /boot/grub/grub.cfg 2>/dev/null; then
    pass "Ensure bootloader password is set"
else
    fail "Ensure bootloader password is set"
fi


# Ensure permissions on bootloader config are configured
if [ "$(stat -c %a /boot/grub/grub.cfg 2>/dev/null)" -le 400 ]; then
    pass "Ensure permissions on bootloader config are configured"
else
    fail "Ensure permissions on bootloader config are configured"
fi


# Ensure authentication required for single user mode
if grep -Eq "^root:[*!]" /etc/shadow; then
    pass "Ensure authentication required for single user mode"
else
    fail "Ensure authentication required for single user mode"
fi