# ==================================================
# SECTION B: SERVICES
# ==================================================

echo
echo "---------------- INETD SERVICES ----------------"

# Ensure xinetd is not installed
if dpkg -s xinetd >/dev/null 2>&1; then
    fail "Ensure xinetd is not installed"
else
    pass "Ensure xinetd is not installed"
fi

# Ensure openbsd-inetd is not installed
if dpkg -s openbsd-inetd >/dev/null 2>&1; then
    fail "Ensure openbsd-inetd is not installed"
else
    pass "Ensure openbsd-inetd is not installed"
fi


echo
echo "------------- TIME SYNCHRONIZATION -------------"

# Ensure time synchronization is in use
if systemctl is-active systemd-timesyncd >/dev/null 2>&1 || dpkg -s chrony >/dev/null 2>&1; then
    pass "Ensure time synchronization is in use"
else
    fail "Ensure time synchronization is in use"
fi


echo
echo "----------- SPECIAL PURPOSE SERVICES -----------"

# Ensure X Window System is not installed
if dpkg -s xserver-xorg-core >/dev/null 2>&1; then
    fail "Ensure X Window System is not installed"
else
    pass "Ensure X Window System is not installed"
fi

# Ensure Avahi Server is not installed
if dpkg -s avahi-daemon >/dev/null 2>&1; then
    fail "Ensure Avahi Server is not installed"
else
    pass "Ensure Avahi Server is not installed"
fi

# Ensure CUPS is not installed
if dpkg -s cups >/dev/null 2>&1; then
    fail "Ensure CUPS is not installed"
else
    pass "Ensure CUPS is not installed"
fi

# Ensure DHCP server is not installed
if dpkg -s isc-dhcp-server >/dev/null 2>&1; then
    fail "Ensure DHCP Server is not installed"
else
    pass "Ensure DHCP Server is not installed"
fi