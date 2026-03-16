# ==================================================
# SECTION C: NETWORK CONFIGURATION
# ==================================================

echo
echo "------------ DISABLE UNUSED NETWORK PROTOCOLS ------------"

# Disable IPv6
if sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "1"; then
    pass "Disable IPv6"
else
    fail "Disable IPv6"
fi


# Ensure wireless interfaces are disabled
if command -v nmcli >/dev/null 2>&1; then
    if nmcli radio wifi | grep -q disabled; then
        pass "Ensure wireless interfaces are disabled"
    else
        fail "Ensure wireless interfaces are disabled"
    fi
else
    manual "Ensure wireless interfaces are disabled"
fi

echo
echo "------------ NETWORK PARAMETERS (HOST ONLY) ------------"

# Ensure packet redirect sending is disabled
if sysctl net.ipv4.conf.all.send_redirects | grep -q "0"; then
    pass "Ensure packet redirect sending is disabled"
else
    fail "Ensure packet redirect sending is disabled"
fi


# Ensure IP forwarding is disabled
if sysctl net.ipv4.ip_forward | grep -q "0"; then
    pass "Ensure IP forwarding is disabled"
else
    fail "Ensure IP forwarding is disabled"
fi

echo
echo "------------ NETWORK PARAMETERS (HOST AND ROUTER) ------------"

if sysctl net.ipv4.conf.all.accept_source_route | grep -q "0"; then
    pass "Ensure source routed packets are not accepted"
else
    fail "Ensure source routed packets are not accepted"
fi

if sysctl net.ipv4.conf.all.accept_redirects | grep -q "0"; then
    pass "Ensure ICMP redirects are not accepted"
else
    fail "Ensure ICMP redirects are not accepted"
fi

if sysctl net.ipv4.conf.all.secure_redirects | grep -q "0"; then
    pass "Ensure secure ICMP redirects are not accepted"
else
    fail "Ensure secure ICMP redirects are not accepted"
fi

echo
echo "------------ UNCOMMON NETWORK PROTOCOLS ------------"

for proto in dccp sctp rds tipc; do
    if lsmod | grep -q "$proto"; then
        fail "Ensure $proto is disabled"
    else
        pass "Ensure $proto is disabled"
    fi
done

