# ==================================================
# CIS Ubuntu Benchmark Section 4
# ==================================================


####################################################
# UFW CONFIGURATION
####################################################

echo
echo "------------ UFW CONFIGURATION ------------"

# Ensure UFW is installed
if command -v ufw >/dev/null 2>&1; then
    echo "[PASS] Ensure Uncomplicated Firewall is installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure Uncomplicated Firewall is installed"
    FAIL=$((FAIL+1))
fi


# Ensure iptables-persistent is not installed
if dpkg -s iptables-persistent >/dev/null 2>&1; then
    echo "[FAIL] Ensure iptables-persistent is not installed"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure iptables-persistent is not installed"
    PASS=$((PASS+1))
fi


# Ensure ufw service is enabled
if command -v ufw >/dev/null 2>&1; then
    if ufw status | grep -q "Status: active"; then
        echo "[PASS] Ensure ufw service is enabled"
        PASS=$((PASS+1))
    else
        echo "[FAIL] Ensure ufw service is enabled"
        FAIL=$((FAIL+1))
    fi
else
    echo "[FAIL] Ensure ufw service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure loopback traffic configured
if command -v ufw >/dev/null 2>&1; then
    if ufw status verbose | grep -q "Anywhere on lo"; then
        echo "[PASS] Ensure loopback traffic is configured"
        PASS=$((PASS+1))
    else
        echo "[FAIL] Ensure loopback traffic is configured"
        FAIL=$((FAIL+1))
    fi
else
    echo "[FAIL] Ensure loopback traffic is configured"
    FAIL=$((FAIL+1))
fi


# Ensure outbound connections configured
if command -v ufw >/dev/null 2>&1; then
    if ufw status verbose | grep -qi "allow out"; then
        echo "[PASS] Ensure outbound connections are configured"
        PASS=$((PASS+1))
    else
        echo "[FAIL] Ensure outbound connections are configured"
        FAIL=$((FAIL+1))
    fi
else
    echo "[FAIL] Ensure outbound connections are configured"
    FAIL=$((FAIL+1))
fi


####################################################
# NFTABLES CONFIGURATION
####################################################

echo
echo "------------ NFTABLES CONFIGURATION ------------"

# Ensure nftables installed
if command -v nft >/dev/null 2>&1; then
    echo "[PASS] Ensure nftables is installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nftables is installed"
    FAIL=$((FAIL+1))
fi


# Ensure nftables table exists
if nft list tables 2>/dev/null | grep -q table; then
    echo "[PASS] Ensure nftables table exists"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nftables table exists"
    FAIL=$((FAIL+1))
fi


# Ensure nftables service enabled
if systemctl is-enabled nftables >/dev/null 2>&1; then
    echo "[PASS] Ensure nftables service is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure nftables service is enabled"
    FAIL=$((FAIL+1))
fi


####################################################
# IPTABLES CONFIGURATION
####################################################

echo
echo "------------ IPTABLES CONFIGURATION ------------"

# Ensure iptables installed
if command -v iptables >/dev/null 2>&1; then
    echo "[PASS] Ensure iptables packages are installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure iptables packages are installed"
    FAIL=$((FAIL+1))
fi


# Ensure IPv4 default deny policy
if iptables -L | grep -q "Chain INPUT (policy DROP)"; then
    echo "[PASS] Ensure IPv4 default deny firewall policy"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure IPv4 default deny firewall policy"
    FAIL=$((FAIL+1))
fi


# Ensure loopback traffic configured
if iptables -L INPUT | grep -q lo; then
    echo "[PASS] Ensure IPv4 loopback traffic configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure IPv4 loopback traffic configured"
    FAIL=$((FAIL+1))
fi


####################################################
# IPV6 IPTABLES CONFIGURATION
####################################################

echo
echo "------------ IPV6 IPTABLES CONFIGURATION ------------"

# Ensure IPv6 default deny policy
if ip6tables -L | grep -q "Chain INPUT (policy DROP)"; then
    echo "[PASS] Ensure IPv6 default deny firewall policy"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure IPv6 default deny firewall policy"
    FAIL=$((FAIL+1))
fi


# Ensure IPv6 loopback configured
if ip6tables -L INPUT | grep -q lo; then
    echo "[PASS] Ensure IPv6 loopback traffic configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure IPv6 loopback traffic configured"
    FAIL=$((FAIL+1))
fi