####################################################
# SSH FILE PERMISSIONS
####################################################


# Ensure permissions on /etc/ssh/sshd_config are configured
if [ "$(stat -c %a /etc/ssh/sshd_config)" -le 600 ]; then
    echo "[PASS] Ensure permissions on /etc/ssh/sshd_config are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/ssh/sshd_config are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on SSH private host key files are configured
if find /etc/ssh -type f -name "ssh_host_*_key" -perm /0177 | grep -q .; then
    echo "[FAIL] Ensure permissions on SSH private host key files are configured"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure permissions on SSH private host key files are configured"
    PASS=$((PASS+1))
fi


# Ensure permissions on SSH public host key files are configured
if find /etc/ssh -type f -name "ssh_host_*_key.pub" -perm /0133 | grep -q .; then
    echo "[FAIL] Ensure permissions on SSH public host key files are configured"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure permissions on SSH public host key files are configured"
    PASS=$((PASS+1))
fi

####################################################
# SSH HARDENING SETTINGS
####################################################

# Ensure SSH LogLevel is appropriate
if sshd -T | grep -i loglevel | grep -q "INFO"; then
    echo "[PASS] Ensure SSH LogLevel is appropriate"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH LogLevel is appropriate"
    FAIL=$((FAIL+1))
fi


# Ensure SSH X11 forwarding is disabled
if sshd -T | grep -i x11forwarding | grep -q "no"; then
    echo "[PASS] Ensure SSH X11 forwarding is disabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH X11 forwarding is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH MaxAuthTries is set to 4 or less
if sshd -T | grep -i maxauthtries | awk '{print $2}' | grep -qE '^[1-4]$'; then
    echo "[PASS] Ensure SSH MaxAuthTries is set to 4 or less"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH MaxAuthTries is set to 4 or less"
    FAIL=$((FAIL+1))
fi


# Ensure SSH IgnoreRhosts is enabled
if sshd -T | grep -i ignorerhosts | grep -q yes; then
    echo "[PASS] Ensure SSH IgnoreRhosts is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH IgnoreRhosts is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH HostbasedAuthentication is disabled
if sshd -T | grep -i hostbasedauthentication | grep -q no; then
    echo "[PASS] Ensure SSH HostbasedAuthentication is disabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH HostbasedAuthentication is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH root login is disabled
if sshd -T | grep -i permitrootlogin | grep -q no; then
    echo "[PASS] Ensure SSH root login is disabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH root login is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH PermitEmptyPasswords is disabled
if sshd -T | grep -i permitemptypasswords | grep -q no; then
    echo "[PASS] Ensure SSH PermitEmptyPasswords is disabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH PermitEmptyPasswords is disabled"
    FAIL=$((FAIL+1))
fi

####################################################
# SSH CRYPTOGRAPHIC SETTINGS
####################################################

# Ensure only strong Ciphers are used
if sshd -T 2>/dev/null | grep -i ciphers | grep -Eq "cbc|arcfour|3des"; then
    echo "[FAIL] Ensure only strong Ciphers are used"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure only strong Ciphers are used"
    PASS=$((PASS+1))
fi


# Ensure only strong MAC algorithms are used
if sshd -T 2>/dev/null | grep -i macs | grep -Eq "md5|hmac-sha1[^-]"; then
    echo "[FAIL] Ensure only strong MAC algorithms are used"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure only strong MAC algorithms are used"
    PASS=$((PASS+1))
fi


# Ensure only strong Key Exchange algorithms are used
if sshd -T 2>/dev/null | grep -i kexalgorithms | grep -Eq "diffie-hellman-group1-sha1|diffie-hellman-group14-sha1"; then
    echo "[FAIL] Ensure only strong Key Exchange algorithms are used"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure only strong Key Exchange algorithms are used"
    PASS=$((PASS+1))
fi

####################################################
# SSH SESSION AND ACCESS CONTROLS
####################################################

# Ensure SSH Idle Timeout Interval is configured
clientalive=$(sshd -T 2>/dev/null | grep -i clientaliveinterval | awk '{print $2}')
if [[ "$clientalive" =~ ^[0-9]+$ ]] && [ "$clientalive" -gt 0 ]; then
    echo "[PASS] Ensure SSH Idle Timeout Interval is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH Idle Timeout Interval is configured"
    FAIL=$((FAIL+1))
fi


# Ensure SSH LoginGraceTime is set to one minute or less
grace=$(sshd -T 2>/dev/null | grep -i logingracetime | awk '{print $2}')
if [[ "$grace" =~ ^[0-9]+$ ]] && [ "$grace" -le 60 ]; then
    echo "[PASS] Ensure SSH LoginGraceTime is set to one minute or less"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH LoginGraceTime is set to one minute or less"
    FAIL=$((FAIL+1))
fi


# Ensure SSH access is limited
if sshd -T 2>/dev/null | grep -E "allowusers|allowgroups|denyusers|denygroups" >/dev/null; then
    echo "[PASS] Ensure SSH access is limited"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH access is limited"
    FAIL=$((FAIL+1))
fi


# Ensure SSH warning banner is configured
if sshd -T 2>/dev/null | grep -i banner | grep -vq "none"; then
    echo "[PASS] Ensure SSH warning banner is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH warning banner is configured"
    FAIL=$((FAIL+1))
fi


# Ensure SSH PAM is enabled
if sshd -T 2>/dev/null | grep -i usepam | grep -q yes; then
    echo "[PASS] Ensure SSH PAM is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH PAM is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH AllowTcpForwarding is disabled
if sshd -T 2>/dev/null | grep -i allowtcpforwarding | grep -q no; then
    echo "[PASS] Ensure SSH AllowTcpForwarding is disabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH AllowTcpForwarding is disabled"
    FAIL=$((FAIL+1))
fi


# Ensure SSH MaxStartups is configured
maxstart=$(sshd -T 2>/dev/null | grep -i maxstartups | awk '{print $2}')
if [[ "$maxstart" =~ ^[0-9]+ ]]; then
    echo "[PASS] Ensure SSH MaxStartups is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH MaxStartups is configured"
    FAIL=$((FAIL+1))
fi


# Ensure SSH MaxSessions is limited
maxsessions=$(sshd -T 2>/dev/null | grep -i maxsessions | awk '{print $2}')
if [[ "$maxsessions" =~ ^[0-9]+$ ]] && [ "$maxsessions" -le 10 ]; then
    echo "[PASS] Ensure SSH MaxSessions is limited"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure SSH MaxSessions is limited"
    FAIL=$((FAIL+1))
fi

