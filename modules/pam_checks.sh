

# Ensure password creation requirements are configured
minlen=$(grep -E '^\s*minlen' /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}')
minclass=$(grep -E '^\s*minclass' /etc/security/pwquality.conf 2>/dev/null | awk '{print $3}')

if [[ "$minlen" =~ ^[0-9]+$ ]] && [ "$minlen" -ge 14 ] && [[ "$minclass" =~ ^[0-9]+$ ]] && [ "$minclass" -ge 4 ]; then
    echo "[PASS] Ensure password creation requirements are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure password creation requirements are configured"
    FAIL=$((FAIL+1))
fi


# Ensure lockout for failed password attempts is configured
if grep -Eq "pam_tally2|pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
    echo "[PASS] Ensure lockout for failed password attempts is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure lockout for failed password attempts is configured"
    FAIL=$((FAIL+1))
fi


# Ensure password reuse is limited
if grep -q "remember=" /etc/pam.d/common-password 2>/dev/null; then
    echo "[PASS] Ensure password reuse is limited"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure password reuse is limited"
    FAIL=$((FAIL+1))
fi


# Ensure password hashing algorithm is SHA-512
if grep -q "sha512" /etc/pam.d/common-password 2>/dev/null; then
    echo "[PASS] Ensure password hashing algorithm is SHA-512"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure password hashing algorithm is SHA-512"
    FAIL=$((FAIL+1))
fi