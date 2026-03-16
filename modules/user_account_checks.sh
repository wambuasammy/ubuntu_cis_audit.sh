

# Ensure password expiration is 365 days or less
maxdays=$(grep PASS_MAX_DAYS /etc/login.defs | awk '{print $2}')

if [[ "$maxdays" =~ ^[0-9]+$ ]] && [ "$maxdays" -le 365 ]; then
    echo "[PASS] Ensure password expiration is 365 days or less"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure password expiration is 365 days or less"
    FAIL=$((FAIL+1))
fi


# Ensure minimum days between password changes is configured
mindays=$(grep PASS_MIN_DAYS /etc/login.defs | awk '{print $2}')

if [[ "$mindays" =~ ^[0-9]+$ ]] && [ "$mindays" -ge 1 ]; then
    echo "[PASS] Ensure minimum days between password changes is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure minimum days between password changes is configured"
    FAIL=$((FAIL+1))
fi


# Ensure password expiration warning days is 7 or more
warndays=$(grep PASS_WARN_AGE /etc/login.defs | awk '{print $2}')

if [[ "$warndays" =~ ^[0-9]+$ ]] && [ "$warndays" -ge 7 ]; then
    echo "[PASS] Ensure password expiration warning days is 7 or more"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure password expiration warning days is 7 or more"
    FAIL=$((FAIL+1))
fi


# Ensure inactive password lock is 30 days or less
inactive=$(useradd -D | grep INACTIVE | cut -d= -f2)

if [[ "$inactive" =~ ^[0-9]+$ ]] && [ "$inactive" -le 30 ]; then
    echo "[PASS] Ensure inactive password lock is 30 days or less"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure inactive password lock is 30 days or less"
    FAIL=$((FAIL+1))
fi


echo "[MANUAL] Ensure all users last password change date is in the past"
MANUAL=$((MANUAL+1))


# Ensure system accounts are non-login
if awk -F: '($3 < 1000 && $1 != "root" && $7 !~ /(nologin|false)/)' /etc/passwd | grep -q .; then
    echo "[FAIL] Ensure system accounts are non-login"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure system accounts are non-login"
    PASS=$((PASS+1))
fi


# Ensure root group is GID 0
if grep "^root:" /etc/passwd | cut -d: -f4 | grep -q "^0$"; then
    echo "[PASS] Ensure default group for the root account is GID 0"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure default group for the root account is GID 0"
    FAIL=$((FAIL+1))
fi


# Ensure default user umask is 027
if grep -R "umask 027" /etc/profile /etc/bash.bashrc /etc/profile.d 2>/dev/null >/dev/null; then
    echo "[PASS] Ensure default user umask is 027 or more restrictive"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure default user umask is 027 or more restrictive"
    FAIL=$((FAIL+1))
fi


# Ensure access to the su command is restricted
if grep -q "pam_wheel.so" /etc/pam.d/su 2>/dev/null; then
    echo "[PASS] Ensure access to the su command is restricted"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure access to the su command is restricted"
    FAIL=$((FAIL+1))
fi