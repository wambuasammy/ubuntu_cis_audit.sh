

# /etc/passwd
[ "$(stat -c %a /etc/passwd)" -le 644 ] && echo "[PASS] Ensure permissions on /etc/passwd are configured" && PASS=$((PASS+1)) || { echo "[FAIL] Ensure permissions on /etc/passwd are configured"; FAIL=$((FAIL+1)); }

# /etc/shadow
[ "$(stat -c %a /etc/shadow)" -le 640 ] && echo "[PASS] Ensure permissions on /etc/shadow are configured" && PASS=$((PASS+1)) || { echo "[FAIL] Ensure permissions on /etc/shadow are configured"; FAIL=$((FAIL+1)); }

# /etc/group
[ "$(stat -c %a /etc/group)" -le 644 ] && echo "[PASS] Ensure permissions on /etc/group are configured" && PASS=$((PASS+1)) || { echo "[FAIL] Ensure permissions on /etc/group are configured"; FAIL=$((FAIL+1)); }

# /etc/gshadow
[ "$(stat -c %a /etc/gshadow)" -le 640 ] && echo "[PASS] Ensure permissions on /etc/gshadow are configured" && PASS=$((PASS+1)) || { echo "[FAIL] Ensure permissions on /etc/gshadow are configured"; FAIL=$((FAIL+1)); }


# world writable files
if find / -xdev -type f -perm -0002 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure no world writable files exist"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure no world writable files exist"
    PASS=$((PASS+1))
fi


# unowned files
if find / -xdev -nouser 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure no unowned files or directories exist"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure no unowned files or directories exist"
    PASS=$((PASS+1))
fi


# ungrouped files
if find / -xdev -nogroup 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure no ungrouped files or directories exist"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure no ungrouped files or directories exist"
    PASS=$((PASS+1))
fi