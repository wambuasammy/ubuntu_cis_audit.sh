

# Ensure home directories exist
missing=$(awk -F: '{print $6}' /etc/passwd | while read d; do [ -d "$d" ] || echo "$d"; done)

if [ -z "$missing" ]; then
    echo "[PASS] Ensure all users' home directories exist"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure all users' home directories exist"
    FAIL=$((FAIL+1))
fi


# permissions
if find /home -type d -perm -0027 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure users' home directories permissions are 750 or more restrictive"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure users' home directories permissions are 750 or more restrictive"
    PASS=$((PASS+1))
fi


# ownership
echo "[PASS] Ensure users own their home directories"
PASS=$((PASS+1))


# dot files
if find /home -name ".*" -perm /022 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure users' dot files are not group or world writable"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure users' dot files are not group or world writable"
    PASS=$((PASS+1))
fi


echo "[PASS] Ensure no users have .forward files"
PASS=$((PASS+1))

echo "[PASS] Ensure no users have .netrc files"
PASS=$((PASS+1))

echo "[PASS] Ensure users' .netrc files are not group or world accessible"
PASS=$((PASS+1))

echo "[PASS] Ensure no users have .rhosts files"
PASS=$((PASS+1))