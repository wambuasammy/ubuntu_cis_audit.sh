print_subsection "PATCH MANAGEMENT"

if apt-get -s upgrade 2>/dev/null | grep -q "0 upgraded"; then
    echo "[PASS] Ensure updates, patches, and additional security software are installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure updates, patches, and additional security software are installed"
    FAIL=$((FAIL+1))
fi