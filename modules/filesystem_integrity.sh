# ==================================================
# FILESYSTEM INTEGRITY CHECKING
# ==================================================

# Ensure AIDE is installed
if dpkg -s aide >/dev/null 2>&1; then
    pass "Ensure AIDE is installed"
else
    fail "Ensure AIDE is installed"
fi


# Ensure filesystem integrity is regularly checked
if systemctl is-enabled aidecheck.timer >/dev/null 2>&1 || crontab -l 2>/dev/null | grep -q aide; then
    pass "Ensure filesystem integrity is regularly checked"
else
    fail "Ensure filesystem integrity is regularly checked"
fi