# Ensure sudo is installed
if dpkg -s sudo >/dev/null 2>&1; then
    pass "Ensure sudo is installed"
else
    fail "Ensure sudo is installed"
fi


# Ensure sudo commands use pty
if grep -q "Defaults.*use_pty" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    pass "Ensure sudo commands use pty"
else
    fail "Ensure sudo commands use pty"
fi


# Ensure sudo log file exists
if grep -q "logfile" /etc/sudoers /etc/sudoers.d/* 2>/dev/null; then
    pass "Ensure sudo log file exists"
else
    fail "Ensure sudo log file exists"
fi