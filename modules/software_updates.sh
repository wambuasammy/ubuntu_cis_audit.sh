# Ensure package manager repositories are configured

if apt-cache policy | grep -q http; then
    pass "Ensure package manager repositories are configured"
else
    fail "Ensure package manager repositories are configured"
fi


# Ensure GPG keys are configured

if apt-key list 2>/dev/null | grep -q pub; then
    pass "Ensure GPG keys are configured"
else
    fail "Ensure GPG keys are configured"
fi