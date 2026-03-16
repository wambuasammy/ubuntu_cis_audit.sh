##################################################
# PATCH MANAGEMENT
##################################################

# Ensure updates, patches, and additional security software are installed

if apt -s upgrade 2>/dev/null | grep -q "0 upgraded"; then
    pass "Ensure updates, patches, and additional security software are installed"
else
    fail "Ensure updates, patches, and additional security software are installed"
fi