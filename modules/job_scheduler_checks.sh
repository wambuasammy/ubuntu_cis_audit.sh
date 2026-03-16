##################################################
# CIS SECTION E
# TIME-BASED JOB SCHEDULERS
##################################################


# Ensure cron daemon is enabled and running
if systemctl is-enabled cron 2>/dev/null | grep -q enabled && \
   systemctl is-active cron 2>/dev/null | grep -q active; then
    echo "[PASS] Ensure cron daemon is enabled and running"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure cron daemon is enabled and running"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/crontab are configured
if [ "$(stat -c %a /etc/crontab)" -le 600 ]; then
    echo "[PASS] Ensure permissions on /etc/crontab are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/crontab are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.hourly are configured
if [ "$(stat -c %a /etc/cron.hourly)" -le 700 ]; then
    echo "[PASS] Ensure permissions on /etc/cron.hourly are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/cron.hourly are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.daily are configured
if [ "$(stat -c %a /etc/cron.daily)" -le 700 ]; then
    echo "[PASS] Ensure permissions on /etc/cron.daily are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/cron.daily are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.weekly are configured
if [ "$(stat -c %a /etc/cron.weekly)" -le 700 ]; then
    echo "[PASS] Ensure permissions on /etc/cron.weekly are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/cron.weekly are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.monthly are configured
if [ "$(stat -c %a /etc/cron.monthly)" -le 700 ]; then
    echo "[PASS] Ensure permissions on /etc/cron.monthly are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/cron.monthly are configured"
    FAIL=$((FAIL+1))
fi


# Ensure permissions on /etc/cron.d are configured
if [ "$(stat -c %a /etc/cron.d)" -le 700 ]; then
    echo "[PASS] Ensure permissions on /etc/cron.d are configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permissions on /etc/cron.d are configured"
    FAIL=$((FAIL+1))
fi


# Ensure cron is restricted to authorized users
if [ -f /etc/cron.allow ] && [ ! -f /etc/cron.deny ]; then
    echo "[PASS] Ensure cron is restricted to authorized users"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure cron is restricted to authorized users"
    FAIL=$((FAIL+1))
fi


# Ensure at is restricted to authorized users
if [ -f /etc/at.allow ] && [ ! -f /etc/at.deny ]; then
    echo "[PASS] Ensure at is restricted to authorized users"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure at is restricted to authorized users"
    FAIL=$((FAIL+1))
fi