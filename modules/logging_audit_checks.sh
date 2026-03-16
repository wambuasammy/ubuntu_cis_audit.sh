####################################################
# AUDITD CONFIGURATION
####################################################

echo
echo "------------ AUDITD CONFIGURATION ------------"

# Ensure auditd is installed
if dpkg -s auditd >/dev/null 2>&1; then
    echo "[PASS] Ensure auditd is installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure auditd is installed"
    FAIL=$((FAIL+1))
fi


# Ensure auditd service is enabled
if systemctl is-enabled auditd >/dev/null 2>&1; then
    echo "[PASS] Ensure auditd service is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure auditd service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure auditing for processes prior to auditd is enabled
if grep -q "audit=1" /proc/cmdline; then
    echo "[PASS] Ensure auditing for processes prior to auditd is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure auditing for processes prior to auditd is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure audit backlog limit configured
if grep -q "audit_backlog_limit" /proc/cmdline; then
    echo "[PASS] Ensure audit backlog limit configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure audit backlog limit configured"
    FAIL=$((FAIL+1))
fi

####################################################
# AUDIT LOG CONFIGURATION
####################################################

echo
echo "------------ AUDIT LOG CONFIGURATION ------------"

# Ensure audit log storage size configured
if grep -E "^\s*max_log_file\s*=" /etc/audit/auditd.conf >/dev/null 2>&1; then
    echo "[PASS] Ensure audit log storage size configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure audit log storage size configured"
    FAIL=$((FAIL+1))
fi


# Ensure audit logs are not automatically deleted
if grep -E "^\s*max_log_file_action\s*=\s*(keep_logs|rotate)" /etc/audit/auditd.conf >/dev/null 2>&1; then
    echo "[PASS] Ensure audit logs are not automatically deleted"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure audit logs are not automatically deleted"
    FAIL=$((FAIL+1))
fi


# Ensure system disabled when audit logs are full
if grep -E "^\s*space_left_action\s*=\s*(email|halt|single)" /etc/audit/auditd.conf >/dev/null 2>&1; then
    echo "[PASS] Ensure system disabled when audit logs are full"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure system disabled when audit logs are full"
    FAIL=$((FAIL+1))
fi

####################################################
# AUDIT RULES CHECKS
####################################################

echo
echo "------------ AUDIT RULES CHECKS ------------"

# Ensure time change events are collected
if grep -rE "adjtimex|settimeofday|clock_settime" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure time change events are collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure time change events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure user/group modification events are collected
if grep -rE "/etc/group|/etc/passwd|/etc/shadow|/etc/gshadow" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure user/group modification events are collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure user/group modification events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure network environment changes are collected
if grep -rE "/etc/issue|/etc/issue.net|/etc/hosts" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure network environment changes are collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure network environment changes are collected"
    FAIL=$((FAIL+1))
fi


# Ensure MAC policy changes are collected
if grep -r "MAC-policy" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure MAC policy changes are collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure MAC policy changes are collected"
    FAIL=$((FAIL+1))
fi


# Ensure login events are collected
if grep -rE "logins|/var/log/faillog|/var/log/lastlog" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure login events are collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure login events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure session initiation events are collected
if grep -rE "session" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure session initiation events are collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure session initiation events are collected"
    FAIL=$((FAIL+1))
fi


# Ensure permission modification events collected
if grep -rE "chmod|chown|setxattr" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure permission modification events collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure permission modification events collected"
    FAIL=$((FAIL+1))
fi


# Ensure unauthorized file access attempts collected
if grep -rE "access" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure unauthorized file access attempts collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure unauthorized file access attempts collected"
    FAIL=$((FAIL+1))
fi


# Ensure file deletion events collected
if grep -rE "unlink|rename" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure file deletion events collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure file deletion events collected"
    FAIL=$((FAIL+1))
fi


# Ensure sudo scope changes collected
if grep -r "sudoers" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure sudo scope changes collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure sudo scope changes collected"
    FAIL=$((FAIL+1))
fi


# Ensure sudo command executions collected
if grep -r "sudo.log" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure sudo command executions collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure sudo command executions collected"
    FAIL=$((FAIL+1))
fi


# Ensure kernel module loading events collected
if grep -rE "init_module|delete_module" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure kernel module loading events collected"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure kernel module loading events collected"
    FAIL=$((FAIL+1))
fi


# Ensure audit configuration is immutable
if grep -r "\-e 2" /etc/audit/rules.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure audit configuration is immutable"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure audit configuration is immutable"
    FAIL=$((FAIL+1))
fi

####################################################
# RSYSLOG CONFIGURATION
####################################################

echo
echo "------------ RSYSLOG CONFIGURATION ------------"

# Ensure rsyslog is installed
if dpkg -s rsyslog >/dev/null 2>&1; then
    echo "[PASS] Ensure rsyslog is installed"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure rsyslog is installed"
    FAIL=$((FAIL+1))
fi


# Ensure rsyslog service is enabled
if systemctl is-enabled rsyslog >/dev/null 2>&1; then
    echo "[PASS] Ensure rsyslog service is enabled"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure rsyslog service is enabled"
    FAIL=$((FAIL+1))
fi


# Ensure logging is configured
if grep -r "^\*.\*" /etc/rsyslog.conf /etc/rsyslog.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure logging is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure logging is configured"
    FAIL=$((FAIL+1))
fi


# Ensure rsyslog default file permissions configured
if grep -r "\$FileCreateMode" /etc/rsyslog.conf /etc/rsyslog.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure rsyslog default file permissions configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure rsyslog default file permissions configured"
    FAIL=$((FAIL+1))
fi


# Ensure rsyslog configured to send logs to remote host
if grep -r "@@" /etc/rsyslog.conf /etc/rsyslog.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure rsyslog configured to send logs to remote host"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure rsyslog configured to send logs to remote host"
    FAIL=$((FAIL+1))
fi

####################################################
# JOURNALD CONFIGURATION
####################################################

echo
echo "------------ JOURNALD CONFIGURATION ------------"

# Ensure journald forwards logs to rsyslog
if grep -E "^\s*ForwardToSyslog=yes" /etc/systemd/journald.conf >/dev/null 2>&1; then
    echo "[PASS] Ensure journald forwards logs to rsyslog"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure journald forwards logs to rsyslog"
    FAIL=$((FAIL+1))
fi


# Ensure journald compresses large log files
if grep -E "^\s*Compress=yes" /etc/systemd/journald.conf >/dev/null 2>&1; then
    echo "[PASS] Ensure journald compresses large log files"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure journald compresses large log files"
    FAIL=$((FAIL+1))
fi


# Ensure journald logs persist to disk
if grep -E "^\s*Storage=persistent" /etc/systemd/journald.conf >/dev/null 2>&1; then
    echo "[PASS] Ensure journald logs persist to disk"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure journald logs persist to disk"
    FAIL=$((FAIL+1))
fi

####################################################
# LOG FILE SECURITY
####################################################

echo
echo "------------ LOG FILE SECURITY ------------"

# Ensure permissions on log files are restricted
if find /var/log -type f -perm /0137 2>/dev/null | grep -q .; then
    echo "[FAIL] Ensure permissions on log files are restricted"
    FAIL=$((FAIL+1))
else
    echo "[PASS] Ensure permissions on log files are restricted"
    PASS=$((PASS+1))
fi

####################################################
# LOGROTATE CONFIGURATION
####################################################

echo
echo "------------ LOGROTATE CONFIGURATION ------------"

# Ensure logrotate is configured
if dpkg -s logrotate >/dev/null 2>&1; then
    echo "[PASS] Ensure logrotate is configured"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure logrotate is configured"
    FAIL=$((FAIL+1))
fi


# Ensure logrotate assigns appropriate permissions
if grep -r "create" /etc/logrotate.conf /etc/logrotate.d/ >/dev/null 2>&1; then
    echo "[PASS] Ensure logrotate assigns appropriate permissions"
    PASS=$((PASS+1))
else
    echo "[FAIL] Ensure logrotate assigns appropriate permissions"
    FAIL=$((FAIL+1))
fi

