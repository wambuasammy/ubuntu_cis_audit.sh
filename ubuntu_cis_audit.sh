#!/bin/bash

############################################################
# Ubuntu CIS Security Audit Script
#
# Author: Sammy Wambua
# Description:
# A lightweight Bash-based auditing tool that validates
# Ubuntu system configurations against CIS-style Linux
# security hardening controls.
#
# The script performs automated security checks across
# multiple system areas including services, authentication,
# SSH configuration, file permissions, cron restrictions,
# PAM policies, and user account security.
#
# Output includes PASS / FAIL / MANUAL results and a
# final compliance summary score.
#
# Supported Platforms:
# Ubuntu 20.04
# Ubuntu 22.04
# Ubuntu 24.04
#
############################################################

print_section() {
    echo
    echo "=================================================="
    echo "$1"
    echo "=================================================="
}

print_subsection() {
    echo
    echo "----------- $1 -----------"
}

pass() {
echo "[PASS] $1"
PASS=$((PASS+1))
TOTAL=$((TOTAL+1))
}

fail() {
echo "[FAIL] $1"
FAIL=$((FAIL+1))
TOTAL=$((TOTAL+1))
}

manual() {
echo "[MANUAL] $1"
MANUAL=$((MANUAL+1))
TOTAL=$((TOTAL+1))
}

warn() {
echo "[WARNING] $1"
WARN=$((WARN+1))
TOTAL=$((TOTAL+1))
}

source modules/section_a_initial_setup.sh

print_section "SECTION B: SERVICES"

source modules/services_checks.sh


print_section "SECTION C: NETWORK CONFIGURATION"

source modules/network_checks.sh



print_section "SECTION D: FIREWALL CONFIGURATION"

source modules/firewall_checks.sh


print_section "SECTION E: LOGGING AND AUDITING"

source modules/logging_audit_checks.sh


print_section "SECTION F: ACCESS, AUTHENTICATION AND AUTHORIZATION"
source modules/access_authentication_authorization.sh


echo
echo "=================================================="
echo "FINAL AUDIT SUMMARY"
echo "=================================================="

# Ensure counters exist (in case earlier sections didn't initialize them)
PASS=${PASS:-0}
FAIL=${FAIL:-0}
MANUAL=${MANUAL:-0}

TOTAL=$((PASS + FAIL + MANUAL))

if [ "$TOTAL" -gt 0 ]; then
    COMPLIANCE=$(awk "BEGIN {printf \"%.2f\", ($PASS/$TOTAL)*100}")
else
    COMPLIANCE="0.00"
fi

echo "Total Checks      : $TOTAL"
echo "Passed Checks     : $PASS"
echo "Failed Checks     : $FAIL"
echo "Manual Checks     : $MANUAL"
echo "Compliance Score  : $COMPLIANCE %"
