#!/bin/bash
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
HOSTNAME=$(hostname)

source "$SCRIPT_DIR/core/helpers.sh"
source "$SCRIPT_DIR/core/reporting.sh"
source "$SCRIPT_DIR/core/scoring.sh"
source "$SCRIPT_DIR/checks/01_initial_setup.sh"
source "$SCRIPT_DIR/checks/02_software_updates.sh"
source "$SCRIPT_DIR/checks/03_sudo.sh"
source "$SCRIPT_DIR/checks/04_file_integrity.sh"
source "$SCRIPT_DIR/checks/05_secure_boot.sh"
source "$SCRIPT_DIR/checks/06_process_hardening.sh"
source "$SCRIPT_DIR/checks/07_apparmor.sh"
source "$SCRIPT_DIR/checks/08_warning_banners.sh"
source "$SCRIPT_DIR/checks/09_updates_gdm.sh"
source "$SCRIPT_DIR/checks/10_services.sh"
source "$SCRIPT_DIR/modules/initial_setup.sh"
source "$SCRIPT_DIR/modules/services.sh"

mkdir -p "$REPORT_DIR"
TXT_REPORT="$REPORT_DIR/cis-audit-$TIMESTAMP.txt"
CSV_REPORT="$REPORT_DIR/cis-audit-$TIMESTAMP.csv"
JSON_REPORT="$REPORT_DIR/cis-audit-$TIMESTAMP.json"

run_module_initial_setup
run_module_services

TOTAL=$((PASS + FAIL + WARNING + MANUAL))
calculate_compliance_score "$PASS" "$FAIL" "$WARNING" "$MANUAL"
COMPLIANCE="$SCORE_PERCENT"
SCORE_BAND=$(score_band "$COMPLIANCE")

write_txt_report "$TXT_REPORT"
write_csv_report "$CSV_REPORT"
write_json_report "$JSON_REPORT"

echo "Ubuntu CIS Audit completed"
echo "Host           : $HOSTNAME"
echo "Total checks   : $TOTAL"
echo "Passed         : $PASS"
echo "Failed         : $FAIL"
echo "Warnings       : $WARNING"
echo "Manual         : $MANUAL"
echo "Compliance     : $COMPLIANCE %"
echo "Score band     : $SCORE_BAND"
echo "TXT report     : $TXT_REPORT"
echo "CSV report     : $CSV_REPORT"
echo "JSON report    : $JSON_REPORT"
