#!/bin/bash
set -u

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPORT_DIR="$SCRIPT_DIR/reports"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
HOSTNAME=$(hostname)

source "$SCRIPT_DIR/core/helpers.sh"
source "$SCRIPT_DIR/core/reporting.sh"
source "$SCRIPT_DIR/checks/01_initial_setup.sh"
source "$SCRIPT_DIR/modules/initial_setup.sh"

mkdir -p "$REPORT_DIR"
TXT_REPORT="$REPORT_DIR/cis-audit-$TIMESTAMP.txt"
CSV_REPORT="$REPORT_DIR/cis-audit-$TIMESTAMP.csv"
JSON_REPORT="$REPORT_DIR/cis-audit-$TIMESTAMP.json"

run_module_initial_setup

TOTAL=$((PASS + FAIL + WARNING + MANUAL))
if [[ $TOTAL -gt 0 ]]; then
  COMPLIANCE=$(awk "BEGIN {printf \"%.2f\", ($PASS/$TOTAL)*100}")
else
  COMPLIANCE="0.00"
fi

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
echo "TXT report     : $TXT_REPORT"
echo "CSV report     : $CSV_REPORT"
echo "JSON report    : $JSON_REPORT"
