#!/bin/bash

RESULTS=()
PASS=0
FAIL=0
WARNING=0
MANUAL=0

record_result() {
  local status="$1"
  case "$status" in
    PASS) ((PASS++));;
    FAIL) ((FAIL++));;
    WARNING) ((WARNING++));;
    MANUAL) ((MANUAL++));;
  esac

  RESULTS+=("$(printf '%s|%s|%s|%s|%s|%s' "$SECTION" "$SUBSECTION" "$CONTROL" "$CHECK_ID" "$CHECK_NAME" "$status")")
}

write_txt_report() {
  local file="$1"
  {
    echo "Ubuntu CIS Audit Report"
    echo "Generated (UTC): $(date -u +'%Y-%m-%d %H:%M:%S')"
    echo
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r s ss c id name st <<< "$row"
      printf '[%s] %s | %s | %s | %s - %s\n' "$st" "$s" "$ss" "$c" "$id" "$name"
    done
  } > "$file"
}

write_csv_report() {
  local file="$1"
  {
    echo "Timestamp,Section,Subsection,Control,Check_ID,Check_Name,Status"
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r s ss c id name st <<< "$row"
      printf '%s,%s,%s,%s,%s,%s,%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" "$s" "$ss" "$c" "$id" "$name" "$st"
    done
  } > "$file"
}

write_json_report() {
  local file="$1"
  {
    echo '{'
    echo '  "generated_utc": "'"$(date -u +'%Y-%m-%dT%H:%M:%SZ')"'",'
    echo '  "results": ['
    local i=0
    local total=${#RESULTS[@]}
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r s ss c id name st <<< "$row"
      i=$((i+1))
      printf '    {"section":"%s","subsection":"%s","control":"%s","check_id":"%s","check_name":"%s","status":"%s"}' "$s" "$ss" "$c" "$id" "$name" "$st"
      if [[ $i -lt $total ]]; then echo ','; else echo; fi
    done
    echo '  ]'
    echo '}'
  } > "$file"
}
