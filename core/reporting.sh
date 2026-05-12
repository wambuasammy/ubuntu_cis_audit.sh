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

csv_escape() {
  local value="$1"
  local quote='"'
  value=${value//$quote/$quote$quote}
  printf '"%s"' "$value"
}

json_escape() {
  printf '%s' "$1" \
    | sed \
      -e 's/\\/\\\\/g' \
      -e 's/"/\\"/g' \
      -e ':a;N;$!ba;s/\n/\\n/g'
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
  local timestamp
  {
    echo 'Timestamp,Section,Subsection,Control,Check_ID,Check_Name,Status'
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r s ss c id name st <<< "$row"
      timestamp=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
      csv_escape "$timestamp"; printf ','
      csv_escape "$s"; printf ','
      csv_escape "$ss"; printf ','
      csv_escape "$c"; printf ','
      csv_escape "$id"; printf ','
      csv_escape "$name"; printf ','
      csv_escape "$st"; printf '\n'
    done
  } > "$file"
}

write_json_report() {
  local file="$1"
  {
    echo '{'
    printf '  "generated_utc": "%s",\n' "$(json_escape "$(date -u +'%Y-%m-%dT%H:%M:%SZ')")"
    echo '  "results": ['
    local i=0
    local total=${#RESULTS[@]}
    for row in "${RESULTS[@]}"; do
      IFS='|' read -r s ss c id name st <<< "$row"
      i=$((i+1))
      printf '    {"section":"%s","subsection":"%s","control":"%s","check_id":"%s","check_name":"%s","status":"%s"}' \
        "$(json_escape "$s")" \
        "$(json_escape "$ss")" \
        "$(json_escape "$c")" \
        "$(json_escape "$id")" \
        "$(json_escape "$name")" \
        "$(json_escape "$st")"
      if [[ $i -lt $total ]]; then echo ','; else echo; fi
    done
    echo '  ]'
    echo '}'
  } > "$file"
}
