#!/bin/bash

calculate_compliance_score() {
  local pass="$1" fail="$2" warning="$3" manual="$4"
  local total=$((pass + fail + warning + manual))

  if [[ $total -eq 0 ]]; then
    SCORE_TOTAL=0
    SCORE_PERCENT="0.00"
    return 0
  fi

  # Weighted scoring model
  # PASS=1.0, WARNING=0.5, MANUAL=0.5, FAIL=0.0
  SCORE_TOTAL="$total"
  SCORE_PERCENT=$(awk "BEGIN {printf \"%.2f\", ((${pass} + 0.5*${warning} + 0.5*${manual})/${total})*100}")
}

score_band() {
  local percent="$1"
  awk -v p="$percent" 'BEGIN {
    if (p >= 95) print "Excellent";
    else if (p >= 80) print "Good";
    else if (p >= 60) print "Moderate";
    else print "Poor";
  }'
}
