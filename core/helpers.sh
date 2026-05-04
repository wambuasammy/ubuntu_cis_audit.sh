#!/bin/bash

command_exists() { command -v "$1" >/dev/null 2>&1; }

audit_modprobe_disabled() {
  local module="$1"
  modprobe -n -v "$module" 2>/dev/null | grep -q "install /bin/true"
}

audit_mount_option() {
  local mountpoint="$1" option="$2"
  mount | grep -E "[[:space:]]${mountpoint}[[:space:]]" | grep -q "$option"
}

audit_mount_exists() {
  local mountpoint="$1"
  mount | grep -E "[[:space:]]${mountpoint}[[:space:]]" >/dev/null
}
