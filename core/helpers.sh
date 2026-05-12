#!/bin/bash

command_exists() { command -v "$1" >/dev/null 2>&1; }

audit_kernel_module_disabled() {
  local module="$1"
  local modprobe_output

  modprobe_output=$(modprobe -n -v "$module" 2>/dev/null || true)
  [[ "$modprobe_output" =~ install[[:space:]]+/bin/(true|false) ]] || return 1
  ! lsmod 2>/dev/null | awk '{print $1}' | grep -Fxq "$module"
}

audit_modprobe_disabled() {
  audit_kernel_module_disabled "$1"
}

audit_mount_exists() {
  local mountpoint="$1"
  findmnt --kernel --mountpoint "$mountpoint" >/dev/null 2>&1
}

audit_mount_option() {
  local mountpoint="$1" option="$2"
  findmnt --kernel --mountpoint "$mountpoint" --options "$option" >/dev/null 2>&1
}

audit_world_writable_sticky_dirs() {
  ! df --local -P 2>/dev/null \
    | awk 'NR != 1 {print $6}' \
    | xargs -r -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null \
    | grep -q .
}

audit_service_not_enabled_or_not_installed() {
  local service="$1" package="${2:-$1}"

  if dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"; then
    ! systemctl is-enabled "$service" 2>/dev/null | grep -q '^enabled$'
  else
    return 0
  fi
}

audit_package_installed() {
  local package="$1"
  dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q "install ok installed"
}

audit_any_package_installed() {
  local package
  for package in "$@"; do
    if audit_package_installed "$package"; then
      return 0
    fi
  done
  return 1
}

audit_apt_repositories_configured() {
  local repo_file

  while IFS= read -r -d '' repo_file; do
    if awk '/^[[:space:]]*#/ { next } /^[[:space:]]*$/ { next } { found=1; exit } END { exit !found }' "$repo_file"; then
      return 0
    fi
  done < <(find /etc/apt -type f \( -name '*.list' -o -name '*.sources' \) -print0 2>/dev/null)

  apt-cache policy 2>/dev/null | awk '/^[[:space:]]*[0-9]+[[:space:]]/ { found=1 } END { exit !found }'
}

audit_apt_gpg_keys_configured() {
  apt-key list 2>/dev/null | grep -q '^pub' && return 0
  find /etc/apt/trusted.gpg.d /etc/apt/keyrings /usr/share/keyrings -type f \( -name '*.gpg' -o -name '*.asc' \) -size +0c -print -quit 2>/dev/null | grep -q .
}

audit_sudo_uses_pty() {
  grep -Eis '^[[:space:]]*Defaults[[:space:]]+([^#]+,[[:space:]]*)?use_pty(,[[:space:]]*[^#]+)?([[:space:]]+#.*)?$' /etc/sudoers /etc/sudoers.d/* >/dev/null 2>&1
}

audit_sudo_logfile_configured() {
  grep -Eis '^[[:space:]]*Defaults[[:space:]]+([^#]+,[[:space:]]*)?logfile="?[^[:space:]",]+"?' /etc/sudoers /etc/sudoers.d/* >/dev/null 2>&1
}

audit_aide_regularly_checked() {
  crontab -u root -l 2>/dev/null | grep -Eq 'aide(\.wrapper)?|aidecheck' && return 0
  find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.weekly /etc/cron.monthly /etc/crontab -type f 2>/dev/null \
    | xargs -r grep -Eil 'aide(\.wrapper)?|aidecheck' >/dev/null 2>&1 && return 0

  systemctl is-enabled aidecheck.timer 2>/dev/null | grep -q '^enabled$' \
    && systemctl is-active aidecheck.timer 2>/dev/null | grep -q '^active$'
}

audit_grub_password_set() {
  local grub_cfg="/boot/grub/grub.cfg"
  [[ -f "$grub_cfg" ]] || return 1
  grep -Eq '^set[[:space:]]+superusers=' "$grub_cfg" \
    && grep -Eq '^password_pbkdf2[[:space:]]+' "$grub_cfg"
}

audit_file_root_owned_group_other_restricted() {
  local file="$1"
  local mode uid gid
  [[ -e "$file" ]] || return 1
  uid=$(stat -c '%u' "$file" 2>/dev/null) || return 1
  gid=$(stat -c '%g' "$file" 2>/dev/null) || return 1
  mode=$(stat -c '%a' "$file" 2>/dev/null) || return 1
  [[ "$uid" -eq 0 && "$gid" -eq 0 ]] || return 1
  (( (8#$mode & 0077) == 0 ))
}

audit_file_root_owned_not_more_permissive_than_0644() {
  local file="$1"
  local mode uid gid
  [[ ! -e "$file" ]] && return 0
  uid=$(stat -c '%u' "$file" 2>/dev/null) || return 1
  gid=$(stat -c '%g' "$file" 2>/dev/null) || return 1
  mode=$(stat -c '%a' "$file" 2>/dev/null) || return 1
  [[ "$uid" -eq 0 && "$gid" -eq 0 ]] || return 1
  (( (8#$mode & 0133) == 0 ))
}

audit_root_password_set() {
  local root_hash
  root_hash=$(awk -F: '$1 == "root" {print $2}' /etc/shadow 2>/dev/null) || return 1
  [[ -n "$root_hash" && ! "$root_hash" =~ ^[!*] ]]
}

audit_nx_enabled() {
  ! grep -Eq '(^|[[:space:]])noexec[0-9]*=off([[:space:]]|$)' /proc/cmdline 2>/dev/null || return 1
  if journalctl -k -b 2>/dev/null | grep -qi 'NX (Execute Disable) protection: active'; then
    return 0
  fi
  grep -Eqi '(^|[[:space:]])(pae|nx)([[:space:]]|$)' /proc/cpuinfo 2>/dev/null
}

audit_sysctl_equals() {
  local key="$1" expected="$2"
  [[ "$(sysctl -n "$key" 2>/dev/null)" == "$expected" ]]
}

audit_sysctl_configured() {
  local key="$1" expected="$2"
  grep -REhs "^[[:space:]]*${key//./\.}[[:space:]]*=[[:space:]]*${expected}([[:space:]]*#.*)?$" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null | grep -q .
}

audit_prelink_disabled() {
  ! audit_package_installed "prelink"
}

audit_core_dumps_restricted() {
  grep -REhs '^[[:space:]]*\*[[:space:]]+hard[[:space:]]+core[[:space:]]+0([[:space:]]+#.*)?$' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null | grep -q . || return 1
  audit_sysctl_equals "fs.suid_dumpable" "0" || return 1
  audit_sysctl_configured "fs.suid_dumpable" "0" || return 1

  if systemctl list-unit-files systemd-coredump.socket systemd-coredump@.service coredump.service 2>/dev/null | grep -q 'coredump'; then
    grep -Ehs '^[[:space:]]*Storage[[:space:]]*=[[:space:]]*none([[:space:]]*#.*)?$' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf 2>/dev/null | grep -q . || return 1
    grep -Ehs '^[[:space:]]*ProcessSizeMax[[:space:]]*=[[:space:]]*0([[:space:]]*#.*)?$' /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/*.conf 2>/dev/null | grep -q . || return 1
  fi
}

audit_apparmor_bootloader_enabled() {
  local grub_cfg="/boot/grub/grub.cfg"
  [[ -f "$grub_cfg" ]] || return 1
  ! grep -E '^[[:space:]]*linux' "$grub_cfg" | grep -vq 'apparmor=1' \
    && ! grep -E '^[[:space:]]*linux' "$grub_cfg" | grep -vq 'security=apparmor'
}

audit_apparmor_profiles_active() {
  command_exists apparmor_status || return 1
  apparmor_status 2>/dev/null | grep -q 'profiles are loaded' || return 1
  ! apparmor_status 2>/dev/null | grep -Eq '[1-9][0-9]* processes are unconfined'
}

audit_apparmor_profiles_enforcing() {
  command_exists apparmor_status || return 1
  apparmor_status 2>/dev/null | grep -q 'profiles are loaded' || return 1
  ! apparmor_status 2>/dev/null | grep -Eq '[1-9][0-9]* profiles are in complain mode' || return 1
  ! apparmor_status 2>/dev/null | grep -Eq '[1-9][0-9]* processes are unconfined'
}

audit_banner_has_no_os_info() {
  local file="$1"
  local os_id
  [[ ! -e "$file" ]] && return 0
  os_id=$(awk -F= '$1 == "ID" {gsub(/"/, "", $2); print $2}' /etc/os-release 2>/dev/null)
  ! grep -Eiq "(\\\\v|\\\\r|\\\\m|\\\\s|${os_id:-ubuntu})" "$file"
}

audit_no_pending_apt_upgrades() {
  ! apt -s upgrade 2>/dev/null | grep -Eq '^Inst[[:space:]]+'
}

audit_gdm_removed_or_configured() {
  if ! audit_package_installed "gdm3"; then
    return 0
  fi

  local config="/etc/gdm3/greeter.dconf-defaults"
  [[ -f "$config" ]] || return 1
  grep -Eq '^[[:space:]]*banner-message-enable[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$config" \
    && grep -Eq "^[[:space:]]*banner-message-text[[:space:]]*=[[:space:]]*'.+'[[:space:]]*$" "$config" \
    && grep -Eq '^[[:space:]]*disable-user-list[[:space:]]*=[[:space:]]*true[[:space:]]*$' "$config"
}

audit_package_not_installed() {
  ! audit_package_installed "$1"
}

audit_all_packages_not_installed() {
  local package
  for package in "$@"; do
    if audit_package_installed "$package"; then
      return 1
    fi
  done
  return 0
}

audit_package_pattern_not_installed() {
  local pattern="$1"
  ! dpkg-query -W -f='${binary:Package}\t${Status}\n' "$pattern" 2>/dev/null | grep -q 'install ok installed'
}

audit_systemd_service_enabled() {
  local service="$1"
  systemctl is-enabled "$service" 2>/dev/null | grep -q '^enabled$'
}

audit_systemd_service_masked_or_unavailable() {
  local service="$1"
  local state
  state=$(systemctl is-enabled "$service" 2>/dev/null || true)
  [[ "$state" == "masked" || "$state" == "" ]]
}

audit_time_sync_in_use() {
  audit_systemd_service_enabled "systemd-timesyncd.service" \
    || audit_systemd_service_enabled "systemd-timesyncd" \
    || audit_package_installed "chrony" \
    || audit_package_installed "ntp"
}

audit_timesyncd_configured() {
  audit_all_packages_not_installed "ntp" "chrony" || return 1
  audit_systemd_service_enabled "systemd-timesyncd.service" || audit_systemd_service_enabled "systemd-timesyncd" || return 1

  timedatectl status 2>/dev/null | grep -Eqi 'NTP (service: )?active|NTP synchronized:[[:space:]]*yes|System clock synchronized:[[:space:]]*yes' || return 1

  local config="/etc/systemd/timesyncd.conf"
  [[ -f "$config" ]] || return 1
  grep -Eiq '^[[:space:]]*NTP[[:space:]]*=[[:space:]]*[^#[:space:]]+' "$config" || return 1
  grep -Eiq '^[[:space:]]*FallbackNTP[[:space:]]*=[[:space:]]*[^#[:space:]]+' "$config" || return 1
  grep -Eiq '^[[:space:]]*RootDistanceMax(Sec)?[[:space:]]*=[[:space:]]*[^#[:space:]]+' "$config"
}

audit_chrony_configured() {
  audit_package_installed "chrony" || return 1
  audit_package_not_installed "ntp" || return 1
  audit_systemd_service_masked_or_unavailable "systemd-timesyncd" || return 1
  grep -Ehs '^[[:space:]]*(server|pool)[[:space:]]+[^#[:space:]]+' /etc/chrony/chrony.conf /etc/chrony/conf.d/*.conf 2>/dev/null | grep -q . || return 1
  ps -eo user=,comm= 2>/dev/null | awk '$2 ~ /^chronyd$/ && $1 == "_chrony" { found=1 } END { exit !found }'
}

audit_ntp_configured() {
  audit_package_installed "ntp" || return 1
  audit_package_not_installed "chrony" || return 1
  audit_systemd_service_masked_or_unavailable "systemd-timesyncd" || return 1
  [[ -f /etc/ntp.conf ]] || return 1
  grep -Eq '^[[:space:]]*restrict[[:space:]]+(-4[[:space:]]+)?default([[:space:]]+[^#]+)*[[:space:]]+kod([[:space:]]+[^#]+)*[[:space:]]+nomodify([[:space:]]+[^#]+)*[[:space:]]+notrap([[:space:]]+[^#]+)*[[:space:]]+nopeer([[:space:]]+[^#]+)*[[:space:]]+noquery' /etc/ntp.conf || return 1
  grep -E '^[[:space:]]*(server|pool)[[:space:]]+[^#[:space:]]+' /etc/ntp.conf | grep -q . || return 1
  grep -Eq '^[[:space:]]*RUNASUSER[[:space:]]*=[[:space:]]*ntp' /etc/init.d/ntp 2>/dev/null
}

audit_mta_local_only() {
  if ! command_exists ss; then
    return 1
  fi

  ! ss -lntu 2>/dev/null | awk '$5 ~ /:25$/ && $5 !~ /(127\.0\.0\.1|\[::1\]|::1):25$/ { found=1 } END { exit found }'
}
