#!/bin/bash

set_services_check_metadata() {
  SECTION="2 Services"
  SUBSECTION="$1"
  CONTROL="$2"
  CHECK_ID="$3"
  CHECK_NAME="$4"
  DESCRIPTION="$5"
  RATIONALE="$6"
  AUDIT="$7"
  REMEDIATION="$8"
  RECOMMENDATION="$8"
}

record_package_absent_check() {
  local package="$1"
  if audit_package_not_installed "$package"; then record_result PASS; else record_result FAIL; fi
}

check_2_1_1() {
  set_services_check_metadata "2.1 inetd Services" "2.1 inetd Services" "2.1.1" "Ensure xinetd is not installed" "xinetd is a super daemon that listens for well-known services and dispatches service daemons." "If no xinetd services are required, the package should be removed." "dpkg -s xinetd" "Remove xinetd with apt purge xinetd."
  record_package_absent_check "xinetd"
}

check_2_1_2() {
  set_services_check_metadata "2.1 inetd Services" "2.1 inetd Services" "2.1.2" "Ensure openbsd-inetd is not installed" "inetd listens for well-known services and dispatches service daemons." "If no inetd services are required, the daemon should be removed." "dpkg -s openbsd-inetd" "Remove openbsd-inetd with apt purge openbsd-inetd."
  record_package_absent_check "openbsd-inetd"
}

check_2_2_1_1() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2.1 Time Synchronization" "2.2.1.1" "Ensure time synchronization is in use" "System time should be synchronized across the environment." "Time synchronization supports time-sensitive security mechanisms and consistent forensic log timelines." "systemctl is-enabled systemd-timesyncd; dpkg -s chrony; dpkg -s ntp" "Configure systemd-timesyncd, chrony, NTP, or host-based time synchronization according to site policy."
  if audit_time_sync_in_use; then record_result PASS; else record_result FAIL; fi
}

check_2_2_1_2() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2.1 Time Synchronization" "2.2.1.2" "Ensure systemd-timesyncd is configured" "systemd-timesyncd synchronizes the system clock across the network using SNTP." "Proper configuration is required for reliable time synchronization." "Verify ntp and chrony are absent, systemd-timesyncd is enabled, timesyncd.conf is configured, and timedatectl reports synchronization." "Remove ntp and chrony, enable systemd-timesyncd, configure NTP/FallbackNTP/RootDistanceMaxSec, start the service, and run timedatectl set-ntp true."
  if audit_timesyncd_configured; then record_result PASS; else record_result FAIL; fi
}

check_2_2_1_3() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2.1 Time Synchronization" "2.2.1.3" "Ensure chrony is configured" "chrony implements NTP and synchronizes system clocks using accurate time sources." "If chrony is used, proper configuration is required for reliable time synchronization." "Verify ntp is absent, systemd-timesyncd is masked, chrony has server/pool entries, and chronyd runs as _chrony." "Remove ntp, mask systemd-timesyncd, configure server/pool entries in chrony.conf, and configure chrony to run as _chrony."
  if audit_chrony_configured; then record_result PASS; else record_result MANUAL; fi
}

check_2_2_1_4() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2.1 Time Synchronization" "2.2.1.4" "Ensure ntp is configured" "ntp implements the Network Time Protocol for system clock synchronization." "If ntp is used, proper configuration is required for reliable time synchronization." "Verify chrony is absent, systemd-timesyncd is masked, ntp restrict and server/pool entries exist, and ntp runs as the ntp user." "Remove chrony, mask systemd-timesyncd, configure ntp restrict/server/pool entries, and set RUNASUSER=ntp."
  if audit_ntp_configured; then record_result PASS; else record_result MANUAL; fi
}

check_2_2_2() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.2" "Ensure X Window System is not installed" "The X Window System provides a graphical user interface." "Servers that do not require graphical login should remove X Windows to reduce attack surface." "dpkg -l xserver-xorg*" "Remove X Window System packages with apt purge xserver-xorg*."
  if audit_package_pattern_not_installed "xserver-xorg*"; then record_result PASS; else record_result FAIL; fi
}

check_2_2_3() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.3" "Ensure Avahi Server is not installed" "Avahi provides multicast DNS/DNS-SD service discovery." "Automatic service discovery is usually unnecessary and increases attack surface." "dpkg -s avahi-daemon" "Stop avahi-daemon services and remove avahi-daemon with apt purge avahi-daemon."
  record_package_absent_check "avahi-daemon"
}

check_2_2_4() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.4" "Ensure CUPS is not installed" "CUPS provides local and network printing services." "Systems that do not need printing should remove CUPS to reduce attack surface." "dpkg -s cups" "Remove cups with apt purge cups."
  record_package_absent_check "cups"
}

check_2_2_5() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.5" "Ensure DHCP Server is not installed" "DHCP dynamically assigns IP addresses to machines." "Systems not acting as DHCP servers should remove this package." "dpkg -s isc-dhcp-server" "Remove isc-dhcp-server with apt purge isc-dhcp-server."
  record_package_absent_check "isc-dhcp-server"
}

check_2_2_6() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.6" "Ensure LDAP server is not installed" "LDAP provides centralized directory lookups." "Systems not acting as LDAP servers should remove slapd to reduce attack surface." "dpkg -s slapd" "Remove slapd with apt purge slapd."
  record_package_absent_check "slapd"
}

check_2_2_7() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.7" "Ensure NFS is not installed" "NFS allows systems to mount remote filesystems over the network." "Systems not exporting NFS shares should remove the NFS server package." "dpkg -s nfs-kernel-server" "Remove nfs-kernel-server with apt purge nfs-kernel-server."
  record_package_absent_check "nfs-kernel-server"
}

check_2_2_8() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.8" "Ensure DNS Server is not installed" "DNS maps host names to IP addresses." "Systems not designated as DNS servers should remove bind9." "dpkg -s bind9" "Remove bind9 with apt purge bind9."
  record_package_absent_check "bind9"
}

check_2_2_9() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.9" "Ensure FTP Server is not installed" "FTP provides network file transfer but does not protect data or credentials." "Use SFTP where file transfer is required; remove FTP server packages otherwise." "dpkg -s vsftpd" "Remove vsftpd with apt purge vsftpd."
  record_package_absent_check "vsftpd"
}

check_2_2_10() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.10" "Ensure HTTP server is not installed" "HTTP servers host website content." "Systems not acting as web servers should remove apache2." "dpkg -s apache2" "Remove apache2 with apt purge apache2."
  record_package_absent_check "apache2"
}

check_2_2_11() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.11" "Ensure IMAP and POP3 server are not installed" "dovecot-imapd and dovecot-pop3d provide IMAP and POP3 mail services." "Systems not providing POP3 or IMAP should remove these packages." "dpkg -s dovecot-imapd dovecot-pop3d" "Remove dovecot-imapd and dovecot-pop3d with apt purge."
  if audit_all_packages_not_installed "dovecot-imapd" "dovecot-pop3d"; then record_result PASS; else record_result FAIL; fi
}

check_2_2_12() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.12" "Ensure Samba is not installed" "Samba shares Linux filesystems and directories with Windows systems using SMB." "Systems not sharing files with Windows systems should remove Samba." "dpkg -s samba" "Remove samba with apt purge samba."
  record_package_absent_check "samba"
}

check_2_2_13() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.13" "Ensure HTTP Proxy Server is not installed" "Squid is a standard HTTP proxy server." "Systems not acting as proxy servers should remove squid." "dpkg -s squid" "Remove squid with apt purge squid."
  record_package_absent_check "squid"
}

check_2_2_14() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.14" "Ensure SNMP Server is not installed" "SNMP servers listen for SNMP management commands and return system information." "SNMP can expose sensitive management data and should be removed if not required." "dpkg -s snmpd" "Remove snmpd with apt purge snmpd."
  record_package_absent_check "snmpd"
}

check_2_2_15() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.15" "Ensure mail transfer agent is configured for local-only mode" "MTAs listen for incoming mail and transfer messages to local users or mail servers." "Systems not intended as mail servers should not expose MTA listeners on non-loopback addresses." "ss -lntu | grep ':25' excluding 127.0.0.1 and ::1" "Configure the MTA to listen only on 127.0.0.1 and ::1, then restart the MTA service."
  if audit_mta_local_only; then record_result PASS; else record_result FAIL; fi
}

check_2_2_16() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.16" "Ensure rsync service is not installed" "rsync can synchronize files between systems over network links." "The rsync service can present risk because it uses unencrypted protocols for communication." "dpkg -s rsync" "Remove rsync with apt purge rsync."
  record_package_absent_check "rsync"
}

check_2_2_17() {
  set_services_check_metadata "2.2 Special Purpose Services" "2.2 Special Purpose Services" "2.2.17" "Ensure NIS Server is not installed" "NIS distributes system configuration files through a client-server directory service." "NIS is inherently insecure and should be removed in favor of more secure services." "dpkg -s nis" "Remove nis with apt purge nis."
  record_package_absent_check "nis"
}

check_2_3_1() {
  set_services_check_metadata "2.3 Service Clients" "2.3 Service Clients" "2.3.1" "Ensure NIS Client is not installed" "The NIS client binds a machine to an NIS server and receives distributed configuration files." "NIS is insecure and has largely been replaced by LDAP; remove the client if not required." "dpkg -s nis" "Remove nis with apt purge nis."
  record_package_absent_check "nis"
}

check_2_3_2() {
  set_services_check_metadata "2.3 Service Clients" "2.3 Service Clients" "2.3.2" "Ensure rsh client is not installed" "The rsh-client package contains client commands for rsh services." "Legacy rsh, rcp, and rlogin clients expose security risks and should be replaced by SSH." "dpkg -s rsh-client" "Remove rsh-client with apt purge rsh-client."
  record_package_absent_check "rsh-client"
}

check_2_3_3() {
  set_services_check_metadata "2.3 Service Clients" "2.3 Service Clients" "2.3.3" "Ensure talk client is not installed" "The talk client allows users to initiate terminal messaging sessions across systems." "talk uses unencrypted protocols and presents a security risk." "dpkg -s talk" "Remove talk with apt purge talk."
  record_package_absent_check "talk"
}

check_2_3_4() {
  set_services_check_metadata "2.3 Service Clients" "2.3 Service Clients" "2.3.4" "Ensure telnet client is not installed" "The telnet client allows users to connect to remote systems using the telnet protocol." "Telnet is insecure and unencrypted; SSH should be used instead." "dpkg -s telnet" "Remove telnet with apt purge telnet."
  record_package_absent_check "telnet"
}

check_2_3_5() {
  set_services_check_metadata "2.3 Service Clients" "2.3 Service Clients" "2.3.5" "Ensure LDAP client is not installed" "ldap-utils provides LDAP client utilities for querying centralized directory services." "If the system does not need LDAP client functionality, remove it to reduce attack surface." "dpkg -s ldap-utils" "Remove ldap-utils with apt purge ldap-utils."
  record_package_absent_check "ldap-utils"
}

check_2_3_6() {
  set_services_check_metadata "2.3 Service Clients" "2.3 Service Clients" "2.3.6" "Ensure RPC is not installed" "RPC is used for low-level client-server applications and requires network-listening components." "If RPC is not required, remove rpcbind to reduce remote attack surface." "dpkg -s rpcbind" "Remove rpcbind with apt purge rpcbind."
  record_package_absent_check "rpcbind"
}

check_2_4() {
  set_services_check_metadata "2.4 Nonessential Services" "2.4 Nonessential Services" "2.4" "Ensure nonessential services are removed or masked" "Listening ports expose applications and services as network communication endpoints." "Services listening on the system can be attack vectors and should be reviewed, removed, stopped, or masked when not required." "lsof -i -P -n | grep -v '(ESTABLISHED)'" "Review listening services; remove unnecessary packages or stop and mask required-package services with systemctl --now mask <service_name>."
  record_result MANUAL
}
