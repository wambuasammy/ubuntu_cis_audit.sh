##################################################
# SECTION A
# INITIAL SYSTEM SETUP
##################################################

print_section "SECTION A: INITIAL SYSTEM SETUP"

# 1.1 Filesystem Configuration
source modules/filesystem_configuration.sh

# 1.2 Software Updates
source modules/software_updates.sh

# 1.3 Configure sudo
source modules/sudo_checks.sh

# 1.4 Filesystem Integrity Checking
source modules/filesystem_integrity.sh

# 1.5 Secure Boot Settings
source modules/secure_boot_checks.sh

# 1.6 Patch Management
source modules/patch_management.sh