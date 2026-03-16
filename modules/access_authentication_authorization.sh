# ==================================================
# CIS Ubuntu Benchmark
# SECTION F: ACCESS, AUTHENTICATION AND AUTHORIZATION
# ==================================================

print_subsection "TIME-BASED JOB SCHEDULERS"
source modules/job_scheduler_checks.sh

print_subsection "PAM CONFIGURATION"
source modules/pam_checks.sh

print_subsection "USER ACCOUNTS AND ENVIRONMENT"
source modules/user_account_checks.sh

print_subsection "SYSTEM MAINTENANCE"
source modules/system_maintenance_checks.sh

print_subsection "HOME DIRECTORY CONTROLS"
source modules/home_directory_checks.sh