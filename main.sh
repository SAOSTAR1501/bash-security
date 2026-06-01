#!/usr/bin/env bash
# ======================================================================
#          LINUX SERVER SECURITY TOOLKIT (Miner & Malware Scanner)
# ======================================================================
# Dynamic MVC modular architecture entrypoint.
# ======================================================================
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 1. CORE COMPONENTS
source "${SCRIPT_DIR}/src/core/colors.sh"
source "${SCRIPT_DIR}/src/core/logger.sh"
source "${SCRIPT_DIR}/src/core/root.sh"
source "${SCRIPT_DIR}/src/core/ui.sh"
source "${SCRIPT_DIR}/src/core/chatops_service.sh"

# 2. SECURITY MODULES
source "${SCRIPT_DIR}/src/modules/system/sys_info.sh"
source "${SCRIPT_DIR}/src/modules/system/cpu_process.sh"
source "${SCRIPT_DIR}/src/modules/network/connections.sh"
source "${SCRIPT_DIR}/src/modules/network/firewall.sh"
source "${SCRIPT_DIR}/src/modules/filesystem/writable_paths.sh"
source "${SCRIPT_DIR}/src/modules/filesystem/integrity.sh"
source "${SCRIPT_DIR}/src/modules/persistence/entries.sh"
source "${SCRIPT_DIR}/src/modules/identity/users.sh"
source "${SCRIPT_DIR}/src/modules/identity/ssh_keys.sh"
source "${SCRIPT_DIR}/src/modules/updater/git_wget.sh"

# 3. INTERFACES & RUNTIME ORCHESTRATORS
source "${SCRIPT_DIR}/src/core/dashboard.sh"
source "${SCRIPT_DIR}/src/core/notifications.sh"
source "${SCRIPT_DIR}/src/core/menu.sh"

# Parse Startup Arguments
if [[ "${1:-}" == "--updated" ]]; then
    SHOW_UPDATE_SUCCESS=1
    shift
fi

if [[ "${1:-}" == "--cron" || "${1:-}" == "-c" ]]; then
    run_cron_scan
    exit 0
fi

# Start Execution
main_menu
