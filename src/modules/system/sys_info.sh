# ======================================================================
# MODULE: SYSTEM INFO AUDITOR
# ======================================================================

display_system_info() {
    print_status "step" "Auditing Host System General Information..."
    
    local os_pretty="Unknown Linux"
    if [[ -f "/etc/os-release" ]]; then
        os_pretty=$(grep PRETTY_NAME /etc/os-release | cut -d'=' -f2 | tr -d '"')
    fi
    
    local load_avg
    load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1", "$2", "$3}')
    
    local uptime_str
    uptime_str=$(uptime -p 2>/dev/null)
    
    local total_mem free_mem
    total_mem=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}')
    free_mem=$(free -h 2>/dev/null | awk '/^Mem:/ {print $4}')
    
    local disk_usage
    disk_usage=$(df -h / 2>/dev/null | tail -n 1 | awk '{print $5" of "$2}')

    echo -e "${C_BWHITE}--- System Specifications ---${C_RESET}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Operating System" "$os_pretty"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Hostname" "$(hostname)"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Kernel Version" "$(uname -r)"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "System Uptime" "${uptime_str:-[N/A]}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Load Average" "${load_avg:-[N/A]}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s (Free: %s)\n" "RAM Resources" "${total_mem:-[N/A]}" "${free_mem:-[N/A]}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s used\n" "Disk Space (Root)" "${disk_usage:-[N/A]}"
    echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
}
