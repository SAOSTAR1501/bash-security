# ======================================================================
# CORE COMPONENT: PRIVILEGE VALIDATOR
# ======================================================================

# Check root privileges prior to core scans
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${C_BRED}[!] ERROR: This toolkit must be run as root (or using sudo).${C_RESET}"
        echo -e "${C_GRAY}Some systems files, process metrics, and network configurations are hidden from regular users.${C_RESET}"
        exit 1
    fi
}
