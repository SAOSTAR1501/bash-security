# ======================================================================
# CORE COMPONENT: VISUAL INTERFACE ENGINE
# ======================================================================

clear_screen() {
    clear
}

print_header() {
    echo -e "${C_CYAN}======================================================================${C_RESET}"
    echo -e "${C_BCYAN}           STAR SECURITY (Miner & Malware Scanner)${C_RESET}"
    echo -e "${C_CYAN}======================================================================${C_RESET}"
}

print_status() {
    local type="$1"
    local msg="$2"
    case "$type" in
        "info")    echo -e "${C_BCYAN}[i]${C_RESET} $msg" ;;
        "success") echo -e "${C_BGREEN}[+]${C_RESET} $msg" ;;
        "warn")    echo -e "${C_BYELLOW}[!] WARNING:${C_RESET} $msg" ;;
        "danger")  echo -e "${C_BRED}[!!!] ALERT:${C_RESET} $msg" ;;
        "step")    echo -e "\n${C_BWHITE}>> $msg${C_RESET}" ;;
        "bullet")  echo -e "   ${C_CYAN}*${C_RESET} $msg" ;;
    esac
}

press_any_key() {
    echo -e "\n${C_GRAY}Press any key to return to the menu...${C_RESET}"
    read -n 1 -s -r
}

banner() {
    clear_screen
    echo -e "${C_BCYAN}"
    echo -e "      ▄████████  ▄████████   ▄████████    ▄████████ "
    echo -e "     ███    ███ ███    ███  ███    ███   ███    ███ "
    echo -e "     ███    █▀  ███    ███  ███    ███   ███    █▀  "
    echo -e "     ███        ███    ███  ███    ███  ▄███▄▄▄     "
    echo -e "   ▀███████████ ███    ███▀▀███████████ ▀▀███▀▀▀     "
    echo -e "            ███ ███    ███  ███    ███   ███    █▄  "
    echo -e "      ▄█    ███ ███    ███  ███    ███   ███    ███ "
    echo -e "    ▄████████▀   ▀██████▀   ███    █▀    ██████████ "
    echo -e "                 S E C U R I T Y   S Y S T E M"
    echo -e "   ${C_RESET}${C_DIM}v1.1.0 | Engine: Antigravity AI | OS: Linux System Audit${C_RESET}\n"
    log_message "INFO" "Star Security started."
}
