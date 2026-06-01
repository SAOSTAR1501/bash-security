# ======================================================================
# CORE MAIN ENTRYPOINT & ORCHESTRATOR
# ======================================================================

# Orchestrate all security scans
run_full_scan() {
    clear_screen
    print_header
    echo -e "${C_BWHITE}Running unified system security assessment. Please wait...${C_RESET}\n"
    
    display_system_info
    check_cpu_processes
    check_network_connections
    check_ports_firewall
    check_globally_writeable
    check_persistence
    check_system_integrity
    audit_system_users
    audit_ssh_keys
    
    echo -e "\n${C_BCYAN}======================================================================${C_RESET}"
    print_status "success" "Security assessment complete. Audit log written to: $LOG_FILE"
    press_any_key
}

# Generate audit reports to disk
generate_report() {
    local report_path="/tmp/security_toolkit_report.txt"
    print_status "step" "Generating audit text report..."
    
    {
        echo "======================================================================"
        echo "           LINUX SERVER SECURITY TOOLKIT - AUDIT REPORT"
        echo "           Generated at: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "======================================================================"
        echo ""
        echo "--- Host Information ---"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Uptime: $(uptime -p)"
        echo ""
        echo "--- High Resource / Suspicious Processes ---"
        ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 20
        echo ""
        echo "--- Active Outbound Network Connections ---"
        if command -v ss &>/dev/null; then
            ss -tupn state established 2>/dev/null
        else
            netstat -nap 2>/dev/null | grep ESTABLISHED
        fi
        echo ""
        echo "--- Persistence Check ---"
        echo "* Systemd units:"
        find /etc/systemd/system/ -name "*.service" -exec grep -H "ExecStart" {} \; 2>/dev/null
        echo "* System Crontab:"
        cat /etc/crontab 2>/dev/null
        echo ""
        echo "--- Library Injections (/etc/ld.so.preload) ---"
        cat /etc/ld.so.preload 2>/dev/null
        echo ""
        echo "--- User Identity & Accounts ---"
        while read -r line; do
            local u uid shell
            u=$(echo "$line" | cut -d':' -f1)
            uid=$(echo "$line" | cut -d':' -f3)
            shell=$(echo "$line" | cut -d':' -f7)
            if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
                echo "   Interactive User: $u (UID: $uid)"
            fi
        done < /etc/passwd
    } > "$report_path"

    log_message "INFO" "Generated report at $report_path"
    print_status "success" "Report generated successfully at: $report_path"
    print_status "info" "You can download or view this file for detailed offline audits."
    press_any_key
}

# --- MAIN MENU CHOICE LOOP ---
main_menu() {
    check_root
    
    while true; do
        banner
        print_header
        echo -e "${C_BMAGENTA}  -- SYSTEM OVERVIEW & REPORTING --${C_RESET}"
        echo -e "   [1]  Run Full System Security Scan (Unified Live Audit)"
        echo -e "   [2]  Generate Comprehensive Text Audit Report (Save to file)"
        echo -e ""
        echo -e "${C_BRED}  -- ACTIVE THREAT REMEDIATION (SOAR) --${C_RESET}"
        echo -e "   [3]  Deep Process Investigator & Host Container Destroyer"
        echo -e "   [4]  Audit Ports, UFW & Docker Firewall Hardening Wizard"
        echo -e ""
        echo -e "${C_BYELLOW}  -- DEEP AUDITING & FORENSICS --${C_RESET}"
        echo -e "   [5]  Inspect Network Connections & Outbound Stratum Pools"
        echo -e "   [6]  Scan Globally Writable Paths (/tmp, /dev/shm) for Payloads"
        echo -e "   [7]  Audit Persistence Mechanisms (Cron Jobs, Systemd Units)"
        echo -e "   [8]  Verify Library Injections (Rootkits / ld.so.preload)"
        echo -e "   [9]  Audit Identity Credentials, Users & SSH Key Leaks"
        echo -e ""
        echo -e "${C_BCYAN}  -- TOOL MAINTENANCE --${C_RESET}"
        echo -e "   [10] Check & Update Security Toolkit (Git Pull)"
        echo -e "   [0]  Exit Security Toolkit"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -n "Select option: "
        read -r main_choice
        
        case "$main_choice" in
            1)
                run_full_scan
                ;;
            2)
                clear_screen
                print_header
                generate_report
                ;;
            3)
                process_investigator
                ;;
            4)
                clear_screen
                print_header
                check_ports_firewall
                press_any_key
                ;;
            5)
                clear_screen
                print_header
                check_network_connections
                press_any_key
                ;;
            6)
                clear_screen
                print_header
                check_globally_writeable
                press_any_key
                ;;
            7)
                clear_screen
                print_header
                check_persistence
                press_any_key
                ;;
            8)
                clear_screen
                print_header
                check_system_integrity
                press_any_key
                ;;
            9)
                clear_screen
                print_header
                audit_system_users
                echo ""
                audit_ssh_keys
                press_any_key
                ;;
            10)
                clear_screen
                print_header
                update_tool
                ;;
            0)
                echo -e "\n${C_BGREEN}[+] Thank you for using Linux Server Security Toolkit. Stay secure!${C_RESET}"
                log_message "INFO" "Security Toolkit closed."
                exit 0
                ;;
            *)
                print_status "danger" "Invalid choice. Please select 0-10."
                sleep 1
                ;;
        esac
    done
}

# Start execution
main_menu
