# ======================================================================
# CORE COMPONENT: MAIN ORCHESTRATOR & USER MENU
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
    send_lark_notification "Full System Scan Completed" "Unified security assessment has successfully completed. Detailed audit logs are written to $LOG_FILE." "success"
    press_any_key
}

# Generate comprehensive audit reports to disk
generate_report() {
    local report_dir="/var/log/sec-toolkit"
    mkdir -p "$report_dir" 2>/dev/null
    local report_path="${report_dir}/audit_report_$(date +%Y%m%d_%H%M%S).txt"
    
    clear_screen
    print_header
    echo -e "${C_BWHITE}>>> GENERATING COMPREHENSIVE TEXT AUDIT REPORT <<<${C_RESET}\n"
    print_status "step" "Executing full security suite in background, capturing output..."
    print_status "info" "This will run all audits (CPU, ports, firewall, writable paths, integrity, users, cron, ssh leaks) and save a clean, color-stripped report."
    echo -e ""

    {
        echo "======================================================================"
        echo "           STAR SECURITY - FULL AUDIT REPORT"
        echo "           Generated at: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "           Hostname: $(hostname 2>/dev/null)"
        echo "           Public IP: $(curl -s --max-time 1.5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}')"
        echo "======================================================================"
        echo ""

        display_system_info
        echo ""
        check_cpu_processes
        echo ""
        check_network_connections
        echo ""
        check_ports_firewall
        echo ""
        check_globally_writeable
        echo ""
        check_persistence
        echo ""
        check_system_integrity
        echo ""
        audit_system_users
        echo ""
        audit_ssh_keys
        echo ""
        
        echo "======================================================================"
        echo "           END OF REPORT - STAR SECURITY"
        echo "======================================================================"
    } | sed -r "s/\x1B\[([0-9]{1,2}(;[0-9]{1,2})?)?[mGKB]//g" > "$report_path"

    # Create convenient persistent symlink to the latest report
    ln -sf "$report_path" "/var/log/security_toolkit_report.txt" 2>/dev/null
    
    # Calculate file size
    local file_size="0 B"
    if [[ -f "$report_path" ]]; then
        file_size=$(stat -c "%s" "$report_path" 2>/dev/null | awk '{ split("B KB MB GB", v); s=1; while($1>1024){$1/=1024; s++} printf "%.1f %s", $1, v[s] }')
    fi

    log_message "INFO" "Generated full audit report at $report_path ($file_size)"
    
    print_status "success" "COMPREHENSIVE AUDIT REPORT GENERATED SUCCESSFULLY!"
    print_status "bullet" "Report Location : ${C_CYAN}${report_path}${C_RESET}"
    print_status "bullet" "Latest Symlink  : ${C_CYAN}/var/log/security_toolkit_report.txt${C_RESET}"
    print_status "bullet" "Report Size     : ${C_BWHITE}${file_size}${C_RESET}"
    echo -e ""
    print_status "info" "You can open or download this file to audit system logs offline."
    print_status "info" "Command to view: ${C_CYAN}cat /var/log/security_toolkit_report.txt${C_RESET}"
    
    press_any_key
}

# --- MAIN MENU CHOICE LOOP ---
main_menu() {
    check_root
    
    if [[ "${SHOW_UPDATE_SUCCESS:-0}" -eq 1 ]]; then
        print_status "success" "Star Security successfully updated to the latest version!"
        SHOW_UPDATE_SUCCESS=0
        sleep 2
    fi
    
    while true; do
        banner
        print_header
        
        # Display Lark integration status in header
        if [[ "${ENABLE_LARK:-}" == "true" && -n "${LARK_WEBHOOK_URL:-}" ]]; then
            echo -e "${C_GRAY}Lark Alerts: ${C_BGREEN}[ACTIVE]${C_RESET} | ${C_GRAY}Cron Audits: ${C_BGREEN}[ACTIVE]${C_RESET}\n"
        else
            echo -e "${C_GRAY}Lark Alerts: ${C_BRED}[INACTIVE]${C_RESET} | ${C_GRAY}Select [11] to configure notifications${C_RESET}\n"
        fi

        echo -e "${C_BMAGENTA}  -- SYSTEM OVERVIEW & REPORTING --${C_RESET}"
        echo -e "   [1]  Launch Live Security Terminal Dashboard (Real-time htop-like)"
        echo -e "   [2]  Run Full System Security Scan (Unified Live Audit)"
        echo -e "   [3]  Generate Comprehensive Text Audit Report (Save to file)"
        echo -e ""
        echo -e "${C_BRED}  -- ACTIVE THREAT REMEDIATION (SOAR) --${C_RESET}"
        echo -e "   [4]  Deep Process Investigator & Host Container Destroyer"
        echo -e "   [5]  Audit Ports, UFW & Docker Firewall Hardening Wizard"
        echo -e ""
        echo -e "${C_BYELLOW}  -- DEEP AUDITING & FORENSICS --${C_RESET}"
        echo -e "   [6]  Inspect Network Connections & Outbound Stratum Pools"
        echo -e "   [7]  Scan Globally Writable Paths (/tmp, /dev/shm) for Payloads"
        echo -e "   [8]  Audit Persistence Mechanisms (Cron Jobs, Systemd Units)"
        echo -e "   [9]  Verify Library Injections (Rootkits / ld.so.preload)"
        echo -e "   [10] Audit Identity Credentials, Users & SSH Key Leaks"
        echo -e ""
        echo -e "${C_BCYAN}  -- TOOL CONFIGURATION & MAINTENANCE --${C_RESET}"
        echo -e "   [11] Configure Security Notifications & Automated Audits"
        echo -e "   [12] Check & Update Star Security (Git Pull)"
        echo -e "   [0]  Exit Star Security"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -n "Select option: "
        read -r main_choice
        
        case "$main_choice" in
            1)
                live_security_dashboard
                ;;
            2)
                run_full_scan
                ;;
            3)
                clear_screen
                print_header
                generate_report
                ;;
            4)
                process_investigator
                ;;
            5)
                clear_screen
                print_header
                check_ports_firewall
                press_any_key
                ;;
            6)
                clear_screen
                print_header
                check_network_connections
                press_any_key
                ;;
            7)
                clear_screen
                print_header
                check_globally_writeable
                press_any_key
                ;;
            8)
                clear_screen
                print_header
                check_persistence
                press_any_key
                ;;
            9)
                clear_screen
                print_header
                check_system_integrity
                press_any_key
                ;;
            10)
                clear_screen
                print_header
                audit_system_users
                echo ""
                audit_ssh_keys
                press_any_key
                ;;
            11)
                configure_notifications
                ;;
            12)
                clear_screen
                print_header
                update_tool
                ;;
            0)
                echo -e "\n${C_BGREEN}[+] Thank you for using Star Security. Stay secure!${C_RESET}"
                log_message "INFO" "Star Security closed."
                exit 0
                ;;
            *)
                print_status "danger" "Invalid choice. Please select 0-12."
                sleep 1
                ;;
        esac
    done
}
