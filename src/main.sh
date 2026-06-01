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
    send_lark_notification "Full System Scan Completed" "Unified security assessment has successfully completed. Detailed audit logs are written to $LOG_FILE."
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

# Automated Cron Alert scan (Silent, non-interactive execution)
run_cron_scan() {
    # Initialize configuration
    [[ -f "/etc/sec_toolkit.conf" ]] && source "/etc/sec_toolkit.conf" 2>/dev/null
    
    if [[ -z "${LARK_WEBHOOK_URL:-}" ]]; then
        log_message "ERROR" "Cron scan aborted: Lark Webhook URL is not configured."
        return
    fi
    
    local audit_text=""
    
    # 1. System Performance Info
    local load_avg cpu_cores load_1m
    load_avg=$(cat /proc/loadavg | awk '{print $1" "$2" "$3}')
    cpu_cores=$(nproc)
    load_1m=$(cat /proc/loadavg | awk '{print $1}' | cut -d. -f1)
    
    audit_text+="**🖥️ System Performance & Health Status:**\n"
    audit_text+="* Load Average: \`$load_avg\` (CPU Cores: $cpu_cores)\n"
    
    local mem_total mem_used mem_pct
    mem_total=$(free -m | awk '/^Mem:/{print $2}')
    mem_used=$(free -m | awk '/^Mem:/{print $3}')
    mem_pct=$(( mem_used * 100 / mem_total ))
    audit_text+="* RAM Resource Usage: \`${mem_used}MB / ${mem_total}MB (${mem_pct}%)\`\n"
    
    local disk_usage
    disk_usage=$(df -h / | tail -n 1 | awk '{print $5}')
    audit_text+="* Host Storage Partition Usage: \`$disk_usage\`\n\n"
    
    # 2. Suspicious High CPU Processes
    local susp_proc=""
    while read -r pid user cpu comm; do
        [[ -z "$pid" || "$pid" == "PID" ]] && continue
        local exe_path=""
        [[ -L "/proc/$pid/exe" ]] && exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        susp_proc+="  * PID \`$pid\` ($user): \`$comm\` ($cpu% CPU) -> \`${exe_path:-deleted/unknown}\`\n"
    done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu | head -n 6 | tail -n 5)
    
    if [[ -n "$susp_proc" ]]; then
        audit_text+="**🛑 Suspicious/High-CPU Running Processes:**\n$susp_proc\n"
    fi
    
    # 3. Docker Socket Mount & Exposed Ports
    local socket_mounts=""
    local dangerous_ports=""
    if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
        # Check docker socket mount
        while read -r cid name; do
            if [[ -z "$cid" ]]; then continue; fi
            local inspect_mounts
            inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' "$cid" 2>/dev/null)
            if echo "$inspect_mounts" | grep -q "docker.sock"; then
                socket_mounts+="  * Container \`$name\` ($cid) mounts host \`docker.sock\`! (CRITICAL ESCAPE RISK)\n"
            fi
        done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
        
        # Check exposed database ports
        while read -r name ports; do
            if [[ -z "$name" ]]; then continue; fi
            if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                local bound_port
                bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                dangerous_ports+="  * Container \`$name\` exposes port \`$bound_port\` to 0.0.0.0! (UFW BYPASS)\n"
            fi
        done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
    fi
    
    if [[ -n "$socket_mounts" ]]; then
        audit_text+="**🐳 Critical Docker Vulnerabilities (Leo Thang Quyền Host):**\n$socket_mounts\n"
    fi
    if [[ -n "$dangerous_ports" ]]; then
        audit_text+="**🌐 Docker Exposed Ports (UFW Bypass Vulnerabilities):**\n$dangerous_ports\n"
    fi
    
    # 4. Outbound Stratum Mining Pool Connections
    local stratum_conns=""
    local port_regex
    port_regex=$(echo "${MINING_PORTS[@]}" | tr ' ' '|')
    if command -v ss &>/dev/null; then
        while read -r proto state recv_q send_q local_addr remote_addr process; do
            [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                stratum_conns+="  * Connection out to stratum miner pool: \`$remote_addr\`\n"
            fi
        done < <(ss -tupn state established 2>/dev/null)
    fi
    
    if [[ -n "$stratum_conns" ]]; then
        audit_text+="**⛏️ Outbound Mining Pool Connections:**\n$stratum_conns\n"
    fi
    
    # Determine alert level and title template
    local alert_level="success"
    local alert_title="Daily Server Health: ALL SYSTEMS NORMAL"
    
    if [[ -n "$socket_mounts" || -n "$dangerous_ports" || -n "$stratum_conns" ]]; then
        alert_level="danger"
        alert_title="VPS SECURITY ALERT: Critical Threats Detected!"
    elif [[ -n "$susp_proc" ]]; then
        alert_level="warn"
        alert_title="VPS SECURITY REPORT: Suspicious Warnings Identified"
    fi
    
    # Send Lark Interactive Card
    send_lark_notification "$alert_title" "$audit_text" "$alert_level"
}

# Schedule Automated Cron Notifications Wizard
configure_cronjob() {
    clear_screen
    print_header
    echo -e "${C_BMAGENTA}        >>> SCHEDULE AUTOMATED CRON NOTIFICATIONS <<<${C_RESET}\n"
    
    local script_path
    script_path=$(realpath "$0" 2>/dev/null)
    [[ -z "$script_path" ]] && script_path="/usr/local/bin/sec.sh"
    
    echo -e "This wizard configures a system cron job to run silently at:"
    echo -e "  * ${C_BCYAN}11:00 AM${C_RESET} (Daily Security Audit)"
    echo -e "  * ${C_BCYAN}05:00 PM${C_RESET} (Daily Security Audit)"
    echo -e "  * ${C_BCYAN}10:00 PM${C_RESET} (Daily Security Audit)"
    echo -e "And sends a structured Lark interactive card with security metrics and warnings."
    
    echo -e "\nScript path to execute: ${C_CYAN}$script_path${C_RESET}"
    echo -e "\nChoose action:"
    echo -e "  [1] ${C_BGREEN}Install/Activate Automated Cron Alert (11AM, 5PM, 10PM)${C_RESET}"
    echo -e "  [2] ${C_BRED}Uninstall/Deactivate Cron Alert${C_RESET}"
    echo -e "  [0] Go back"
    echo -n "Select action [1-2, or 0]: "
    read -r cron_choice
    
    case "$cron_choice" in
        1)
            # Remove any existing custom cron lines for sec.sh
            (crontab -l 2>/dev/null | grep -v "sec.sh") | crontab -
            
            # Install new cronjob
            (crontab -l 2>/dev/null; echo "0 11,17,22 * * * bash $script_path --cron >/dev/null 2>&1") | crontab -
            
            print_status "success" "Cron job scheduled successfully!"
            print_status "bullet" "Scheduled to run at 11:00, 17:00, 22:00 daily."
            print_status "bullet" "Verify with: crontab -l"
            ;;
        2)
            # Uninstall
            (crontab -l 2>/dev/null | grep -v "sec.sh") | crontab -
            print_status "success" "Cron job uninstalled successfully."
            ;;
        0|*)
            print_status "info" "No changes made."
            ;;
    esac
    press_any_key
}

# Lark Alert Webhook Configuration Manager
configure_lark_webhook() {
    clear_screen
    print_header
    echo -e "${C_BMAGENTA}            >>> LARK ALERT WEBHOOK CONFIGURATION <<<${C_RESET}\n"
    
    local current_webhook="${LARK_WEBHOOK_URL:-}"
    if [[ -n "$current_webhook" ]]; then
        echo -e "Current Webhook URL: ${C_BGREEN}${current_webhook:0:60}...${C_RESET}\n"
    else
        echo -e "Current Webhook URL: ${C_BRED}[NOT CONFIGURED]${C_RESET}\n"
    fi
    
    echo -e "Lark Webhooks allow the toolkit to send real-time security alerts"
    echo -e "directly to your Lark or Feishu chat groups when threats are detected."
    echo -e "\nEnter new Lark Webhook URL (or press Enter to keep current, type 'none' to clear):"
    read -r new_webhook
    
    if [[ "$new_webhook" == "none" ]]; then
        if [[ -f "/etc/sec_toolkit.conf" ]]; then
            sed -i '/LARK_WEBHOOK_URL/d' /etc/sec_toolkit.conf 2>/dev/null
        fi
        LARK_WEBHOOK_URL=""
        print_status "success" "Lark Webhook URL cleared successfully."
    elif [[ -n "$new_webhook" ]]; then
        if [[ ! -d "/etc" ]]; then
            mkdir -p "/etc" 2>/dev/null
        fi
        
        if [[ -f "/etc/sec_toolkit.conf" ]]; then
            sed -i '/LARK_WEBHOOK_URL/d' /etc/sec_toolkit.conf 2>/dev/null
        fi
        echo "LARK_WEBHOOK_URL=\"$new_webhook\"" >> "/etc/sec_toolkit.conf"
        chmod 600 "/etc/sec_toolkit.conf" 2>/dev/null
        LARK_WEBHOOK_URL="$new_webhook"
        
        print_status "success" "Lark Webhook URL saved successfully to /etc/sec_toolkit.conf"
        
        # Send test notification
        print_status "info" "Sending test notification to Lark..."
        send_lark_notification "Test Alert" "Lark Webhook Alert System has been successfully configured on $(hostname)!"
    fi
    
    press_any_key
}

# --- MAIN MENU CHOICE LOOP ---
main_menu() {
    check_root
    
    while true; do
        banner
        print_header
        
        # Display Lark integration status in header
        if [[ -n "${LARK_WEBHOOK_URL:-}" ]]; then
            echo -e "${C_GRAY}Lark Alerts: ${C_BGREEN}[ACTIVE]${C_RESET}\n"
        else
            echo -e "${C_GRAY}Lark Alerts: ${C_BRED}[INACTIVE] (Select [10] to configure)${C_RESET}\n"
        fi

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
        echo -e "${C_BCYAN}  -- TOOL CONFIGURATION & MAINTENANCE --${C_RESET}"
        echo -e "   [10] Configure Lark Alert Webhook URL"
        echo -e "   [11] Schedule Automated Cron Notifications (11AM, 5PM, 10PM)"
        echo -e "   [12] Check & Update Security Toolkit (Git Pull)"
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
                configure_lark_webhook
                ;;
            11)
                configure_cronjob
                ;;
            12)
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
                print_status "danger" "Invalid choice. Please select 0-12."
                sleep 1
                ;;
        esac
    done
}

# Check for silent cron execution mode
if [[ "${1:-}" == "--cron" || "${1:-}" == "-c" ]]; then
    run_cron_scan
    exit 0
fi

# Start execution
main_menu
