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

# Save configuration variables persistently (Survivable across Git updates)
save_config() {
    if [[ ! -d "/etc/sec-toolkit" ]]; then
        mkdir -p "/etc/sec-toolkit" 2>/dev/null
    fi
    cat <<EOF > "/etc/sec-toolkit/config.env"
ENABLE_LARK="${ENABLE_LARK:-false}"
LARK_WEBHOOK_URL="${LARK_WEBHOOK_URL:-}"
ENABLE_CRON="${ENABLE_CRON:-false}"
CRON_HOURS="${CRON_HOURS:-11,17,22}"
EOF
    chmod 600 "/etc/sec-toolkit/config.env" 2>/dev/null
}

# Automated Cron Alert scan (Silent, non-interactive execution)
run_cron_scan() {
    # Initialize configuration from persistent OS directory
    [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
    
    if [[ "${ENABLE_LARK:-}" != "true" || -z "${LARK_WEBHOOK_URL:-}" ]]; then
        log_message "INFO" "Cron scan executed, but Lark notifications are disabled or not configured."
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

# Unified Notification & Automated Cron Audits settings manager
configure_notifications() {
    while true; do
        # Reload configuration
        [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
        
        clear_screen
        print_header
        echo -e "${C_BMAGENTA}            >>> NOTIFICATION & ALERTS MANAGER <<<${C_RESET}\n"
        
        # Lark Alerts config status
        if [[ "${ENABLE_LARK:-}" == "true" ]]; then
            echo -e "Lark Notifications : ${C_BGREEN}[ENABLED]${C_RESET}"
        else
            echo -e "Lark Notifications : ${C_BRED}[DISABLED]${C_RESET}"
        fi
        
        if [[ -n "${LARK_WEBHOOK_URL:-}" ]]; then
            echo -e "Lark Webhook URL   : ${C_CYAN}${LARK_WEBHOOK_URL:0:60}...${C_RESET}"
        else
            echo -e "Lark Webhook URL   : ${C_GRAY}[NOT CONFIGURED]${C_RESET}"
        fi
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # Cron Audits config status
        if [[ "${ENABLE_CRON:-}" == "true" ]]; then
            echo -e "Automated Audits   : ${C_BGREEN}[ENABLED]${C_RESET}"
            echo -e "Audit Hours (Cron) : ${C_CYAN}${CRON_HOURS:-11,17,22} daily${C_RESET}"
        else
            echo -e "Automated Audits   : ${C_BRED}[DISABLED]${C_RESET}"
        fi
        
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -e "Settings Menu:"
        echo -e "  [1] Toggle & Configure Lark Webhook Alerts"
        echo -e "  [2] Toggle & Configure Automated Cron Audits"
        echo -e "  [3] Send Test Notification to Lark"
        echo -e "  [0] Back to Main Menu"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -n "Select action [0-3]: "
        read -r alert_choice
        
        case "$alert_choice" in
            1)
                echo -e "\nToggle Lark Notifications? (current: ${ENABLE_LARK:-false})"
                echo -e "  [1] Enable Lark Notifications"
                echo -e "  [2] Disable Lark Notifications"
                echo -n "Choice: "
                read -r lark_toggle
                if [[ "$lark_toggle" == "1" ]]; then
                    ENABLE_LARK="true"
                    echo -e "\nEnter Lark Webhook URL (press Enter to keep current):"
                    read -r temp_webhook
                    if [[ -n "$temp_webhook" ]]; then
                        LARK_WEBHOOK_URL="$temp_webhook"
                    fi
                elif [[ "$lark_toggle" == "2" ]]; then
                    ENABLE_LARK="false"
                fi
                save_config
                print_status "success" "Lark Notification settings updated."
                sleep 1.5
                ;;
            2)
                echo -e "\nToggle Automated Cron Audits? (current: ${ENABLE_CRON:-false})"
                echo -e "  [1] Enable Cron Audits"
                echo -e "  [2] Disable Cron Audits"
                echo -n "Choice: "
                read -r cron_toggle
                if [[ "$cron_toggle" == "1" ]]; then
                    ENABLE_CRON="true"
                    echo -e "\nConfigure Audit Hours:"
                    echo -e "  [1] Default Hours (11:00 AM, 5:00 PM, 10:00 PM)"
                    echo -e "  [2] Custom Hours (Comma-separated, e.g. 9,15,21)"
                    echo -n "Choice: "
                    read -r hour_choice
                    if [[ "$hour_choice" == "1" ]]; then
                        CRON_HOURS="11,17,22"
                    elif [[ "$hour_choice" == "2" ]]; then
                        echo -n "Enter custom hours (0-23, comma-separated): "
                        read -r temp_hours
                        if [[ "$temp_hours" =~ ^[0-9,]+$ ]]; then
                            CRON_HOURS="$temp_hours"
                        else
                            print_status "danger" "Invalid hours format. Using default: 11,17,22"
                            CRON_HOURS="11,17,22"
                        fi
                    fi
                    
                    local script_path
                    script_path=$(realpath "$0" 2>/dev/null)
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/sec.sh"
                    
                    # Register/update cron rules
                    (crontab -l 2>/dev/null | grep -v "sec.sh") | crontab -
                    (crontab -l 2>/dev/null; echo "0 $CRON_HOURS * * * bash $script_path --cron >/dev/null 2>&1") | crontab -
                    print_status "success" "Automated Audits cronjob activated successfully for hours: $CRON_HOURS"
                elif [[ "$cron_toggle" == "2" ]]; then
                    ENABLE_CRON="false"
                    local script_path
                    script_path=$(realpath "$0" 2>/dev/null)
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/sec.sh"
                    
                    (crontab -l 2>/dev/null | grep -v "sec.sh") | crontab -
                    print_status "success" "Automated Audits cronjob deactivated."
                fi
                save_config
                sleep 1.5
                ;;
            3)
                if [[ "${ENABLE_LARK:-}" == "true" && -n "${LARK_WEBHOOK_URL:-}" ]]; then
                    print_status "info" "Sending test interactive card to Lark..."
                    send_lark_notification "Lark Card Test Success" "Lark Alert Webhook is fully verified and connected to $(hostname)!" "success"
                else
                    print_status "danger" "Cannot send test. Lark Notifications are disabled or Webhook URL is missing."
                fi
                press_any_key
                ;;
            0)
                break
                ;;
            *)
                print_status "danger" "Invalid choice."
                sleep 1
                ;;
        esac
    done
}

# --- PRO HACKER LIVE SECURITY DASHBOARD (Real-time htop-like) ---
live_security_dashboard() {
    # Enter non-blocking terminal display loop
    clear_screen
    
    # Hide terminal cursor for professional look
    tput civis 2>/dev/null
    
    # Setup exit trap to restore cursor in case of Ctrl+C
    trap 'tput cnorm 2>/dev/null; exit' SIGINT SIGTERM
    
    while true; do
        # Move cursor to top left instead of clear to prevent screen flashing
        printf "\033[H"
        
        # Load latest configurations
        [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
        
        # 1. Header Information
        local hostname=$(hostname)
        local server_ip=$(curl -s --max-time 1 https://api.ipify.org || hostname -I | awk '{print $1}')
        local date_time=$(date "+%Y-%m-%d %H:%M:%S")
        local uptime_val=$(uptime -p 2>/dev/null | sed 's/up //')
        
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -e " 🛡️  ${C_BCYAN}VPS SECURITY LIVE DASHBOARD${C_RESET} | ${C_GRAY}Refreshes every 2s (Press [q] to exit)${C_RESET}"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        
        # System Stats Header
        printf " ${C_BOLD}%-12s:${C_RESET} %-15s | ${C_BOLD}%-10s:${C_RESET} %-15s\n" "Hostname" "$hostname" "Public IP" "$server_ip"
        printf " ${C_BOLD}%-12s:${C_RESET} %-15s | ${C_BOLD}%-10s:${C_RESET} %-15s\n" "System Uptime" "$uptime_val" "Live Time" "$date_time"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # 2. Left Panel: System Resources Metrics
        # CPU
        local cpu_pct=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' | cut -d. -f1)
        local cpu_bar=""
        local cpu_color="$C_BGREEN"
        if [[ "$cpu_pct" -ge 80 ]]; then cpu_color="$C_BRED"; elif [[ "$cpu_pct" -ge 50 ]]; then cpu_color="$C_BYELLOW"; fi
        local cpu_ticks=$((cpu_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $cpu_ticks ]]; then cpu_bar+="|"; else cpu_bar+=" "; fi
        done
        printf " ${C_BOLD}CPU Usage:${C_RESET}  [%-20s] ${cpu_color}%d%%${C_RESET}\n" "$cpu_bar" "$cpu_pct"
        
        # RAM
        local mem_total=$(free -m | awk '/^Mem:/{print $2}')
        local mem_used=$(free -m | awk '/^Mem:/{print $3}')
        local mem_pct=$(( mem_used * 100 / mem_total ))
        local mem_bar=""
        local mem_color="$C_BGREEN"
        if [[ "$mem_pct" -ge 90 ]]; then mem_color="$C_BRED"; elif [[ "$mem_pct" -ge 70 ]]; then mem_color="$C_BYELLOW"; fi
        local mem_ticks=$((mem_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $mem_ticks ]]; then mem_bar+="|"; else mem_bar+=" "; fi
        done
        printf " ${C_BOLD}RAM Usage:${C_RESET}  [%-20s] ${mem_color}%d%%${C_RESET} (%sMB/%sMB)\n" "$mem_bar" "$mem_pct" "$mem_used" "$mem_total"
        
        # Load Average
        local load_avg=$(cat /proc/loadavg | awk '{print $1" "$2" "$3}')
        printf " ${C_BOLD}Load Avg :${C_RESET}  %-25s\n" "$load_avg"
        
        # Storage Disk
        local disk_pct=$(df -h / | tail -n 1 | awk '{print $5}' | cut -d% -f1)
        local disk_bar=""
        local disk_color="$C_BGREEN"
        if [[ "$disk_pct" -ge 85 ]]; then disk_color="$C_BRED"; elif [[ "$disk_pct" -ge 70 ]]; then disk_color="$C_BYELLOW"; fi
        local disk_ticks=$((disk_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $disk_ticks ]]; then disk_bar+="|"; else disk_bar+=" "; fi
        done
        printf " ${C_BOLD}Disk /   :${C_RESET}  [%-20s] ${disk_color}%d%%${C_RESET}\n" "$disk_bar" "$disk_pct"
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        echo -e " 🚨 ${C_BWHITE}SECURITY SHIELD STATUS & ALERTS${C_RESET}"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # UFW Status
        local ufw_live="INACTIVE"
        local ufw_color="$C_BRED"
        if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
            ufw_live="ACTIVE"
            ufw_color="$C_BGREEN"
        fi
        
        # Exposed Database Ports
        local exposed_count=0
        if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
            while read -r name ports; do
                if [[ -z "$name" ]]; then continue; fi
                if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                    exposed_count=$((exposed_count + 1))
                fi
            done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
        fi
        local exposed_color="$C_BGREEN"
        [[ "$exposed_count" -gt 0 ]] && exposed_color="$C_BRED"
        
        # Docker Socket Mount Vulnerability
        local sock_mount_count=0
        if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
            while read -r cid name; do
                if [[ -z "$cid" ]]; then continue; fi
                local inspect_mounts
                inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}}{{end}}' "$cid" 2>/dev/null)
                if echo "$inspect_mounts" | grep -q "docker.sock"; then
                    sock_mount_count=$((sock_mount_count + 1))
                fi
            done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
        fi
        local sock_color="$C_BGREEN"
        [[ "$sock_mount_count" -gt 0 ]] && sock_color="$C_BRED"
        
        # Outbound stratum connections
        local stratum_count=0
        local port_regex=$(echo "${MINING_PORTS[@]}" | tr ' ' '|')
        if command -v ss &>/dev/null; then
            while read -r proto state recv_q send_q local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
                local rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
                if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                    stratum_count=$((stratum_count + 1))
                fi
            done < <(ss -tupn state established 2>/dev/null)
        fi
        local stratum_color="$C_BGREEN"
        [[ "$stratum_count" -gt 0 ]] && stratum_color="$C_BRED"
        
        # Display side-by-side or listed indicators
        printf "   * Tường lửa UFW    : ${ufw_color}%-10s${C_RESET} | * Lỗ hổng Cổng Docker   : ${exposed_color}%d Exposed${C_RESET}\n" "$ufw_live" "$exposed_count"
        printf "   * Docker Escapes   : ${sock_color}%-10s${C_RESET} | * Kết nối Pool Đào Coin : ${stratum_color}%d Active${C_RESET}\n" "$sock_mount_count Vulnerable" "$stratum_count Sockets"
        
        # Logged-in Users list
        local active_users=$(who | awk '{print $1" ("$2")"}' | tr '\n' ',' | sed 's/,$//')
        printf "   * Users Đăng nhập  : ${C_BCYAN}%s${C_RESET}\n" "${active_users:-[None]}"
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        echo -e " 🛑 ${C_BWHITE}TOP 5 CPU-CONSUMING / SUSPICIOUS RUNNING PROCESSES${C_RESET}"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # Top 5 CPU processes table
        printf "   ${C_BOLD}%-8s %-12s %-6s %-12s %-25s${C_RESET}\n" "PID" "USER" "CPU%" "COMM" "REAL EXEC PATH"
        
        while read -r pid user cpu comm; do
            [[ -z "$pid" || "$pid" == "PID" ]] && continue
            local exe_path=""
            [[ -L "/proc/$pid/exe" ]] && exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
            
            local is_sus=0
            if [[ "$exe_path" == *" (deleted)"* ]]; then is_sus=1; fi
            for path in "${SUSPICIOUS_PATHS[@]}"; do
                if [[ "$exe_path" == "$path"* ]]; then is_sus=1; break; fi
            done
            
            local line_color="$C_RESET"
            if [[ "$is_sus" -eq 1 ]]; then
                line_color="$C_BRED"
            elif [[ $(awk -v cpu="$cpu" -v limit="40" 'BEGIN {print (cpu > limit) ? 1 : 0}') -eq 1 ]]; then
                line_color="$C_BYELLOW"
            fi
            
            printf "   ${line_color}%-8s %-12s %-6s %-12s %-25s${C_RESET}\n" "$pid" "${user:0:11}" "$cpu" "$comm" "${exe_path:0:28}"
        done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu | head -n 6 | tail -n 5)
        
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        
        # Non-blocking key check for 2 seconds
        read -t 2 -n 1 input_key 2>/dev/null
        if [[ "${input_key,,}" == "q" ]]; then
            break
        fi
    done
    
    # Restore terminal cursor cleanly and reset trap
    tput cnorm 2>/dev/null
    trap - SIGINT SIGTERM
    clear_screen
}

# --- MAIN MENU CHOICE LOOP ---
main_menu() {
    check_root
    
    while true; do
        banner
        print_header
        
        # Display Lark integration status in header
        if [[ "${ENABLE_LARK:-}" == "true" && -n "${LARK_WEBHOOK_URL:-}" ]]; then
            echo -e "${C_GRAY}Lark Alerts: ${C_BGREEN}[ACTIVE]${C_RESET} | ${C_GRAY}Cron Audits: ${C_BGREEN}[ACTIVE]${C_RESET}\n"
        else
            echo -e "${C_GRAY}Lark Alerts: ${C_BRED}[INACTIVE]${C_RESET} | ${C_GRAY}Select [10] to configure notifications${C_RESET}\n"
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
        echo -e "   [12] Check & Update Security Toolkit (Git Pull)"
        echo -e "   [0]  Exit Security Toolkit"
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
