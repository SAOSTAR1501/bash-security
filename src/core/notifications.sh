# ======================================================================
# CORE COMPONENT: NOTIFICATION ENGINE & WEBHOOK SCHEDULER
# ======================================================================

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
    local is_test="${1:-false}"
    
    # Initialize configuration from persistent OS directory
    [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
    
    if [[ "$is_test" != "true" ]]; then
        if [[ "${ENABLE_LARK:-}" != "true" || -z "${LARK_WEBHOOK_URL:-}" ]]; then
            log_message "INFO" "Cron scan executed, but Lark notifications are disabled or not configured."
            return
        fi
    fi
    
    local audit_text=""
    
    # 1. OS & System Information Overview
    local os_desc
    os_desc=$(lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d= -f2 | tr -d '"' || uname -sr)
    local cpu_model
    cpu_model=$(lscpu 2>/dev/null | grep "Model name:" | sed 's/Model name:\s*//' || echo "Unknown CPU")
    
    audit_text+="**🖥️ System Configuration Overview:**\n"
    audit_text+="* OS Distro: \`$os_desc\`\n"
    audit_text+="* CPU Model: \`$cpu_model\`\n"
    
    # Resources (Load, RAM, Disk)
    local load_avg cpu_cores
    load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}')
    cpu_cores=$(nproc 2>/dev/null || echo "1")
    audit_text+="* Load Average: \`$load_avg\` (Cores: $cpu_cores)\n"
    
    local mem_total mem_used mem_pct
    mem_total=$(free -m | awk '/^Mem:/{print $2}' 2>/dev/null)
    mem_used=$(free -m | awk '/^Mem:/{print $3}' 2>/dev/null)
    [[ -z "$mem_total" ]] && mem_total=1
    [[ -z "$mem_used" ]] && mem_used=0
    mem_pct=$(( mem_used * 100 / mem_total ))
    audit_text+="* RAM Resource: \`${mem_used}MB / ${mem_total}MB (${mem_pct}%)\`\n"
    
    local disk_usage
    disk_usage=$(df -h / | tail -n 1 | awk '{print $5}' 2>/dev/null)
    audit_text+="* Disk Partition: \`$disk_usage\` on \`/\`\n\n"
    
    # 2. Host Detailed Security Configurations
    local ufw_status="INACTIVE"
    command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && ufw_status="ACTIVE"
    
    local ssh_port
    ssh_port=$(grep -i '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    local ssh_root_login
    ssh_root_login=$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (default)")
    
    local logged_users
    logged_users=$(who 2>/dev/null | awk '{print $1" ("$2" "$5")"}' | tr '\n' ',' | sed 's/,$//')
    [[ -z "$logged_users" ]] && logged_users="None"
    
    audit_text+="**🛡️ Host Security Configuration Details:**\n"
    audit_text+="* UFW Firewall Status: \`$ufw_status\`\n"
    audit_text+="* SSH Port: \`$ssh_port\` | Permit Root Login: \`$ssh_root_login\`\n"
    audit_text+="* Logged-in Users: \`$logged_users\`\n\n"
    
    # 3. Docker Running Containers & Resources
    local container_list=""
    local docker_stats=""
    local socket_mounts=""
    local dangerous_ports=""
    
    if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
        # List running containers
        while read -r line; do
            [[ -z "$line" ]] && continue
            local c_name=$(echo "$line" | awk -F'||' '{print $1}')
            local c_id=$(echo "$line" | awk -F'||' '{print $2}')
            local c_status=$(echo "$line" | awk -F'||' '{print $3}')
            local c_ports=$(echo "$line" | awk -F'||' '{print $4}')
            [[ -z "$c_ports" ]] && c_ports="None"
            container_list+="  * **${c_name}** (\`${c_id}\`): \`${c_status}\` | Ports: \`$c_ports\`\n"
        done < <(docker ps --format "{{.Names}}||{{.ID}}||{{.Status}}||{{.Ports}}" 2>/dev/null)
        
        # Container resource stats
        while read -r line; do
            [[ -z "$line" ]] && continue
            local c_name=$(echo "$line" | awk -F'||' '{print $1}')
            local c_cpu=$(echo "$line" | awk -F'||' '{print $2}')
            local c_mem=$(echo "$line" | awk -F'||' '{print $3}')
            docker_stats+="  * **${c_name}**: CPU: \`${c_cpu}\` | RAM: \`${c_mem}\`\n"
        done < <(docker stats --no-stream --format "{{.Name}}||{{.CPUPerc}}||{{.MemPerc}}" 2>/dev/null)
        
        # Check docker socket mount
        while read -r cid name; do
            if [[ -z "$cid" ]]; then continue; fi
            local inspect_mounts
            inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' "$cid" 2>/dev/null)
            if echo "$inspect_mounts" | grep -q "docker.sock"; then
                socket_mounts+="  * Container **$name** (\`$cid\`) mounts \`docker.sock\`! (CRITICAL ESCAPE RISK)\n"
            fi
        done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
        
        # Check exposed database ports
        while read -r name ports; do
            if [[ -z "$name" ]]; then continue; fi
            if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                local bound_port
                bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                dangerous_ports+="  * Container **$name** exposes database port \`$bound_port\` to 0.0.0.0! (UFW BYPASS)\n"
            fi
        done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
    fi
    
    audit_text+="**🐳 Running Docker Containers:**\n"
    if [[ -n "$container_list" ]]; then
        audit_text+="$container_list"
    else
        audit_text+="  * No running containers.\n"
    fi
    audit_text+="\n"
    
    audit_text+="**📊 Container Resource Utilization:**\n"
    if [[ -n "$docker_stats" ]]; then
        audit_text+="$docker_stats"
    else
        audit_text+="  * No stats available.\n"
    fi
    audit_text+="\n"
    
    if [[ -n "$socket_mounts" ]]; then
        audit_text+="**🐳 Critical Docker Vulnerabilities (Leo Thang Quyền Host):**\n$socket_mounts\n"
    fi
    if [[ -n "$dangerous_ports" ]]; then
        audit_text+="**🌐 Docker Exposed Ports (UFW Bypass Vulnerabilities):**\n$dangerous_ports\n"
    fi
    
    # 4. Top 5 CPU Processes
    local susp_proc=""
    while read -r pid user cpu comm; do
        [[ -z "$pid" || "$pid" == "PID" ]] && continue
        local exe_path=""
        [[ -L "/proc/$pid/exe" ]] && exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        
        local is_sus=0
        if [[ "$exe_path" == *" (deleted)"* ]]; then is_sus=1; fi
        for path in "/tmp" "/var/tmp" "/dev/shm"; do
            if [[ "$exe_path" == "$path"* ]]; then is_sus=1; break; fi
        done
        
        local susp_label=""
        [[ "$is_sus" -eq 1 ]] && susp_label=" 🔥 [SUSPICIOUS]"
        susp_proc+="  * PID \`$pid\` ($user): \`$comm\` (\`$cpu%\` CPU)${susp_label} -> \`${exe_path:-deleted/unknown}\`\n"
    done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu 2>/dev/null | head -n 6 | tail -n 5)
    
    if [[ -n "$susp_proc" ]]; then
        audit_text+="**🛑 Top 5 CPU-Consuming/Active Processes:**\n$susp_proc\n"
    fi
    
    # 5. Outbound Mining stratum Connections
    local stratum_conns=""
    local port_regex
    port_regex=$(echo "${MINING_PORTS[@]:-3333 4444 5555 7777 8888 9999}" | tr ' ' '|')
    if command -v ss &>/dev/null; then
        while read -r proto state recv_q send_q local_addr remote_addr process; do
            [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                stratum_conns+="  * Outbound mining pool connection: \`$remote_addr\`\n"
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
    elif [[ -n "$susp_proc" && "$susp_proc" == *"🔥 [SUSPICIOUS]"* ]]; then
        alert_level="danger"
        alert_title="VPS SECURITY ALERT: Suspicious Processes Executing!"
    elif [[ -n "$susp_proc" ]]; then
        alert_level="warn"
        alert_title="VPS SECURITY REPORT: High Resource Warnings"
    fi
    
    # Send Lark Interactive Card
    send_lark_notification "$alert_title" "$audit_text" "$alert_level" "$is_test"
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
        echo -e "  [3] Send FULL System Security Audit Test Report to Lark"
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
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/main.sh"
                    
                    # Register/update cron rules
                    (crontab -l 2>/dev/null | grep -v "main.sh") | crontab -
                    (crontab -l 2>/dev/null; echo "0 $CRON_HOURS * * * bash $script_path --cron >/dev/null 2>&1") | crontab -
                    print_status "success" "Automated Audits cronjob activated successfully for hours: $CRON_HOURS"
                elif [[ "$cron_toggle" == "2" ]]; then
                    ENABLE_CRON="false"
                    local script_path
                    script_path=$(realpath "$0" 2>/dev/null)
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/main.sh"
                    
                    (crontab -l 2>/dev/null | grep -v "main.sh") | crontab -
                    print_status "success" "Automated Audits cronjob deactivated."
                fi
                save_config
                sleep 1.5
                ;;
            3)
                if [[ -n "${LARK_WEBHOOK_URL:-}" ]]; then
                    print_status "info" "Compiling and sending FULL system security audit test report to Lark..."
                    run_cron_scan "true"
                else
                    print_status "danger" "Cannot send test. Lark Webhook URL is missing."
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
