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
    local BR="<br>"
    local soar_actions=""
    
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
    cpu_model=$(lscpu 2>/dev/null | grep "Model name:" | sed 's/Model name:\s*//' | sed 's/\s\+/ /g' || echo "Unknown CPU")
    
    audit_text+="**🖥️ SYSTEM CONFIGURATION & HARDWARE:**${BR}"
    audit_text+="├─ Operating System : \`$os_desc\`${BR}"
    audit_text+="└─ CPU Processor    : \`$cpu_model\`${BR}${BR}"
    
    # Resources (Load, RAM, Disk)
    local load_avg cpu_cores
    load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}')
    cpu_cores=$(nproc 2>/dev/null || echo "1")
    
    local mem_total mem_used mem_pct
    mem_total=$(free -m | awk '/^Mem:/{print $2}' 2>/dev/null)
    mem_used=$(free -m | awk '/^Mem:/{print $3}' 2>/dev/null)
    [[ -z "$mem_total" ]] && mem_total=1
    [[ -z "$mem_used" ]] && mem_used=0
    mem_pct=$(( mem_used * 100 / mem_total ))
    
    local disk_usage disk_total
    disk_usage=$(df -h / | tail -n 1 | awk '{print $5}' 2>/dev/null)
    disk_total=$(df -h / | tail -n 1 | awk '{print $2}' 2>/dev/null)
    
    audit_text+="**📊 REAL-TIME CORE RESOURCE METRICS:**${BR}"
    audit_text+="├─ CPU Load Average : \`$load_avg\` (Cores: $cpu_cores)${BR}"
    audit_text+="├─ Memory Resource  : \`${mem_used}MB / ${mem_total}MB (${mem_pct}%)\`${BR}"
    audit_text+="└─ Disk Partition   : \`$disk_usage\` used of \`$disk_total\` on \`/\`${BR}${BR}"
    
    # 2. Host Detailed Security Configurations
    local ufw_status="INACTIVE"
    command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && ufw_status="ACTIVE"
    
    local ufw_tag="🔴 INACTIVE"
    [[ "$ufw_status" == "ACTIVE" ]] && ufw_tag="🟢 ACTIVE"
    
    local ssh_port
    ssh_port=$(grep -i '^Port ' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "22")
    local ssh_root_login
    ssh_root_login=$(grep -i '^PermitRootLogin' /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "yes (default)")
    
    local ssh_root_tag="\`$ssh_root_login\`"
    if [[ "$ssh_root_login" == "yes" || "$ssh_root_login" == "yes (default)" ]]; then
        ssh_root_tag="\`$ssh_root_login\` ⚠️ (HIGH RISK)"
    fi
    
    # Fast SUID/SGID Backdoor scan in writable paths (maxdepth 3)
    local suid_count=0
    local suid_list=""
    for target_dir in "/tmp" "/var/tmp" "/dev/shm"; do
        if [[ -d "$target_dir" ]]; then
            while read -r suid_path; do
                [[ -z "$suid_path" || ! -f "$suid_path" ]] && continue
                suid_count=$((suid_count + 1))
                local s_owner=$(stat -c "%U:%G" "$suid_path" 2>/dev/null)
                suid_list+="  ⚠️ SUID file: \`$suid_path\` (Owner: \`$s_owner\`)${BR}"
            done < <(find "$target_dir" -maxdepth 3 -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
        fi
    done
    local suid_tag="🟢 Clean (0 backdoors)"
    [[ "$suid_count" -gt 0 ]] && suid_tag="🔴 $suid_count DETECTED! ⚠️"

    # Fast Log Integrity Check (auth.log / wtmp / lastlog truncation anomalies)
    local log_tampered=0
    local log_anomalies_list=""
    local logs_check=("/var/log/wtmp" "/var/log/lastlog" "/var/log/auth.log" "/var/log/secure")
    for log_p in "${logs_check[@]}"; do
        if [[ -f "$log_p" ]]; then
            local f_sz
            f_sz=$(stat -c "%s" "$log_p" 2>/dev/null)
            if [[ "$f_sz" -eq 0 ]]; then
                log_tampered=1
                log_anomalies_list+="  ⚠️ Truncated (0 bytes): \`$log_p\`${BR}"
            fi
        fi
    done
    local log_tag="🟢 Intact"
    [[ "$log_tampered" -eq 1 ]] && log_tag="🔴 TAMPERED! ⚠️"

    # Fast Sudoers NOPASSWD backdoor check
    local sudo_count=0
    local sudo_list=""
    if [[ -f "/etc/sudoers" ]]; then
        while read -r line; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            if echo "$line" | grep -q "NOPASSWD"; then
                sudo_count=$((sudo_count + 1))
                sudo_list+="  ⚠️ Sudoers: NOPASSWD in \`/etc/sudoers\` -> \`$line\`${BR}"
            fi
        done < "/etc/sudoers"
    fi
    if [[ -d "/etc/sudoers.d" ]]; then
        for f in /etc/sudoers.d/*; do
            [[ ! -f "$f" ]] && continue
            while read -r line; do
                [[ -z "$line" || "$line" == "#"* ]] && continue
                if echo "$line" | grep -q "NOPASSWD"; then
                    sudo_count=$((sudo_count + 1))
                    sudo_list+="  ⚠️ Sudoers: NOPASSWD in \`$(basename "$f")\` -> \`$line\`${BR}"
                fi
            done < "$f"
        done
    fi
    local sudo_tag="🟢 Secure (No NOPASSWD)"
    [[ "$sudo_count" -gt 0 ]] && sudo_tag="🔴 $sudo_count DETECTED! ⚠️"

    # Fast SSH Brute Force failed logins check
    local failed_logins=0
    local failed_ips=""
    local auth_l=""
    [[ -f "/var/log/auth.log" ]] && auth_l="/var/log/auth.log"
    [[ -f "/var/log/secure" ]] && auth_l="/var/log/secure"
    if [[ -n "$auth_l" ]]; then
        failed_logins=$(grep -i "failed password" "$auth_l" 2>/dev/null | wc -l)
        if [[ "$failed_logins" -gt 0 ]]; then
            # Parse top 3 attacking IPs and dynamically label them if already firewall-blocked
            local temp_failed_ips=""
            while read -r count ip; do
                if [[ -n "$ip" ]]; then
                    local block_label=""
                    # Check firewall status of this IP
                    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
                        if ufw status numbered 2>/dev/null | grep -Fq "$ip"; then
                            block_label=" 🛡️ [BLOCKED]"
                        fi
                    else
                        if iptables -S 2>/dev/null | grep -Fq "$ip"; then
                            block_label=" 🛡️ [BLOCKED]"
                        fi
                    fi
                    temp_failed_ips+="    * IP: ${ip} - ${count} attempts${block_label}${BR}"
                fi
            done < <(grep -i "failed password" "$auth_l" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -nr | head -n 3)
            failed_ips=$(echo "$temp_failed_ips" | sed 's/<br>$//')
            
            # --- ACTIVE SOAR: SSH Brute-Force Autoblocking ---
            while read -r count ip; do
                if [[ -n "$ip" && "$count" -gt 15 ]]; then
                    if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                        # Whitelist sanity checks
                        if [[ "$ip" == "127.0.0.1" || "$ip" == "0.0.0.0" ]]; then
                            continue
                        fi
                        
                        # Check firewall rules
                        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
                            if ! ufw status numbered 2>/dev/null | grep -Fq "$ip"; then
                                ufw insert 1 deny from "$ip" to any &>/dev/null
                                soar_actions+="  🛡️ **Auto-blocked IP (UFW)**: \`$ip\` ($count failed attempts)${BR}"
                                log_message "WARNING" "Active SOAR: Automatically blocked IP $ip via UFW ($count failed attempts)"
                            fi
                        else
                            if ! iptables -S 2>/dev/null | grep -Fq "$ip"; then
                                iptables -I INPUT -s "$ip" -j DROP &>/dev/null
                                soar_actions+="  🛡️ **Auto-blocked IP (iptables)**: \`$ip\` ($count failed attempts)${BR}"
                                log_message "WARNING" "Active SOAR: Automatically blocked IP $ip via iptables ($count failed attempts)"
                            fi
                        fi
                    fi
                fi
            done < <(grep -i "failed password" "$auth_l" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -nr | awk '$1 > 15 {print $1, $2}')
        fi
    fi
    local ssh_bf_tag="🟢 Clean (0 failed)"
    [[ "$failed_logins" -gt 0 ]] && ssh_bf_tag="🔴 $failed_logins attacks! ⚠️"
    
    local logged_users
    logged_users=$(who 2>/dev/null | awk '{print $1" ("$2" "$5")"}' | tr '\n' ',' | sed 's/,$//')
    [[ -z "$logged_users" ]] && logged_users="None (No active sessions)"
    
    audit_text+="**🛡️ HOST SECURITY CONFIGURATIONS:**${BR}"
    audit_text+="├─ UFW Firewall Status  : $ufw_tag${BR}"
    audit_text+="├─ SSH Configured Port  : \`$ssh_port\`${BR}"
    audit_text+="├─ SSH Permit Root Login: $ssh_root_tag${BR}"
    audit_text+="├─ Log Integrity Status : $log_tag${BR}"
    audit_text+="├─ SUID Backdoors Temp  : $suid_tag${BR}"
    audit_text+="├─ Sudoers Privilege    : $sudo_tag${BR}"
    audit_text+="├─ SSH Brute Force      : $ssh_bf_tag${BR}"
    audit_text+="└─ Active Logged-in Users: \`$logged_users\`${BR}${BR}"
    
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
            container_list+="  ├─ **${c_name}** (\`${c_id}\`): \`${c_status}\` (Ports: \`$c_ports\`)${BR}"
        done < <(docker ps --format "{{.Names}}||{{.ID}}||{{.Status}}||{{.Ports}}" 2>/dev/null)
        
        # Container resource stats
        while read -r line; do
            [[ -z "$line" ]] && continue
            local c_name=$(echo "$line" | awk -F'||' '{print $1}')
            local c_cpu=$(echo "$line" | awk -F'||' '{print $2}')
            local c_mem=$(echo "$line" | awk -F'||' '{print $3}')
            docker_stats+="  ├─ **${c_name}**: CPU \`${c_cpu}\` | RAM \`${c_mem}\`${BR}"
        done < <(docker stats --no-stream --format "{{.Name}}||{{.CPUPerc}}||{{.MemPerc}}" 2>/dev/null)
        
        # Check docker socket mount
        while read -r cid name; do
            if [[ -z "$cid" ]]; then continue; fi
            local inspect_mounts
            inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' "$cid" 2>/dev/null)
            if echo "$inspect_mounts" | grep -q "docker.sock"; then
                socket_mounts+="  ⚠️ **$name** (\`$cid\`) mounts \`docker.sock\`! (CRITICAL ESCAPE RISK)${BR}"
            fi
        done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
        
        # Find default public interface for Docker hardening
        local interface="eth0"
        local try_interface
        try_interface=$(ip route show | grep default | grep -oE "dev [^ ]+" | awk '{print $2}' | head -n 1)
        [[ -n "$try_interface" ]] && interface="$try_interface"

        # Check exposed database ports
        while read -r name ports; do
            if [[ -z "$name" ]]; then continue; fi
            if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                local bound_port
                bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                
                # --- ACTIVE SOAR: Docker UFW-Bypass Auto-Hardening ---
                local port_secured=0
                if iptables -S DOCKER-USER 2>/dev/null | grep -qE "(-p tcp -m tcp --dport $bound_port -j DROP|-p tcp --dport $bound_port -j DROP)"; then
                    port_secured=1
                else
                    if iptables -I DOCKER-USER -i "$interface" -p tcp --dport "$bound_port" -j DROP &>/dev/null; then
                        port_secured=1
                        soar_actions+="  🛡️ **Auto-secured Docker Port**: Blocked public access to port \`$bound_port\` (Container: \`$name\` • Dev: \`$interface\`)${BR}"
                        log_message "WARNING" "Active SOAR: Automatically blocked public access to Docker exposed port $bound_port (container $name) via DOCKER-USER chain"
                    fi
                fi
                
                local secure_label=""
                [[ "$port_secured" -eq 1 ]] && secure_label=" 🛡️ [AUTO-SECURED]"
                dangerous_ports+="  ⚠️ **$name** exposes database port \`$bound_port\` publicly! (UFW BYPASS)${secure_label}${BR}"
            fi
        done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
    fi
    
    if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
        audit_text+="**🐳 DOCKER ENVIRONMENT AUDIT:**${BR}"
        if [[ -n "$container_list" ]]; then
            container_list=$(echo "$container_list" | sed 's/\(.*\)  ├─/\1  └─/')
            audit_text+="$container_list"
        else
            audit_text+="  └─ No running containers.${BR}"
        fi
        audit_text+="${BR}"
        
        audit_text+="**📊 CONTAINER PERFORMANCE METRICS:**${BR}"
        if [[ -n "$docker_stats" ]]; then
            docker_stats=$(echo "$docker_stats" | sed 's/\(.*\)  ├─/\1  └─/')
            audit_text+="$docker_stats"
        else
            audit_text+="  └─ No stats available.${BR}"
        fi
        audit_text+="${BR}"
    else
        audit_text+="**🐳 DOCKER STATUS:** Not installed or inactive.${BR}${BR}"
    fi
    
    if [[ -n "$socket_mounts" ]]; then
        audit_text+="**🚨 CRITICAL CONTAINER ESCAPE THREATS:**${BR}$socket_mounts${BR}"
    fi
    if [[ -n "$dangerous_ports" ]]; then
        audit_text+="**🌐 EXPOSED DATABASE PORTS (UFW BYPASS):**${BR}$dangerous_ports${BR}"
    fi
    
    if [[ -n "$suid_list" ]]; then
        audit_text+="**🚨 CRITICAL PRIVILEGE ESCALATION THREATS (SUID):**${BR}$suid_list${BR}"
    fi
    if [[ -n "$log_anomalies_list" ]]; then
        audit_text+="**🚨 SYSTEM LOG INTEGRITY VIOLATIONS (TAMPERING):**${BR}$log_anomalies_list${BR}"
    fi
    if [[ "$failed_logins" -gt 0 ]]; then
        audit_text+="**🌐 SSH BRUTE FORCE ATTACK ANALYSIS:**${BR}$failed_ips${BR}${BR}"
    fi
    if [[ -n "$sudo_list" ]]; then
        audit_text+="**🚨 CRITICAL SUDOERS PRIVILEGE BACKDOORS:**${BR}$sudo_list${BR}"
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
        if [[ "$is_sus" -eq 1 ]]; then
            susp_label=" 🔥 [SUSPICIOUS]"
            
            # --- ACTIVE SOAR: Cryptojacker / Suspicious High-CPU Process Auto-Freezing ---
            local cpu_int=0
            if [[ -n "$cpu" ]]; then
                cpu_int=$(echo "$cpu" | cut -d'.' -f1)
            fi
            
            if [[ "$cpu_int" -ge 80 ]]; then
                local proc_state=""
                proc_state=$(ps -q "$pid" -o state= 2>/dev/null | tr -d '[:space:]')
                if [[ "$proc_state" != "T" ]]; then
                    if kill -STOP "$pid" 2>/dev/null; then
                        soar_actions+="  ❄️ **Auto-frozen Process**: PID \`$pid\` (\`$comm\` • CPU: \`$cpu%\`)${BR}     ├─ Path  : \`$exe_path\`${BR}     └─ Status: Suspended (SIGSTOP). Memory preserved for forensics.${BR}"
                        log_message "WARNING" "Active SOAR: Automatically suspended suspicious high-resource process PID $pid ($comm, CPU $cpu%) using SIGSTOP"
                        susp_label=" ❄️ [AUTO-FROZEN]"
                    fi
                else
                    susp_label=" ❄️ [FROZEN]"
                fi
            fi
        fi
        
        susp_proc+="  ├─ PID \`$pid\` ($user): \`$comm\` (\`$cpu%\` CPU)${susp_label} -> \`${exe_path:-deleted/unknown}\`${BR}"
    done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu 2>/dev/null | head -n 6 | tail -n 5)
    
    if [[ -n "$susp_proc" ]]; then
        susp_proc=$(echo "$susp_proc" | sed 's/\(.*\)  ├─/\1  └─/')
        audit_text+="**🛑 TOP 5 ACTIVE PROCESSES (CPU):**${BR}$susp_proc${BR}"
    fi
    
    # --- ACTIVE SOAR & FORENSICS: Kernel-Space Hidden Process Auditor ---
    local hidden_pids=""
    local hidden_count=0
    for pid_dir in /proc/[0-9]*; do
        [[ ! -d "$pid_dir" ]] && continue
        local pid
        pid=$(basename "$pid_dir")
        
        # Check if PID is absent in standard ps output
        if ! ps -p "$pid" &>/dev/null; then
            # Double check after a small delay to filter out transient/short-lived bash process forks
            sleep 0.1
            if [[ -d "/proc/$pid" ]] && ! ps -p "$pid" &>/dev/null; then
                hidden_count=$((hidden_count + 1))
                local comm="unknown"
                [[ -f "/proc/$pid/comm" ]] && comm=$(cat "/proc/$pid/comm" 2>/dev/null)
                local exe_path=""
                [[ -L "/proc/$pid/exe" ]] && exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
                
                # Auto-freeze the hidden process via SIGSTOP to drop CPU and preserve state
                if kill -STOP "$pid" 2>/dev/null; then
                    soar_actions+="  🚨 **Auto-frozen Hidden Process (Rootkit)**: PID \`$pid\` (\`$comm\`)${BR}     ├─ Path  : \`${exe_path:-unknown/deleted}\`${BR}     └─ Status: Suspended (SIGSTOP). Critical hidden threat neutralized.${BR}"
                    log_message "WARNING" "Active SOAR: Automatically suspended hidden rootkit process PID $pid ($comm) using SIGSTOP"
                    hidden_pids+="  ⚠️ **Hidden Process**: PID \`$pid\` (\`$comm\`) -> \`${exe_path:-unknown/deleted}\` ❄️ [AUTO-FROZEN]${BR}"
                else
                    hidden_pids+="  ⚠️ **Hidden Process**: PID \`$pid\` (\`$comm\`) -> \`${exe_path:-unknown/deleted}\` 🚨 [FREEZE FAILED]${BR}"
                fi
            fi
        fi
    done
    
    if [[ "$hidden_count" -gt 0 ]]; then
        hidden_pids=$(echo "$hidden_pids" | sed 's/<br>$//')
        audit_text+="**🚨 CRITICAL HIDDEN ROOTKIT PROCESSES:**${BR}$hidden_pids${BR}${BR}"
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
                stratum_conns+="  ├─ Mining pool host: \`$remote_addr\`${BR}"
            fi
        done < <(ss -tupn state established 2>/dev/null)
    fi
    
    if [[ -n "$stratum_conns" ]]; then
        stratum_conns=$(echo "$stratum_conns" | sed 's/\(.*\)  ├─/\1  └─/')
        audit_text+="**⛏️ OUTBOUND MINING STRATUM POOLS DETECTED:**${BR}$stratum_conns${BR}"
    fi
    
    # Format Active SOAR Automation Actions into audit_text
    if [[ -n "$soar_actions" ]]; then
        soar_actions=$(echo "$soar_actions" | sed 's/<br>$//')
        audit_text+="**🛡️ ACTIVE SOAR AUTOMATION DEFENSES:**${BR}$soar_actions${BR}${BR}"
    fi

    # Determine alert level and title template
    local alert_level="success"
    local alert_title="Daily Server Health: ALL SYSTEMS NORMAL"
    
    if [[ "$hidden_count" -gt 0 ]]; then
        alert_level="danger"
        alert_title="VPS SECURITY ALERT: Critical Hidden Rootkits Detected!"
    elif [[ -n "$soar_actions" ]]; then
        alert_level="danger"
        alert_title="VPS SECURITY ALERT: Active SOAR Auto-Defenses Triggered!"
    elif [[ -n "$socket_mounts" || -n "$dangerous_ports" || -n "$stratum_conns" || "$suid_count" -gt 0 || "$log_tampered" -eq 1 || "$sudo_count" -gt 0 || "$failed_logins" -gt 15 ]]; then
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
                    
                    # Register/update cron rules (clean out both legacy sec.sh and main.sh entries)
                    (crontab -l 2>/dev/null | grep -v -E "(main\.sh|sec\.sh)") | crontab -
                    (crontab -l 2>/dev/null; echo "0 $CRON_HOURS * * * bash $script_path --cron >/dev/null 2>&1") | crontab -
                    print_status "success" "Automated Audits cronjob activated successfully for hours: $CRON_HOURS"
                elif [[ "$cron_toggle" == "2" ]]; then
                    ENABLE_CRON="false"
                    local script_path
                    script_path=$(realpath "$0" 2>/dev/null)
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/main.sh"
                    
                    (crontab -l 2>/dev/null | grep -v -E "(main\.sh|sec\.sh)") | crontab -
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

# Auto-migrate legacy cron entries from sec.sh to the new main.sh (silently runs when toolkit boots)
migrate_legacy_cron() {
    if crontab -l 2>/dev/null | grep -q "sec.sh"; then
        local script_path
        script_path=$(realpath "$0" 2>/dev/null)
        [[ -z "$script_path" ]] && script_path="/usr/local/bin/main.sh"
        
        # Read the current audit hours from the legacy crontab or fallback to default
        local legacy_hours
        legacy_hours=$(crontab -l 2>/dev/null | grep "sec.sh" | head -n 1 | awk '{print $2}')
        [[ -z "$legacy_hours" ]] && legacy_hours="11,17,22"
        
        # Clear all legacy references and register the correct new main.sh path
        (crontab -l 2>/dev/null | grep -v -E "(main\.sh|sec\.sh)") | crontab -
        (crontab -l 2>/dev/null; echo "0 $legacy_hours * * * bash $script_path --cron >/dev/null 2>&1") | crontab -
        
        log_message "INFO" "Migrated legacy cron entry pointing to sec.sh to the new main.sh successfully."
    fi
}

# Run legacy crontab migration check automatically
migrate_legacy_cron
