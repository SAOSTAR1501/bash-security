# ======================================================================
# CORE COMPONENT: PRO HACKER LIVE SECURITY DASHBOARD
# ======================================================================

live_security_dashboard() {
    # Fetch hostname and public IP once before entering the loop to ensure zero delay
    local hostname=$(hostname 2>/dev/null || echo "localhost")
    local server_ip
    server_ip=$(curl -s --max-time 1.5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

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
        local cpu_pct=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' | cut -d. -f1 2>/dev/null)
        [[ -z "$cpu_pct" ]] && cpu_pct=0
        local cpu_bar=""
        local cpu_ticks=$((cpu_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $cpu_ticks ]]; then
                if [[ $i -ge 16 ]]; then
                    cpu_bar+="${C_BRED}|${C_RESET}"
                elif [[ $i -ge 10 ]]; then
                    cpu_bar+="${C_BYELLOW}|${C_RESET}"
                else
                    cpu_bar+="${C_BGREEN}|${C_RESET}"
                fi
            else
                cpu_bar+="${C_GRAY}.${C_RESET}"
            fi
        done
        local cpu_bar_eval
        cpu_bar_eval=$(echo -e "$cpu_bar")
        local cpu_color="$C_BGREEN"
        if [[ "$cpu_pct" -ge 80 ]]; then cpu_color="$C_BRED"; elif [[ "$cpu_pct" -ge 50 ]]; then cpu_color="$C_BYELLOW"; fi
        printf " ${C_BOLD}CPU Usage:${C_RESET}  [%s] ${cpu_color}%d%%${C_RESET}\n" "$cpu_bar_eval" "$cpu_pct"
        
        # RAM
        local mem_total=$(free -m | awk '/^Mem:/{print $2}' 2>/dev/null)
        local mem_used=$(free -m | awk '/^Mem:/{print $3}' 2>/dev/null)
        [[ -z "$mem_total" ]] && mem_total=1
        [[ -z "$mem_used" ]] && mem_used=0
        local mem_pct=$(( mem_used * 100 / mem_total ))
        local mem_bar=""
        local mem_ticks=$((mem_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $mem_ticks ]]; then
                if [[ $i -ge 18 ]]; then
                    mem_bar+="${C_BRED}|${C_RESET}"
                elif [[ $i -ge 14 ]]; then
                    mem_bar+="${C_BYELLOW}|${C_RESET}"
                else
                    mem_bar+="${C_BGREEN}|${C_RESET}"
                fi
            else
                mem_bar+="${C_GRAY}.${C_RESET}"
            fi
        done
        local mem_bar_eval
        mem_bar_eval=$(echo -e "$mem_bar")
        local mem_color="$C_BGREEN"
        if [[ "$mem_pct" -ge 90 ]]; then mem_color="$C_BRED"; elif [[ "$mem_pct" -ge 70 ]]; then mem_color="$C_BYELLOW"; fi
        printf " ${C_BOLD}RAM Usage:${C_RESET}  [%s] ${mem_color}%d%%${C_RESET} (%sMB/%sMB)\n" "$mem_bar_eval" "$mem_pct" "$mem_used" "$mem_total"
        
        # Load Average
        local load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}')
        printf " ${C_BOLD}Load Avg :${C_RESET}  %-25s\n" "${load_avg:-0.00 0.00 0.00}"
        
        # Storage Disk
        local disk_pct=$(df -h / | tail -n 1 | awk '{print $5}' | cut -d% -f1 2>/dev/null)
        [[ -z "$disk_pct" ]] && disk_pct=0
        local disk_bar=""
        local disk_ticks=$((disk_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $disk_ticks ]]; then
                if [[ $i -ge 17 ]]; then
                    disk_bar+="${C_BRED}|${C_RESET}"
                elif [[ $i -ge 14 ]]; then
                    disk_bar+="${C_BYELLOW}|${C_RESET}"
                else
                    disk_bar+="${C_BGREEN}|${C_RESET}"
                fi
            else
                disk_bar+="${C_GRAY}.${C_RESET}"
            fi
        done
        local disk_bar_eval
        disk_bar_eval=$(echo -e "$disk_bar")
        local disk_color="$C_BGREEN"
        if [[ "$disk_pct" -ge 85 ]]; then disk_color="$C_BRED"; elif [[ "$disk_pct" -ge 70 ]]; then disk_color="$C_BYELLOW"; fi
        printf " ${C_BOLD}Disk /   :${C_RESET}  [%s] ${disk_color}%d%%${C_RESET}\n" "$disk_bar_eval" "$disk_pct"
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        echo -e " 🚨 ${C_BWHITE}SECURITY SHIELD STATUS & ALERTS${C_RESET}"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # UFW Status
        local ufw_live="INACTIVE"
        local ufw_color="$C_BRED"
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
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
        local exposed_status="0 (SECURE)"
        local exposed_color="$C_BGREEN"
        if [[ "$exposed_count" -gt 0 ]]; then
            exposed_status="${exposed_count} EXPOSED!"
            exposed_color="$C_BRED"
        fi
        
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
        local sock_status="0 (SECURE)"
        local sock_color="$C_BGREEN"
        if [[ "$sock_mount_count" -gt 0 ]]; then
            sock_status="${sock_mount_count} DETECTED!"
            sock_color="$C_BRED"
        fi
        
        # Outbound stratum connections
        local stratum_count=0
        local port_regex=$(echo "${MINING_PORTS[@]:-3333 4444 5555 7777 8888 9999}" | tr ' ' '|')
        if command -v ss &>/dev/null; then
            while read -r proto state recv_q send_q local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
                local rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
                if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                    stratum_count=$((stratum_count + 1))
                fi
            done < <(ss -tupn state established 2>/dev/null)
        fi
        local stratum_status="0 Active"
        local stratum_color="$C_BGREEN"
        if [[ "$stratum_count" -gt 0 ]]; then
            stratum_status="${stratum_count} ACTIVE!"
            stratum_color="$C_BRED"
        fi
        
        # Display side-by-side or listed indicators
        printf "   * Tường lửa UFW    : ${ufw_color}%-10s${C_RESET} | * Lỗ hổng Cổng Docker   : ${exposed_color}%-15s${C_RESET}\n" "$ufw_live" "$exposed_status"
        printf "   * Docker Escapes   : ${sock_color}%-10s${C_RESET} | * Kết nối Pool Đào Coin : ${stratum_color}%-15s${C_RESET}\n" "$sock_status" "$stratum_status"
        
        # Logged-in Users list
        local active_users=$(who 2>/dev/null | awk '{print $1" ("$2")"}' | tr '\n' ',' | sed 's/,$//')
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
            for path in "${SUSPICIOUS_PATHS[@]:-/tmp /var/tmp /dev/shm}"; do
                if [[ "$exe_path" == "$path"* ]]; then is_sus=1; break; fi
            done
            
            local line_color="$C_RESET"
            if [[ "$is_sus" -eq 1 ]]; then
                line_color="$C_BRED"
            elif [[ $(awk -v cpu="$cpu" -v limit="40" 'BEGIN {print (cpu > limit) ? 1 : 0}' 2>/dev/null) -eq 1 ]]; then
                line_color="$C_BYELLOW"
            fi
            
            printf "   ${line_color}%-8s %-12s %-6s %-12s %-25s${C_RESET}\n" "$pid" "${user:0:11}" "$cpu" "$comm" "${exe_path:0:28}"
        done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu 2>/dev/null | head -n 6 | tail -n 5)
        
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
