# ======================================================================
# MODULE: PORTS & FIREWALL AUDITOR (WITH DOCKER EXPOSURE CHECKS)
# ======================================================================

check_ports_firewall() {
    print_status "step" "Auditing Listening Ports, UFW Firewall & Docker Exposures..."
    log_message "INFO" "Auditing ports and firewall rules."

    # 1. Check Firewall Status (UFW / iptables)
    echo -e "${C_BWHITE}--- Firewall Daemon Status ---${C_RESET}"
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null)
        if echo "$ufw_status" | grep -q "active"; then
            print_status "success" "UFW Firewall is ACTIVE!"
            echo -e "${C_GRAY}$ufw_status${C_RESET}"
        else
            print_status "danger" "UFW Firewall is INACTIVE / DISABLED! All ports are unprotected."
        fi
    else
        print_status "warn" "UFW utility is not installed. Checking raw iptables..."
        if command -v iptables &>/dev/null; then
            local rules_count
            rules_count=$(iptables -S 2>/dev/null | wc -l)
            if [[ "$rules_count" -gt 3 ]]; then
                print_status "info" "iptables is active with $rules_count active filter rules."
            else
                print_status "danger" "iptables appears to be unconfigured (default ACCEPT all)."
            fi
        fi
    fi

    # 2. Check System Listening Ports
    echo -e "\n${C_BWHITE}--- System Listening Ports (Local Sockets) ---${C_RESET}"
    local net_tool=""
    if command -v ss &>/dev/null; then
        net_tool="ss"
    elif command -v netstat &>/dev/null; then
        net_tool="netstat"
    fi

    if [[ -n "$net_tool" ]]; then
        printf "${C_BOLD}%-6s %-25s %-12s %-25s${C_RESET}\n" "PROTO" "LOCAL BIND ADDRESS" "PID/PORT" "PROCESS NAME"
        echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
        
        if [[ "$net_tool" == "ss" ]]; then
            while read -r proto state local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$local_addr" ]] && continue
                
                # Extract port from local address
                local port
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                local bind_ip
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")

                local pid="-" pname="-"
                if [[ "$process" == *"pid="* ]]; then
                    pid=$(echo "$process" | grep -o -E 'pid=[0-9]+' | cut -d'=' -f2)
                    pname=$(echo "$process" | grep -o -E '"[^"]+"' | head -n 1 | tr -d '"')
                fi

                # Flag public exposures (0.0.0.0 or *) for sensitive ports
                local is_public=0
                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    is_public=1
                fi

                if [[ "$is_public" -eq 1 ]]; then
                    # Highlight sensitive publicly exposed ports
                    if [[ "$port" =~ ^(22|3306|5432|6379|27017|9200|8080)$ ]]; then
                        printf "${C_BRED}%-6s %-25s %-12s %-25s${C_RESET} ${C_RED}(PUBLIC EXPOSURE!)${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    else
                        printf "${C_BYELLOW}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    fi
                else
                    printf "${C_BGREEN}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                        "$proto" "$local_addr" "$port" "$pname ($pid)"
                fi
            done < <(ss -tulnp 2>/dev/null)
        else
            # netstat
            netstat -tulnp 2>/dev/null | grep LISTEN | while read -r proto recv_q send_q local_addr remote_addr state process; do
                [[ -z "$local_addr" ]] && continue
                local port bind_ip pid pname
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")
                
                pid=$(echo "$process" | cut -d'/' -f1)
                pname=$(echo "$process" | cut -d'/' -f2-)

                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    if [[ "$port" =~ ^(22|3306|5432|6379|27017|9200|8080)$ ]]; then
                        printf "${C_BRED}%-6s %-25s %-12s %-25s${C_RESET} ${C_RED}(PUBLIC EXPOSURE!)${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    else
                        printf "${C_BYELLOW}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    fi
                else
                    printf "${C_BGREEN}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                        "$proto" "$local_addr" "$port" "$pname ($pid)"
                fi
            done
        fi
        echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
    else
        print_status "warn" "Unable to fetch socket states (no ss/netstat)."
    fi

    # 3. Check Docker Container Port Exposures
    echo -e "\n${C_BWHITE}--- Docker Container Port Exposures & UFW Bypass Audit ---${C_RESET}"
    if command -v docker &>/dev/null; then
        local docker_running
        docker_running=$(systemctl is-active docker 2>/dev/null)
        if [[ "$docker_running" == "active" ]]; then
            local containers
            containers=$(docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Ports}}" 2>/dev/null)
            
            if [[ -n "$containers" ]]; then
                echo -e "$containers"
                
                # Check for public binding database/sensitive ports inside docker
                local dangerous_bindings=0
                docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null | while read -r name ports; do
                    # Look for 0.0.0.0 or [::] bindings to databases
                    if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|6379|27017|9200|8080|22)->"; then
                        local bound_port
                        bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                        dangerous_bindings=$((dangerous_bindings + 1))
                        
                        log_message "WARNING" "Dangerous Docker binding exposed publicly: Container $name on port $bound_port"
                        print_status "danger" "DOCKER BYPASS VULNERABILITY: Container '$name' exposes port $bound_port to 0.0.0.0!"
                        print_status "bullet" "CRITICAL RATIONALE: Docker automatically writes raw iptables rules."
                        print_status "bullet" "Even if UFW status is ACTIVE, Docker's rules bypass UFW completely!"
                        print_status "bullet" "Tin tặc có thể quét thấy và tấn công trực tiếp vào database trong container này."
                    fi
                done
                
                if [[ "$dangerous_bindings" -eq 0 ]]; then
                    print_status "success" "All running Docker container ports are bound securely or do not expose sensitive DB services publicly."
                else
                    print_status "warn" "Exposed ports identified! Recommendation: Sửa file docker-compose.yml"
                    print_status "bullet" "Thay đổi '- p 3306:3306' thành '- p 127.0.0.1:3306:3306' rồi restart container."
                fi
            else
                print_status "info" "Docker daemon is active but no containers are currently running."
            fi
        else
            print_status "info" "Docker service is installed but not running."
        fi
    else
        print_status "info" "Docker is not installed on this host system."
    fi
}
