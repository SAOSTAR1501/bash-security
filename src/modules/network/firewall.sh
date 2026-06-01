# ======================================================================
# MODULE: PORTS & FIREWALL AUDITOR (WITH DOCKER EXPOSURE CHECKS)
# ======================================================================

remediate_docker_ports() {
    local pub_interface
    pub_interface=$(ip route show | grep default | awk '{print $5}')
    [[ -z "$pub_interface" ]] && pub_interface="eth0"

    echo -e "\n${C_BCYAN}======================================================================${C_RESET}"
    echo -e "${C_BYELLOW}            DOCKER PORT REMEDIATION WIZARD${C_RESET}"
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    print_status "info" "We detected exposed Docker container ports accessible from the internet."
    print_status "info" "Public Network Interface: $pub_interface"
    echo -e "\nHow would you like to secure your server?"
    echo -e "  [1] ${C_BGREEN}Block ALL external connections to ALL Docker containers (Highly Recommended)${C_RESET}"
    echo -e "      -> Completely safe for host reverse-proxies (like Nginx) and internal containers."
    echo -e "      -> Locks down all databases, MinIO, APIs, mail containers instantly."
    echo -e "  [2] ${C_BYELLOW}Block external connections only to Postgres Database (Port 5432/5433)${C_RESET}"
    echo -e "  [3] Block a custom port of your choice from the internet"
    echo -e "  [0] Skip hardening (Keep ports exposed to internet)"
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    echo -n "Select action [1-3, or 0 to skip]: "
    read -r wizard_choice

    case "$wizard_choice" in
        1)
            print_status "info" "Injecting global block rule into iptables DOCKER-USER chain..."
            if iptables -I DOCKER-USER -i "$pub_interface" -j DROP 2>/dev/null; then
                log_message "ACTION" "Blocked all external access to Docker containers on interface $pub_interface"
                print_status "success" "Rule successfully injected! All Docker ports are now protected from the internet."
                
                # Handle persistence
                echo -e ""
                print_status "info" "Do you want to save this rule permanently so it survives reboots? [Y/n]: "
                read -r save_confirm
                if [[ "$save_confirm" != "n" && "$save_confirm" != "N" ]]; then
                    if command -v netfilter-persistent &>/dev/null; then
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully using netfilter-persistent."
                    else
                        print_status "warn" "netfilter-persistent is not installed. Installing iptables-persistent..."
                        apt-get update -y && apt-get install -y iptables-persistent
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully!"
                    fi
                fi
            else
                print_status "danger" "Failed to inject iptables rule. Ensure you have root privileges."
            fi
            ;;
        2)
            print_status "info" "Injecting Postgres block rule into iptables DOCKER-USER chain..."
            if iptables -I DOCKER-USER -i "$pub_interface" -p tcp --dport 5432 -j DROP 2>/dev/null; then
                log_message "ACTION" "Blocked external access to Postgres container on interface $pub_interface"
                print_status "success" "Rule successfully injected! Port 5432/5433 are now protected."
                
                echo -e ""
                print_status "info" "Do you want to save this rule permanently so it survives reboots? [Y/n]: "
                read -r save_confirm
                if [[ "$save_confirm" != "n" && "$save_confirm" != "N" ]]; then
                    if command -v netfilter-persistent &>/dev/null; then
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully."
                    else
                        print_status "warn" "netfilter-persistent is not installed. Installing..."
                        apt-get update -y && apt-get install -y iptables-persistent
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully!"
                    fi
                fi
            else
                print_status "danger" "Failed to inject rule."
            fi
            ;;
        3)
            echo -n "Enter the port number to block from external access: "
            read -r custom_port
            if [[ "$custom_port" =~ ^[0-9]+$ ]]; then
                print_status "info" "Injecting block rule for port $custom_port..."
                if iptables -I DOCKER-USER -i "$pub_interface" -p tcp --dport "$custom_port" -j DROP 2>/dev/null; then
                    log_message "ACTION" "Blocked external access to Docker port $custom_port on interface $pub_interface"
                    print_status "success" "Port $custom_port successfully blocked from the internet!"
                    
                    echo -e ""
                    print_status "info" "Save rule permanently? [Y/n]: "
                    read -r save_confirm
                    if [[ "$save_confirm" != "n" && "$save_confirm" != "N" ]]; then
                        if command -v netfilter-persistent &>/dev/null; then
                            netfilter-persistent save 2>/dev/null
                        else
                            apt-get update -y && apt-get install -y iptables-persistent
                            netfilter-persistent save 2>/dev/null
                        fi
                        print_status "success" "Rules saved successfully!"
                    fi
                else
                    print_status "danger" "Failed to block port."
                fi
            else
                print_status "danger" "Invalid port number."
            fi
            ;;
        0|*)
            print_status "info" "Remediation skipped. Ports remain publicly exposed."
            ;;
    esac
}

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
            while read -r proto state recv_q send_q local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$local_addr" ]] && continue
                
                local port
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                local bind_ip
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")

                local pid="-" pname="-"
                if [[ "$process" == *"pid="* ]]; then
                    pid=$(echo "$process" | grep -o -E 'pid=[0-9]+' | cut -d'=' -f2)
                    pname=$(echo "$process" | grep -o -E '"[^"]+"' | head -n 1 | tr -d '"')
                fi

                local is_public=0
                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    is_public=1
                fi

                if [[ "$is_public" -eq 1 ]]; then
                    if [[ "$port" =~ ^(22|3306|5432|5433|6379|27017|9200|8080)$ ]]; then
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
            netstat -tulnp 2>/dev/null | grep LISTEN | while read -r proto recv_q send_q local_addr remote_addr state process; do
                [[ -z "$local_addr" ]] && continue
                local port bind_ip pid pname
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")
                
                pid=$(echo "$process" | cut -d'/' -f1)
                pname=$(echo "$process" | cut -d'/' -f2-)

                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    if [[ "$port" =~ ^(22|3306|5432|5433|6379|27017|9200|8080)$ ]]; then
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
                
                # Giám sát tài nguyên Container
                echo -e "\n${C_BWHITE}--- Docker Container Resource Usage Dashboard ---${C_RESET}"
                local stats
                stats=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null)
                if [[ -n "$stats" ]]; then
                    echo -e "$stats"
                else
                    print_status "warn" "Unable to collect live Docker container stats."
                fi
                
                # Quét lỗ hổng Docker Socket Mount
                echo -e "\n${C_BWHITE}--- Docker Socket Mount Vulnerability Audit ---${C_RESET}"
                local socket_mounts=0
                while read -r cid name; do
                    if [[ -z "$cid" ]]; then continue; fi
                    local inspect_mounts
                    inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' "$cid" 2>/dev/null)
                    if echo "$inspect_mounts" | grep -q "docker.sock"; then
                        socket_mounts=$((socket_mounts + 1))
                        log_message "WARNING" "Vulnerability: Container '$name' ($cid) mounts host docker.sock!"
                        print_status "danger" "DOCKER SOCKET ESCAPE VECTOR: Container '$name' mounts '/var/run/docker.sock'!"
                        print_status "bullet" "CRITICAL RATIONALE: Gives full root-level control over the physical host!"
                        send_lark_notification "Docker Socket Mount Escape Vulnerability" "Container '$name' ($cid) mounts '/var/run/docker.sock'. This allows full host takeover!"
                    fi
                done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
                if [[ "$socket_mounts" -eq 0 ]]; then
                    print_status "success" "All running containers are protected against host Docker Socket Mount escape vectors."
                fi
                
                # Public Port Binding & UFW Bypass Check
                echo -e "\n${C_BWHITE}--- Public Port Binding & UFW Bypass Check ---${C_RESET}"
                local dangerous_bindings=0
                while read -r name ports; do
                    if [[ -z "$name" ]]; then continue; fi
                    if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                        local bound_port
                        bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                        dangerous_bindings=$((dangerous_bindings + 1))
                        
                        log_message "WARNING" "Dangerous Docker binding exposed publicly: Container $name on port $bound_port"
                        print_status "danger" "DOCKER BYPASS VULNERABILITY: Container '$name' exposes port $bound_port to 0.0.0.0!"
                        print_status "bullet" "CRITICAL RATIONALE: Docker automatically writes raw iptables rules."
                        print_status "bullet" "Even if UFW status is ACTIVE, Docker's rules bypass UFW completely!"
                        send_lark_notification "Dangerous Exposed Port Bindings" "Container '$name' exposes port $bound_port to 0.0.0.0. This bypasses active UFW configs!"
                    fi
                done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
                
                if [[ "$dangerous_bindings" -eq 0 ]]; then
                    print_status "success" "All running Docker container ports are bound securely or do not expose sensitive DB services publicly."
                    echo -e ""
                    print_status "info" "Would you like to open the Docker Port Hardening Wizard to review or block other ports?"
                    echo -n "Launch Hardening Wizard? [y/N]: "
                    read -r launch_choice
                    if [[ "$launch_choice" == "y" || "$launch_choice" == "Y" ]]; then
                        remediate_docker_ports
                    fi
                else
                    print_status "danger" "CRITICAL: Publicly exposed database ports detected on running containers!"
                    print_status "warn" "Recommendation: Sửa file docker-compose.yml (e.g. bind to 127.0.0.1)."
                    
                    echo -e ""
                    print_status "warn" "Do you want to run the Docker Port Hardening Wizard now to block these ports immediately?"
                    echo -n "Block exposed ports now? [Y/n]: "
                    read -r launch_choice
                    if [[ "$launch_choice" != "n" && "$launch_choice" != "N" ]]; then
                        remediate_docker_ports
                    fi
                fi
            else
                print_status "info" "Docker daemon is active but no containers are currently running."
                echo -e ""
                print_status "info" "Would you like to run the Docker Port Hardening Wizard to block all incoming public Docker traffic anyway?"
                echo -n "Launch Hardening Wizard? [y/N]: "
                read -r launch_choice
                if [[ "$launch_choice" == "y" || "$launch_choice" == "Y" ]]; then
                    remediate_docker_ports
                fi
            fi
        else
            print_status "info" "Docker service is installed but not running."
        fi
    else
        print_status "info" "Docker is not installed on this host system."
    fi
}
