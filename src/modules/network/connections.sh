# ======================================================================
# MODULE: NETWORK SOCKET AUDITOR
# ======================================================================

MINING_PORTS=(3333 4444 5555 7777 8888 9999 14444 8008 8080)

check_network_connections() {
    print_status "step" "Auditing Network Connections & Outbound Stratum Pools..."
    log_message "INFO" "Running network scan."

    local network_threats=0
    local net_tool=""
    
    if command -v ss &>/dev/null; then
        net_tool="ss"
    elif command -v netstat &>/dev/null; then
        net_tool="netstat"
    fi

    if [[ -z "$net_tool" ]]; then
        print_status "warn" "Neither 'ss' nor 'netstat' is installed. Reading direct socket connections is limited."
        print_status "info" "Falling back to scanning /proc/net/tcp..."
        if [[ -f "/proc/net/tcp" ]]; then
            echo -e "${C_BOLD}%-20s %-20s %-10s${C_RESET}" "Local Hex IP:Port" "Remote Hex IP:Port" "Status"
            tail -n +2 /proc/net/tcp | head -n 10
        fi
        return
    fi

    printf "${C_BOLD}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" "PROTO" "PID" "PROCESS" "LOCAL ADDRESS" "REMOTE PORT" "STATE"
    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"

    local port_regex
    port_regex=$(echo "${MINING_PORTS[@]}" | tr ' ' '|')

    if [[ "$net_tool" == "ss" ]]; then
        while read -r proto state local_addr remote_addr process; do
            [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
            
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            
            local pid="-"
            local pname="-"
            if [[ "$process" == *"pid="* ]]; then
                pid=$(echo "$process" | grep -o -E 'pid=[0-9]+' | cut -d'=' -f2)
                pname=$(echo "$process" | grep -o -E '"[^"]+"' | head -n 1 | tr -d '"')
            fi

            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                network_threats=$((network_threats + 1))
                log_message "WARNING" "Stratum miner connection detected: PID $pid ($pname) on port $rport"
                printf "${C_BRED}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" \
                    "$proto" "$pid" "${pname:0:19}" "${local_addr:0:24}" "$rport" "$state"
            else
                if [[ "$state" == "ESTAB" && "$remote_addr" != "127.0.0.1"* && "$remote_addr" != "::1"* && "$remote_addr" != "localhost"* ]]; then
                    if [[ "$pid" != "-" ]]; then
                        local exe_path
                        exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
                        for path in "${SUSPICIOUS_PATHS[@]}"; do
                            if [[ "$exe_path" == "$path"* ]]; then
                                network_threats=$((network_threats + 1))
                                log_message "WARNING" "Suspicious process outbound connection: PID $pid ($pname) -> $remote_addr"
                                printf "${C_BYELLOW}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" \
                                    "$proto" "$pid" "${pname:0:19}*" "${local_addr:0:24}" "$rport" "$state"
                                break
                            fi
                        done
                    fi
                fi
            fi
        done < <(ss -tupn state established 2>/dev/null)
    else
        while read -r proto recv_q send_q local_addr remote_addr state process; do
            [[ "$proto" != "tcp" && "$proto" != "udp" ]] && continue
            
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            
            local pid="-"
            local pname="-"
            if [[ "$process" == *"/"* ]]; then
                pid=$(echo "$process" | cut -d'/' -f1)
                pname=$(echo "$process" | cut -d'/' -f2-)
            fi

            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                network_threats=$((network_threats + 1))
                log_message "WARNING" "Stratum miner connection detected (netstat): PID $pid ($pname) on port $rport"
                printf "${C_BRED}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" \
                    "$proto" "$pid" "${pname:0:19}" "${local_addr:0:24}" "$rport" "$state"
            fi
        done < <(netstat -nap 2>/dev/null)
    fi

    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"
    if [[ "$network_threats" -gt 0 ]]; then
        print_status "danger" "Found $network_threats network connections linking suspicious paths or stratum ports."
    else
        print_status "success" "No stratum pool connections or suspicious path network sockets identified."
    fi
}
