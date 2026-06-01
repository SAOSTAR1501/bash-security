# ======================================================================
# MODULE: ROOTKIT & SYSTEM INTEGRITY CHECKER
# ======================================================================

check_system_integrity() {
    print_status "step" "Checking System Integrity & Library Injection Rootkits..."
    log_message "INFO" "Checking system integrity."

    # 1. Check ld.so.preload
    local preload_file="/etc/ld.so.preload"
    if [[ -f "$preload_file" ]]; then
        local active_entries
        active_entries=$(grep -v -E "^\s*(#|$)" "$preload_file" 2>/dev/null)
        if [[ -n "$active_entries" ]]; then
            log_message "ALERT" "ld.so.preload contains active library injections!"
            print_status "danger" "Rootkit Danger: '/etc/ld.so.preload' contains active library injections!"
            echo -e "${C_BRED}$active_entries${C_RESET}"
            print_status "bullet" "Malware preloads library injectors to hide processes and network ports!"
        else
            print_status "success" "'/etc/ld.so.preload' exists but has no active preloaded libraries."
        fi
    else
        print_status "success" "'/etc/ld.so.preload' does not exist (Standard healthy configuration)."
    fi

    # 2. Check essential binaries for hijacking
    print_status "info" "Verifying core commands for suspicious aliasing/wrappers..."
    local hijacked_tools=0
    for cmd in "ps" "top" "ss" "netstat" "lsof"; do
        local cmd_path
        cmd_path=$(which "$cmd" 2>/dev/null)
        if [[ -n "$cmd_path" ]]; then
            if file "$cmd_path" 2>/dev/null | grep -q "script"; then
                hijacked_tools=$((hijacked_tools + 1))
                log_message "ALERT" "Core command hijacked: $cmd_path is a text script!"
                print_status "danger" "Core tool '$cmd_path' has been replaced by a script wrapper! High chance of rootkit."
            fi
        fi
    done

    if [[ "$hijacked_tools" -eq 0 ]]; then
        print_status "success" "System tools (ps, top, ss, lsof) appear to be clean binary executables."
    fi

    # 3. Check for Log Tampering / Truncation (Common post-exploitation covering tracks)
    echo -e "\n${C_BWHITE}--- Auditing System Logs & History Integrity ---${C_RESET}"
    local logs_to_check=(
        "/var/log/wtmp"
        "/var/log/btmp"
        "/var/log/lastlog"
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/syslog"
    )
    local log_anomalies=0
    for log_path in "${logs_to_check[@]}"; do
        # Handle auth logs mapping
        if [[ "$log_path" == "/var/log/auth.log" && ! -f "/var/log/auth.log" && ! -f "/var/log/secure" ]]; then
            print_status "danger" "Authentication log is completely MISSING! (Neither auth.log nor secure exists)"
            log_anomalies=$((log_anomalies + 1))
            continue
        elif [[ ! -f "$log_path" ]]; then
            # Skip if it is not expected for the distro
            if [[ "$log_path" == "/var/log/auth.log" || "$log_path" == "/var/log/secure" ]]; then
                continue
            fi
            print_status "warn" "System log file '$log_path' is missing from disk."
            continue
        fi

        # Check if log was truncated to 0 bytes
        local file_size
        file_size=$(stat -c "%s" "$log_path" 2>/dev/null)
        if [[ "$file_size" -eq 0 ]]; then
            # Failed logins (btmp) can naturally be 0 bytes if no failures occurred
            if [[ "$log_path" != "/var/log/btmp" ]]; then
                log_anomalies=$((log_anomalies + 1))
                print_status "danger" "CRITICAL TAMPERING WARNING: Log file '$log_path' is empty (0 bytes)!"
                print_status "bullet" "Attackers often truncate system logs to erase trace logs of their operations."
                log_message "ALERT" "Tampering detected: $log_path was truncated to 0 bytes"
            fi
        fi
    done
    if [[ "$log_anomalies" -eq 0 ]]; then
        print_status "success" "System authentication and session logs are active and intact."
    fi

    # 4. Check for SUID/SGID backdoor binaries in globally writable paths
    echo -e "\n${C_BWHITE}--- Auditing Writable Paths for SUID/SGID Backdoors ---${C_RESET}"
    local suid_files=0
    for target_dir in "/tmp" "/var/tmp" "/dev/shm" "/run/user"; do
        if [[ -d "$target_dir" ]]; then
            while read -r suid_path; do
                [[ -z "$suid_path" || ! -f "$suid_path" ]] && continue
                suid_files=$((suid_files + 1))
                local owner perms
                owner=$(stat -c "%U:%G" "$suid_path" 2>/dev/null)
                perms=$(stat -c "%a" "$suid_path" 2>/dev/null)
                print_status "danger" "SUID/SGID BINARY FOUND: '$suid_path' (Owner: $owner, Perms: $perms)"
                print_status "bullet" "CRITICAL RATIONALE: Writable temporary paths should NEVER host SUID executable files!"
                log_message "ALERT" "SUID/SGID backdoor detected: $suid_path ($owner, $perms)"
                send_lark_notification "SUID/SGID Privilege Escalation Backdoor Detected" "Found SUID/SGID file: '$suid_path' in writable storage ($target_dir). Owner: $owner, Perms: $perms. This allows local privilege escalation!" "danger"
            done < <(find "$target_dir" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
        fi
    done
    if [[ "$suid_files" -eq 0 ]]; then
        print_status "success" "No SUID/SGID privilege escalation backdoors found in temporary directories."
    fi

    # 5. Check DNS Configuration Tampering
    echo -e "\n${C_BWHITE}--- Auditing DNS Configurations (/etc/resolv.conf) ---${C_RESET}"
    if [[ -f "/etc/resolv.conf" ]]; then
        local nameservers=()
        while read -r line; do
            if [[ "$line" == "nameserver "* ]]; then
                local ns
                ns=$(echo "$line" | awk '{print $2}')
                nameservers+=("$ns")
            fi
        done < "/etc/resolv.conf"
        
        if [[ "${#nameservers[@]}" -gt 0 ]]; then
            print_status "info" "Configured system DNS Nameservers:"
            for ns in "${nameservers[@]}"; do
                print_status "bullet" "Nameserver IP: \`$ns\`"
            done
        else
            print_status "warn" "No DNS nameservers configured in '/etc/resolv.conf'."
        fi
    else
        print_status "danger" "DNS configuration file '/etc/resolv.conf' is completely MISSING!"
    fi

    # 6. Check Hosts File Static Mapping Tampering
    echo -e "\n${C_BWHITE}--- Auditing Hosts Static Mappings (/etc/hosts) ---${C_RESET}"
    if [[ -f "/etc/hosts" ]]; then
        local hosts_tampered=0
        while read -r line; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            # Look for static mappings of sensitive domains (github, google, lark, update services)
            if echo "$line" | grep -qE "github|google|lark|feishu|microsoft|apple|api|raw.githubusercontent.com"; then
                hosts_tampered=$((hosts_tampered + 1))
                print_status "danger" "SUSPICIOUS STATIC MAPPING IN HOSTS FILE: $line"
                print_status "bullet" "CRITICAL: Attackers map public update sites or APIs to loopback/local IPs to block patches or hijack API requests!"
                log_message "ALERT" "Suspicious hosts mapping: $line"
            fi
        done < "/etc/hosts"
        
        if [[ "$hosts_tampered" -eq 0 ]]; then
            print_status "success" "Static hosts mapping file '/etc/hosts' is clean."
        fi
    else
        print_status "danger" "Hosts static mapping file '/etc/hosts' is completely MISSING!"
    fi
}
