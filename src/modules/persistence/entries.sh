# ======================================================================
# MODULE: PERSISTENCE MECHANISMS AUDITOR
# ======================================================================

check_persistence() {
    print_status "step" "Auditing System Persistence (Cron, Systemd Services, Startup)..."
    log_message "INFO" "Auditing persistence."

    local persistence_issues=0

    # 1. Systemd Service Audit
    print_status "info" "Scanning Systemd custom units..."
    local systemd_root="/etc/systemd/system"
    if [[ -d "$systemd_root" ]]; then
        while read -r service_file; do
            [[ -z "$service_file" || ! -f "$service_file" ]] && continue
            
            local exec_start
            exec_start=$(grep -E '^\s*ExecStart\s*=' "$service_file" 2>/dev/null)
            if [[ -n "$exec_start" ]]; then
                local cmd_binary
                cmd_binary=$(echo "$exec_start" | sed -E 's/^\s*ExecStart\s*=\s*-?//' | awk '{print $1}' | tr -d '"'\')
                
                for path in "${SUSPICIOUS_PATHS[@]}"; do
                    if [[ "$cmd_binary" == "$path"* ]]; then
                        persistence_issues=$((persistence_issues + 1))
                        log_message "WARNING" "Suspicious Systemd service: $service_file -> Runs out of $path"
                        print_status "warn" "Systemd Unit: $(basename "$service_file")"
                        print_status "bullet" "Command: $exec_start"
                        break
                    fi
                done
            fi
        done < <(find "$systemd_root" -maxdepth 2 -name "*.service" 2>/dev/null)
    fi

    # 2. Cron Jobs Audit
    print_status "info" "Scanning Crontabs & Cron folders..."
    
    if [[ -f "/etc/crontab" ]]; then
        if grep -qE "curl|wget|chmod|/tmp|/dev/shm" "/etc/crontab" 2>/dev/null; then
            persistence_issues=$((persistence_issues + 1))
            print_status "warn" "Potential downloader/miner script pattern matched in /etc/crontab!"
            grep -E "curl|wget|chmod|/tmp|/dev/shm" "/etc/crontab" 2>/dev/null | while read -r line; do
                print_status "bullet" "Match: $line"
            done
        fi
    fi

    local cron_dir="/var/spool/cron/crontabs"
    if [[ -d "$cron_dir" ]]; then
        while read -r cron_user_file; do
            [[ -z "$cron_user_file" || ! -f "$cron_user_file" ]] && continue
            local u
            u=$(basename "$cron_user_file")
            
            if grep -qE "curl|wget|chmod|/tmp|/dev/shm" "$cron_user_file" 2>/dev/null; then
                persistence_issues=$((persistence_issues + 1))
                log_message "WARNING" "Suspicious cron found for user $u"
                print_status "warn" "Suspicious Cron Job found for user: $u"
                grep -E "curl|wget|chmod|/tmp|/dev/shm" "$cron_user_file" 2>/dev/null | while read -r line; do
                    print_status "bullet" "Line: $line"
                done
            fi
        done < <(find "$cron_dir" -type f 2>/dev/null)
    fi

    # 3. Shell Profile Check
    print_status "info" "Scanning shell profiles & rc.local..."
    if [[ -f "/etc/rc.local" ]]; then
        if grep -qE "curl|wget|/tmp|/dev/shm" "/etc/rc.local" 2>/dev/null; then
            persistence_issues=$((persistence_issues + 1))
            print_status "warn" "/etc/rc.local contains execution from suspicious paths or network fetch commands!"
        fi
    fi

    if [[ "$persistence_issues" -eq 0 ]]; then
        print_status "success" "Persistence vectors (Cron, Systemd, Startup) appear clean."
    else
        print_status "danger" "Found $persistence_issues persistence vulnerabilities or malicious entries."
    fi
}
