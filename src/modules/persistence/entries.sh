# ======================================================================
# MODULE: PERSISTENCE MECHANISMS AUDITOR
# ======================================================================

check_persistence() {
    print_status "step" "Auditing System Persistence (Cron, Systemd Services, Startup)..."
    log_message "INFO" "Auditing persistence."

    local persistence_issues=0
    local sec_cron_active=0
    local sec_cron_details=""

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
                
                for path in "${SUSPICIOUS_PATHS[@]:-/tmp /var/tmp /dev/shm}"; do
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
    
    # Helper function to scan a single cron file
    scan_cron_file() {
        local file="$1"
        local label="$2"
        [[ ! -f "$file" || ! -r "$file" ]] && return
        
        while read -r line; do
            # Skip empty lines and comments
            [[ -z "$line" || "$line" =~ ^\s*# ]] && continue
            
            # Check if it is the Security Toolkit cron job
            if echo "$line" | grep -q "sec.sh --cron"; then
                sec_cron_active=1
                sec_cron_details="$line"
                continue
            fi
            
            # Check for suspicious patterns
            if echo "$line" | grep -qE "curl|wget|chmod|/tmp|/dev/shm"; then
                persistence_issues=$((persistence_issues + 1))
                print_status "warn" "Suspicious entry found in $label:"
                print_status "bullet" "Match: $line"
            fi
        done < "$file"
    }

    # Scan /etc/crontab
    scan_cron_file "/etc/crontab" "/etc/crontab"
    
    # Scan /etc/cron.d/ files
    if [[ -d "/etc/cron.d" ]]; then
        for f in /etc/cron.d/*; do
            [[ -f "$f" ]] && scan_cron_file "$f" "/etc/cron.d/$(basename "$f")"
        done
    fi
    
    # Scan user crontabs under /var/spool/cron and /var/spool/cron/crontabs
    local cron_spool_dirs=("/var/spool/cron" "/var/spool/cron/crontabs")
    for d in "${cron_spool_dirs[@]}"; do
        if [[ -d "$d" ]]; then
            while read -r f; do
                [[ -f "$f" ]] && scan_cron_file "$f" "User Crontab ($(basename "$f"))"
            done < <(find "$d" -maxdepth 1 -type f 2>/dev/null)
        fi
    done

    # Report if Security Toolkit Cron Job is Active
    if [[ "$sec_cron_active" -eq 1 ]]; then
        print_status "success" "Security Toolkit Automated Scan Cronjob is ACTIVE!"
        print_status "bullet" "Cron Entry: $sec_cron_details"
    fi

    # 3. Shell Profile Check & rc.local
    print_status "info" "Scanning shell profiles & rc.local..."
    if [[ -f "/etc/rc.local" ]]; then
        if grep -qE "curl|wget|/tmp|/dev/shm" "/etc/rc.local" 2>/dev/null; then
            persistence_issues=$((persistence_issues + 1))
            print_status "warn" "/etc/rc.local contains execution from suspicious paths or network fetch commands!"
        fi
    fi

    local profiles=("/etc/profile" "/etc/bash.bashrc" "/root/.bashrc" "/root/.profile" "/root/.bash_profile")
    for p in "${profiles[@]}"; do
        if [[ -f "$p" ]]; then
            if grep -qE "curl|wget|/tmp|/dev/shm" "$p" 2>/dev/null; then
                persistence_issues=$((persistence_issues + 1))
                print_status "warn" "Suspicious execution pattern found in shell profile: $p"
                grep -E "curl|wget|/tmp|/dev/shm" "$p" 2>/dev/null | while read -r line; do
                    print_status "bullet" "Match: $line"
                done
            fi
        fi
    done

    if [[ "$persistence_issues" -eq 0 ]]; then
        print_status "success" "Persistence audit complete. No malicious entries or suspicious vectors detected."
    else
        print_status "danger" "Found $persistence_issues persistence vulnerabilities or malicious entries."
    fi
}
