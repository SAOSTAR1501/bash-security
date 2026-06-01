# ======================================================================
# MODULE: USER IDENTITY & PRIVILEGE AUDITOR
# ======================================================================

audit_system_users() {
    print_status "step" "Auditing System User Accounts & Login Privileges..."
    log_message "INFO" "Auditing user accounts."

    local backdoor_users=0
    local login_shells=("/bin/bash" "/bin/sh" "/bin/zsh" "/usr/bin/bash" "/usr/bin/zsh" "/bin/dash")

    # 1. Check for unauthorized UID 0 (Root Privileged) accounts
    echo -e "${C_BWHITE}--- Superuser (UID 0) Account Check ---${C_RESET}"
    while read -r line; do
        local u uid
        u=$(echo "$line" | cut -d':' -f1)
        uid=$(echo "$line" | cut -d':' -f3)
        
        if [[ "$uid" -eq 0 ]]; then
            if [[ "$u" != "root" ]]; then
                backdoor_users=$((backdoor_users + 1))
                log_message "ALERT" "Backdoor user detected with UID 0: $u"
                print_status "danger" "PRIVILEGE ESCALATION: User '$u' has UID 0 (Full Root Access)!"
            else
                print_status "bullet" "Authorized root account verified: root (UID 0)"
            fi
        fi
    done < /etc/passwd

    if [[ "$backdoor_users" -eq 0 ]]; then
        print_status "success" "No unauthorized UID 0 (superuser) accounts found."
    fi

    # 2. Check for interactive login accounts
    echo -e "\n${C_BWHITE}--- Active Shell Login Accounts ---${C_RESET}"
    printf "${C_BOLD}%-15s %-6s %-6s %-30s %-20s${C_RESET}\n" "USER" "UID" "GID" "HOME DIRECTORY" "LOGIN SHELL"
    echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
    
    local active_accounts=0
    while read -r line; do
        local u uid gid home shell
        u=$(echo "$line" | cut -d':' -f1)
        uid=$(echo "$line" | cut -d':' -f3)
        gid=$(echo "$line" | cut -d':' -f4)
        home=$(echo "$line" | cut -d':' -f6)
        shell=$(echo "$line" | cut -d':' -f7)
        
        local is_login=0
        for sh in "${login_shells[@]}"; do
            if [[ "$shell" == "$sh" ]]; then
                is_login=1
                break
            fi
        done
        
        if [[ "$is_login" -eq 1 ]]; then
            active_accounts=$((active_accounts + 1))
            # Highlight non-standard login accounts
            if [[ "$u" != "root" && "$uid" -lt 1000 ]]; then
                printf "${C_BYELLOW}%-15s %-6s %-6s %-30s %-20s${C_RESET}\n" \
                     "$u" "$uid" "$gid" "${home:0:29}" "$shell"
            else
                printf "%-15s %-6s %-6s %-30s %-20s\n" \
                     "$u" "$uid" "$gid" "${home:0:29}" "$shell"
            fi
        fi
    done < /etc/passwd
    echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
    print_status "info" "Found $active_accounts accounts with active login shells."

    # 3. Sudoers NOPASSWD backdoors check
    echo -e "\n${C_BWHITE}--- Auditing Sudoers Privileges & NOPASSWD Backdoors ---${C_RESET}"
    local sudoers_issues=0
    
    # Audit /etc/sudoers
    if [[ -f "/etc/sudoers" ]]; then
        while read -r line; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            if echo "$line" | grep -q "NOPASSWD"; then
                sudoers_issues=$((sudoers_issues + 1))
                print_status "danger" "SUDOERS PRIVILEGE BACKDOOR: NOPASSWD config found in /etc/sudoers!"
                print_status "bullet" "Match: $line"
            fi
        done < "/etc/sudoers"
    fi
    
    # Audit /etc/sudoers.d/*
    if [[ -d "/etc/sudoers.d" ]]; then
        for f in /etc/sudoers.d/*; do
            [[ ! -f "$f" ]] && continue
            while read -r line; do
                [[ -z "$line" || "$line" == "#"* ]] && continue
                if echo "$line" | grep -q "NOPASSWD"; then
                    sudoers_issues=$((sudoers_issues + 1))
                    print_status "danger" "SUDOERS PRIVILEGE BACKDOOR: NOPASSWD found in /etc/sudoers.d/$(basename "$f")!"
                    print_status "bullet" "Match: $line"
                fi
            done < "$f"
        done
    fi
    
    if [[ "$sudoers_issues" -eq 0 ]]; then
        print_status "success" "Sudoers permissions are securely configured (No NOPASSWD backdoors found)."
    fi

    # 4. SSH Brute Force failed logins check
    echo -e "\n${C_BWHITE}--- Auditing SSH Brute-Force & Failed Logins ---${C_RESET}"
    local auth_log=""
    [[ -f "/var/log/auth.log" ]] && auth_log="/var/log/auth.log"
    [[ -f "/var/log/secure" ]] && auth_log="/var/log/secure"
    
    if [[ -n "$auth_log" ]]; then
        local failed_count
        failed_count=$(grep -i "failed password" "$auth_log" 2>/dev/null | wc -l)
        if [[ "$failed_count" -gt 0 ]]; then
            print_status "danger" "DETECTED: $failed_count failed SSH login attempts in log!"
            print_status "info" "Top 3 brute-force source IP addresses attempting access:"
            grep -i "failed password" "$auth_log" 2>/dev/null | grep -oE "[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" | sort | uniq -c | sort -nr | head -n 3 | while read -r count ip; do
                echo -e "   ${C_CYAN}*${C_RESET} IP: ${C_BRED}${ip}${C_RESET} - ${C_RED}${count} attempts${C_RESET}"
            done
        else
            print_status "success" "No failed SSH login attempts detected in current authentication logs."
        fi
    else
        print_status "warn" "Authentication logs (/var/log/auth.log or /var/log/secure) are missing. Unable to audit login failures."
    fi

    # 5. Recent Logins Check
    echo -e "\n${C_BWHITE}--- Recent System SSH Login Records ---${C_RESET}"
    if command -v last &>/dev/null; then
        last -n 8 | grep -v "wtmp" | while read -r line; do
            [[ -z "$line" ]] && continue
            echo -e "   ${C_CYAN}*${C_RESET} $line"
        done
    else
        echo -e "   ${C_GRAY}'last' command is missing or login log (/var/log/wtmp) is unreadable.${C_RESET}"
    fi
}
