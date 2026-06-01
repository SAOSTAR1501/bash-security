# ======================================================================
# MODULE: SSH KEYS AUDITOR
# ======================================================================

audit_ssh_keys() {
    print_status "step" "Auditing SSH Authorized Keys & Searching for Private Key Leaks..."
    log_message "INFO" "Auditing SSH keys."

    local ssh_keys_found=0
    local leaked_keys_found=0

    # 1. Scan Authorized SSH Keys
    echo -e "${C_BWHITE}--- Authorized Keys Scanner ---${C_RESET}"
    printf "${C_BOLD}%-12s %-12s %-30s %-20s${C_RESET}\n" "ACCOUNT" "KEY TYPE" "KEY COMMENT/OWNER" "SOURCE FILE"
    echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"

    # Scan root
    local root_auth="/root/.ssh/authorized_keys"
    if [[ -f "$root_auth" ]]; then
        while read -r line; do
            [[ -z "$line" || "$line" == "#"* ]] && continue
            ssh_keys_found=$((ssh_keys_found + 1))
            
            local key_type="Unknown"
            local comment="No Comment"
            
            key_type=$(echo "$line" | awk '{print $1}')
            # If options are present, the first field might contain options, key_type is second
            if [[ "$key_type" == *"="* ]]; then
                key_type=$(echo "$line" | awk '{print $2}')
                comment=$(echo "$line" | cut -d' ' -f3-)
            else
                comment=$(echo "$line" | cut -d' ' -f3-)
            fi
            
            printf "${C_BYELLOW}%-12s %-12s %-30s %-20s${C_RESET}\n" \
                "root" "$key_type" "${comment:0:29}" "root/authorized_keys"
        done < "$root_auth"
    fi

    # Scan regular users
    if [[ -d "/home" ]]; then
        while read -r user_dir; do
            [[ ! -d "$user_dir" ]] && continue
            local u
            u=$(basename "$user_dir")
            local auth_file="${user_dir}/.ssh/authorized_keys"
            
            if [[ -f "$auth_file" ]]; then
                while read -r line; do
                    [[ -z "$line" || "$line" == "#"* ]] && continue
                    ssh_keys_found=$((ssh_keys_found + 1))
                    
                    local key_type="Unknown"
                    local comment="No Comment"
                    
                    key_type=$(echo "$line" | awk '{print $1}')
                    if [[ "$key_type" == *"="* ]]; then
                        key_type=$(echo "$line" | awk '{print $2}')
                        comment=$(echo "$line" | cut -d' ' -f3-)
                    else
                        comment=$(echo "$line" | cut -d' ' -f3-)
                    fi
                    
                    printf "%-12s %-12s %-30s %-20s\n" \
                        "$u" "$key_type" "${comment:0:29}" "~${u}/authorized_keys"
                done < "$auth_file"
            fi
        done < <(find /home -maxdepth 1 -mindepth 1 -type d 2>/dev/null)
    fi

    echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
    print_status "info" "Total authorized SSH keys audited: $ssh_keys_found"

    # 2. Scan for exposed private SSH keys
    echo -e "\n${C_BWHITE}--- Exposed Private SSH Key Hunter ---${C_RESET}"
    print_status "info" "Searching home directories and /root for private keys left in plaintext..."

    # Common private key headers
    local headers=("BEGIN OPENSSH PRIVATE KEY" "BEGIN RSA PRIVATE KEY" "BEGIN EC PRIVATE KEY" "BEGIN DSA PRIVATE KEY" "BEGIN PRIVATE KEY")
    
    for scan_dir in "/root" "/home"; do
        if [[ ! -d "$scan_dir" ]]; then
            continue
        fi

        # Find all files of reasonable size (to avoid reading huge text logs) up to depth 4
        while read -r file_path; do
            [[ -z "$file_path" || ! -f "$file_path" || ! -r "$file_path" ]] && continue
            
            # Skip standard system directories and git files
            if [[ "$file_path" == *"/.git/"* || "$file_path" == *"/.cache/"* || "$file_path" == *"/node_modules/"* ]]; then
                continue
            fi

            # Read first line to inspect header
            local first_line
            first_line=$(head -n 1 "$file_path" 2>/dev/null)
            
            for h in "${headers[@]}"; do
                if [[ "$first_line" == *"$h"* ]]; then
                    leaked_keys_found=$((leaked_keys_found + 1))
                    log_message "WARNING" "Exposed private key found: $file_path"
                    
                    local owner perms
                    owner=$(stat -c "%U:%G" "$file_path" 2>/dev/null)
                    perms=$(stat -c "%a" "$file_path" 2>/dev/null)
                    
                    print_status "danger" "Exposed Private Key File: $file_path"
                    print_status "bullet" "Owner: $owner | Permissions: $perms (Recommended: 600 or delete!)"
                    break
                fi
            done
        done < <(find "$scan_dir" -maxdepth 4 -type f -size -100k 2>/dev/null)
    done

    if [[ "$leaked_keys_found" -eq 0 ]]; then
        print_status "success" "No exposed private SSH keys identified in standard locations."
    else
        print_status "warn" "Found $leaked_keys_found exposed private key(s). Secure these immediately!"
    fi
}
