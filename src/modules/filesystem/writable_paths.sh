# ======================================================================
# MODULE: WRITEABLE STORAGE SCANNER
# ======================================================================

check_globally_writeable() {
    print_status "step" "Scanning Globals/Temp Storage (/tmp, /dev/shm) for Binaries & Miner Configs..."
    log_message "INFO" "Scanning temporary folders."

    local threat_files=0
    
    printf "${C_BOLD}%-25s %-12s %-15s %-10s %-15s${C_RESET}\n" "PATH" "PERMISSIONS" "OWNER" "SIZE" "TYPE"
    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"

    for target_dir in "/tmp" "/var/tmp" "/dev/shm" "/run/user"; do
        if [[ ! -d "$target_dir" ]]; then
            continue
        fi

        while read -r file_path; do
            [[ -z "$file_path" || ! -f "$file_path" ]] && continue

            local matches_sig=0
            local threat_type=""

            if is_elf_binary "$file_path"; then
                matches_sig=1
                threat_type="ELF Executable"
            fi

            local base_name
            base_name=$(basename "$file_path")
            if [[ "$base_name" == *"xmrig"* || "$base_name" == "config.json" && "$target_dir" == "/tmp" || "$base_name" == "pool.txt" || "$base_name" == ".miner"* ]]; then
                matches_sig=1
                threat_type="Miner Signature/Config"
            fi

            if [[ "$base_name" == .* && ( "$base_name" == *".sh" || "$base_name" == *".py" || "$base_name" == *".pl" ) ]]; then
                matches_sig=1
                threat_type="Hidden Script"
            fi

            if [[ "$matches_sig" -eq 1 ]]; then
                threat_files=$((threat_files + 1))
                log_message "WARNING" "Malicious file signature found: $file_path ($threat_type)"
                
                local perms owner size
                perms=$(stat -c "%a" "$file_path" 2>/dev/null)
                owner=$(stat -c "%U:%G" "$file_path" 2>/dev/null)
                size=$(stat -c "%s" "$file_path" 2>/dev/null | awk '{ split("B KB MB GB", v); s=1; while($1>1024){$1/=1024; s++} printf "%.1f %s", $1, v[s] }')
                
                printf "${C_BRED}%-25s %-12s %-15s %-10s %-15s${C_RESET}\n" \
                    "${file_path:0:24}" "$perms" "$owner" "$size" "$threat_type"
            fi
        done < <(find "$target_dir" -maxdepth 3 -type f 2>/dev/null)
    done

    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"
    if [[ "$threat_files" -gt 0 ]]; then
        print_status "danger" "Found $threat_files suspicious files in writable systems storage."
        print_status "bullet" "Consider quarantining these files using 'chmod 000 <file>' or moving them to a quarantine directory."
    else
        print_status "success" "Globally-writable directories look clean."
    fi
}
