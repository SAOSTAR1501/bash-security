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
}
