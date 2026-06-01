# ======================================================================
# MODULE: TOOL AUTO-UPDATER
# ======================================================================

update_tool() {
    print_status "step" "Updating Linux Server Security Toolkit..."
    log_message "INFO" "Initiating tool auto-update."

    # Verify if we are inside a Git repository
    if git rev-parse --is-inside-work-tree &>/dev/null; then
        print_status "info" "Detected Git repository. Running fetch and reset..."
        
        git fetch --all 2>&1
        if git reset --hard origin/main 2>&1; then
            chmod +x sec.sh
            print_status "success" "Tool updated successfully via Git!"
            log_message "INFO" "Tool updated via Git."
            print_status "info" "Reloading tool process..."
            sleep 1.5
            exec bash "$0"
        else
            print_status "danger" "Git update failed! Please check your network or git configuration."
            press_any_key
        fi
    else
        print_status "info" "Standalone installation detected. Downloading fresh copy from GitHub..."
        
        local tmp_file="/tmp/sec_new.sh"
        if command -v wget &>/dev/null; then
            wget -q -O "$tmp_file" https://raw.githubusercontent.com/SAOSTAR1501/bash-security/main/sec.sh
        elif command -v curl &>/dev/null; then
            curl -s -o "$tmp_file" https://raw.githubusercontent.com/SAOSTAR1501/bash-security/main/sec.sh
        else
            print_status "danger" "Neither 'wget' nor 'curl' is installed. Cannot download updates."
            press_any_key
            return
        fi

        if [[ -f "$tmp_file" && -s "$tmp_file" ]]; then
            if grep -q "LINUX SERVER SECURITY TOOLKIT" "$tmp_file"; then
                mv "$tmp_file" "$0"
                chmod +x "$0"
                print_status "success" "Standalone tool updated successfully from GitHub!"
                log_message "INFO" "Standalone tool updated from GitHub."
                print_status "info" "Reloading tool process..."
                sleep 1.5
                exec bash "$0"
            else
                print_status "danger" "Downloaded file is corrupted or invalid! Update aborted."
                rm -f "$tmp_file"
                press_any_key
            fi
        else
            print_status "danger" "Failed to download update file from GitHub!"
            press_any_key
        fi
    fi
}
