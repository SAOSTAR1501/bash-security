# ======================================================================
# MODULE: TOOL AUTO-UPDATER
# ======================================================================

update_tool() {
    print_status "step" "Updating Star Security..."
    log_message "INFO" "Initiating tool auto-update."

    # Resolve the absolute realpath of the entrypoint script
    local script_path
    script_path=$(realpath "$0" 2>/dev/null)
    [[ -z "$script_path" ]] && script_path=$(readlink -f "$0" 2>/dev/null)
    [[ -z "$script_path" ]] && script_path="$0"

    local git_dir
    git_dir=$(dirname "$script_path")

    # Bypass Git dubious ownership security block when executing under sudo root
    if command -v git &>/dev/null; then
        git config --global --add safe.directory "$git_dir" &>/dev/null
    fi

    # Verify if we are inside a Git repository
    if git -C "$git_dir" rev-parse --is-inside-work-tree &>/dev/null; then
        print_status "info" "Detected Git repository. Syncing with remote repository..."
        
        # Run fetch securely
        git -C "$git_dir" fetch --all &>/dev/null
        
        # Attempt to hard reset to origin/main
        if git -C "$git_dir" reset --hard origin/main &>/dev/null; then
            print_status "success" "Star Security successfully updated!"
            print_status "info" "Reloading toolkit to apply new updates..."
            sleep 1.2
            exec bash "$script_path" --updated
        else
            print_status "warn" "Git hard reset failed. Attempting standard git pull fallback..."
            if git -C "$git_dir" pull origin main &>/dev/null; then
                print_status "success" "Star Security successfully updated via Pull!"
                print_status "info" "Reloading toolkit..."
                sleep 1.2
                exec bash "$script_path" --updated
            else
                print_status "danger" "Git update failed! Please verify internet connection or Git remote config."
                press_any_key
            fi
        fi
    else
        print_status "info" "Standalone installation detected. Syncing full repository zip..."
        
        local zip_file="/tmp/star_security_latest.zip"
        local dl_success=0
        
        # For modular multi-file toolkit, standalone must download the entire codebase zip
        if command -v wget &>/dev/null; then
            wget -q -O "$zip_file" https://github.com/SAOSTAR1501/bash-security/archive/refs/heads/main.zip && dl_success=1
        elif command -v curl &>/dev/null; then
            curl -s -L -o "$zip_file" https://github.com/SAOSTAR1501/bash-security/archive/refs/heads/main.zip && dl_success=1
        fi

        if [[ "$dl_success" -eq 1 && -f "$zip_file" && -s "$zip_file" ]]; then
            if command -v unzip &>/dev/null; then
                print_status "info" "Unpacking latest codebase modules..."
                unzip -q -o "$zip_file" -d "/tmp"
                if [[ -d "/tmp/bash-security-main" ]]; then
                    cp -r /tmp/bash-security-main/* "$git_dir/" 2>/dev/null
                    rm -rf /tmp/bash-security-main "$zip_file"
                    chmod +x "$script_path" 2>/dev/null
                    print_status "success" "Star Security standalone files updated successfully!"
                    print_status "info" "Reloading toolkit..."
                    sleep 1.2
                    exec bash "$script_path" --updated
                fi
            else
                print_status "danger" "Extraction failed: 'unzip' utility is missing on your host."
                rm -f "$zip_file"
                press_any_key
            fi
        else
            print_status "danger" "Failed to download update packages from GitHub!"
            press_any_key
        fi
    fi
}
