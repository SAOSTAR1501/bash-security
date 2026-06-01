# ======================================================================
# MODULE: PROCESS SECURITY & CPU INVESTIGATOR
# ======================================================================

CPU_THRESHOLD=40 # Flag processes using > 40% CPU
SUSPICIOUS_PATHS=("/tmp" "/var/tmp" "/dev/shm" "/run/user" "/home" "/var/spool/cron")
COMMON_MASQUERADE=("mysql" "nginx" "apache2" "httpd" "syslogd" "systemd" "kworker" "sshd" "crond" "init")

get_process_cpu() {
    local pid="$1"
    ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' '
}

get_process_mem() {
    local pid="$1"
    ps -p "$pid" -o %mem= 2>/dev/null | tr -d ' '
}

# Detect if process runs inside Docker container
get_process_cgroup() {
    local pid="$1"
    if [[ -f "/proc/$pid/cgroup" ]]; then
        local cgroup_content
        cgroup_content=$(cat "/proc/$pid/cgroup" 2>/dev/null)
        if echo "$cgroup_content" | grep -qE 'docker|kubepods|containerd|libpod|lxc'; then
            local cid
            cid=$(echo "$cgroup_content" | grep -o -E '[a-f0-9]{64}' | head -n 1 | cut -c1-12)
            if [[ -n "$cid" ]]; then
                echo "Docker/Container ($cid)"
            else
                echo "Containerized"
            fi
        else
            echo "Host System"
        fi
    else
        echo "Unknown"
    fi
}

# Check if a file is an ELF binary by reading its magic bytes
is_elf_binary() {
    local file_path="$1"
    if [[ -f "$file_path" && -r "$file_path" ]]; then
        local hex_magic
        hex_magic=$(od -t x1 -N 4 "$file_path" 2>/dev/null | head -n 1 | cut -d' ' -f2-5 | tr -d ' ')
        if [[ "$hex_magic" == "7f454c46" ]]; then
            return 0
        fi
    fi
    return 1
}

# Scan and print suspicious or high resource CPU processes
check_cpu_processes() {
    print_status "step" "Analyzing High CPU Usage & Masqueraded Processes..."
    log_message "INFO" "Running process scan."
    
    printf "${C_BOLD}%-8s %-12s %-6s %-6s %-15s %-12s %-25s${C_RESET}\n" "PID" "USER" "CPU%" "MEM%" "CGROUP" "NAME" "REAL PATH/DETAILS"
    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"

    local suspects_found=0
    
    while read -r pid user cpu mem comm; do
        [[ -z "$pid" || "$pid" == "PID" ]] && continue
        
        local is_suspicious=0
        local reason=""
        local exe_path=""
        
        if [[ -L "/proc/$pid/exe" ]]; then
            exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        fi
        
        if [[ "$exe_path" == *" (deleted)"* ]]; then
            is_suspicious=1
            reason="Deleted Binary Exec"
        fi
        
        local base_exe=""
        if [[ -n "$exe_path" ]]; then
            base_exe=$(basename "${exe_path// (deleted)/}")
            
            for path in "${SUSPICIOUS_PATHS[@]}"; do
                if [[ "$exe_path" == "$path"* ]]; then
                    is_suspicious=1
                    reason="Exec out of $path"
                    break
                fi
            done
            
            for fake in "${COMMON_MASQUERADE[@]}"; do
                if [[ "$comm" == "$fake" ]]; then
                    if [[ "$exe_path" != "/usr/bin/"* && "$exe_path" != "/usr/sbin/"* && "$exe_path" != "/lib/"* && "$exe_path" != "/usr/lib/"* && "$exe_path" != "/usr/lib64/"* && "$exe_path" != "/usr/libexec/"* && "$exe_path" != "/run/current-system/"* ]]; then
                        is_suspicious=1
                        reason="Fake $fake process"
                    fi
                fi
            done
        fi
        
        local high_cpu
        high_cpu=$(awk -v cpu="$cpu" -v limit="$CPU_THRESHOLD" 'BEGIN {print (cpu > limit) ? 1 : 0}')
        if [[ "$high_cpu" -eq 1 ]]; then
            if [[ "$is_suspicious" -eq 0 ]]; then
                if [[ "$user" != "root" && "$user" != "systemd-"* ]]; then
                    is_suspicious=1
                    reason="High CPU (${cpu}%)"
                fi
            fi
        fi

        local cgroup_label
        cgroup_label=$(get_process_cgroup "$pid")

        if [[ "$is_suspicious" -eq 1 ]]; then
            suspects_found=$((suspects_found + 1))
            log_message "WARNING" "Suspicious process found: PID $pid ($comm) - $reason"
            printf "${C_BRED}%-8s %-12s %-6s %-6s %-15s %-12s %-25s${C_RESET}\n" \
                "$pid" "${user:0:11}" "$cpu" "$mem" "${cgroup_label:0:14}" "${comm:0:11}" "${reason} -> ${exe_path:0:40}"
        else
            if [[ "$high_cpu" -eq 1 ]]; then
                printf "${C_BYELLOW}%-8s %-12s %-6s %-6s %-15s %-12s %-25s${C_RESET}\n" \
                    "$pid" "${user:0:11}" "$cpu" "$mem" "${cgroup_label:0:14}" "${comm:0:11}" "High Resource Consumer"
            fi
        fi
        
    done < <(ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 30)

    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"
    if [[ "$suspects_found" -gt 0 ]]; then
        print_status "danger" "Found $suspects_found highly suspicious process(es). Recommended actions:"
        print_status "bullet" "Use menu option [3] to Freeze/Investigate them."
    else
        print_status "success" "No highly suspicious processes detected using standard signatures."
    fi
}

# Safe Mode interactive Investigator
process_investigator() {
    while true; do
        clear_screen
        print_header
        echo -e "${C_BYELLOW}               >>> SUSPICIOUS PROCESS DEEP DIVE <<<${C_RESET}\n"
        
        print_status "info" "Here are current running processes matching high-CPU or non-standard paths:"
        printf "   ${C_BOLD}%-8s %-12s %-6s %-12s %-30s${C_RESET}\n" "PID" "USER" "CPU%" "COMM" "REAL BINARY PATH"
        echo -e "   ${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
        
        local displayed=0
        while read -r pid user cpu comm; do
            [[ -z "$pid" || "$pid" == "PID" ]] && continue
            local exe_path=""
            if [[ -L "/proc/$pid/exe" ]]; then
                exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
            fi
            
            local is_sus=0
            if [[ "$exe_path" == *" (deleted)"* ]]; then is_sus=1; fi
            for path in "${SUSPICIOUS_PATHS[@]}"; do
                if [[ "$exe_path" == "$path"* ]]; then is_sus=1; break; fi
            done
            for fake in "${COMMON_MASQUERADE[@]}"; do
                if [[ "$comm" == "$fake" && "$exe_path" != "/usr/"* && "$exe_path" != "/lib/"* ]]; then is_sus=1; fi
            done
            
            if [[ "$is_sus" -eq 1 ]]; then
                displayed=$((displayed + 1))
                printf "   ${C_BRED}%-8s %-12s %-6s %-12s %-30s${C_RESET}\n" "$pid" "${user:0:11}" "$cpu" "$comm" "${exe_path:0:40}"
            elif [[ $(awk -v cpu="$cpu" -v limit="$CPU_THRESHOLD" 'BEGIN {print (cpu > limit) ? 1 : 0}') -eq 1 ]]; then
                displayed=$((displayed + 1))
                printf "   ${C_BYELLOW}%-8s %-12s %-6s %-12s %-30s${C_RESET}\n" "$pid" "${user:0:11}" "$cpu" "$comm" "${exe_path:0:40}"
            fi
        done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu | head -n 25)
        
        if [[ "$displayed" -eq 0 ]]; then
            echo -e "   ${C_GREEN}[+] No high-CPU or obvious suspicious path processes are running right now.${C_RESET}"
        fi
        echo -e "   ${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
        
        echo -e "\n${C_BWHITE}Enter the PID of the process you want to investigate (or 0 to go back):${C_RESET}"
        read -r target_pid
        
        if [[ "$target_pid" == "0" || -z "$target_pid" ]]; then
            break
        fi
        
        if [[ ! -d "/proc/$target_pid" ]]; then
            print_status "danger" "PID $target_pid does not exist. Please enter a valid running process ID."
            sleep 2
            continue
        fi

        while true; do
            clear_screen
            print_header
            echo -e "${C_BMAGENTA}            INVESTIGATING PROCESS: PID $target_pid${C_RESET}\n"
            
            local comm="-" user="-" cpu="0" mem="0" exe_path="-" cgroup="-" cmdline="-" parent_pid="-" cwd="-"
            
            [[ -f "/proc/$target_pid/comm" ]] && comm=$(cat "/proc/$target_pid/comm")
            user=$(ps -p "$target_pid" -o user= 2>/dev/null | tr -d ' ')
            cpu=$(get_process_cpu "$target_pid")
            mem=$(get_process_mem "$target_pid")
            [[ -L "/proc/$target_pid/exe" ]] && exe_path=$(readlink "/proc/$target_pid/exe")
            cgroup=$(get_process_cgroup "$target_pid")
            [[ -f "/proc/$target_pid/cmdline" ]] && cmdline=$(cat "/proc/$target_pid/cmdline" 2>/dev/null | tr '\0' ' ')
            [[ -f "/proc/$target_pid/status" ]] && parent_pid=$(grep PPid "/proc/$target_pid/status" | awk '{print $2}')
            [[ -L "/proc/$target_pid/cwd" ]] && cwd=$(readlink "/proc/$target_pid/cwd")

            # Resolve compromised docker container if running in cgroup
            local container_id=""
            local container_name=""
            if [[ "$cgroup" == *"Docker"* || "$cgroup" == *"Container"* ]]; then
                container_id=$(cat "/proc/$target_pid/cgroup" 2>/dev/null | grep -o -E '[a-f0-9]{64}' | head -n 1 | cut -c1-12)
                if [[ -n "$container_id" && -x $(which docker 2>/dev/null) ]]; then
                    container_name=$(docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null | tr -d '/')
                fi
            fi

            echo -e "${C_BWHITE}--- Process Dossier ---${C_RESET}"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Command Name" "$comm"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Owner/User" "$user"
            printf "${C_BOLD}%-20s:${C_RESET} %s%%\n" "CPU Resource Usage" "$cpu"
            printf "${C_BOLD}%-20s:${C_RESET} %s%%\n" "Memory Resource Usage" "$mem"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Cgroup/Namespace" "$cgroup"
            
            if [[ -n "$container_id" ]]; then
                printf "${C_BOLD}%-20s:${C_RESET} ${C_BRED}%s (ID: %s)${C_RESET}\n" "Exposed Container" "${container_name:-Unknown}" "$container_id"
            fi
            
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Parent PID" "$parent_pid"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Working Directory" "$cwd"
            
            if [[ "$exe_path" == *" (deleted)"* ]]; then
                printf "${C_BOLD}%-20s:${C_RESET} ${C_BRED}%s (DANGER: Binary deleted from disk!)${C_RESET}\n" "Executable Path" "$exe_path"
            else
                printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Executable Path" "$exe_path"
            fi
            
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Launch Commandline" "${cmdline:-[Empty or hidden]}"
            
            echo -e "\n${C_BWHITE}--- Open File Descriptors (Sockets, Log Files, Ports) ---${C_RESET}"
            if [[ -d "/proc/$target_pid/fd" ]]; then
                local count=0
                ls -l "/proc/$target_pid/fd" 2>/dev/null | tail -n +2 | while read -r line; do
                    local link
                    link=$(echo "$line" | awk -F'-> ' '{print $2}')
                    if [[ -n "$link" ]]; then
                        count=$((count + 1))
                        if [[ "$count" -le 12 ]]; then
                            echo -e "   ${C_CYAN}*${C_RESET} File: $link"
                        fi
                    fi
                done
                local total_fds
                total_fds=$(ls -1 "/proc/$target_pid/fd" 2>/dev/null | wc -l)
                if [[ "$total_fds" -gt 12 ]]; then
                    echo -e "   ${C_GRAY}... and $((total_fds - 12)) more descriptors.${C_RESET}"
                fi
            else
                echo -e "   ${C_GRAY}Failed to access descriptors (Permission or gone).${C_RESET}"
            fi

            if command -v ss &>/dev/null; then
                local conns
                conns=$(ss -tupn state established 2>/dev/null | grep "pid=$target_pid")
                if [[ -n "$conns" ]]; then
                    echo -e "\n${C_BWHITE}--- Active Outbound TCP Connections ---${C_RESET}"
                    echo -e "${C_BRED}$conns${C_RESET}"
                fi
            fi

            echo -e "\n${C_BWHITE}--- Key Environment Variables ---${C_RESET}"
            if [[ -f "/proc/$target_pid/environ" ]]; then
                local envs
                envs=$(cat "/proc/$target_pid/environ" 2>/dev/null | tr '\0' '\n' | grep -E -v 'PASS|TOKEN|KEY|SECRET|AUTH|SIGN' | head -n 8)
                if [[ -n "$envs" ]]; then
                    echo -e "${C_GRAY}$envs${C_RESET}"
                else
                    echo -e "   ${C_GRAY}[No env variables displayed or empty]${C_RESET}"
                fi
            fi

            echo -e "\n${C_BCYAN}======================================================================${C_RESET}"
            echo -e "${C_BOLD}Remediation Actions:${C_RESET}"
            echo -e "  [S] ${C_BYELLOW}Freeze/Suspend (STOP)${C_RESET}   - Safely pauses process (releases 100% CPU)"
            echo -e "  [C] ${C_BGREEN}Resume/Continue (CONT)${C_RESET}   - Resumes process if frozen"
            echo -e "  [K] ${C_BRED}Hard Terminate (KILL)${C_RESET}    - Sends SIGKILL (kill -9) to destroy process"
            
            if [[ -n "$container_id" ]]; then
                echo -e "  [D] ${C_BRED}Destroy Host Container (${container_name})${C_RESET} - STOPS & DELETES container instantly"
            fi
            
            echo -e "  [I] ${C_BMAGENTA}Isolate Source Binary${C_RESET}    - Revokes execute permissions & renames binary"
            echo -e "  [B] Back to Process List"
            echo -e "${C_BCYAN}======================================================================${C_RESET}"
            echo -n "Select action: "
            read -r action_choice
            
            case "${action_choice^^}" in
                "S")
                    print_status "info" "Sending SIGSTOP to process $target_pid..."
                    if kill -STOP "$target_pid" 2>/dev/null; then
                        log_message "ACTION" "Suspended process $target_pid ($comm)"
                        print_status "success" "Process successfully SUSPENDED. CPU usage will drop to 0% immediately."
                    else
                        print_status "danger" "Failed to suspend process. Check permission."
                    fi
                    sleep 2
                    ;;
                "C")
                    print_status "info" "Sending SIGCONT to process $target_pid..."
                    if kill -CONT "$target_pid" 2>/dev/null; then
                        log_message "ACTION" "Resumed process $target_pid ($comm)"
                        print_status "success" "Process successfully RESUMED."
                    else
                        print_status "danger" "Failed to resume process."
                    fi
                    sleep 2
                    ;;
                "K")
                    print_status "warn" "Are you sure you want to KILL PID $target_pid? [y/N]: "
                    read -r confirm
                    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                        log_message "ACTION" "Killing process $target_pid ($comm)"
                        if kill -9 "$target_pid" 2>/dev/null; then
                            print_status "success" "Process PID $target_pid successfully TERMINATED."
                            sleep 2
                            break
                        else
                            print_status "danger" "Failed to terminate process."
                            sleep 2
                        fi
                    fi
                    ;;
                "D")
                    if [[ -n "$container_id" ]]; then
                        print_status "warn" "WARNING: This will permanently STOP and DELETE the container '${container_name}' ($container_id)!"
                        echo -n "Confirm container destruction? [y/N]: "
                        read -r confirm
                        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                            print_status "info" "Stopping container '${container_name}' ($container_id)..."
                            docker stop "$container_id" &>/dev/null
                            print_status "info" "Removing container '${container_name}' ($container_id)..."
                            docker rm "$container_id" &>/dev/null
                            log_message "ACTION" "Destroyed compromised container ${container_name} ($container_id)"
                            print_status "success" "Container successfully DELETED! The miner process inside has been permanently neutralized."
                            sleep 3
                            break 2 # Break both loops (Dossier & Target PID) to go back to Process List!
                        fi
                    else
                        print_status "danger" "Process is not running inside a Docker container."
                        sleep 2
                    fi
                    ;;
                "I")
                    local clean_exe="${exe_path// (deleted)/}"
                    if [[ -f "$clean_exe" ]]; then
                        print_status "warn" "About to isolate executable: $clean_exe"
                        print_status "info" "This will suspend execution permissions and append '.infected'."
                        echo -n "Confirm isolation? [y/N]: "
                        read -r confirm
                        if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
                            log_message "ACTION" "Isolating file $clean_exe"
                            chmod 000 "$clean_exe" 2>/dev/null
                            mv "$clean_exe" "${clean_exe}.infected" 2>/dev/null
                            print_status "success" "Binary file isolated successfully to '${clean_exe}.infected' with 000 permissions."
                            sleep 2.5
                        fi
                    else
                        print_status "danger" "Source binary does not exist on disk (cannot isolate) or has already been deleted."
                        sleep 2
                    fi
                    ;;
                "B")
                    break
                    ;;
                *)
                    print_status "danger" "Invalid selection. Please choose S, C, K, D, I or B."
                    sleep 1.5
                    ;;
            esac
        done
    done
}
