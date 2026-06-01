#!/usr/bin/env bash
# ======================================================================
#          LINUX SERVER SECURITY TOOLKIT (Miner & Malware Scanner)
#                 Compiled production build: 2026-06-01 10:19:00
#                 Source Architecture: MVC Modular / Domain-Driven
# ======================================================================
set -o pipefail

# ======================================================================
# CORE COMPONENT: TERMINAL COLORS
# ======================================================================

# Formatting Escapes
C_RESET="\e[0m"
C_BOLD="\e[1m"
C_DIM="\e[2m"
C_UNDERLINE="\e[4m"

# Text Colors
C_RED="\e[31m"
C_GREEN="\e[32m"
C_YELLOW="\e[33m"
C_BLUE="\e[34m"
C_MAGENTA="\e[35m"
C_CYAN="\e[36m"
C_WHITE="\e[37m"
C_GRAY="\e[90m"

# Bold Text Colors
C_BRED="\e[1;31m"
C_BGREEN="\e[1;32m"
C_BYELLOW="\e[1;33m"
C_BBLUE="\e[1;34m"
C_BMAGENTA="\e[1;35m"
C_BCYAN="\e[1;36m"
C_BWHITE="\e[1;37m"

# Background Colors
BG_RED="\e[41m"
BG_YELLOW="\e[43m"
BG_BLUE="\e[44m"

# ======================================================================
# CORE COMPONENT: AUDITING LOG SYSTEM
# ======================================================================

LOG_FILE="/var/log/sec_toolkit.log"

# Standardized logging to LOG_FILE
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
}

# ======================================================================
# CORE COMPONENT: PRIVILEGE VALIDATOR
# ======================================================================

# Check root privileges prior to core scans
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${C_BRED}[!] ERROR: This toolkit must be run as root (or using sudo).${C_RESET}"
        echo -e "${C_GRAY}Some systems files, process metrics, and network configurations are hidden from regular users.${C_RESET}"
        exit 1
    fi
}

# ======================================================================
# CORE COMPONENT: VISUAL INTERFACE ENGINE
# ======================================================================

clear_screen() {
    clear
}

print_header() {
    echo -e "${C_CYAN}======================================================================${C_RESET}"
    echo -e "${C_BCYAN}      LINUX SERVER SECURITY TOOLKIT (Miner & Malware Scanner)${C_RESET}"
    echo -e "${C_CYAN}======================================================================${C_RESET}"
}

print_status() {
    local type="$1"
    local msg="$2"
    case "$type" in
        "info")    echo -e "${C_BCYAN}[i]${C_RESET} $msg" ;;
        "success") echo -e "${C_BGREEN}[+]${C_RESET} $msg" ;;
        "warn")    echo -e "${C_BYELLOW}[!] WARNING:${C_RESET} $msg" ;;
        "danger")  echo -e "${C_BRED}[!!!] ALERT:${C_RESET} $msg" ;;
        "step")    echo -e "\n${C_BWHITE}>> $msg${C_RESET}" ;;
        "bullet")  echo -e "   ${C_CYAN}*${C_RESET} $msg" ;;
    esac
}

press_any_key() {
    echo -e "\n${C_GRAY}Press any key to return to the menu...${C_RESET}"
    read -n 1 -s -r
}

banner() {
    clear_screen
    echo -e "${C_BCYAN}"
    echo -e "    ▄▄▄█████▓ ▄████▄   ▒█████   ▒█████   ██▓     ██▓  ▄▄▄█████▓"
    echo -e "    ▓  ██▒ ▓▒▒██▀ ▀█  ▒██▒  ██▒▒██▒  ██▒▓██▒    ▓██▒  ▓  ██▒ ▓▒"
    echo -e "    ▒ ▓██░ ▒░▒▓█    ▄ ▒██░  ██▒▒██░  ██▒▒██░    ▒██░  ▒ ▓██░ ▒░"
    echo -e "    ░ ▓██▀ ░ ▒▓▓▄ ▄██▒▒██   ██░▒██   ██░▒██░    ▒██░  ░ ▓██▀ ░ "
    echo -e "      ▒██▒ ░ ▒ ▓███▀ ░░ ████▓▒░░ ████▓▒░░██████▒░██████▒ ▒██▒ ░ "
    echo -e "      ▒ ░░   ░ ░ ▒ ░  ░ ▒░▒░▒░ ░ ▒░▒░▒░ ░ ▒░▓  ░░ ▒░▓  ░ ▒ ░░   "
    echo -e "        ░      ░  ▒     ░ ▒ ▒░   ░ ▒ ▒░ ░ ░ ▒  ░░ ░ ▒  ░   ░    "
    echo -e "      ░      ░        ░ ░ ░ ▒  ░ ░ ░ ▒    ░ ░     ░ ░    ░      "
    echo -e "             ░ ▄       ░   ░░    ░   ░░     ░  ░    ░  ░        "
    echo -e "             ░                                                  "
    echo -e "             ${C_RESET}${C_DIM}v1.1.0 | Engine: Antigravity AI | OS: Linux System Audit${C_RESET}\n"
    log_message "INFO" "Security Toolkit started."
}


# ======================================================================
# MODULE: SYSTEM INFO AUDITOR
# ======================================================================

display_system_info() {
    print_status "step" "Auditing Host System General Information..."
    
    local os_pretty="Unknown Linux"
    if [[ -f "/etc/os-release" ]]; then
        os_pretty=$(grep PRETTY_NAME /etc/os-release | cut -d'=' -f2 | tr -d '"')
    fi
    
    local load_avg
    load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1", "$2", "$3}')
    
    local uptime_str
    uptime_str=$(uptime -p 2>/dev/null)
    
    local total_mem free_mem
    total_mem=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}')
    free_mem=$(free -h 2>/dev/null | awk '/^Mem:/ {print $4}')
    
    local disk_usage
    disk_usage=$(df -h / 2>/dev/null | tail -n 1 | awk '{print $5" of "$2}')

    echo -e "${C_BWHITE}--- System Specifications ---${C_RESET}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Operating System" "$os_pretty"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Hostname" "$(hostname)"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Kernel Version" "$(uname -r)"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "System Uptime" "${uptime_str:-[N/A]}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s\n" "Load Average" "${load_avg:-[N/A]}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s (Free: %s)\n" "RAM Resources" "${total_mem:-[N/A]}" "${free_mem:-[N/A]}"
    printf "   ${C_BOLD}%-20s:${C_RESET} %s used\n" "Disk Space (Root)" "${disk_usage:-[N/A]}"
    echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
}


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
        print_status "bullet" "Use menu option [2] to Freeze/Investigate them."
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

            echo -e "${C_BWHITE}--- Process Dossier ---${C_RESET}"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Command Name" "$comm"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Owner/User" "$user"
            printf "${C_BOLD}%-20s:${C_RESET} %s%%\n" "CPU Resource Usage" "$cpu"
            printf "${C_BOLD}%-20s:${C_RESET} %s%%\n" "Memory Resource Usage" "$mem"
            printf "${C_BOLD}%-20s:${C_RESET} %s\n" "Cgroup/Namespace" "$cgroup"
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
                    print_status "danger" "Invalid selection. Please choose S, C, K, I or B."
                    sleep 1.5
                    ;;
            esac
        done
    done
}


# ======================================================================
# MODULE: NETWORK SOCKET AUDITOR
# ======================================================================

MINING_PORTS=(3333 4444 5555 7777 8888 9999 14444 8008 8080)

check_network_connections() {
    print_status "step" "Auditing Network Connections & Outbound Stratum Pools..."
    log_message "INFO" "Running network scan."

    local network_threats=0
    local net_tool=""
    
    if command -v ss &>/dev/null; then
        net_tool="ss"
    elif command -v netstat &>/dev/null; then
        net_tool="netstat"
    fi

    if [[ -z "$net_tool" ]]; then
        print_status "warn" "Neither 'ss' nor 'netstat' is installed. Reading direct socket connections is limited."
        print_status "info" "Falling back to scanning /proc/net/tcp..."
        if [[ -f "/proc/net/tcp" ]]; then
            echo -e "${C_BOLD}%-20s %-20s %-10s${C_RESET}" "Local Hex IP:Port" "Remote Hex IP:Port" "Status"
            tail -n +2 /proc/net/tcp | head -n 10
        fi
        return
    fi

    printf "${C_BOLD}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" "PROTO" "PID" "PROCESS" "LOCAL ADDRESS" "REMOTE PORT" "STATE"
    echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"

    local port_regex
    port_regex=$(echo "${MINING_PORTS[@]}" | tr ' ' '|')

    if [[ "$net_tool" == "ss" ]]; then
        while read -r proto state local_addr remote_addr process; do
            [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
            
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            
            local pid="-"
            local pname="-"
            if [[ "$process" == *"pid="* ]]; then
                pid=$(echo "$process" | grep -o -E 'pid=[0-9]+' | cut -d'=' -f2)
                pname=$(echo "$process" | grep -o -E '"[^"]+"' | head -n 1 | tr -d '"')
            fi

            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                network_threats=$((network_threats + 1))
                log_message "WARNING" "Stratum miner connection detected: PID $pid ($pname) on port $rport"
                printf "${C_BRED}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" \
                    "$proto" "$pid" "${pname:0:19}" "${local_addr:0:24}" "$rport" "$state"
            else
                if [[ "$state" == "ESTAB" && "$remote_addr" != "127.0.0.1"* && "$remote_addr" != "::1"* && "$remote_addr" != "localhost"* ]]; then
                    if [[ "$pid" != "-" ]]; then
                        local exe_path
                        exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
                        for path in "${SUSPICIOUS_PATHS[@]}"; do
                            if [[ "$exe_path" == "$path"* ]]; then
                                network_threats=$((network_threats + 1))
                                log_message "WARNING" "Suspicious process outbound connection: PID $pid ($pname) -> $remote_addr"
                                printf "${C_BYELLOW}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" \
                                    "$proto" "$pid" "${pname:0:19}*" "${local_addr:0:24}" "$rport" "$state"
                                break
                            fi
                        done
                    fi
                fi
            fi
        done < <(ss -tupn state established 2>/dev/null)
    else
        while read -r proto recv_q send_q local_addr remote_addr state process; do
            [[ "$proto" != "tcp" && "$proto" != "udp" ]] && continue
            
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            
            local pid="-"
            local pname="-"
            if [[ "$process" == *"/"* ]]; then
                pid=$(echo "$process" | cut -d'/' -f1)
                pname=$(echo "$process" | cut -d'/' -f2-)
            fi

            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                network_threats=$((network_threats + 1))
                log_message "WARNING" "Stratum miner connection detected (netstat): PID $pid ($pname) on port $rport"
                printf "${C_BRED}%-6s %-12s %-20s %-25s %-12s %-15s${C_RESET}\n" \
                    "$proto" "$pid" "${pname:0:19}" "${local_addr:0:24}" "$rport" "$state"
            fi
        done < <(netstat -nap 2>/dev/null)
    fi

    echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
    if [[ "$network_threats" -gt 0 ]]; then
        print_status "danger" "Found $network_threats network connections linking suspicious paths or stratum ports."
    else
        print_status "success" "No stratum pool connections or suspicious path network sockets identified."
    fi
}


# ======================================================================
# MODULE: PORTS & FIREWALL AUDITOR (WITH DOCKER EXPOSURE CHECKS)
# ======================================================================

check_ports_firewall() {
    print_status "step" "Auditing Listening Ports, UFW Firewall & Docker Exposures..."
    log_message "INFO" "Auditing ports and firewall rules."

    # 1. Check Firewall Status (UFW / iptables)
    echo -e "${C_BWHITE}--- Firewall Daemon Status ---${C_RESET}"
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null)
        if echo "$ufw_status" | grep -q "active"; then
            print_status "success" "UFW Firewall is ACTIVE!"
            echo -e "${C_GRAY}$ufw_status${C_RESET}"
        else
            print_status "danger" "UFW Firewall is INACTIVE / DISABLED! All ports are unprotected."
        fi
    else
        print_status "warn" "UFW utility is not installed. Checking raw iptables..."
        if command -v iptables &>/dev/null; then
            local rules_count
            rules_count=$(iptables -S 2>/dev/null | wc -l)
            if [[ "$rules_count" -gt 3 ]]; then
                print_status "info" "iptables is active with $rules_count active filter rules."
            else
                print_status "danger" "iptables appears to be unconfigured (default ACCEPT all)."
            fi
        fi
    fi

    # 2. Check System Listening Ports
    echo -e "\n${C_BWHITE}--- System Listening Ports (Local Sockets) ---${C_RESET}"
    local net_tool=""
    if command -v ss &>/dev/null; then
        net_tool="ss"
    elif command -v netstat &>/dev/null; then
        net_tool="netstat"
    fi

    if [[ -n "$net_tool" ]]; then
        printf "${C_BOLD}%-6s %-25s %-12s %-25s${C_RESET}\n" "PROTO" "LOCAL BIND ADDRESS" "PID/PORT" "PROCESS NAME"
        echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
        
        if [[ "$net_tool" == "ss" ]]; then
            while read -r proto state local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$local_addr" ]] && continue
                
                # Extract port from local address
                local port
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                local bind_ip
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")

                local pid="-" pname="-"
                if [[ "$process" == *"pid="* ]]; then
                    pid=$(echo "$process" | grep -o -E 'pid=[0-9]+' | cut -d'=' -f2)
                    pname=$(echo "$process" | grep -o -E '"[^"]+"' | head -n 1 | tr -d '"')
                fi

                # Flag public exposures (0.0.0.0 or *) for sensitive ports
                local is_public=0
                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    is_public=1
                fi

                if [[ "$is_public" -eq 1 ]]; then
                    # Highlight sensitive publicly exposed ports
                    if [[ "$port" =~ ^(22|3306|5432|6379|27017|9200|8080)$ ]]; then
                        printf "${C_BRED}%-6s %-25s %-12s %-25s${C_RESET} ${C_RED}(PUBLIC EXPOSURE!)${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    else
                        printf "${C_BYELLOW}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    fi
                else
                    printf "${C_BGREEN}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                        "$proto" "$local_addr" "$port" "$pname ($pid)"
                fi
            done < <(ss -tulnp 2>/dev/null)
        else
            # netstat
            netstat -tulnp 2>/dev/null | grep LISTEN | while read -r proto recv_q send_q local_addr remote_addr state process; do
                [[ -z "$local_addr" ]] && continue
                local port bind_ip pid pname
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")
                
                pid=$(echo "$process" | cut -d'/' -f1)
                pname=$(echo "$process" | cut -d'/' -f2-)

                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    if [[ "$port" =~ ^(22|3306|5432|6379|27017|9200|8080)$ ]]; then
                        printf "${C_BRED}%-6s %-25s %-12s %-25s${C_RESET} ${C_RED}(PUBLIC EXPOSURE!)${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    else
                        printf "${C_BYELLOW}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                            "$proto" "$local_addr" "$port" "$pname ($pid)"
                    fi
                else
                    printf "${C_BGREEN}%-6s %-25s %-12s %-25s${C_RESET}\n" \
                        "$proto" "$local_addr" "$port" "$pname ($pid)"
                fi
            done
        fi
        echo -e "${C_GRAY}----------------------------------------------------------------------------------${C_RESET}"
    else
        print_status "warn" "Unable to fetch socket states (no ss/netstat)."
    fi

    # 3. Check Docker Container Port Exposures
    echo -e "\n${C_BWHITE}--- Docker Container Port Exposures & UFW Bypass Audit ---${C_RESET}"
    if command -v docker &>/dev/null; then
        local docker_running
        docker_running=$(systemctl is-active docker 2>/dev/null)
        if [[ "$docker_running" == "active" ]]; then
            local containers
            containers=$(docker ps --format "table {{.ID}}\t{{.Names}}\t{{.Ports}}" 2>/dev/null)
            
            if [[ -n "$containers" ]]; then
                echo -e "$containers"
                
                # Check for public binding database/sensitive ports inside docker
                local dangerous_bindings=0
                docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null | while read -r name ports; do
                    # Look for 0.0.0.0 or [::] bindings to databases
                    if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|6379|27017|9200|8080|22)->"; then
                        local bound_port
                        bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                        dangerous_bindings=$((dangerous_bindings + 1))
                        
                        log_message "WARNING" "Dangerous Docker binding exposed publicly: Container $name on port $bound_port"
                        print_status "danger" "DOCKER BYPASS VULNERABILITY: Container '$name' exposes port $bound_port to 0.0.0.0!"
                        print_status "bullet" "CRITICAL RATIONALE: Docker automatically writes raw iptables rules."
                        print_status "bullet" "Even if UFW status is ACTIVE, Docker's rules bypass UFW completely!"
                        print_status "bullet" "Tin tặc có thể quét thấy và tấn công trực tiếp vào database trong container này."
                    fi
                done
                
                if [[ "$dangerous_bindings" -eq 0 ]]; then
                    print_status "success" "All running Docker container ports are bound securely or do not expose sensitive DB services publicly."
                else
                    print_status "warn" "Exposed ports identified! Recommendation: Sửa file docker-compose.yml"
                    print_status "bullet" "Thay đổi '- p 3306:3306' thành '- p 127.0.0.1:3306:3306' rồi restart container."
                fi
            else
                print_status "info" "Docker daemon is active but no containers are currently running."
            fi
        else
            print_status "info" "Docker service is installed but not running."
        fi
    else
        print_status "info" "Docker is not installed on this host system."
    fi
}


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

    # 3. Recent Logins Check
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

    local headers=("BEGIN OPENSSH PRIVATE KEY" "BEGIN RSA PRIVATE KEY" "BEGIN EC PRIVATE KEY" "BEGIN DSA PRIVATE KEY" "BEGIN PRIVATE KEY")
    
    for scan_dir in "/root" "/home"; do
        if [[ ! -d "$scan_dir" ]]; then
            continue
        fi

        while read -r file_path; do
            [[ -z "$file_path" || ! -f "$file_path" || ! -r "$file_path" ]] && continue
            
            if [[ "$file_path" == *"/.git/"* || "$file_path" == *"/.cache/"* || "$file_path" == *"/node_modules/"* ]]; then
                continue
            fi

            # Read first line to inspect header, removing null bytes to avoid console warnings
            local first_line
            first_line=$(head -n 1 "$file_path" 2>/dev/null | tr -d '\0')
            
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


# ======================================================================
# ENTRYPOINT & MENU
# ======================================================================

# Orchestrate all security scans
run_full_scan() {
    clear_screen
    print_header
    echo -e "${C_BWHITE}Running unified system security assessment. Please wait...${C_RESET}\n"
    
    display_system_info
    check_cpu_processes
    check_network_connections
    check_ports_firewall
    check_globally_writeable
    check_persistence
    check_system_integrity
    audit_system_users
    audit_ssh_keys
    
    echo -e "\n${C_BCYAN}======================================================================${C_RESET}"
    print_status "success" "Security assessment complete. Audit log written to: $LOG_FILE"
    press_any_key
}

# Generate audit reports to disk
generate_report() {
    local report_path="/tmp/security_toolkit_report.txt"
    print_status "step" "Generating audit text report..."
    
    {
        echo "======================================================================"
        echo "           LINUX SERVER SECURITY TOOLKIT - AUDIT REPORT"
        echo "           Generated at: $(date "+%Y-%m-%d %H:%M:%S")"
        echo "======================================================================"
        echo ""
        echo "--- Host Information ---"
        echo "Hostname: $(hostname)"
        echo "Kernel: $(uname -r)"
        echo "Uptime: $(uptime -p)"
        echo ""
        echo "--- High Resource / Suspicious Processes ---"
        ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu | head -n 20
        echo ""
        echo "--- Active Outbound Network Connections ---"
        if command -v ss &>/dev/null; then
            ss -tupn state established 2>/dev/null
        else
            netstat -nap 2>/dev/null | grep ESTABLISHED
        fi
        echo ""
        echo "--- Persistence Check ---"
        echo "* Systemd units:"
        find /etc/systemd/system/ -name "*.service" -exec grep -H "ExecStart" {} \; 2>/dev/null
        echo "* System Crontab:"
        cat /etc/crontab 2>/dev/null
        echo ""
        echo "--- Library Injections (/etc/ld.so.preload) ---"
        cat /etc/ld.so.preload 2>/dev/null
        echo ""
        echo "--- User Identity & Accounts ---"
        while read -r line; do
            local u uid shell
            u=$(echo "$line" | cut -d':' -f1)
            uid=$(echo "$line" | cut -d':' -f3)
            shell=$(echo "$line" | cut -d':' -f7)
            if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
                echo "   Interactive User: $u (UID: $uid)"
            fi
        done < /etc/passwd
    } > "$report_path"

    log_message "INFO" "Generated report at $report_path"
    print_status "success" "Report generated successfully at: $report_path"
    print_status "info" "You can download or view this file for detailed offline audits."
    press_any_key
}

# --- MAIN MENU CHOICE LOOP ---
main_menu() {
    check_root
    
    while true; do
        banner
        print_header
        echo -e " [1]  Run Full System Security Scan (Unified Report)"
        echo -e " [2]  Deep Process Investigator (Freeze / Analyze / Kill)"
        echo -e " [3]  Inspect Network Connections & Stratum Pools"
        echo -e " [4]  Scan Ports, UFW Firewall & Docker Exposures"
        echo -e " [5]  Scan Temp Writable Folders (/tmp, /dev/shm) for Signatures"
        echo -e " [6]  Check System Persistence (Cron Jobs, Systemd Services)"
        echo -e " [7]  Verify Rootkits & ld.so.preload"
        echo -e " [8]  Audit Identity Credentials & SSH Keys (Users / Keys / Leaks)"
        echo -e " [9]  Generate Comprehensive Text Audit Report"
        echo -e " [10] Update Tool (Reset & Pull from GitHub)"
        echo -e " [0]  Exit Tool"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -n "Select option: "
        read -r main_choice
        
        case "$main_choice" in
            1)
                run_full_scan
                ;;
            2)
                process_investigator
                ;;
            3)
                clear_screen
                print_header
                check_network_connections
                press_any_key
                ;;
            4)
                clear_screen
                print_header
                check_ports_firewall
                press_any_key
                ;;
            5)
                clear_screen
                print_header
                check_globally_writeable
                press_any_key
                ;;
            6)
                clear_screen
                print_header
                check_persistence
                press_any_key
                ;;
            7)
                clear_screen
                print_header
                check_system_integrity
                press_any_key
                ;;
            8)
                clear_screen
                print_header
                audit_system_users
                echo ""
                audit_ssh_keys
                press_any_key
                ;;
            9)
                clear_screen
                print_header
                generate_report
                ;;
            10)
                clear_screen
                print_header
                update_tool
                ;;
            0)
                echo -e "\n${C_BGREEN}[+] Thank you for using Linux Server Security Toolkit. Stay secure!${C_RESET}"
                log_message "INFO" "Security Toolkit closed."
                exit 0
                ;;
            *)
                print_status "danger" "Invalid choice. Please select 0-10."
                sleep 1
                ;;
        esac
    done
}

# Start execution
main_menu
