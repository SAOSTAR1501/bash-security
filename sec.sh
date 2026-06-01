#!/usr/bin/env bash
# ======================================================================
#          LINUX SERVER SECURITY TOOLKIT (Miner & Malware Scanner)
#                 Compiled production build: 2026-06-01 14:36:52
#                 Source Architecture: MVC Modular / Domain-Driven
# ======================================================================
set -o pipefail

# ======================================================================
# MODULE: src/core/colors.sh
# ======================================================================
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
# MODULE: src/core/logger.sh
# ======================================================================
# ======================================================================
# CORE COMPONENT: AUDITING LOG SYSTEM & NOTIFICATIONS
# ======================================================================

LOG_FILE="/var/log/sec_toolkit.log"
CONF_DIR="/etc/sec-toolkit"
CONF_FILE="${CONF_DIR}/config.env"

# Load global configuration (Survivable across Git updates)
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE" 2>/dev/null
fi

# Standardized logging to LOG_FILE
log_message() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null
}

# Lark Webhook Notification engine
send_lark_notification() {
    local title="$1"
    local text="$2"
    local level="${3:-info}" # info, success, warn, danger
    
    # Only execute if ENABLE_LARK is true and webhook URL is configured
    if [[ "${ENABLE_LARK:-}" == "true" && -n "${LARK_WEBHOOK_URL:-}" ]]; then
        local webhook_url="$LARK_WEBHOOK_URL"
        local header_color="blue"
        case "$level" in
            "danger")  header_color="red" ;;
            "warn")    header_color="orange" ;;
            "success") header_color="green" ;;
            "info"|*)  header_color="blue" ;;
        esac
        
        local hostname
        hostname=$(hostname)
        local server_ip
        server_ip=$(curl -s https://api.ipify.org || hostname -I | awk '{print $1}')
        local date_time
        date_time=$(date "+%Y-%m-%d %H:%M:%S")
        local uptime_val
        uptime_val=$(uptime -p 2>/dev/null || echo "N/A")
        
        # Build JSON using Python to ensure 100% bulletproof JSON escaping and compatibility
        local payload
        payload=$(python3 -c '
import sys, json
title = sys.argv[1]
text = sys.argv[2]
level = sys.argv[3]
color = sys.argv[4]
hname = sys.argv[5]
ip = sys.argv[6]
uptime = sys.argv[7]
dtime = sys.argv[8]

card = {
    "msg_type": "interactive",
    "card": {
        "config": {
            "wide_screen_mode": True,
            "enable_forward": True
        },
        "header": {
            "template": color,
            "title": {
                "tag": "plain_text",
                "content": f"🚨 SECURITY ALERT: {hname}" if level == "danger" else f"🛡️ SECURITY UPDATE: {hname}"
            }
        },
        "elements": [
            {
                "tag": "div",
                "fields": [
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**🖥️ Hostname:**\n{hname}"
                        }
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**🌐 Public IP:**\n{ip}"
                        }
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**⏱️ Uptime:**\n{uptime}"
                        }
                    },
                    {
                        "is_short": True,
                        "text": {
                            "tag": "lark_md",
                            "content": f"**📅 Time:**\n{dtime}"
                        }
                    }
                ]
            },
            {"tag": "hr"},
            {
                "tag": "div",
                "text": {
                    "tag": "lark_md",
                    "content": f"{text}"
                }
            },
            {"tag": "hr"},
            {
                "tag": "note",
                "elements": [
                    {
                        "tag": "plain_text",
                        "content": "💡 Linux Server Security Toolkit - Miner & Malware Scanner"
                    }
                ]
            }
        ]
    }
}
print(json.dumps(card))
' "$title" "$text" "$level" "$header_color" "$hostname" "$server_ip" "$uptime_val" "$date_time" 2>/dev/null)

        # Fallback to jq if python3 fails, or if python3 is not available
        if [[ -z "$payload" ]]; then
            if command -v jq &>/dev/null; then
                payload=$(jq -n \
                    --arg hname "$hostname" \
                    --arg ip "$server_ip" \
                    --arg uptime "$uptime_val" \
                    --arg dtime "$date_time" \
                    --arg title "$title" \
                    --arg text "$text" \
                    --arg color "$header_color" \
                    '{
                        msg_type: "interactive",
                        card: {
                            config: { wide_screen_mode: true, enable_forward: true },
                            header: {
                                template: $color,
                                title: { tag: "plain_text", content: ("🛡️ SECURITY REPORT: " + $hname) }
                            },
                            elements: [
                                {
                                    tag: "div",
                                    fields: [
                                        { is_short: true, text: { tag: "lark_md", content: ("**🖥️ Hostname:**\n" + $hname) } },
                                        { is_short: true, text: { tag: "lark_md", content: ("**🌐 Public IP:**\n" + $ip) } },
                                        { is_short: true, text: { tag: "lark_md", content: ("**⏱️ Uptime:**\n" + $uptime) } },
                                        { is_short: true, text: { tag: "lark_md", content: ("**📅 Time:**\n" + $dtime) } }
                                    ]
                                },
                                { tag: "hr" },
                                { tag: "div", text: { tag: "lark_md", content: ($text) } },
                                { tag: "hr" },
                                { tag: "note", elements: [{ tag: "plain_text", content: "💡 Linux Server Security Toolkit" }] }
                            ]
                        }
                    }')
            else
                # Safe plain text fallback
                local full_msg="🛡️ [SECURITY REPORT: $hostname]\nTitle: $title\nTime: $date_time\nIP: $server_ip\n------------------\n$text"
                local json_safe_msg
                json_safe_msg=$(echo "$full_msg" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | awk '{printf "%s\\n", $0}' | sed 's/\\n$//')
                payload="{\"msg_type\":\"text\",\"content\":{\"text\":\"$json_safe_msg\"}}"
            fi
        fi

        curl -s -X POST -H "Content-Type: application/json" -d "$payload" "$webhook_url" &>/dev/null &
    fi
}

# Optimize Log Size (Setup logrotate rules)
setup_logrotate() {
    if [[ -w "/etc/logrotate.d" && ! -f "/etc/logrotate.d/sec_toolkit" ]]; then
        cat << 'EOF' > "/etc/logrotate.d/sec_toolkit" 2>/dev/null
/var/log/sec_toolkit.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 0600 root root
}
EOF
    fi
}

# Auto-run logrotate configuration
setup_logrotate


# ======================================================================
# MODULE: src/core/root.sh
# ======================================================================
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
# MODULE: src/core/ui.sh
# ======================================================================
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
# MODULE: src/modules/system/sys_info.sh
# ======================================================================
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
# MODULE: src/modules/system/cpu_process.sh
# ======================================================================
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


# ======================================================================
# MODULE: src/modules/network/connections.sh
# ======================================================================
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
    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"

    local port_regex
    port_regex=$(echo "${MINING_PORTS[@]}" | tr ' ' '|')

    if [[ "$net_tool" == "ss" ]]; then
        while read -r proto state recv_q send_q local_addr remote_addr process; do
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

    echo -e "${C_GRAY}----------------------------------------------------------------------------------------------------${C_RESET}"
    if [[ "$network_threats" -gt 0 ]]; then
        print_status "danger" "Found $network_threats network connections linking suspicious paths or stratum ports."
    else
        print_status "success" "No stratum pool connections or suspicious path network sockets identified."
    fi
}


# ======================================================================
# MODULE: src/modules/network/firewall.sh
# ======================================================================
# ======================================================================
# MODULE: PORTS & FIREWALL AUDITOR (WITH DOCKER EXPOSURE CHECKS)
# ======================================================================

remediate_docker_ports() {
    local pub_interface
    pub_interface=$(ip route show | grep default | awk '{print $5}')
    [[ -z "$pub_interface" ]] && pub_interface="eth0"

    echo -e "\n${C_BCYAN}======================================================================${C_RESET}"
    echo -e "${C_BYELLOW}            DOCKER PORT REMEDIATION WIZARD${C_RESET}"
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    print_status "info" "We detected exposed Docker container ports accessible from the internet."
    print_status "info" "Public Network Interface: $pub_interface"
    echo -e "\nHow would you like to secure your server?"
    echo -e "  [1] ${C_BGREEN}Block ALL external connections to ALL Docker containers (Highly Recommended)${C_RESET}"
    echo -e "      -> Completely safe for host reverse-proxies (like Nginx) and internal containers."
    echo -e "      -> Locks down all databases, MinIO, APIs, mail containers instantly."
    echo -e "  [2] ${C_BYELLOW}Block external connections only to Postgres Database (Port 5432/5433)${C_RESET}"
    echo -e "  [3] Block a custom port of your choice from the internet"
    echo -e "  [0] Skip hardening (Keep ports exposed to internet)"
    echo -e "${C_BCYAN}======================================================================${C_RESET}"
    echo -n "Select action [1-3, or 0 to skip]: "
    read -r wizard_choice

    case "$wizard_choice" in
        1)
            print_status "info" "Injecting global block rule into iptables DOCKER-USER chain..."
            if iptables -I DOCKER-USER -i "$pub_interface" -j DROP 2>/dev/null; then
                log_message "ACTION" "Blocked all external access to Docker containers on interface $pub_interface"
                print_status "success" "Rule successfully injected! All Docker ports are now protected from the internet."
                
                # Handle persistence
                echo -e ""
                print_status "info" "Do you want to save this rule permanently so it survives reboots? [Y/n]: "
                read -r save_confirm
                if [[ "$save_confirm" != "n" && "$save_confirm" != "N" ]]; then
                    if command -v netfilter-persistent &>/dev/null; then
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully using netfilter-persistent."
                    else
                        print_status "warn" "netfilter-persistent is not installed. Installing iptables-persistent..."
                        apt-get update -y && apt-get install -y iptables-persistent
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully!"
                    fi
                fi
            else
                print_status "danger" "Failed to inject iptables rule. Ensure you have root privileges."
            fi
            ;;
        2)
            print_status "info" "Injecting Postgres block rule into iptables DOCKER-USER chain..."
            if iptables -I DOCKER-USER -i "$pub_interface" -p tcp --dport 5432 -j DROP 2>/dev/null; then
                log_message "ACTION" "Blocked external access to Postgres container on interface $pub_interface"
                print_status "success" "Rule successfully injected! Port 5432/5433 are now protected."
                
                echo -e ""
                print_status "info" "Do you want to save this rule permanently so it survives reboots? [Y/n]: "
                read -r save_confirm
                if [[ "$save_confirm" != "n" && "$save_confirm" != "N" ]]; then
                    if command -v netfilter-persistent &>/dev/null; then
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully."
                    else
                        print_status "warn" "netfilter-persistent is not installed. Installing..."
                        apt-get update -y && apt-get install -y iptables-persistent
                        netfilter-persistent save 2>/dev/null
                        print_status "success" "Rules saved successfully!"
                    fi
                fi
            else
                print_status "danger" "Failed to inject rule."
            fi
            ;;
        3)
            echo -n "Enter the port number to block from external access: "
            read -r custom_port
            if [[ "$custom_port" =~ ^[0-9]+$ ]]; then
                print_status "info" "Injecting block rule for port $custom_port..."
                if iptables -I DOCKER-USER -i "$pub_interface" -p tcp --dport "$custom_port" -j DROP 2>/dev/null; then
                    log_message "ACTION" "Blocked external access to Docker port $custom_port on interface $pub_interface"
                    print_status "success" "Port $custom_port successfully blocked from the internet!"
                    
                    echo -e ""
                    print_status "info" "Save rule permanently? [Y/n]: "
                    read -r save_confirm
                    if [[ "$save_confirm" != "n" && "$save_confirm" != "N" ]]; then
                        if command -v netfilter-persistent &>/dev/null; then
                            netfilter-persistent save 2>/dev/null
                        else
                            apt-get update -y && apt-get install -y iptables-persistent
                            netfilter-persistent save 2>/dev/null
                        fi
                        print_status "success" "Rules saved successfully!"
                    fi
                else
                    print_status "danger" "Failed to block port."
                fi
            else
                print_status "danger" "Invalid port number."
            fi
            ;;
        0|*)
            print_status "info" "Remediation skipped. Ports remain publicly exposed."
            ;;
    esac
}

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
            while read -r proto state recv_q send_q local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$local_addr" ]] && continue
                
                local port
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                local bind_ip
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")

                local pid="-" pname="-"
                if [[ "$process" == *"pid="* ]]; then
                    pid=$(echo "$process" | grep -o -E 'pid=[0-9]+' | cut -d'=' -f2)
                    pname=$(echo "$process" | grep -o -E '"[^"]+"' | head -n 1 | tr -d '"')
                fi

                local is_public=0
                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    is_public=1
                fi

                if [[ "$is_public" -eq 1 ]]; then
                    if [[ "$port" =~ ^(22|3306|5432|5433|6379|27017|9200|8080)$ ]]; then
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
            netstat -tulnp 2>/dev/null | grep LISTEN | while read -r proto recv_q send_q local_addr remote_addr state process; do
                [[ -z "$local_addr" ]] && continue
                local port bind_ip pid pname
                port=$(echo "$local_addr" | awk -F':' '{print $NF}')
                bind_ip=$(echo "$local_addr" | sed "s/:${port}$//")
                
                pid=$(echo "$process" | cut -d'/' -f1)
                pname=$(echo "$process" | cut -d'/' -f2-)

                if [[ "$bind_ip" == "0.0.0.0" || "$bind_ip" == "*" || "$bind_ip" == "[::]" ]]; then
                    if [[ "$port" =~ ^(22|3306|5432|5433|6379|27017|9200|8080)$ ]]; then
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
                
                # Giám sát tài nguyên Container
                echo -e "\n${C_BWHITE}--- Docker Container Resource Usage Dashboard ---${C_RESET}"
                local stats
                stats=$(docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" 2>/dev/null)
                if [[ -n "$stats" ]]; then
                    echo -e "$stats"
                else
                    print_status "warn" "Unable to collect live Docker container stats."
                fi
                
                # Quét lỗ hổng Docker Socket Mount
                echo -e "\n${C_BWHITE}--- Docker Socket Mount Vulnerability Audit ---${C_RESET}"
                local socket_mounts=0
                while read -r cid name; do
                    if [[ -z "$cid" ]]; then continue; fi
                    local inspect_mounts
                    inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' "$cid" 2>/dev/null)
                    if echo "$inspect_mounts" | grep -q "docker.sock"; then
                        socket_mounts=$((socket_mounts + 1))
                        log_message "WARNING" "Vulnerability: Container '$name' ($cid) mounts host docker.sock!"
                        print_status "danger" "DOCKER SOCKET ESCAPE VECTOR: Container '$name' mounts '/var/run/docker.sock'!"
                        print_status "bullet" "CRITICAL RATIONALE: Gives full root-level control over the physical host!"
                        send_lark_notification "Docker Socket Mount Escape Vulnerability" "Container '$name' ($cid) mounts '/var/run/docker.sock'. This allows full host takeover!"
                    fi
                done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
                if [[ "$socket_mounts" -eq 0 ]]; then
                    print_status "success" "All running containers are protected against host Docker Socket Mount escape vectors."
                fi
                
                # Public Port Binding & UFW Bypass Check
                echo -e "\n${C_BWHITE}--- Public Port Binding & UFW Bypass Check ---${C_RESET}"
                local dangerous_bindings=0
                while read -r name ports; do
                    if [[ -z "$name" ]]; then continue; fi
                    if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                        local bound_port
                        bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                        dangerous_bindings=$((dangerous_bindings + 1))
                        
                        log_message "WARNING" "Dangerous Docker binding exposed publicly: Container $name on port $bound_port"
                        print_status "danger" "DOCKER BYPASS VULNERABILITY: Container '$name' exposes port $bound_port to 0.0.0.0!"
                        print_status "bullet" "CRITICAL RATIONALE: Docker automatically writes raw iptables rules."
                        print_status "bullet" "Even if UFW status is ACTIVE, Docker's rules bypass UFW completely!"
                        send_lark_notification "Dangerous Exposed Port Bindings" "Container '$name' exposes port $bound_port to 0.0.0.0. This bypasses active UFW configs!"
                    fi
                done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
                
                if [[ "$dangerous_bindings" -eq 0 ]]; then
                    print_status "success" "All running Docker container ports are bound securely or do not expose sensitive DB services publicly."
                    echo -e ""
                    print_status "info" "Would you like to open the Docker Port Hardening Wizard to review or block other ports?"
                    echo -n "Launch Hardening Wizard? [y/N]: "
                    read -r launch_choice
                    if [[ "$launch_choice" == "y" || "$launch_choice" == "Y" ]]; then
                        remediate_docker_ports
                    fi
                else
                    print_status "danger" "CRITICAL: Publicly exposed database ports detected on running containers!"
                    print_status "warn" "Recommendation: Sửa file docker-compose.yml (e.g. bind to 127.0.0.1)."
                    
                    echo -e ""
                    print_status "warn" "Do you want to run the Docker Port Hardening Wizard now to block these ports immediately?"
                    echo -n "Block exposed ports now? [Y/n]: "
                    read -r launch_choice
                    if [[ "$launch_choice" != "n" && "$launch_choice" != "N" ]]; then
                        remediate_docker_ports
                    fi
                fi
            else
                print_status "info" "Docker daemon is active but no containers are currently running."
                echo -e ""
                print_status "info" "Would you like to run the Docker Port Hardening Wizard to block all incoming public Docker traffic anyway?"
                echo -n "Launch Hardening Wizard? [y/N]: "
                read -r launch_choice
                if [[ "$launch_choice" == "y" || "$launch_choice" == "Y" ]]; then
                    remediate_docker_ports
                fi
            fi
        else
            print_status "info" "Docker service is installed but not running."
        fi
    else
        print_status "info" "Docker is not installed on this host system."
    fi
}


# ======================================================================
# MODULE: src/modules/filesystem/writable_paths.sh
# ======================================================================
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
# MODULE: src/modules/filesystem/integrity.sh
# ======================================================================
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
# MODULE: src/modules/persistence/entries.sh
# ======================================================================
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
# MODULE: src/modules/identity/users.sh
# ======================================================================
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
# MODULE: src/modules/identity/ssh_keys.sh
# ======================================================================
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
# MODULE: src/modules/updater/git_wget.sh
# ======================================================================
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
# MODULE: src/main.sh
# ======================================================================
# ======================================================================
# CORE MAIN ENTRYPOINT & ORCHESTRATOR
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
    send_lark_notification "Full System Scan Completed" "Unified security assessment has successfully completed. Detailed audit logs are written to $LOG_FILE."
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

# Save configuration variables persistently (Survivable across Git updates)
save_config() {
    if [[ ! -d "/etc/sec-toolkit" ]]; then
        mkdir -p "/etc/sec-toolkit" 2>/dev/null
    fi
    cat <<EOF > "/etc/sec-toolkit/config.env"
ENABLE_LARK="${ENABLE_LARK:-false}"
LARK_WEBHOOK_URL="${LARK_WEBHOOK_URL:-}"
ENABLE_CRON="${ENABLE_CRON:-false}"
CRON_HOURS="${CRON_HOURS:-11,17,22}"
EOF
    chmod 600 "/etc/sec-toolkit/config.env" 2>/dev/null
}

# Automated Cron Alert scan (Silent, non-interactive execution)
run_cron_scan() {
    # Initialize configuration from persistent OS directory
    [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
    
    if [[ "${ENABLE_LARK:-}" != "true" || -z "${LARK_WEBHOOK_URL:-}" ]]; then
        log_message "INFO" "Cron scan executed, but Lark notifications are disabled or not configured."
        return
    fi
    
    local audit_text=""
    
    # 1. System Performance Info
    local load_avg cpu_cores load_1m
    load_avg=$(cat /proc/loadavg | awk '{print $1" "$2" "$3}')
    cpu_cores=$(nproc)
    load_1m=$(cat /proc/loadavg | awk '{print $1}' | cut -d. -f1)
    
    audit_text+="**🖥️ System Performance & Health Status:**\n"
    audit_text+="* Load Average: \`$load_avg\` (CPU Cores: $cpu_cores)\n"
    
    local mem_total mem_used mem_pct
    mem_total=$(free -m | awk '/^Mem:/{print $2}')
    mem_used=$(free -m | awk '/^Mem:/{print $3}')
    mem_pct=$(( mem_used * 100 / mem_total ))
    audit_text+="* RAM Resource Usage: \`${mem_used}MB / ${mem_total}MB (${mem_pct}%)\`\n"
    
    local disk_usage
    disk_usage=$(df -h / | tail -n 1 | awk '{print $5}')
    audit_text+="* Host Storage Partition Usage: \`$disk_usage\`\n\n"
    
    # 2. Suspicious High CPU Processes
    local susp_proc=""
    while read -r pid user cpu comm; do
        [[ -z "$pid" || "$pid" == "PID" ]] && continue
        local exe_path=""
        [[ -L "/proc/$pid/exe" ]] && exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
        susp_proc+="  * PID \`$pid\` ($user): \`$comm\` ($cpu% CPU) -> \`${exe_path:-deleted/unknown}\`\n"
    done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu | head -n 6 | tail -n 5)
    
    if [[ -n "$susp_proc" ]]; then
        audit_text+="**🛑 Suspicious/High-CPU Running Processes:**\n$susp_proc\n"
    fi
    
    # 3. Docker Socket Mount & Exposed Ports
    local socket_mounts=""
    local dangerous_ports=""
    if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
        # Check docker socket mount
        while read -r cid name; do
            if [[ -z "$cid" ]]; then continue; fi
            local inspect_mounts
            inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}} -> {{.Destination}} {{end}}' "$cid" 2>/dev/null)
            if echo "$inspect_mounts" | grep -q "docker.sock"; then
                socket_mounts+="  * Container \`$name\` ($cid) mounts host \`docker.sock\`! (CRITICAL ESCAPE RISK)\n"
            fi
        done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
        
        # Check exposed database ports
        while read -r name ports; do
            if [[ -z "$name" ]]; then continue; fi
            if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                local bound_port
                bound_port=$(echo "$ports" | grep -o -E "0.0.0.0:[0-9]+" | cut -d':' -f2)
                dangerous_ports+="  * Container \`$name\` exposes port \`$bound_port\` to 0.0.0.0! (UFW BYPASS)\n"
            fi
        done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
    fi
    
    if [[ -n "$socket_mounts" ]]; then
        audit_text+="**🐳 Critical Docker Vulnerabilities (Leo Thang Quyền Host):**\n$socket_mounts\n"
    fi
    if [[ -n "$dangerous_ports" ]]; then
        audit_text+="**🌐 Docker Exposed Ports (UFW Bypass Vulnerabilities):**\n$dangerous_ports\n"
    fi
    
    # 4. Outbound Stratum Mining Pool Connections
    local stratum_conns=""
    local port_regex
    port_regex=$(echo "${MINING_PORTS[@]}" | tr ' ' '|')
    if command -v ss &>/dev/null; then
        while read -r proto state recv_q send_q local_addr remote_addr process; do
            [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
            local rport
            rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
            if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                stratum_conns+="  * Connection out to stratum miner pool: \`$remote_addr\`\n"
            fi
        done < <(ss -tupn state established 2>/dev/null)
    fi
    
    if [[ -n "$stratum_conns" ]]; then
        audit_text+="**⛏️ Outbound Mining Pool Connections:**\n$stratum_conns\n"
    fi
    
    # Determine alert level and title template
    local alert_level="success"
    local alert_title="Daily Server Health: ALL SYSTEMS NORMAL"
    
    if [[ -n "$socket_mounts" || -n "$dangerous_ports" || -n "$stratum_conns" ]]; then
        alert_level="danger"
        alert_title="VPS SECURITY ALERT: Critical Threats Detected!"
    elif [[ -n "$susp_proc" ]]; then
        alert_level="warn"
        alert_title="VPS SECURITY REPORT: Suspicious Warnings Identified"
    fi
    
    # Send Lark Interactive Card
    send_lark_notification "$alert_title" "$audit_text" "$alert_level"
}

# Unified Notification & Automated Cron Audits settings manager
configure_notifications() {
    while true; do
        # Reload configuration
        [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
        
        clear_screen
        print_header
        echo -e "${C_BMAGENTA}            >>> NOTIFICATION & ALERTS MANAGER <<<${C_RESET}\n"
        
        # Lark Alerts config status
        if [[ "${ENABLE_LARK:-}" == "true" ]]; then
            echo -e "Lark Notifications : ${C_BGREEN}[ENABLED]${C_RESET}"
        else
            echo -e "Lark Notifications : ${C_BRED}[DISABLED]${C_RESET}"
        fi
        
        if [[ -n "${LARK_WEBHOOK_URL:-}" ]]; then
            echo -e "Lark Webhook URL   : ${C_CYAN}${LARK_WEBHOOK_URL:0:60}...${C_RESET}"
        else
            echo -e "Lark Webhook URL   : ${C_GRAY}[NOT CONFIGURED]${C_RESET}"
        fi
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # Cron Audits config status
        if [[ "${ENABLE_CRON:-}" == "true" ]]; then
            echo -e "Automated Audits   : ${C_BGREEN}[ENABLED]${C_RESET}"
            echo -e "Audit Hours (Cron) : ${C_CYAN}${CRON_HOURS:-11,17,22} daily${C_RESET}"
        else
            echo -e "Automated Audits   : ${C_BRED}[DISABLED]${C_RESET}"
        fi
        
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -e "Settings Menu:"
        echo -e "  [1] Toggle & Configure Lark Webhook Alerts"
        echo -e "  [2] Toggle & Configure Automated Cron Audits"
        echo -e "  [3] Send Test Notification to Lark"
        echo -e "  [0] Back to Main Menu"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -n "Select action [0-3]: "
        read -r alert_choice
        
        case "$alert_choice" in
            1)
                echo -e "\nToggle Lark Notifications? (current: ${ENABLE_LARK:-false})"
                echo -e "  [1] Enable Lark Notifications"
                echo -e "  [2] Disable Lark Notifications"
                echo -n "Choice: "
                read -r lark_toggle
                if [[ "$lark_toggle" == "1" ]]; then
                    ENABLE_LARK="true"
                    echo -e "\nEnter Lark Webhook URL (press Enter to keep current):"
                    read -r temp_webhook
                    if [[ -n "$temp_webhook" ]]; then
                        LARK_WEBHOOK_URL="$temp_webhook"
                    fi
                elif [[ "$lark_toggle" == "2" ]]; then
                    ENABLE_LARK="false"
                fi
                save_config
                print_status "success" "Lark Notification settings updated."
                sleep 1.5
                ;;
            2)
                echo -e "\nToggle Automated Cron Audits? (current: ${ENABLE_CRON:-false})"
                echo -e "  [1] Enable Cron Audits"
                echo -e "  [2] Disable Cron Audits"
                echo -n "Choice: "
                read -r cron_toggle
                if [[ "$cron_toggle" == "1" ]]; then
                    ENABLE_CRON="true"
                    echo -e "\nConfigure Audit Hours:"
                    echo -e "  [1] Default Hours (11:00 AM, 5:00 PM, 10:00 PM)"
                    echo -e "  [2] Custom Hours (Comma-separated, e.g. 9,15,21)"
                    echo -n "Choice: "
                    read -r hour_choice
                    if [[ "$hour_choice" == "1" ]]; then
                        CRON_HOURS="11,17,22"
                    elif [[ "$hour_choice" == "2" ]]; then
                        echo -n "Enter custom hours (0-23, comma-separated): "
                        read -r temp_hours
                        if [[ "$temp_hours" =~ ^[0-9,]+$ ]]; then
                            CRON_HOURS="$temp_hours"
                        else
                            print_status "danger" "Invalid hours format. Using default: 11,17,22"
                            CRON_HOURS="11,17,22"
                        fi
                    fi
                    
                    local script_path
                    script_path=$(realpath "$0" 2>/dev/null)
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/sec.sh"
                    
                    # Register/update cron rules
                    (crontab -l 2>/dev/null | grep -v "sec.sh") | crontab -
                    (crontab -l 2>/dev/null; echo "0 $CRON_HOURS * * * bash $script_path --cron >/dev/null 2>&1") | crontab -
                    print_status "success" "Automated Audits cronjob activated successfully for hours: $CRON_HOURS"
                elif [[ "$cron_toggle" == "2" ]]; then
                    ENABLE_CRON="false"
                    local script_path
                    script_path=$(realpath "$0" 2>/dev/null)
                    [[ -z "$script_path" ]] && script_path="/usr/local/bin/sec.sh"
                    
                    (crontab -l 2>/dev/null | grep -v "sec.sh") | crontab -
                    print_status "success" "Automated Audits cronjob deactivated."
                fi
                save_config
                sleep 1.5
                ;;
            3)
                if [[ "${ENABLE_LARK:-}" == "true" && -n "${LARK_WEBHOOK_URL:-}" ]]; then
                    print_status "info" "Sending test interactive card to Lark..."
                    send_lark_notification "Lark Card Test Success" "Lark Alert Webhook is fully verified and connected to $(hostname)!" "success"
                else
                    print_status "danger" "Cannot send test. Lark Notifications are disabled or Webhook URL is missing."
                fi
                press_any_key
                ;;
            0)
                break
                ;;
            *)
                print_status "danger" "Invalid choice."
                sleep 1
                ;;
        esac
    done
}

# --- PRO HACKER LIVE SECURITY DASHBOARD (Real-time htop-like) ---
live_security_dashboard() {
    # Fetch hostname and public IP once before entering the loop to ensure zero delay
    local hostname=$(hostname 2>/dev/null || echo "localhost")
    local server_ip
    server_ip=$(curl -s --max-time 1.5 https://api.ipify.org 2>/dev/null || hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")

    # Enter non-blocking terminal display loop
    clear_screen
    
    # Hide terminal cursor for professional look
    tput civis 2>/dev/null
    
    # Setup exit trap to restore cursor in case of Ctrl+C
    trap 'tput cnorm 2>/dev/null; exit' SIGINT SIGTERM
    
    while true; do
        # Move cursor to top left instead of clear to prevent screen flashing
        printf "\033[H"
        
        # Load latest configurations
        [[ -f "/etc/sec-toolkit/config.env" ]] && source "/etc/sec-toolkit/config.env" 2>/dev/null
        
        # 1. Header Information
        local date_time=$(date "+%Y-%m-%d %H:%M:%S")
        local uptime_val=$(uptime -p 2>/dev/null | sed 's/up //')
        
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -e " 🛡️  ${C_BCYAN}VPS SECURITY LIVE DASHBOARD${C_RESET} | ${C_GRAY}Refreshes every 2s (Press [q] to exit)${C_RESET}"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        
        # System Stats Header
        printf " ${C_BOLD}%-12s:${C_RESET} %-15s | ${C_BOLD}%-10s:${C_RESET} %-15s\n" "Hostname" "$hostname" "Public IP" "$server_ip"
        printf " ${C_BOLD}%-12s:${C_RESET} %-15s | ${C_BOLD}%-10s:${C_RESET} %-15s\n" "System Uptime" "$uptime_val" "Live Time" "$date_time"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # 2. Left Panel: System Resources Metrics
        # CPU
        local cpu_pct=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | awk '{print 100 - $1}' | cut -d. -f1 2>/dev/null)
        [[ -z "$cpu_pct" ]] && cpu_pct=0
        local cpu_bar=""
        local cpu_ticks=$((cpu_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $cpu_ticks ]]; then
                if [[ $i -ge 16 ]]; then
                    cpu_bar+="${C_BRED}|${C_RESET}"
                elif [[ $i -ge 10 ]]; then
                    cpu_bar+="${C_BYELLOW}|${C_RESET}"
                else
                    cpu_bar+="${C_BGREEN}|${C_RESET}"
                fi
            else
                cpu_bar+="${C_GRAY}.${C_RESET}"
            fi
        done
        local cpu_color="$C_BGREEN"
        if [[ "$cpu_pct" -ge 80 ]]; then cpu_color="$C_BRED"; elif [[ "$cpu_pct" -ge 50 ]]; then cpu_color="$C_BYELLOW"; fi
        printf " ${C_BOLD}CPU Usage:${C_RESET}  [%-20s] ${cpu_color}%d%%${C_RESET}\n" "$cpu_bar" "$cpu_pct"
        
        # RAM
        local mem_total=$(free -m | awk '/^Mem:/{print $2}' 2>/dev/null)
        local mem_used=$(free -m | awk '/^Mem:/{print $3}' 2>/dev/null)
        [[ -z "$mem_total" ]] && mem_total=1
        [[ -z "$mem_used" ]] && mem_used=0
        local mem_pct=$(( mem_used * 100 / mem_total ))
        local mem_bar=""
        local mem_ticks=$((mem_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $mem_ticks ]]; then
                if [[ $i -ge 18 ]]; then
                    mem_bar+="${C_BRED}|${C_RESET}"
                elif [[ $i -ge 14 ]]; then
                    mem_bar+="${C_BYELLOW}|${C_RESET}"
                else
                    mem_bar+="${C_BGREEN}|${C_RESET}"
                fi
            else
                mem_bar+="${C_GRAY}.${C_RESET}"
            fi
        done
        local mem_color="$C_BGREEN"
        if [[ "$mem_pct" -ge 90 ]]; then mem_color="$C_BRED"; elif [[ "$mem_pct" -ge 70 ]]; then mem_color="$C_BYELLOW"; fi
        printf " ${C_BOLD}RAM Usage:${C_RESET}  [%-20s] ${mem_color}%d%%${C_RESET} (%sMB/%sMB)\n" "$mem_bar" "$mem_pct" "$mem_used" "$mem_total"
        
        # Load Average
        local load_avg=$(cat /proc/loadavg 2>/dev/null | awk '{print $1" "$2" "$3}')
        printf " ${C_BOLD}Load Avg :${C_RESET}  %-25s\n" "${load_avg:-0.00 0.00 0.00}"
        
        # Storage Disk
        local disk_pct=$(df -h / | tail -n 1 | awk '{print $5}' | cut -d% -f1 2>/dev/null)
        [[ -z "$disk_pct" ]] && disk_pct=0
        local disk_bar=""
        local disk_ticks=$((disk_pct / 5))
        for ((i=0; i<20; i++)); do
            if [[ $i -lt $disk_ticks ]]; then
                if [[ $i -ge 17 ]]; then
                    disk_bar+="${C_BRED}|${C_RESET}"
                elif [[ $i -ge 14 ]]; then
                    disk_bar+="${C_BYELLOW}|${C_RESET}"
                else
                    disk_bar+="${C_BGREEN}|${C_RESET}"
                fi
            else
                disk_bar+="${C_GRAY}.${C_RESET}"
            fi
        done
        local disk_color="$C_BGREEN"
        if [[ "$disk_pct" -ge 85 ]]; then disk_color="$C_BRED"; elif [[ "$disk_pct" -ge 70 ]]; then disk_color="$C_BYELLOW"; fi
        printf " ${C_BOLD}Disk /   :${C_RESET}  [%-20s] ${disk_color}%d%%${C_RESET}\n" "$disk_bar" "$disk_pct"
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        echo -e " 🚨 ${C_BWHITE}SECURITY SHIELD STATUS & ALERTS${C_RESET}"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # UFW Status
        local ufw_live="INACTIVE"
        local ufw_color="$C_BRED"
        if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
            ufw_live="ACTIVE"
            ufw_color="$C_BGREEN"
        fi
        
        # Exposed Database Ports
        local exposed_count=0
        if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
            while read -r name ports; do
                if [[ -z "$name" ]]; then continue; fi
                if echo "$ports" | grep -qE "0.0.0.0:(3306|5432|5433|6379|27017|9200|8080|22)->"; then
                    exposed_count=$((exposed_count + 1))
                fi
            done < <(docker ps --format "{{.Names}} {{.Ports}}" 2>/dev/null)
        fi
        local exposed_status="0 (SECURE)"
        local exposed_color="$C_BGREEN"
        if [[ "$exposed_count" -gt 0 ]]; then
            exposed_status="${exposed_count} EXPOSED!"
            exposed_color="$C_BRED"
        fi
        
        # Docker Socket Mount Vulnerability
        local sock_mount_count=0
        if command -v docker &>/dev/null && [[ $(systemctl is-active docker 2>/dev/null) == "active" ]]; then
            while read -r cid name; do
                if [[ -z "$cid" ]]; then continue; fi
                local inspect_mounts
                inspect_mounts=$(docker inspect -f '{{range .Mounts}}{{.Source}}{{end}}' "$cid" 2>/dev/null)
                if echo "$inspect_mounts" | grep -q "docker.sock"; then
                    sock_mount_count=$((sock_mount_count + 1))
                fi
            done < <(docker ps --format "{{.ID}} {{.Names}}" 2>/dev/null)
        fi
        local sock_status="0 (SECURE)"
        local sock_color="$C_BGREEN"
        if [[ "$sock_mount_count" -gt 0 ]]; then
            sock_status="${sock_mount_count} DETECTED!"
            sock_color="$C_BRED"
        fi
        
        # Outbound stratum connections
        local stratum_count=0
        local port_regex=$(echo "${MINING_PORTS[@]:-3333 4444 5555 7777 8888 9999}" | tr ' ' '|')
        if command -v ss &>/dev/null; then
            while read -r proto state recv_q send_q local_addr remote_addr process; do
                [[ "$proto" == "Netid" || -z "$remote_addr" ]] && continue
                local rport=$(echo "$remote_addr" | awk -F':' '{print $NF}')
                if echo "$rport" | grep -q -E "^(${port_regex})$"; then
                    stratum_count=$((stratum_count + 1))
                fi
            done < <(ss -tupn state established 2>/dev/null)
        fi
        local stratum_status="0 Active"
        local stratum_color="$C_BGREEN"
        if [[ "$stratum_count" -gt 0 ]]; then
            stratum_status="${stratum_count} ACTIVE!"
            stratum_color="$C_BRED"
        fi
        
        # Display side-by-side or listed indicators
        printf "   * Tường lửa UFW    : ${ufw_color}%-10s${C_RESET} | * Lỗ hổng Cổng Docker   : ${exposed_color}%-15s${C_RESET}\n" "$ufw_live" "$exposed_status"
        printf "   * Docker Escapes   : ${sock_color}%-10s${C_RESET} | * Kết nối Pool Đào Coin : ${stratum_color}%-15s${C_RESET}\n" "$sock_status" "$stratum_status"
        
        # Logged-in Users list
        local active_users=$(who 2>/dev/null | awk '{print $1" ("$2")"}' | tr '\n' ',' | sed 's/,$//')
        printf "   * Users Đăng nhập  : ${C_BCYAN}%s${C_RESET}\n" "${active_users:-[None]}"
        
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        echo -e " 🛑 ${C_BWHITE}TOP 5 CPU-CONSUMING / SUSPICIOUS RUNNING PROCESSES${C_RESET}"
        echo -e "${C_GRAY}----------------------------------------------------------------------${C_RESET}"
        
        # Top 5 CPU processes table
        printf "   ${C_BOLD}%-8s %-12s %-6s %-12s %-25s${C_RESET}\n" "PID" "USER" "CPU%" "COMM" "REAL EXEC PATH"
        
        while read -r pid user cpu comm; do
            [[ -z "$pid" || "$pid" == "PID" ]] && continue
            local exe_path=""
            [[ -L "/proc/$pid/exe" ]] && exe_path=$(readlink "/proc/$pid/exe" 2>/dev/null)
            
            local is_sus=0
            if [[ "$exe_path" == *" (deleted)"* ]]; then is_sus=1; fi
            for path in "${SUSPICIOUS_PATHS[@]:-/tmp /var/tmp /dev/shm}"; do
                if [[ "$exe_path" == "$path"* ]]; then is_sus=1; break; fi
            done
            
            local line_color="$C_RESET"
            if [[ "$is_sus" -eq 1 ]]; then
                line_color="$C_BRED"
            elif [[ $(awk -v cpu="$cpu" -v limit="40" 'BEGIN {print (cpu > limit) ? 1 : 0}' 2>/dev/null) -eq 1 ]]; then
                line_color="$C_BYELLOW"
            fi
            
            printf "   ${line_color}%-8s %-12s %-6s %-12s %-25s${C_RESET}\n" "$pid" "${user:0:11}" "$cpu" "$comm" "${exe_path:0:28}"
        done < <(ps -eo pid,user,%cpu,comm --sort=-%cpu 2>/dev/null | head -n 6 | tail -n 5)
        
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        
        # Non-blocking key check for 2 seconds
        read -t 2 -n 1 input_key 2>/dev/null
        if [[ "${input_key,,}" == "q" ]]; then
            break
        fi
    done
    
    # Restore terminal cursor cleanly and reset trap
    tput cnorm 2>/dev/null
    trap - SIGINT SIGTERM
    clear_screen
}

# --- MAIN MENU CHOICE LOOP ---
main_menu() {
    check_root
    
    while true; do
        banner
        print_header
        
        # Display Lark integration status in header
        if [[ "${ENABLE_LARK:-}" == "true" && -n "${LARK_WEBHOOK_URL:-}" ]]; then
            echo -e "${C_GRAY}Lark Alerts: ${C_BGREEN}[ACTIVE]${C_RESET} | ${C_GRAY}Cron Audits: ${C_BGREEN}[ACTIVE]${C_RESET}\n"
        else
            echo -e "${C_GRAY}Lark Alerts: ${C_BRED}[INACTIVE]${C_RESET} | ${C_GRAY}Select [10] to configure notifications${C_RESET}\n"
        fi

        echo -e "${C_BMAGENTA}  -- SYSTEM OVERVIEW & REPORTING --${C_RESET}"
        echo -e "   [1]  Launch Live Security Terminal Dashboard (Real-time htop-like)"
        echo -e "   [2]  Run Full System Security Scan (Unified Live Audit)"
        echo -e "   [3]  Generate Comprehensive Text Audit Report (Save to file)"
        echo -e ""
        echo -e "${C_BRED}  -- ACTIVE THREAT REMEDIATION (SOAR) --${C_RESET}"
        echo -e "   [4]  Deep Process Investigator & Host Container Destroyer"
        echo -e "   [5]  Audit Ports, UFW & Docker Firewall Hardening Wizard"
        echo -e ""
        echo -e "${C_BYELLOW}  -- DEEP AUDITING & FORENSICS --${C_RESET}"
        echo -e "   [6]  Inspect Network Connections & Outbound Stratum Pools"
        echo -e "   [7]  Scan Globally Writable Paths (/tmp, /dev/shm) for Payloads"
        echo -e "   [8]  Audit Persistence Mechanisms (Cron Jobs, Systemd Units)"
        echo -e "   [9]  Verify Library Injections (Rootkits / ld.so.preload)"
        echo -e "   [10] Audit Identity Credentials, Users & SSH Key Leaks"
        echo -e ""
        echo -e "${C_BCYAN}  -- TOOL CONFIGURATION & MAINTENANCE --${C_RESET}"
        echo -e "   [11] Configure Security Notifications & Automated Audits"
        echo -e "   [12] Check & Update Security Toolkit (Git Pull)"
        echo -e "   [0]  Exit Security Toolkit"
        echo -e "${C_CYAN}======================================================================${C_RESET}"
        echo -n "Select option: "
        read -r main_choice
        
        case "$main_choice" in
            1)
                live_security_dashboard
                ;;
            2)
                run_full_scan
                ;;
            3)
                clear_screen
                print_header
                generate_report
                ;;
            4)
                process_investigator
                ;;
            5)
                clear_screen
                print_header
                check_ports_firewall
                press_any_key
                ;;
            6)
                clear_screen
                print_header
                check_network_connections
                press_any_key
                ;;
            7)
                clear_screen
                print_header
                check_globally_writeable
                press_any_key
                ;;
            8)
                clear_screen
                print_header
                check_persistence
                press_any_key
                ;;
            9)
                clear_screen
                print_header
                check_system_integrity
                press_any_key
                ;;
            10)
                clear_screen
                print_header
                audit_system_users
                echo ""
                audit_ssh_keys
                press_any_key
                ;;
            11)
                configure_notifications
                ;;
            12)
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
                print_status "danger" "Invalid choice. Please select 0-12."
                sleep 1
                ;;
        esac
    done
}

# Check for silent cron execution mode
if [[ "${1:-}" == "--cron" || "${1:-}" == "-c" ]]; then
    run_cron_scan
    exit 0
fi

# Start execution
main_menu


