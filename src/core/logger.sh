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
