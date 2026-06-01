# ======================================================================
# CORE COMPONENT: AUDITING LOG SYSTEM & NOTIFICATIONS
# ======================================================================

LOG_FILE="/var/log/sec_toolkit.log"
CONF_FILE="/etc/sec_toolkit.conf"

# Load global configuration
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
    local webhook_url="${LARK_WEBHOOK_URL:-}"
    
    if [[ -n "$webhook_url" ]]; then
        local full_msg="🛡️ [SECURITY ALERT: $(hostname)] - $title\n---------------------------------\n$text"
        
        # Escape backslashes, double quotes, and newlines for JSON safety
        local json_safe_msg
        json_safe_msg=$(echo "$full_msg" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g' | awk '{printf "%s\\n", $0}' | sed 's/\\n$//')
        
        curl -s -X POST -H "Content-Type: application/json" \
            -d "{\"msg_type\":\"text\",\"content\":{\"text\":\"$json_safe_msg\"}}" \
            "$webhook_url" &>/dev/null &
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
