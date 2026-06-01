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
