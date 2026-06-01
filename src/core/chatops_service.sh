#!/usr/bin/env bash
# ======================================================================
# CORE COMPONENT: CHATOPS SYSTEMD SERVICE MANAGER
# ======================================================================

# Install and register the systemd service for ChatOps
install_chatops_service() {
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local src_py="${script_dir}/chatops.py"
    local dest_py="/usr/local/bin/sec-chatops.py"
    local service_file="/etc/systemd/system/sec-chatops.service"
    
    if [[ ! -f "$src_py" ]]; then
        print_status "danger" "Source chatops.py not found at $src_py"
        return 1
    fi
    
    print_status "info" "Registering ChatOps service daemon..."
    cp "$src_py" "$dest_py" 2>/dev/null
    chmod +x "$dest_py" 2>/dev/null
    
    cat <<EOF > "$service_file" 2>/dev/null
[Unit]
Description=Linux Server Security Toolkit - Lark ChatOps Webhook Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 $dest_py
Restart=always
RestartSec=5
StandardOutput=syslog
StandardError=syslog
SyslogIdentifier=sec-chatops

[Install]
WantedBy=multi-user.target
EOF
    
    if [[ -f "$service_file" ]]; then
        systemctl daemon-reload 2>/dev/null
        print_status "success" "ChatOps daemon registered successfully as systemd service 'sec-chatops'."
        return 0
    else
        print_status "danger" "Failed to write systemd service file. Ensure you have root privileges."
        return 1
    fi
}

# Control the ChatOps systemd service
manage_chatops_service() {
    local action="$1"
    
    case "$action" in
        "start")
            # Install service first if not registered
            if [[ ! -f "/etc/systemd/system/sec-chatops.service" ]]; then
                install_chatops_service || return 1
            fi
            print_status "info" "Starting sec-chatops background service..."
            systemctl enable sec-chatops &>/dev/null
            systemctl start sec-chatops &>/dev/null
            if systemctl is-active sec-chatops &>/dev/null; then
                print_status "success" "ChatOps daemon is active and listening."
            else
                print_status "danger" "Failed to start sec-chatops. Check syslog for errors."
            fi
            ;;
        "stop")
            print_status "info" "Stopping sec-chatops service..."
            systemctl stop sec-chatops &>/dev/null
            systemctl disable sec-chatops &>/dev/null
            print_status "success" "ChatOps service stopped."
            ;;
        "restart")
            print_status "info" "Restarting sec-chatops service..."
            systemctl restart sec-chatops &>/dev/null
            print_status "success" "ChatOps service restarted."
            ;;
        "status")
            if systemctl is-active sec-chatops &>/dev/null; then
                echo "active"
            else
                echo "inactive"
            fi
            ;;
    esac
}
