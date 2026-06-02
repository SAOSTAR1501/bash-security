#!/usr/bin/env python3
# ======================================================================
# CORE COMPONENT: SECURE CHATOPS WEBHOOK RECEIVER DAEMON
# ======================================================================
import os
import sys
import urllib.parse
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

CONFIG_FILE = "/etc/sec-toolkit/config.env"
DEFAULT_PORT = 8080

def load_config():
    config = {
        "CHATOPS_PORT": str(DEFAULT_PORT),
        "CHATOPS_TOKEN": "",
        "ENABLE_CHATOPS": "false"
    }
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip().strip('"').strip("'")
        except Exception:
            pass
    return config

class ChatOpsHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to log cleanly to syslog instead of stderr
        sys.stdout.write(f"[ChatOps Server] {format % args}\n")
        sys.stdout.flush()

    def send_html_response(self, title, heading, message, status_type="success"):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        # Premium sleek dark mode style
        accent_color = "#10b981" # green
        bg_gradient = "linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)"
        
        if status_type == "danger":
            accent_color = "#ef4444" # red
        elif status_type == "warn":
            accent_color = "#f59e0b" # yellow
        elif status_type == "info":
            accent_color = "#3b82f6" # blue

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Outfit', sans-serif;
            background: {bg_gradient};
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        .card {{
            background: rgba(30, 41, 59, 0.75);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 24px;
            padding: 40px;
            width: 100%;
            max-width: 520px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            animation: fadeIn 0.6s ease-out;
        }}
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(20px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        .status-icon {{
            font-size: 64px;
            margin-bottom: 20px;
            display: inline-block;
            animation: pulse 2s infinite alternate;
        }}
        h1 {{
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 16px;
            color: #ffffff;
            letter-spacing: -0.5px;
        }}
        .badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 9999px;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 24px;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid {accent_color};
            color: {accent_color};
        }}
        .message-box {{
            background: rgba(15, 23, 42, 0.5);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 30px;
            border: 1px solid rgba(255, 255, 255, 0.03);
            text-align: left;
            font-family: monospace;
            font-size: 14px;
            color: #cbd5e1;
            line-height: 1.6;
            word-break: break-all;
            white-space: pre-wrap;
        }}
        .btn {{
            display: inline-block;
            width: 100%;
            padding: 14px 28px;
            background: {accent_color};
            color: #000000;
            font-weight: 600;
            text-decoration: none;
            border-radius: 12px;
            transition: all 0.3s ease;
            font-size: 16px;
            border: none;
            cursor: pointer;
        }}
        .btn:hover {{
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
            filter: brightness(1.1);
        }}
        .footer {{
            margin-top: 30px;
            font-size: 12px;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="status-icon">
            {"🟢" if status_type == "success" else "🔴" if status_type == "danger" else "⚠️" if status_type == "warn" else "ℹ️"}
        </div>
        <h1>{heading}</h1>
        <div class="badge">{status_type}</div>
        <div class="message-box">{message}</div>
        <button class="btn" onclick="window.close();">Close Window</button>
        <div class="footer">Star Security • Active SOAR Gateway</div>
    </div>
</body>
</html>
"""
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        config = load_config()
        
        # Verify ChatOps is enabled globally
        if config.get("ENABLE_CHATOPS") != "true":
            self.send_html_response("Access Denied", "ChatOps Disabled", "Lark ChatOps triggers are currently disabled in settings.", "warn")
            return

        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path
        query = urllib.parse.parse_qs(parsed_url.query)

        # 1. Token-Based Authentication
        req_token = query.get("token", [""])[0]
        stored_token = config.get("CHATOPS_TOKEN", "")
        
        if not stored_token or req_token != stored_token:
            self.send_html_response("Unauthorized", "Access Denied", "Invalid or missing ChatOps authorization token. Action blocked.", "danger")
            return

        # 2. Command Execution routing
        if path == "/kill":
            pid_str = query.get("pid", [""])[0]
            if not pid_str.isdigit():
                self.send_html_response("Error", "Invalid Parameter", "The provided process ID (PID) must be numeric.", "warn")
                return
            
            pid = int(pid_str)
            try:
                # Safely get process details before killing
                comm = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip()
                # Run the hard kill command safely
                subprocess.check_call(["kill", "-9", str(pid)])
                self.send_html_response("Process Terminated", "Process Destroyed Successfully", 
                                        f"🟢 ACTION EXECUTED:\n\nPID     : {pid}\nProcess : {comm}\nResult  : SIGKILL (-9) successfully delivered. Process terminated.", "success")
            except Exception as e:
                self.send_html_response("Action Failed", "Execution Failed", f"🔴 ERROR DETAILS:\n\nFailed to kill PID {pid}.\nReason: {str(e)}", "danger")

        elif path == "/suspend":
            pid_str = query.get("pid", [""])[0]
            if not pid_str.isdigit():
                self.send_html_response("Error", "Invalid Parameter", "The provided process ID (PID) must be numeric.", "warn")
                return
            
            pid = int(pid_str)
            try:
                comm = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip()
                subprocess.check_call(["kill", "-STOP", str(pid)])
                self.send_html_response("Process Frozen", "Process Paused Successfully", 
                                        f"🟢 ACTION EXECUTED:\n\nPID     : {pid}\nProcess : {comm}\nResult  : SIGSTOP delivered. Process frozen, CPU usage dropped to 0%.", "success")
            except Exception as e:
                self.send_html_response("Action Failed", "Execution Failed", f"🔴 ERROR DETAILS:\n\nFailed to pause PID {pid}.\nReason: {str(e)}", "danger")

        elif path == "/resume":
            pid_str = query.get("pid", [""])[0]
            if not pid_str.isdigit():
                self.send_html_response("Error", "Invalid Parameter", "The provided process ID (PID) must be numeric.", "warn")
                return
            
            pid = int(pid_str)
            try:
                comm = subprocess.check_output(["ps", "-p", str(pid), "-o", "comm="], text=True).strip()
                subprocess.check_call(["kill", "-CONT", str(pid)])
                self.send_html_response("Process Resumed", "Process Resumed Successfully", 
                                        f"🟢 ACTION EXECUTED:\n\nPID     : {pid}\nProcess : {comm}\nResult  : SIGCONT delivered. Process resumed operations.", "success")
            except Exception as e:
                self.send_html_response("Action Failed", "Execution Failed", f"🔴 ERROR DETAILS:\n\nFailed to resume PID {pid}.\nReason: {str(e)}", "danger")

        elif path == "/block_port":
            port_str = query.get("port", [""])[0]
            if not port_str.isdigit():
                self.send_html_response("Error", "Invalid Parameter", "The provided port number must be numeric.", "warn")
                return
            
            port = int(port_str)
            try:
                # Find default public interface
                interface = "eth0"
                try:
                    route_out = subprocess.check_output("ip route show | grep default", shell=True, text=True)
                    if "dev" in route_out:
                        interface = route_out.split("dev")[1].split()[0]
                except Exception:
                    pass

                # Block port in DOCKER-USER chain
                subprocess.check_call(["iptables", "-I", "DOCKER-USER", "-i", interface, "-p", "tcp", "--dport", str(port), "-j", "DROP"])
                self.send_html_response("Port Blocked", "Port Secured Successfully", 
                                        f"🟢 ACTION EXECUTED:\n\nPort    : {port}\nInterface: {interface}\nResult  : Block rule injected into iptables DOCKER-USER chain. External public access fully dropped.", "success")
            except Exception as e:
                self.send_html_response("Action Failed", "Execution Failed", f"🔴 ERROR DETAILS:\n\nFailed to block port {port}.\nReason: {str(e)}", "danger")

        else:
            self.send_html_response("Not Found", "Invalid Action Route", "Requested operation route is unsupported by ChatOps engine.", "warn")

def run(port=DEFAULT_PORT):
    # Bind to all interfaces securely
    server_address = ("", port)
    httpd = HTTPServer(server_address, ChatOpsHandler)
    sys.stdout.write(f"[ChatOps Server] Listening securely on port {port}...\n")
    sys.stdout.flush()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        sys.stdout.write("[ChatOps Server] Stopped.\n")
        sys.stdout.flush()

if __name__ == "__main__":
    config = load_config()
    chatops_port = DEFAULT_PORT
    try:
        chatops_port = int(config.get("CHATOPS_PORT", str(DEFAULT_PORT)))
    except ValueError:
        pass
    
    run(chatops_port)
