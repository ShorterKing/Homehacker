#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# Captive Portal Setup Script for Ubuntu/Kali
# ═══════════════════════════════════════════════════════════════════════════════
# Enforces form submission and file download before granting internet access.
# Blocks HTTPS (443) and Private DNS (853) at all times.
# Allows only HTTP (80) and DNS (53) after authentication.
#
# Android Compatibility:
#   - DNS interception is mandatory (dnsmasq or built-in Python DNS)
#   - HTTPS/DoT are REJECT'd (not DROP'd) for fast probe failure
#   - All captive portal probe URLs are handled via catch-all redirect
# ═══════════════════════════════════════════════════════════════════════════════
set -e

# ─── Color codes ──────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ─── Configuration ────────────────────────────────────────────────────────────
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PORTAL_DIR="/var/www/captive_portal"
APACHE_CONF="/etc/apache2/sites-available/captive-portal.conf"
DNS_SERVER_SCRIPT="/usr/local/bin/captive_portal_dns.py"
DNS_SERVER_PID_FILE="/var/run/captive_portal_dns.pid"
SERVER_IP=""
INTERFACE=""
DNS_MODE=""                # "dnsmasq" or "builtin"
BLOCK_INTERNET_AFTER_AUTH=false
IPTABLES_RULES_ADDED=false
RESOLVED_WAS_ACTIVE=false
CUSTOM_PORTAL_FILE=""
CUSTOM_PORTAL_DIR=""
PORTAL_INDEX_FILE="index.html"
PORTAL_IS_PHP=false
UPSTREAM_DNS_1="8.8.8.8"
UPSTREAM_DNS_2="1.1.1.1"

# ─── Helper functions ─────────────────────────────────────────────────────────
print_msg() {
    echo -e "${2}${1}${NC}"
}

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --portal-file <path>   Path to a custom .html or .php file to use as"
    echo "                         the captive portal page instead of the built-in one."
    echo "  -h, --help             Show this help message and exit."
    echo ""
    echo "If --portal-file is not supplied the script generates the default portal page."
}

# ─── Argument parsing ─────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --portal-file)
                if [[ -z "$2" || "$2" == --* ]]; then
                    print_msg "ERROR: --portal-file requires a file path argument." "$RED"
                    usage
                    exit 1
                fi
                CUSTOM_PORTAL_FILE="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                print_msg "ERROR: Unknown option: $1" "$RED"
                usage
                exit 1
                ;;
        esac
    done

    if [[ -n "$CUSTOM_PORTAL_FILE" ]]; then
        if [[ ! -f "$CUSTOM_PORTAL_FILE" ]]; then
            print_msg "ERROR: Portal file not found: $CUSTOM_PORTAL_FILE" "$RED"
            exit 1
        fi
        local ext="${CUSTOM_PORTAL_FILE##*.}"
        if [[ "$ext" != "html" && "$ext" != "php" ]]; then
            print_msg "ERROR: --portal-file must be a .html or .php file (got .$ext)" "$RED"
            exit 1
        fi
        print_msg "Custom portal file: $CUSTOM_PORTAL_FILE" "$GREEN"
    fi
}

# ─── Root check ───────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "This script must be run as root" "$RED"
        exit 1
    fi
}

# ─── Detect server IP and interface ──────────────────────────────────────────
detect_server_ip() {
    print_msg "Detecting server IP address and network interface..." "$YELLOW"
    INTERFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $5; exit}' || echo "")
    local default_ip=$(ip route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || echo "")

    if [ -z "$default_ip" ]; then
        default_ip=$(hostname -I | awk '{print $1}' || echo "")
    fi

    if [ -z "$INTERFACE" ] || [ -z "$default_ip" ]; then
        print_msg "Could not auto-detect network interface or IP." "$RED"
        read -p "Enter network interface (e.g., eth0, wlan0): " INTERFACE
        read -p "Enter server IP address: " default_ip
        if [ -z "$INTERFACE" ] || [ -z "$default_ip" ]; then
            print_msg "Interface and IP are required. Exiting." "$RED"
            exit 1
        fi
    fi

    echo -e "${GREEN}Detected IP: $default_ip, Interface: $INTERFACE${NC}"
    read -p "Enter your server IP address (press Enter to use $default_ip): " input_ip
    SERVER_IP="${input_ip:-$default_ip}"

    if ! echo "$SERVER_IP" | grep -Pq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        print_msg "Invalid IP address: $SERVER_IP. Exiting." "$RED"
        exit 1
    fi

    print_msg "Using IP: $SERVER_IP, Interface: $INTERFACE" "$GREEN"
}

# ─── Detect PHP version ──────────────────────────────────────────────────────
detect_php_version() {
    print_msg "Detecting PHP version..." "$YELLOW"
    PHP_VERSION=$(php -v 2>/dev/null | grep -oP 'PHP \K[0-9]+\.[0-9]+' || echo "")
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION=$(apt list --installed 2>/dev/null | grep -oP 'php[0-9]+\.[0-9]+' | head -n1 | grep -oP '[0-9]+\.[0-9]+')
    fi
    if [ -z "$PHP_VERSION" ]; then
        print_msg "No PHP version detected. Install PHP first (apt install php libapache2-mod-php)." "$RED"
        exit 1
    fi
    print_msg "Detected PHP version: $PHP_VERSION" "$GREEN"
}

# ─── Free port 53 (handle systemd-resolved) ─────────────────────────────────
free_port_53() {
    if ss -lnup | grep -q ':53 '; then
        print_msg "Port 53 is in use. Checking for systemd-resolved..." "$YELLOW"
        if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
            RESOLVED_WAS_ACTIVE=true
            print_msg "Stopping systemd-resolved to free port 53..." "$YELLOW"
            systemctl stop systemd-resolved
            # Point /etc/resolv.conf to upstream DNS so the server itself can resolve
            if [ -L /etc/resolv.conf ]; then
                rm /etc/resolv.conf
            fi
            cat > /etc/resolv.conf <<EOF
nameserver $UPSTREAM_DNS_1
nameserver $UPSTREAM_DNS_2
EOF
            print_msg "systemd-resolved stopped. Using $UPSTREAM_DNS_1 for server DNS." "$GREEN"
        else
            print_msg "WARNING: Port 53 is in use by another service. DNS server may fail to start." "$YELLOW"
            print_msg "Check with: ss -lnup | grep :53" "$YELLOW"
        fi
    fi
}

# ─── Install packages ────────────────────────────────────────────────────────
install_packages() {
    print_msg "Installing required packages..." "$YELLOW"
    apt-get update

    # Core packages
    apt-get install -y apache2 apache2-utils php libapache2-mod-php
    detect_php_version
    a2enmod "php$PHP_VERSION" || {
        print_msg "Failed to enable PHP module php$PHP_VERSION." "$RED"
        exit 1
    }

    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent

    # PDF generation (optional, non-fatal)
    apt-get install -y texlive-base 2>/dev/null || {
        print_msg "texlive-base not installed. Will create placeholder PDF." "$YELLOW"
    }

    # DNS server
    if [ "$DNS_MODE" = "dnsmasq" ]; then
        apt-get install -y dnsmasq
    else
        # Built-in DNS uses Python 3 (usually pre-installed on Ubuntu/Kali)
        apt-get install -y python3 2>/dev/null || true
        if ! command -v python3 &>/dev/null; then
            print_msg "Python 3 is required for the built-in DNS server." "$RED"
            exit 1
        fi
    fi

    # Apache modules
    a2enmod rewrite headers proxy proxy_http

    print_msg "Packages installed successfully" "$GREEN"
}

# ─── Create the built-in Python DNS server ────────────────────────────────────
create_builtin_dns_server() {
    print_msg "Creating built-in DNS server..." "$YELLOW"

    cat > "$DNS_SERVER_SCRIPT" <<'PYEOF'
#!/usr/bin/env python3
"""
Captive Portal DNS Server
Responds to all A queries with the portal server IP.
Lightweight daemon — no external dependencies.
"""
import socket
import struct
import sys
import os
import signal

def build_response(data, portal_ip):
    """Build a DNS response pointing all A queries to the portal IP."""
    if len(data) < 12:
        return None

    # Parse header
    tx_id = data[:2]
    flags = b'\x81\x80'  # Standard response, recursion available, no error
    qdcount = struct.unpack('!H', data[4:6])[0]

    # Find end of question section
    offset = 12
    for _ in range(qdcount):
        while offset < len(data) and data[offset] != 0:
            if (data[offset] & 0xC0) == 0xC0:  # Compression pointer
                offset += 1
                break
            offset += data[offset] + 1
        offset += 1  # null terminator or pointer second byte
        if offset + 4 > len(data):
            return None
        offset += 4  # qtype + qclass

    question_section = data[12:offset]

    # Check query type of the first question
    # qtype is at end_of_name + 0..1
    qtype_offset = offset - 4
    qtype = struct.unpack('!H', data[qtype_offset:qtype_offset + 2])[0]

    ancount = 0
    answer = b''

    if qtype == 1:  # A record query
        ancount = 1
        ip_parts = [int(p) for p in portal_ip.split('.')]
        answer = (
            b'\xc0\x0c'              # Name: pointer to question
            + b'\x00\x01'            # Type: A
            + b'\x00\x01'            # Class: IN
            + b'\x00\x00\x00\x0a'   # TTL: 10 seconds
            + b'\x00\x04'            # RDLENGTH: 4 bytes
            + struct.pack('BBBB', *ip_parts)
        )
    # For AAAA, HTTPS, SRV, etc.: return 0 answers (forces A-record fallback)

    return (
        tx_id
        + flags
        + struct.pack('!H', qdcount)
        + struct.pack('!H', ancount)
        + b'\x00\x00'  # NSCOUNT
        + b'\x00\x00'  # ARCOUNT
        + question_section
        + answer
    )

def main():
    if len(sys.argv) < 2:
        print("Usage: captive_portal_dns.py <portal_ip>", file=sys.stderr)
        sys.exit(1)

    portal_ip = sys.argv[1]

    # Write PID file
    pid_file = '/var/run/captive_portal_dns.pid'
    with open(pid_file, 'w') as f:
        f.write(str(os.getpid()))

    def handle_signal(signum, _frame):
        print(f"\n[DNS] Shutting down (signal {signum})")
        try:
            os.remove(pid_file)
        except OSError:
            pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.bind(('0.0.0.0', 53))
    except PermissionError:
        print("[DNS] ERROR: Cannot bind to port 53. Run as root.", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[DNS] ERROR: Cannot bind — {e}", file=sys.stderr)
        print("[DNS] Is another DNS server running? Check: ss -lnup | grep :53", file=sys.stderr)
        sys.exit(1)

    print(f"[DNS] Captive portal DNS server started on 0.0.0.0:53")
    print(f"[DNS] All A record queries → {portal_ip}")
    sys.stdout.flush()

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            response = build_response(data, portal_ip)
            if response:
                sock.sendto(response, addr)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[DNS] Error from {addr}: {e}", file=sys.stderr)
            sys.stderr.flush()

    sock.close()
    try:
        os.remove(pid_file)
    except OSError:
        pass

if __name__ == '__main__':
    main()
PYEOF

    chmod +x "$DNS_SERVER_SCRIPT"
    print_msg "Built-in DNS server created at $DNS_SERVER_SCRIPT" "$GREEN"
}

# ─── Create captive portal page and supporting files ─────────────────────────
create_portal_page() {
    if [[ -n "$CUSTOM_PORTAL_DIR" ]]; then
        print_msg "Using custom portal directory. Skipping default page creation." "$YELLOW"
        return
    fi
    print_msg "Creating captive portal page..." "$YELLOW"
    mkdir -p "$PORTAL_DIR"

    # ── Custom portal file ────────────────────────────────────────────────
    if [[ -n "$CUSTOM_PORTAL_FILE" ]]; then
        local ext="${CUSTOM_PORTAL_FILE##*.}"
        local dest_name="index.$ext"
        print_msg "Copying custom portal file → $PORTAL_DIR/$dest_name" "$YELLOW"
        cp "$CUSTOM_PORTAL_FILE" "$PORTAL_DIR/$dest_name"
        PORTAL_INDEX_FILE="$dest_name"
        PORTAL_IS_PHP=false
        [[ "$ext" == "php" ]] && PORTAL_IS_PHP=true
        print_msg "Custom portal file installed as $dest_name" "$GREEN"
    else
        # ── Default generated portal ──────────────────────────────────────
        PORTAL_INDEX_FILE="index.html"
        PORTAL_IS_PHP=false

        cat > "$PORTAL_DIR/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to WiFi Portal</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex; justify-content: center; align-items: center; padding: 20px;
        }
        .container {
            background: white; border-radius: 20px; padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px; width: 100%; text-align: center;
        }
        h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 16px; }
        .wifi-icon {
            width: 80px; height: 80px; margin: 0 auto 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%; display: flex; align-items: center; justify-content: center;
        }
        .wifi-icon svg { width: 40px; height: 40px; fill: white; }
        .form-group { margin-bottom: 20px; text-align: left; }
        label { display: block; margin-bottom: 5px; color: #555; font-size: 14px; }
        input {
            width: 100%; padding: 12px; border: 1px solid #ddd;
            border-radius: 8px; font-size: 16px; transition: border-color 0.3s;
        }
        input:focus { outline: none; border-color: #667eea; }
        .terms { margin: 20px 0; font-size: 14px; color: #666; }
        .terms input { width: auto; margin-right: 8px; }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 14px 30px; border-radius: 8px;
            font-size: 16px; font-weight: 600; cursor: pointer; width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover { transform: translateY(-2px); box-shadow: 0 10px 20px rgba(102,126,234,0.4); }
        .btn:active { transform: translateY(0); }
        .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
        .download-link { display: block; margin: 20px 0; color: #667eea; font-size: 16px; text-decoration: none; }
        .download-link:hover { text-decoration: underline; }
        .message { margin-top: 20px; padding: 12px; border-radius: 8px; display: none; }
        .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .error   { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
    </style>
</head>
<body>
    <div class="container">
        <div class="wifi-icon">
            <svg viewBox="0 0 24 24">
                <path d="M1 9L12 2L23 9V20C23 20.5304 22.7893 21.0391 22.4142 21.4142C22.0391 21.7893 21.5304 22 21 22H3C2.46957 22 1.96086 21.7893 1.58579 21.4142C1.21071 21.0391 1 20.5304 1 20V9Z"/>
                <path d="M9 22V12H15V22"/>
            </svg>
        </div>
        <h1>Welcome to Our Network</h1>
        <p class="subtitle">Please enter your details and download the file to connect</p>
        <a href="/file.pdf" class="download-link" id="downloadLink">📥 Download Required File (file.pdf)</a>
        <form id="portalForm" method="POST" action="/connect">
            <div class="form-group">
                <label for="name">Your Name</label>
                <input type="text" id="name" name="name" required placeholder="John Doe">
            </div>
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required placeholder="john@example.com">
            </div>
            <div class="terms">
                <label><input type="checkbox" id="agree" name="agree" required> I agree to the terms and conditions</label>
            </div>
            <button type="submit" class="btn" id="submitBtn" disabled>Connect to Internet</button>
        </form>
        <div id="message" class="message"></div>
    </div>
    <script>
        const downloadLink = document.getElementById('downloadLink');
        const submitBtn    = document.getElementById('submitBtn');
        const messageDiv   = document.getElementById('message');

        downloadLink.addEventListener('click', () => {
            fetch('/track_download.php', {
                method: 'POST',
                body: JSON.stringify({ action: 'track_download' }),
                headers: { 'Content-Type': 'application/json' }
            }).then(r => r.json()).then(data => {
                if (data.status === 'success') {
                    submitBtn.disabled = false;
                    messageDiv.style.display = 'block';
                    messageDiv.className = 'message success';
                    messageDiv.textContent = 'File download tracked. You can now submit the form.';
                }
            }).catch(() => {});
        });

        document.getElementById('portalForm').addEventListener('submit', function(e) {
            e.preventDefault();
            fetch('/connect.php', { method: 'POST', body: new FormData(this) })
                .then(r => { if (!r.ok) throw new Error('err'); return r.json(); })
                .then(data => {
                    messageDiv.style.display = 'block';
                    if (data.status === 'success') {
                        messageDiv.className = 'message success';
                        messageDiv.textContent = data.message;
                        setTimeout(() => { window.location.href = 'http://www.google.com'; }, 2000);
                    } else {
                        messageDiv.className = 'message error';
                        messageDiv.textContent = data.message;
                    }
                })
                .catch(() => {
                    messageDiv.style.display = 'block';
                    messageDiv.className = 'message error';
                    messageDiv.textContent = 'Connection failed. Please try again.';
                });
        });
    </script>
</body>
</html>
EOF
    fi

    # ── track_download.php ────────────────────────────────────────────────
    cat > "$PORTAL_DIR/track_download.php" <<'EOF'
<?php
session_start();
header('Content-Type: application/json');
$client_ip = $_SERVER['REMOTE_ADDR'];
$_SESSION['downloaded_file'] = true;
$_SESSION['client_ip'] = $client_ip;
error_log("Captive Portal: Download tracked for IP: $client_ip");
echo json_encode(['status' => 'success', 'message' => 'Download tracked']);
?>
EOF

    # ── connect.php ───────────────────────────────────────────────────────
    # FIXED: loads $BLOCK_INTERNET_AFTER_AUTH and $UPSTREAM_DNS from config.php
    #        instead of referencing undefined bash variables
    cat > "$PORTAL_DIR/connect.php" <<'EOF'
<?php
session_start();
header('Content-Type: application/json');

// Load configuration (generated by setup script)
require_once(__DIR__ . '/config.php');

$client_ip = $_SERVER['REMOTE_ADDR'];

// Validate IP
if (!filter_var($client_ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid client IP']);
    exit;
}

// Verify session IP
if (!isset($_SESSION['client_ip']) || $_SESSION['client_ip'] !== $client_ip) {
    echo json_encode(['status' => 'error', 'message' => 'Session mismatch. Please download the file first.']);
    exit;
}

// Sanitize inputs (compatible with PHP 8.1+)
$name  = isset($_POST['name'])  ? htmlspecialchars(strip_tags(trim($_POST['name'])), ENT_QUOTES, 'UTF-8') : '';
$email = isset($_POST['email']) ? filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL) : '';
$agree = isset($_POST['agree']);
$downloaded = !empty($_SESSION['downloaded_file']);

if ($name && $email && $agree && $downloaded) {
    if (!$BLOCK_INTERNET_AFTER_AUTH) {
        $ip = escapeshellarg($client_ip);
        $dns = escapeshellarg($UPSTREAM_DNS);

        // Bypass HTTP DNAT → client can browse real websites
        shell_exec("iptables -t nat -I PREROUTING 1 -s $ip -p tcp --dport 80 -j ACCEPT");
        // Allow HTTP forwarding through gateway
        shell_exec("iptables -I FORWARD 1 -s $ip -p tcp --dport 80 -j ACCEPT");

        // Bypass DNS DNAT → send to real upstream DNS server
        shell_exec("iptables -t nat -I PREROUTING 1 -s $ip -p udp --dport 53 -j DNAT --to-destination $dns");
        shell_exec("iptables -t nat -I PREROUTING 1 -s $ip -p tcp --dport 53 -j DNAT --to-destination $dns");
        // Allow DNS forwarding through gateway
        shell_exec("iptables -I FORWARD 1 -s $ip -p udp --dport 53 -j ACCEPT");
        shell_exec("iptables -I FORWARD 1 -s $ip -p tcp --dport 53 -j ACCEPT");

        // Note: HTTPS (443) and DoT (853) remain REJECT'd
    }

    error_log("Captive Portal: GRANTED — IP=$client_ip Name=$name Email=$email");
    echo json_encode(['status' => 'success', 'message' => 'Connected successfully! Redirecting...']);
    session_destroy();
} else {
    $r = [];
    if (!$name)       $r[] = 'name';
    if (!$email)      $r[] = 'email';
    if (!$agree)      $r[] = 'terms';
    if (!$downloaded) $r[] = 'download';
    error_log("Captive Portal: DENIED — IP=$client_ip Missing: " . implode(',', $r));
    echo json_encode(['status' => 'error', 'message' => 'Please complete all fields and download the file first.']);
}
?>
EOF

    # ── Generate PDF ──────────────────────────────────────────────────────
    if command -v pdflatex &>/dev/null; then
        cat > /tmp/captive_temp.tex <<'EOF'
\documentclass{article}
\begin{document}
\title{Welcome to the Network}
\author{}
\date{}
\maketitle
\section{Terms and Conditions}
Please read our terms and conditions before connecting.
\end{document}
EOF
        if pdflatex -output-directory=/tmp /tmp/captive_temp.tex >/dev/null 2>&1; then
            mv /tmp/captive_temp.pdf "$PORTAL_DIR/file.pdf"
        else
            echo "Terms and Conditions — Welcome to the Network" > "$PORTAL_DIR/file.pdf"
        fi
        rm -f /tmp/captive_temp.*
    else
        echo "Terms and Conditions — Welcome to the Network" > "$PORTAL_DIR/file.pdf"
        print_msg "pdflatex not found — created placeholder file.pdf" "$YELLOW"
    fi

    chmod -R 755 "$PORTAL_DIR"
    chown -R www-data:www-data "$PORTAL_DIR"
    print_msg "Portal page created" "$GREEN"
}

# ─── Generate config.php from bash variables ──────────────────────────────────
# FIXED: Original script used bash $BLOCK_INTERNET_AFTER_AUTH inside PHP code,
# where it was always undefined (null/falsy). Now we generate a real PHP file.
create_php_config() {
    print_msg "Generating PHP configuration..." "$YELLOW"

    local php_bool="false"
    [ "$BLOCK_INTERNET_AFTER_AUTH" = true ] && php_bool="true"

    local target_dir="$PORTAL_DIR"
    if [[ -n "$CUSTOM_PORTAL_DIR" ]]; then
        target_dir="$CUSTOM_PORTAL_DIR"
    fi

    cat > "$target_dir/config.php" <<EOF
<?php
// Auto-generated by captive_portal_setup.sh — do not edit manually
\$BLOCK_INTERNET_AFTER_AUTH = $php_bool;
\$UPSTREAM_DNS = '${UPSTREAM_DNS_1}:53';
?>
EOF

    chown www-data:www-data "$target_dir/config.php"
    print_msg "PHP config generated (BLOCK_INTERNET_AFTER_AUTH=$php_bool)" "$GREEN"
}

# ─── Configure Apache ────────────────────────────────────────────────────────
# FIXED: Removed all <Location> + RewriteRule blocks (unreliable in Apache).
# Replaced with a single catch-all RewriteRule at VirtualHost level that
# redirects ANY request (except portal resources) to the portal page.
# This automatically handles EVERY captive portal probe URL:
#   Android: /generate_204, /gen_204
#   Apple:   /hotspot-detect.html, /library/test/success.html
#   Windows: /ncsi.txt, /connecttest.txt
#   Firefox: /success.txt, /canonical.html, /connectivity-check
configure_apache() {
    print_msg "Configuring Apache..." "$YELLOW"

    # Disable default sites
    a2dissite 000-default.conf 2>/dev/null || true
    a2dissite default-ssl.conf 2>/dev/null || true

    local dir_index="DirectoryIndex index.html index.php"
    [[ "$PORTAL_IS_PHP" == true ]] && dir_index="DirectoryIndex index.php index.html"

    local doc_root="$PORTAL_DIR"
    if [[ -n "$CUSTOM_PORTAL_DIR" ]]; then
        doc_root="$CUSTOM_PORTAL_DIR"
    fi

    cat > "$APACHE_CONF" <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot $doc_root
    $dir_index

    ErrorLog  \${APACHE_LOG_DIR}/captive_portal_error.log
    CustomLog \${APACHE_LOG_DIR}/captive_portal_access.log combined

    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"

    <Directory $doc_root>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    RewriteEngine On

    # Pretty URL mappings
    RewriteRule ^/connect\$        /connect.php       [L]
    RewriteRule ^/track_download\$ /track_download.php [L]

    # ─── Catch-all redirect ──────────────────────────────────────────
    # Everything that is NOT a portal resource → 302 to portal page.
    # This handles ALL captive portal probe URLs automatically.
    RewriteCond %{REQUEST_URI} !^/index\.(html|php)\$
    RewriteCond %{REQUEST_URI} !^/connect(\.php)?\$
    RewriteCond %{REQUEST_URI} !^/track_download(\.php)?\$
    RewriteCond %{REQUEST_URI} !^/file\.pdf\$
    RewriteCond %{REQUEST_URI} !^/config\.php\$
    RewriteRule ^(.*)$ http://$SERVER_IP/$PORTAL_INDEX_FILE [R=302,L]
</VirtualHost>
EOF

    a2ensite captive-portal.conf

    # Ensure Apache only listens on port 80
    sed -i 's/^Listen 443/#Listen 443/' /etc/apache2/ports.conf 2>/dev/null || true

    apachectl configtest || {
        print_msg "Apache config test failed! Check /var/log/apache2/error.log" "$RED"
        exit 1
    }

    systemctl restart apache2
    print_msg "Apache configured successfully" "$GREEN"
}

# ─── Configure DNS server ────────────────────────────────────────────────────
configure_dns() {
    free_port_53

    if [ "$DNS_MODE" = "dnsmasq" ]; then
        configure_dnsmasq
    else
        configure_builtin_dns
    fi
}

configure_dnsmasq() {
    print_msg "Configuring dnsmasq..." "$YELLOW"

    [ -f /etc/dnsmasq.conf ] && cp /etc/dnsmasq.conf /etc/dnsmasq.conf.captive_backup
    systemctl stop dnsmasq 2>/dev/null || true

    mkdir -p /etc/dnsmasq.d
    cat > /etc/dnsmasq.d/captive-portal.conf <<EOF
# Captive Portal DNS — all domains → portal IP
domain-needed
bogus-priv
address=/#/$SERVER_IP
server=$UPSTREAM_DNS_1
server=$UPSTREAM_DNS_2
listen-address=0.0.0.0
bind-interfaces
local-ttl=10
log-queries
log-facility=/var/log/dnsmasq.log
EOF

    systemctl restart dnsmasq || {
        print_msg "dnsmasq failed to start. Check: journalctl -u dnsmasq" "$RED"
        exit 1
    }
    print_msg "dnsmasq configured (all domains → $SERVER_IP)" "$GREEN"
}

configure_builtin_dns() {
    print_msg "Starting built-in DNS server..." "$YELLOW"

    create_builtin_dns_server

    # Kill any previous instance
    if [ -f "$DNS_SERVER_PID_FILE" ]; then
        kill "$(cat "$DNS_SERVER_PID_FILE")" 2>/dev/null || true
        rm -f "$DNS_SERVER_PID_FILE"
    fi
    pkill -f "captive_portal_dns.py" 2>/dev/null || true
    sleep 1

    # Start in background
    nohup python3 "$DNS_SERVER_SCRIPT" "$SERVER_IP" > /var/log/captive_portal_dns.log 2>&1 &
    local dns_pid=$!

    sleep 1
    if ! kill -0 "$dns_pid" 2>/dev/null; then
        print_msg "Built-in DNS server failed to start!" "$RED"
        cat /var/log/captive_portal_dns.log
        exit 1
    fi

    print_msg "Built-in DNS server running (PID: $dns_pid, all A queries → $SERVER_IP)" "$GREEN"
}

# ─── Configure iptables ──────────────────────────────────────────────────────
# FIXED (compared to original):
#   1. DNS DNAT — all port 53 redirected to local DNS (mandatory for Android)
#   2. HTTPS 443 — REJECT tcp-reset instead of DROP (Android probe fails <5ms)
#   3. DoT 853 — REJECT tcp-reset (Android 9+ falls back to port 53)
#   4. MASQUERADE — required for post-auth NAT to the internet
configure_iptables() {
    print_msg "Configuring iptables rules..." "$YELLOW"

    # Enable IP forwarding (immediately + persist across reboots)
    sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || echo 1 > /proc/sys/net/ipv4/ip_forward
    # Persist in sysctl.conf if it exists
    if [ -f /etc/sysctl.conf ]; then
        sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null || true
    elif [ -d /etc/sysctl.d ]; then
        echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-captive-portal.conf 2>/dev/null || true
    fi

    # Backup existing rules
    iptables-save > /tmp/iptables_captive_backup.rules 2>/dev/null || true

    # Flush relevant chains
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F FORWARD
    # NOTE: We do NOT flush INPUT entirely — that would break SSH etc.

    # ═══════════════════════════════════════════════════════════════════════
    # NAT PREROUTING
    # Post-auth per-client rules will be inserted at position 1 by connect.php
    # ═══════════════════════════════════════════════════════════════════════

    # Redirect ALL DNS to local DNS server (MANDATORY for captive portal)
    # Without this, Android resolves connectivitycheck.gstatic.com to Google's
    # real IP, the HTTP probe never reaches us, and the portal never triggers.
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p udp --dport 53 \
        -j DNAT --to-destination "$SERVER_IP":53
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 53 \
        -j DNAT --to-destination "$SERVER_IP":53

    # Redirect ALL HTTP to portal web server
    iptables -t nat -A PREROUTING -i "$INTERFACE" -p tcp --dport 80 \
        -j DNAT --to-destination "$SERVER_IP":80

    # ═══════════════════════════════════════════════════════════════════════
    # NAT POSTROUTING — masquerade for post-auth internet access
    # ═══════════════════════════════════════════════════════════════════════
    iptables -t nat -A POSTROUTING -o "$INTERFACE" -j MASQUERADE

    # ═══════════════════════════════════════════════════════════════════════
    # FORWARD chain
    # ═══════════════════════════════════════════════════════════════════════

    # Allow established/related (return traffic for forwarded connections)
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow HTTP to portal server
    iptables -A FORWARD -d "$SERVER_IP" -p tcp --dport 80 -j ACCEPT

    # Allow DNS forwarding (needed after auth: client → 8.8.8.8 via gateway)
    iptables -A FORWARD -p udp --dport 53 -j ACCEPT
    iptables -A FORWARD -p tcp --dport 53 -j ACCEPT

    # REJECT HTTPS — tcp-reset causes instant failure (<5ms)
    # Original used DROP which causes 10-30s timeout on Android.
    # Android's NetworkMonitor runs HTTP+HTTPS probes in parallel.
    # DROP → HTTPS hangs → Android shows "No internet"
    # REJECT → HTTPS fails instantly → Android processes HTTP 302 → portal popup ✓
    iptables -A FORWARD -p tcp --dport 443 -j REJECT --reject-with tcp-reset

    # REJECT Private DNS / DNS-over-TLS (port 853)
    # Android 9+ tries DoT before standard DNS.
    # DROP → DNS resolution stalls → no probes run → "No internet"
    # REJECT → instant fallback to port 53 → DNS works → probes run ✓
    iptables -A FORWARD -p tcp --dport 853 -j REJECT --reject-with tcp-reset

    # Drop everything else
    iptables -A FORWARD -i "$INTERFACE" -j DROP

    # ═══════════════════════════════════════════════════════════════════════
    # INPUT chain (minimal additions — don't break SSH, etc.)
    # ═══════════════════════════════════════════════════════════════════════
    iptables -A INPUT -p tcp --dport 443 -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p tcp --dport 853 -j REJECT --reject-with tcp-reset

    # Save rules
    netfilter-persistent save 2>/dev/null || {
        print_msg "WARNING: Could not persist iptables rules." "$YELLOW"
    }

    IPTABLES_RULES_ADDED=true
    print_msg "iptables rules configured" "$GREEN"

    echo ""
    print_msg "  iptables summary:" "$CYAN"
    print_msg "  ├─ DNS (53)    → DNAT to $SERVER_IP (local DNS)" "$CYAN"
    print_msg "  ├─ HTTP (80)   → DNAT to $SERVER_IP (portal page)" "$CYAN"
    print_msg "  ├─ HTTPS (443) → REJECT tcp-reset (instant fail)" "$CYAN"
    print_msg "  ├─ DoT (853)   → REJECT tcp-reset (instant fail)" "$CYAN"
    print_msg "  ├─ NAT         → MASQUERADE (post-auth internet)" "$CYAN"
    print_msg "  └─ Default     → DROP" "$CYAN"
    echo ""
}

# ─── Cleanup ──────────────────────────────────────────────────────────────────
cleanup() {
    echo ""
    print_msg "Cleaning up..." "$YELLOW"

    # Stop built-in DNS server
    if [ -f "$DNS_SERVER_PID_FILE" ]; then
        kill "$(cat "$DNS_SERVER_PID_FILE")" 2>/dev/null || true
        rm -f "$DNS_SERVER_PID_FILE"
    fi
    pkill -f "captive_portal_dns.py" 2>/dev/null || true
    rm -f "$DNS_SERVER_SCRIPT"

    # Restore dnsmasq
    if [ "$DNS_MODE" = "dnsmasq" ]; then
        rm -f /etc/dnsmasq.d/captive-portal.conf
        if [ -f /etc/dnsmasq.conf.captive_backup ]; then
            mv /etc/dnsmasq.conf.captive_backup /etc/dnsmasq.conf
        fi
        systemctl restart dnsmasq 2>/dev/null || true
    fi

    # Restore Apache
    if [ -f "$APACHE_CONF" ]; then
        a2dissite captive-portal.conf 2>/dev/null || true
        rm -f "$APACHE_CONF"
    fi
    a2ensite 000-default.conf 2>/dev/null || true
    sed -i 's/^#Listen 443/Listen 443/' /etc/apache2/ports.conf 2>/dev/null || true
    systemctl restart apache2 2>/dev/null || true

    # Remove portal files (but don't delete custom folders)
    if [[ -z "$CUSTOM_PORTAL_DIR" ]]; then
        rm -rf "$PORTAL_DIR"
    else
        rm -f "$CUSTOM_PORTAL_DIR/config.php" 2>/dev/null || true
    fi

    # Restore iptables
    if [ "$IPTABLES_RULES_ADDED" = true ]; then
        if [ -f /tmp/iptables_captive_backup.rules ]; then
            iptables-restore < /tmp/iptables_captive_backup.rules 2>/dev/null || {
                iptables -t nat -F
                iptables -t mangle -F
                iptables -F FORWARD
            }
            rm -f /tmp/iptables_captive_backup.rules
        else
            iptables -t nat -F
            iptables -t mangle -F
            iptables -F FORWARD
        fi
        netfilter-persistent save 2>/dev/null || true
    fi

    # Remove sysctl.d override if we created one
    rm -f /etc/sysctl.d/99-captive-portal.conf 2>/dev/null || true

    # Restore systemd-resolved
    if [ "$RESOLVED_WAS_ACTIVE" = true ]; then
        systemctl start systemd-resolved 2>/dev/null || true
        if [ ! -L /etc/resolv.conf ]; then
            ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || true
        fi
        print_msg "systemd-resolved restored" "$GREEN"
    fi

    print_msg "Cleanup completed" "$GREEN"
    exit 0
}

# ─── Show status ──────────────────────────────────────────────────────────────
show_status() {
    echo ""
    print_msg "══════════════════════════════════════════════════════" "$GREEN"
    print_msg "   Captive Portal is RUNNING (Android-Compatible)" "$GREEN"
    print_msg "══════════════════════════════════════════════════════" "$GREEN"
    echo ""
    print_msg "Server IP:    $SERVER_IP" "$YELLOW"
    print_msg "Interface:    $INTERFACE" "$YELLOW"
    print_msg "Portal URL:   http://$SERVER_IP/" "$YELLOW"

    if [[ -n "$CUSTOM_PORTAL_DIR" ]]; then
        print_msg "Portal Dir:   $CUSTOM_PORTAL_DIR (custom folder)" "$YELLOW"
    elif [[ -n "$CUSTOM_PORTAL_FILE" ]]; then
        print_msg "Portal Page:  $CUSTOM_PORTAL_FILE (custom file)" "$YELLOW"
    else
        print_msg "Portal Page:  built-in default" "$YELLOW"
    fi

    if [ "$DNS_MODE" = "dnsmasq" ]; then
        print_msg "DNS Server:   dnsmasq (all domains → $SERVER_IP)" "$YELLOW"
    else
        print_msg "DNS Server:   built-in Python (all A queries → $SERVER_IP)" "$YELLOW"
    fi

    print_msg "HTTPS (443):  REJECT tcp-reset (instant fail)" "$YELLOW"
    print_msg "DoT (853):    REJECT tcp-reset (Android 9+ fallback)" "$YELLOW"

    if [ "$BLOCK_INTERNET_AFTER_AUTH" = true ]; then
        print_msg "After Auth:   Internet remains BLOCKED" "$YELLOW"
    else
        print_msg "After Auth:   HTTP + DNS granted, HTTPS stays blocked" "$YELLOW"
    fi

    echo ""
    print_msg "─── Client Setup ───────────────────────────────────" "$GREEN"
    print_msg "  On client devices, set:" "$NC"
    print_msg "    • Gateway: $SERVER_IP" "$NC"
    print_msg "    • DNS: anything (all DNS is intercepted via iptables)" "$NC"
    echo ""
    print_msg "─── How Android Captive Portal Detection Works ─────" "$GREEN"
    print_msg "  1. Android connects to WiFi" "$NC"
    print_msg "  2. DNS query for connectivitycheck.gstatic.com" "$NC"
    print_msg "     → iptables DNAT redirects to $SERVER_IP" "$NC"
    print_msg "     → DNS server responds with $SERVER_IP" "$NC"
    print_msg "  3. HTTPS probe to $SERVER_IP:443" "$NC"
    print_msg "     → REJECT tcp-reset (fails in <5ms) ✓" "$NC"
    print_msg "  4. HTTP probe to $SERVER_IP:80/generate_204" "$NC"
    print_msg "     → Apache returns 302 redirect to portal ✓" "$NC"
    print_msg "  5. Android shows 'Sign in to network' popup ✓" "$NC"
    echo ""
    print_msg "─── Monitoring ─────────────────────────────────────" "$GREEN"
    print_msg "  Apache:    tail -f /var/log/apache2/captive_portal_access.log" "$NC"
    if [ "$DNS_MODE" = "dnsmasq" ]; then
        print_msg "  DNS:       tail -f /var/log/dnsmasq.log" "$NC"
    else
        print_msg "  DNS:       tail -f /var/log/captive_portal_dns.log" "$NC"
    fi
    print_msg "  iptables:  iptables -t nat -L -n -v" "$NC"
    print_msg "  auth'd:    iptables -t nat -L PREROUTING -n --line-numbers" "$NC"
    echo ""
    print_msg "Press Ctrl+C to stop and cleanup" "$YELLOW"
    echo ""
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    parse_args "$@"

    clear
    print_msg "═══════════════════════════════════════════════" "$GREEN"
    print_msg "  Captive Portal Setup (Android-Compatible)" "$GREEN"
    print_msg "═══════════════════════════════════════════════" "$GREEN"
    echo ""

    check_root
    detect_server_ip

    # ── DNS server choice ─────────────────────────────────────────────────
    echo ""
    print_msg "Choose DNS server:" "$CYAN"
    print_msg "  1) dnsmasq   — system package, well-tested (recommended)" "$NC"
    print_msg "  2) built-in  — lightweight Python DNS, no extra packages" "$NC"
    echo ""
    while true; do
        read -p "Select DNS server [1/2]: " dns_choice
        case "$dns_choice" in
            1) DNS_MODE="dnsmasq"; break ;;
            2) DNS_MODE="builtin"; break ;;
            *) print_msg "Please enter 1 or 2" "$RED" ;;
        esac
    done
    print_msg "DNS mode: $DNS_MODE" "$GREEN"

    # ── Block internet after auth? ────────────────────────────────────────
    echo ""
    read -p "Block internet even after authentication? (y/n): " block_choice
    if [[ "$block_choice" =~ ^[Yy]$ ]]; then
        BLOCK_INTERNET_AFTER_AUTH=true
        print_msg "Internet will remain blocked after authentication" "$YELLOW"
    else
        BLOCK_INTERNET_AFTER_AUTH=false
        print_msg "HTTP + DNS unblocked after auth (HTTPS stays blocked)" "$GREEN"
    fi

    # ── Custom Portal Directory Choice ────────────────────────────────────
    echo ""
    print_msg "Do you want to use the default portal page or a custom portal folder?" "$CYAN"
    print_msg "If you choose a custom folder, Apache will serve it directly." "$NC"
    echo ""
    read -p "Enter path to custom portal folder (or press Enter for default): " custom_folder_input
    
    if [[ -n "$custom_folder_input" ]]; then
        if [[ -d "$custom_folder_input" ]]; then
            # Check for an index file
            if [[ -f "$custom_folder_input/index.php" ]]; then
                PORTAL_INDEX_FILE="index.php"
                PORTAL_IS_PHP=true
                CUSTOM_PORTAL_DIR=$(realpath "$custom_folder_input")
                print_msg "Using custom portal directory: $CUSTOM_PORTAL_DIR (index.php)" "$GREEN"
            elif [[ -f "$custom_folder_input/index.html" ]]; then
                PORTAL_INDEX_FILE="index.html"
                PORTAL_IS_PHP=false
                CUSTOM_PORTAL_DIR=$(realpath "$custom_folder_input")
                print_msg "Using custom portal directory: $CUSTOM_PORTAL_DIR (index.html)" "$GREEN"
            else
                 print_msg "WARNING: No index.html or index.php found in $custom_folder_input" "$YELLOW"
                 print_msg "Falling back to default portal." "$YELLOW"
                 CUSTOM_PORTAL_DIR=""
            fi
        else
            print_msg "ERROR: Directory $custom_folder_input does not exist." "$RED"
            print_msg "Falling back to default portal." "$YELLOW"
            CUSTOM_PORTAL_DIR=""
        fi
    else
        print_msg "Using default captive portal." "$GREEN"
        CUSTOM_PORTAL_DIR=""
    fi

    trap cleanup SIGINT SIGTERM

    echo ""
    install_packages
    echo ""
    create_portal_page
    create_php_config
    echo ""
    configure_apache
    echo ""
    configure_dns
    echo ""
    configure_iptables

    show_status

    while true; do
        sleep 1
    done
}

main "$@"
