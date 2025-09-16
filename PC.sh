#!/bin/bash
# Captive Portal Setup Script for Ubuntu/Kali
# Enforces form submission and file download before granting internet access
# Blocks HTTPS traffic 100%, allows only HTTP and DNS
set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PORTAL_DIR="/var/www/captive_portal"
APACHE_CONF="/etc/apache2/sites-available/captive-portal.conf"
BACKUP_DIR="/tmp/captive_portal_backup_$(date +%s)"
SERVER_IP=""
USE_DNSMASQ=false
IPTABLES_RULES_ADDED=false
INTERFACE=""
BLOCK_INTERNET_AFTER_AUTH=false

# Function to print colored messages
print_msg() {
    echo -e "${2}${1}${NC}"
}

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_msg "This script must be run as root" "$RED"
        exit 1
    fi
}

# Function to detect server IP and interface
detect_server_ip() {
    print_msg "Detecting server IP address and network interface..." "$YELLOW"
    INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}' || echo "")
    local default_ip=$(ip route get 1.1.1.1 | awk '{print $7; exit}' || echo "")
    if [ -z "$default_ip" ]; then
        default_ip=$(hostname -I | awk '{print $1}' || echo "")
    fi
    if [ -z "$INTERFACE" ] || [ -z "$default_ip" ]; then
        print_msg "Could not detect network interface or IP. Please specify them manually." "$RED"
        read -p "Enter network interface (e.g., eth0, wlan0): " INTERFACE
        read -p "Enter server IP address: " default_ip
        if [ -z "$INTERFACE" ] || [ -z "$default_ip" ]; then
            print_msg "Interface and IP are required. Exiting." "$RED"
            exit 1
        fi
    fi
    echo -e "${GREEN}Detected IP: $default_ip, Interface: $INTERFACE${NC}"
    read -p "Enter your server IP address (press Enter to use $default_ip): " input_ip
    if [ -z "$input_ip" ]; then
        SERVER_IP=$default_ip
    else
        SERVER_IP=$input_ip
    fi
    # Validate SERVER_IP
    if ! echo "$SERVER_IP" | grep -Pq '^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$'; then
        print_msg "Invalid IP address: $SERVER_IP. Exiting." "$RED"
        exit 1
    fi
    print_msg "Using IP: $SERVER_IP, Interface: $INTERFACE" "$GREEN"
}

# Function to detect PHP version
detect_php_version() {
    print_msg "Detecting PHP version..." "$YELLOW"
    PHP_VERSION=$(php -v 2>/dev/null | grep -oP 'PHP \K[0-9]+\.[0-9]+' || echo "")
    if [ -z "$PHP_VERSION" ]; then
        PHP_VERSION=$(apt list --installed 2>/dev/null | grep -oP 'php[0-9]+\.[0-9]+' | head -n 1 | grep -oP '[0-9]+\.[0-9]+')
    fi
    if [ -z "$PHP_VERSION" ]; then
        print_msg "No PHP version detected. Please install PHP (e.g., apt install php libapache2-mod-php)." "$RED"
        exit 1
    fi
    print_msg "Detected PHP version: $PHP_VERSION" "$GREEN"
}

# Function to install required packages
install_packages() {
    print_msg "Installing required packages..." "$YELLOW"
    apt-get update
    apt-get install -y apache2 apache2-utils
    apt-get install -y php libapache2-mod-php
    detect_php_version
    a2enmod php$PHP_VERSION || {
        print_msg "Failed to enable PHP module php$PHP_VERSION. Check PHP installation." "$RED"
        exit 1
    }
    DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
    apt-get install -y texlive-base
    if [ "$USE_DNSMASQ" = true ]; then
        apt-get install -y dnsmasq
    else
        systemctl stop dnsmasq 2>/dev/null || true
        systemctl disable dnsmasq 2>/dev/null || true
    fi
    a2enmod rewrite
    a2enmod headers
    a2enmod proxy
    a2enmod proxy_http
    print_msg "Packages installed successfully" "$GREEN"
}

# Function to create captive portal HTML page and PDF
create_portal_page() {
    print_msg "Creating captive portal page and PDF..." "$YELLOW"
    mkdir -p "$PORTAL_DIR"
    cat > "$PORTAL_DIR/index.html" <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome to WiFi Portal</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 90%;
            text-align: center;
        }
        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 28px;
        }
        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 16px;
        }
        .wifi-icon {
            width: 80px;
            height: 80px;
            margin: 0 auto 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .wifi-icon svg {
            width: 40px;
            height: 40px;
            fill: white;
        }
        .form-group {
            margin-bottom: 20px;
            text-align: left;
        }
        label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-size: 14px;
        }
        input {
            width: 100%;
            padding: 12px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #667eea;
        }
        .terms {
            margin: 20px 0;
            font-size: 14px;
            color: #666;
        }
        .terms input {
            width: auto;
            margin-right: 8px;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 14px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .btn:active {
            transform: translateY(0);
        }
        .download-link {
            display: block;
            margin: 20px 0;
            color: #667eea;
            font-size: 16px;
            text-decoration: none;
        }
        .download-link:hover {
            text-decoration: underline;
        }
        .message {
            margin-top: 20px;
            padding: 12px;
            border-radius: 8px;
            display: none;
        }
        .success {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
        }
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
        <a href="/file.pdf" class="download-link" id="downloadLink">Download Required File (file.pdf)</a>
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
                <label>
                    <input type="checkbox" id="agree" name="agree" required>
                    I agree to the terms and conditions
                </label>
            </div>
            <button type="submit" class="btn" id="submitBtn" disabled>Connect to Internet</button>
        </form>
        <div id="message" class="message"></div>
    </div>
    <script>
        const downloadLink = document.getElementById('downloadLink');
        const submitBtn = document.getElementById('submitBtn');
        const messageDiv = document.getElementById('message');
        downloadLink.addEventListener('click', () => {
            fetch('/track_download.php', {
                method: 'POST',
                body: JSON.stringify({ action: 'track_download' }),
                headers: { 'Content-Type': 'application/json' }
            }).then(response => response.json()).then(data => {
                if (data.status === 'success') {
                    submitBtn.disabled = false;
                    messageDiv.style.display = 'block';
                    messageDiv.className = 'message success';
                    messageDiv.textContent = 'File download tracked. You can now submit the form.';
                }
            });
        });
        document.getElementById('portalForm').addEventListener('submit', function(e) {
            e.preventDefault();
            const formData = new FormData(this);
            fetch('/connect.php', {
                method: 'POST',
                body: formData
            }).then(response => {
                if (!response.ok) throw new Error('Network response was not ok');
                return response.json();
            }).then(data => {
                messageDiv.style.display = 'block';
                if (data.status === 'success') {
                    messageDiv.className = 'message success';
                    messageDiv.textContent = data.message;
                    setTimeout(() => {
                        window.location.href = 'http://www.google.com';
                    }, 2000);
                } else {
                    messageDiv.className = 'message error';
                    messageDiv.textContent = data.message;
                }
            }).catch(error => {
                messageDiv.style.display = 'block';
                messageDiv.className = 'message error';
                messageDiv.textContent = 'Connection failed. Please try again.';
            });
        });
    </script>
</body>
</html>
EOF
    # Create track_download.php
    cat > "$PORTAL_DIR/track_download.php" <<'EOF'
<?php
session_start();
header('Content-Type: application/json');
$client_ip = $_SERVER['REMOTE_ADDR'];
$_SESSION['downloaded_file'] = true;
$_SESSION['client_ip'] = $client_ip; // Store client IP in session
error_log("File download tracked for IP: $client_ip");
echo json_encode(['status' => 'success', 'message' => 'Download tracked']);
?>
EOF
    # Create connect.php
    cat > "$PORTAL_DIR/connect.php" <<'EOF'
<?php
session_start();
header('Content-Type: application/json');
$client_ip = $_SERVER['REMOTE_ADDR'];
// Validate IP address
if (!filter_var($client_ip, FILTER_VALIDATE_IP)) {
    echo json_encode(['status' => 'error', 'message' => 'Invalid client IP']);
    exit;
}
// Verify client IP matches session
if (!isset($_SESSION['client_ip']) || $_SESSION['client_ip'] !== $client_ip) {
    echo json_encode(['status' => 'error', 'message' => 'Session IP mismatch']);
    exit;
}
$name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
$email = filter_input(INPUT_POST, 'email', FILTER_SANITIZE_EMAIL);
$agree = isset($_POST['agree']);
$downloaded = isset($_SESSION['downloaded_file']) && $_SESSION['downloaded_file'];
if ($name && $email && $agree && $downloaded) {
    if (!$BLOCK_INTERNET_AFTER_AUTH) {
        // Allow HTTP traffic for this client
        shell_exec("iptables -t nat -I PREROUTING 1 -s " . escapeshellarg($client_ip) . " -p tcp --dport 80 -j ACCEPT");
        shell_exec("iptables -I FORWARD 1 -s " . escapeshellarg($client_ip) . " -p tcp --dport 80 -j ACCEPT");
        // Allow DNS traffic for this client
        shell_exec("iptables -I FORWARD 1 -s " . escapeshellarg($client_ip) . " -p udp --dport 53 -j ACCEPT");
        shell_exec("iptables -I FORWARD 1 -s " . escapeshellarg($client_ip) . " -p tcp --dport 53 -j ACCEPT");
        // Explicitly block HTTPS for this client
        shell_exec("iptables -I FORWARD 1 -s " . escapeshellarg($client_ip) . " -p tcp --dport 443 -j DROP");
    }
    echo json_encode(['status' => 'success', 'message' => 'Connected successfully']);
    session_destroy();
} else {
    echo json_encode(['status' => 'error', 'message' => 'Form incomplete or file not downloaded']);
    exit;
}
error_log("Connection attempt: IP=$client_ip, Name=$name, Email=$email, Agree=" . ($agree ? 'true' : 'false') . ", Downloaded=" . ($downloaded ? 'true' : 'false'));
?>
EOF
    # Create a sample PDF using pdflatex
    cat > /tmp/temp.tex <<'EOF'
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
    pdflatex -output-directory=/tmp /tmp/temp.tex
    mv /tmp/temp.pdf "$PORTAL_DIR/file.pdf"
    rm /tmp/temp.*
    chmod -R 755 "$PORTAL_DIR"
    chown -R www-data:www-data "$PORTAL_DIR"
    print_msg "Portal page and PDF created" "$GREEN"
}

# Function to configure Apache
configure_apache() {
    print_msg "Configuring Apache..." "$YELLOW"
    if [ -f "/etc/apache2/sites-enabled/000-default.conf" ]; then
        a2dissite 000-default.conf
    fi
    cat > "$APACHE_CONF" <<EOF
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot $PORTAL_DIR
    ErrorLog \${APACHE_LOG_DIR}/captive_portal_error.log
    CustomLog \${APACHE_LOG_DIR}/captive_portal_access.log combined
    Header always set X-Frame-Options "SAMEORIGIN"
    Header always set X-Content-Type-Options "nosniff"
    <Directory $PORTAL_DIR>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    # Specific handling for Android probes
    <Location /generate_204>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    <Location /gen_204>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    # Apple probes
    <Location /hotspot-detect.html>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    # Windows probes
    <Location /ncsi.txt>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    <Location /connecttest.txt>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    # Additional probes
    <Location /connectivity-check>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    <Location /captive.apple.com>
        RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
    </Location>
    RewriteEngine On
    RewriteRule ^/connect$ /connect.php [L]
    RewriteRule ^/track_download$ /track_download.php [L]
    RewriteCond %{REQUEST_URI} !^/index\.html$
    RewriteCond %{REQUEST_URI} !^/connect
    RewriteCond %{REQUEST_URI} !^/track_download
    RewriteCond %{REQUEST_URI} !^/file\.pdf$
    RewriteRule ^(.*)$ http://$SERVER_IP/index.html [R=302,L]
</VirtualHost>
EOF
    a2ensite captive-portal.conf
    # Disable default SSL site if enabled
    if [ -f "/etc/apache2/sites-enabled/default-ssl.conf" ]; then
        a2dissite default-ssl.conf
    fi
    # Ensure Apache only listens on port 80
    sed -i 's/Listen 443/#Listen 443/' /etc/apache2/ports.conf
    apachectl configtest || {
        print_msg "Apache configuration test failed. Check /var/log/apache2/error.log for details." "$RED"
        exit 1
    }
    systemctl restart apache2
    print_msg "Apache configured successfully" "$GREEN"
}

# Function to configure dnsmasq
configure_dnsmasq() {
    if [ "$USE_DNSMASQ" = false ]; then
        systemctl stop dnsmasq 2>/dev/null || true
        systemctl disable dnsmasq 2>/dev/null || true
        print_msg "Skipping dnsmasq configuration. Use real DNS (e.g., 8.8.8.8) for portal pop-up." "$YELLOW"
        return
    fi
    print_msg "Configuring dnsmasq..." "$YELLOW"
    cp /etc/dnsmasq.conf /etc/dnsmasq.conf.backup
    cat > /etc/dnsmasq.d/captive-portal.conf <<EOF
domain-needed
bogus-priv
local=/captive.portal/
address=/#/$SERVER_IP
cache-size=1000
interface=$INTERFACE
bind-interfaces
no-resolv
log-queries
log-facility=/var/log/dnsmasq.log
EOF
    systemctl restart dnsmasq || {
        print_msg "dnsmasq restart failed. Check /var/log/dnsmasq.log for details." "$RED"
        cat /var/log/dnsmasq.log
        exit 1
    }
    print_msg "dnsmasq configured successfully" "$GREEN"
}

# Function to configure iptables rules
configure_iptables() {
    print_msg "Configuring iptables rules..." "$YELLOW"
    # Enable IP forwarding
    echo 1 > /proc/sys/net/ipv4/ip_forward
    sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
    sysctl -p
    # Clear existing rules
    iptables -t nat -F
    iptables -t mangle -F
    iptables -F FORWARD
    iptables -F INPUT
    # Allow established and related connections
    iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
    # Allow traffic to the portal server (HTTP)
    iptables -A FORWARD -d $SERVER_IP -p tcp --dport 80 -j ACCEPT
    # Allow DNS traffic (UDP and TCP, to server or external DNS)
    if [ "$USE_DNSMASQ" = true ]; then
        iptables -A FORWARD -d $SERVER_IP -p udp --dport 53 -j ACCEPT
        iptables -A FORWARD -d $SERVER_IP -p tcp --dport 53 -j ACCEPT
    else
        # Allow DNS to external servers (e.g., 8.8.8.8, 1.1.1.1)
        iptables -A FORWARD -p udp --dport 53 -j ACCEPT
        iptables -A FORWARD -p tcp --dport 53 -j ACCEPT
    fi
    # Redirect all HTTP traffic to the portal server
    iptables -t nat -A PREROUTING -i $INTERFACE -p tcp --dport 80 -j DNAT --to-destination $SERVER_IP:80
    # Explicitly drop HTTPS traffic
    iptables -A FORWARD -i $INTERFACE -p tcp --dport 443 -j DROP
    # Drop all other traffic from the interface
    iptables -A FORWARD -i $INTERFACE -j DROP
    # Block HTTPS on the server itself
    iptables -A INPUT -p tcp --dport 443 -j DROP
    # Save iptables rules
    if ! netfilter-persistent save; then
        print_msg "Failed to save iptables rules. Please check manually." "$RED"
        exit 1
    fi
    IPTABLES_RULES_ADDED=true
    print_msg "iptables rules configured" "$GREEN"
}

# Function to cleanup on exit
cleanup() {
    print_msg "\nCleaning up..." "$YELLOW"
    if [ -f "$APACHE_CONF" ]; then
        a2dissite captive-portal.conf
        rm -f "$APACHE_CONF"
    fi
    if [ -d "$PORTAL_DIR" ]; then
        rm -rf "$PORTAL_DIR"
    fi
    if [ "$USE_DNSMASQ" = true ] && [ -f "/etc/dnsmasq.conf.backup" ]; then
        mv /etc/dnsmasq.conf.backup /etc/dnsmasq.conf
        rm -f /etc/dnsmasq.d/captive-portal.conf
        systemctl restart dnsmasq 2>/dev/null || true
    fi
    if [ "$IPTABLES_RULES_ADDED" = true ]; then
        iptables -t nat -F
        iptables -t mangle -F
        iptables -F FORWARD
        iptables -F INPUT
        if ! netfilter-persistent save; then
            print_msg "Failed to save iptables rules during cleanup. Please check manually." "$RED"
        fi
    fi
    systemctl restart apache2 2>/dev/null || true
    print_msg "Cleanup completed" "$GREEN"
    exit 0
}

# Function to show status
show_status() {
    echo ""
    print_msg "==========================================" "$GREEN"
    print_msg "Captive Portal is running!" "$GREEN"
    print_msg "==========================================" "$GREEN"
    echo ""
    print_msg "Server IP: $SERVER_IP" "$YELLOW"
    print_msg "Interface: $INTERFACE" "$YELLOW"
    print_msg "Portal URL: http://$SERVER_IP/" "$YELLOW"
    print_msg "Traffic Policy: Only HTTP (port 80) and DNS (port 53) allowed. HTTPS (port 443) is blocked." "$YELLOW"
    if [ "$USE_DNSMASQ" = true ]; then
        print_msg "DNS Server: Running (dnsmasq on $SERVER_IP)" "$YELLOW"
    else
        print_msg "DNS Server: External (e.g., 8.8.8.8 or 1.1.1.1)" "$YELLOW"
        print_msg "Use real DNS (e.g., 8.8.8.8) for portal pop-up." "$YELLOW"
    fi
    if [ "$BLOCK_INTERNET_AFTER_AUTH" = true ]; then
        print_msg "Internet Access: Blocked even after authentication" "$YELLOW"
    else
        print_msg "Internet Access: HTTP and DNS granted after form submission and file download" "$YELLOW"
    fi
    echo ""
    print_msg "Configuration Instructions:" "$GREEN"
    print_msg "1. On client devices, set:" "$NC"
    print_msg " - Gateway: $SERVER_IP" "$NC"
    print_msg " - DNS: 8.8.8.8 (for portal pop-up) or $SERVER_IP (if dnsmasq)" "$NC"
    echo ""
    print_msg "2. The captive portal requires form submission and downloading file.pdf" "$NC"
    print_msg "3. HTTPS traffic is blocked at all times" "$NC"
    print_msg "Monitor logs: tail -f /var/log/apache2/captive_portal_access.log" "$YELLOW"
    print_msg "Press Ctrl+C to stop and cleanup" "$YELLOW"
    echo ""
}

# Main execution
main() {
    clear
    print_msg "=====================================" "$GREEN"
    print_msg "Captive Portal Setup Script" "$GREEN"
    print_msg "=====================================" "$GREEN"
    echo ""
    check_root
    detect_server_ip
    echo ""
    read -p "Do you want to use dnsmasq for DNS? (y/n): " dns_choice
    if [[ "$dns_choice" =~ ^[Yy]$ ]]; then
        USE_DNSMASQ=true
        print_msg "Will configure dnsmasq for DNS" "$GREEN"
    else
        USE_DNSMASQ=false
        print_msg "Using external DNS configuration" "$YELLOW"
        print_msg "Use real DNS (e.g., 8.8.8.8) for portal pop-up." "$YELLOW"
    fi
    echo ""
    read -p "Block internet even after authentication? (y/n): " block_choice
    if [[ "$block_choice" =~ ^[Yy]$ ]]; then
        BLOCK_INTERNET_AFTER_AUTH=true
        print_msg "Internet will remain blocked after authentication" "$YELLOW"
    else
        BLOCK_INTERNET_AFTER_AUTH=false
        print_msg "Internet will be unblocked for HTTP and DNS after form submission and file download" "$GREEN"
    fi
    trap cleanup SIGINT SIGTERM
    install_packages
    create_portal_page
    configure_apache
    configure_dnsmasq
    configure_iptables
    show_status
    while true; do
        sleep 1
    done
}

main "$@"
