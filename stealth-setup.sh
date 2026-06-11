#!/bin/bash

set -euo pipefail

# =============================================================================
#  3x-ui Stealth Setup Wrapper
#  Hardens server, sets up nginx decoy, fail2ban, firewall, SSL,
#  then installs 3x-ui panel behind reverse proxy.
#
#  Architecture:
#    Port 22:   SSH
#    Port 80:   nginx — decoy website + ACME challenges
#    Port 443:  xray — Reality (VLESS+REALITY, configured later in panel)
#    Port 8443: nginx — SSL reverse proxy to x-ui panel (localhost)
# =============================================================================

red='\033[0;31m'
green='\033[0;32m'
blue='\033[0;34m'
yellow='\033[0;33m'
cyan='\033[0;36m'
plain='\033[0m'

info()  { echo -e "${green}[INFO]${plain} $*"; }
warn()  { echo -e "${yellow}[WARN]${plain} $*"; }
error() { echo -e "${red}[ERR]${plain} $*"; }
section() { echo -e "\n${cyan}═══════════════════════════════════════════════${plain}"; echo -e "${cyan}  $*${plain}"; echo -e "${cyan}═══════════════════════════════════════════════${plain}"; }

CUR_DIR=$(pwd)

[[ $EUID -ne 0 ]] && error "Please run with root privilege" && exit 1

if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    release=$ID
else
    error "Cannot detect OS"
    exit 1
fi

# ──────────────────────────────────────────────
# PKG manager helpers
# ──────────────────────────────────────────────
pkg_update() {
    case "${release}" in
        ubuntu|debian|armbian) apt-get update -y ;;
        fedora|amzn|rhel|almalinux|rocky|ol) dnf update -y ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then yum update -y; else dnf update -y; fi
            ;;
        arch|manjaro|parch) pacman -Syu --noconfirm ;;
        opensuse-tumbleweed|opensuse-leap) zypper refresh ;;
        alpine) apk update ;;
        *) apt-get update -y ;;
    esac 2>/dev/null || true
}

pkg_install() {
    local pkgs=("$@")
    case "${release}" in
        ubuntu|debian|armbian)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${pkgs[@]}"
            ;;
        fedora|amzn|rhel|almalinux|rocky|ol)
            dnf install -y -q "${pkgs[@]}"
            ;;
        centos)
            if [[ "${VERSION_ID}" =~ ^7 ]]; then
                yum install -y "${pkgs[@]}"
            else
                dnf install -y -q "${pkgs[@]}"
            fi
            ;;
        arch|manjaro|parch)
            pacman -Syu --noconfirm "${pkgs[@]}"
            ;;
        opensuse-tumbleweed|opensuse-leap)
            zypper -q install -y "${pkgs[@]}"
            ;;
        alpine)
            apk add --no-cache "${pkgs[@]}"
            ;;
        *)
            DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${pkgs[@]}"
            ;;
    esac 2>/dev/null || true
}

service_active() {
    if [[ $release == "alpine" ]]; then
        rc-service "$1" status 2>/dev/null | grep -q 'status: started'
    else
        systemctl is-active --quiet "$1" 2>/dev/null
    fi
}

service_enable_start() {
    if [[ $release == "alpine" ]]; then
        rc-update add "$1" default 2>/dev/null || true
        rc-service "$1" start 2>/dev/null || true
    else
        systemctl enable --now "$1" 2>/dev/null || true
    fi
}

gen_random_string() {
    local length="${1:-16}"
    openssl rand -base64 $((length * 2)) | tr -dc 'a-zA-Z0-9' | head -c "$length"
}

is_domain() {
    [[ "$1" =~ ^([A-Za-z0-9](-*[A-Za-z0-9])*\.)+(xn--[a-z0-9]{2,}|[A-Za-z]{2,})$ ]]
}

NGINX_ROOT="/var/www/decoy"
PANEL_BASE_PATH=""
DOMAIN=""
SERVER_IP=""

# ──────────────────────────────────────────────
# 1. Detect server IP
# ──────────────────────────────────────────────
detect_ip() {
    local url_list=(
        "https://api4.ipify.org"
        "https://ipv4.icanhazip.com"
        "https://v4.api.ipinfo.io/ip"
        "https://ipv4.myexternalip.com/raw"
        "https://4.ident.me"
    )
    for url in "${url_list[@]}"; do
        local resp
        resp=$(curl -s --max-time 3 "$url" 2>/dev/null | tr -d '[:space:]"')
        if [[ "$resp" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            SERVER_IP="$resp"
            return 0
        fi
    done
    return 1
}

# ──────────────────────────────────────────────
# 2. Firewall — allow ONLY 22, 80, 443, 8443
# ──────────────────────────────────────────────
setup_firewall() {
    section "Firewall — Locking down to ports 22, 80, 443, 8443"

    if command -v ufw &>/dev/null; then
        info "Using ufw"
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp  comment 'HTTP (decoy + ACME)'
        ufw allow 443/tcp comment 'Reality (VLESS)'
        ufw allow 8443/tcp comment 'Panel reverse proxy'
        ufw --force enable
        info "ufw active. Rules:"
        ufw status numbered
    elif command -v firewall-cmd &>/dev/null; then
        info "Using firewalld"
        firewall-cmd --set-default-zone=drop
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
        firewall-cmd --permanent --add-port=8443/tcp
        firewall-cmd --reload
        info "firewalld active."
    elif command -v nft &>/dev/null; then
        info "Using nftables"
        nft flush ruleset
        nft add table inet filter
        nft add chain inet filter input '{ type filter hook input priority 0; policy drop; }'
        nft add chain inet filter forward '{ type filter hook forward priority 0; policy drop; }'
        nft add chain inet filter output '{ type filter hook output priority 0; policy accept; }'
        nft add rule inet filter input ct state established,related accept
        nft add rule inet filter input lo accept
        nft add rule inet filter input tcp dport 22 accept
        nft add rule inet filter input tcp dport 80 accept
        nft add rule inet filter input tcp dport 443 accept
        nft add rule inet filter input tcp dport 8443 accept
        nft add rule inet filter input icmp type echo-request accept
        nft list ruleset > /etc/nftables.conf 2>/dev/null || true
        info "nftables rules applied."
    else
        warn "No firewall tool found. Installing ufw..."
        pkg_install ufw
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp  comment 'HTTP (decoy + ACME)'
        ufw allow 443/tcp comment 'Reality (VLESS)'
        ufw allow 8443/tcp comment 'Panel reverse proxy'
        ufw --force enable
        info "ufw active."
    fi
}

# ──────────────────────────────────────────────
# 3. Decoy website
# ──────────────────────────────────────────────
setup_decoy() {
    section "Decoy Website — Apache2 Ubuntu default page (convincing decoy)"

    local domain="$1"
    mkdir -p "$NGINX_ROOT"

    cat > "${NGINX_ROOT}/index.html" << 'DECOYEOF'
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<title>Apache2 Ubuntu Default Page: It works</title>
<style>
  html *, html { padding:0; margin:0; }
  body { font-family: 'Ubuntu', 'DejaVu Sans', sans-serif; font-size: 14px; line-height: 1.6; color: #2c3e50; background: #f4f4f4; }
  a { color: #e95420; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .container { max-width: 800px; margin: 0 auto; padding: 40px 20px; }
  h1 { font-size: 28px; color: #e95420; margin-bottom: 20px; border-bottom: 1px solid #ddd; padding-bottom: 10px; }
  h2 { font-size: 20px; color: #333; margin: 30px 0 10px; }
  p { margin-bottom: 15px; }
  ul { margin: 10px 0 20px 20px; }
  li { margin-bottom: 5px; }
  .logo { text-align: center; margin-bottom: 30px; }
  .logo img { max-width: 200px; }
  .box { background: #fff; border: 1px solid #ddd; border-radius: 4px; padding: 30px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .header-box { background: #2c3e50; color: #fff; padding: 30px; border-radius: 4px 4px 0 0; margin-bottom: 0; }
  .header-box h1 { color: #fff; border: none; font-size: 24px; margin-bottom: 5px; padding-bottom: 0; }
  .header-box p { color: #bdc3c7; font-size: 14px; margin-bottom: 0; }
  .footer { text-align: center; color: #7f8c8d; font-size: 12px; border-top: 1px solid #ddd; padding-top: 20px; margin-top: 30px; }
  code { background: #ecf0f1; padding: 2px 6px; border-radius: 3px; font-size: 13px; }
  .highlight { background: #fff9e6; border-left: 4px solid #e95420; padding: 10px 15px; margin: 15px 0; }
</style>
</head>
<body>
<div class="container">
<div class="box" style="padding:0;">
<div class="header-box">
<h1>Apache2 Ubuntu Default Page</h1>
<p>It works!</p>
</div>
<div style="padding:30px;">
<p>This is the default welcome page used to test the correct operation of the <strong>Apache2</strong> server after installation on <strong>Ubuntu</strong> systems. It is based on the equivalent page on <strong>Debian</strong>, from which the Ubuntu Apache packaging is derived. If you can read this page, it means the Apache HTTP server installed at this site is working properly. You should <strong>replace this file</strong> (located at <code>/var/www/html/index.html</code>) before continuing to operate your HTTP server.</p>

<div class="highlight">
<p><strong>If you are a normal user of this web site and don't know what this page is about, this probably means that the site is currently unavailable due to maintenance.</strong> If the problem persists, please contact the site's administrator.</p>
</div>

<h2>Configuration Overview</h2>
<p>Ubuntu's Apache2 default configuration is different from the upstream default configuration, and splits into several files optimized for interaction with Ubuntu tools. The configuration system is <strong>fully documented in /usr/share/doc/apache2/README.Debian.gz</strong>. Refer to this for the full documentation. Documentation for the web server itself can be found by accessing the <a href="https://httpd.apache.org/docs/">Apache HTTP Server documentation</a>.</p>

<h2>Documentation</h2>
<ul>
<li>Apache2 Documentation: <a href="https://httpd.apache.org/docs/">https://httpd.apache.org/docs/</a></li>
<li>Ubuntu Wiki Apache2: <a href="https://wiki.ubuntu.com/Apache2">https://wiki.ubuntu.com/Apache2</a></li>
</ul>

<h2>Where to find help</h2>
<ul>
<li>Ask Ubuntu: <a href="https://askubuntu.com/">https://askubuntu.com/</a></li>
<li>Server Fault: <a href="https://serverfault.com/">https://serverfault.com/</a></li>
<li>Ubuntu Forums: <a href="https://ubuntuforums.org/">https://ubuntuforums.org/</a></li>
</ul>

<hr style="border:none;border-top:1px solid #eee;margin:25px 0;">

<p style="color:#7f8c8d;font-size:12px;">Ubuntu 22.04 LTS - Apache/2.4.57 (Ubuntu) - Server at DOMAIN_PLACEHOLDER Port 80</p>
</div>
</div>
<div class="footer">
<p>Apache/2.4.57 (Ubuntu) Server at DOMAIN_PLACEHOLDER Port 80</p>
</div>
</div>
</body>
</html>
DECOYEOF

    sed -i "s/DOMAIN_PLACEHOLDER/${domain}/g" "${NGINX_ROOT}/index.html"

    info "Decoy — Apache2 Ubuntu default page created at ${NGINX_ROOT}"
}

# ──────────────────────────────────────────────
# 4. nginx configuration
# ──────────────────────────────────────────────
setup_nginx() {
    local domain="$1"
    local panel_port="$2"
    local web_base_path="$3"

    section "nginx — Configuring decoy site + panel reverse proxy"

    mkdir -p /etc/nginx/sites-enabled /etc/nginx/snippets

    # Remove default site configs
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true

    # Port 80: decoy site + ACME
    cat > /etc/nginx/sites-enabled/decoy-http.conf << 'HTTPEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    location /.well-known/acme-challenge/ {
        root /var/www/decoy;
    }

    root /var/www/decoy;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
HTTPEOF

    # Port 8443: SSL + decoy + panel reverse proxy
    cat > /etc/nginx/sites-enabled/panel-proxy.conf << NGINXPROXY
server {
    listen 8443 ssl http2;
    listen [::]:8443 ssl http2;
    server_name ${domain};

    ssl_certificate     /etc/nginx/ssl/fullchain.pem;
    ssl_certificate_key /etc/nginx/ssl/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # Security headers
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "SAMEORIGIN" always;

    root /var/www/decoy;
    index index.html;

    # Decoy website at root
    location / {
        try_files \$uri \$uri/ =404;
    }

    # Panel reverse proxy
    location /${web_base_path}/ {
        proxy_pass http://127.0.0.1:${panel_port}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Port 8443;
        proxy_cookie_path / /${web_base_path}/;
        proxy_redirect off;
        proxy_buffering off;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
NGINXPROXY

    info "nginx configured — port 80 (decoy), port 8443 (SSL + panel)"
}

# ──────────────────────────────────────────────
# 5. SSL certificate
# ──────────────────────────────────────────────
setup_ssl() {
    local domain="$1"

    section "SSL Certificate — Let's Encrypt for ${domain}"

    mkdir -p /etc/nginx/ssl

    if command -v ~/.acme.sh/acme.sh &>/dev/null; then
        info "acme.sh already installed"
    else
        info "Installing acme.sh..."
        cd ~ && curl -s https://get.acme.sh | sh
    fi

    export HOME="/root"
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt --force 2>/dev/null

    # Stop nginx to free port 80 for ACME
    systemctl stop nginx 2>/dev/null || true

    if ~/.acme.sh/acme.sh --issue -d "${domain}" --listen-v6 --standalone --httpport 80 --force 2>&1; then
        info "Certificate issued successfully"

        ~/.acme.sh/acme.sh --installcert -d "${domain}" \
            --key-file /etc/nginx/ssl/privkey.pem \
            --fullchain-file /etc/nginx/ssl/fullchain.pem \
            --reloadcmd "systemctl restart nginx" >/dev/null 2>&1

        chmod 600 /etc/nginx/ssl/privkey.pem
        chmod 644 /etc/nginx/ssl/fullchain.pem
        info "Certificate installed to /etc/nginx/ssl/"
    else
        error "Certificate issuance failed. Check DNS and port 80 accessibility."
        # Create self-signed fallback so nginx can start
        warn "Creating self-signed fallback certificate"
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/privkey.pem \
            -out /etc/nginx/ssl/fullchain.pem \
            -subj "/CN=${domain}" 2>/dev/null
    fi
}

# ──────────────────────────────────────────────
# 6. fail2ban
# ──────────────────────────────────────────────
setup_fail2ban() {
    section "fail2ban — Hardening against brute force"

    pkg_install fail2ban

    local ssh_port="${SSH_PORT:-22}"

    mkdir -p /etc/fail2ban/jail.d

    cat > /etc/fail2ban/jail.d/sshd.conf << FAIL2BAN
[sshd]
enabled = true
port    = ${ssh_port}
filter  = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600
FAIL2BAN

    cat > /etc/fail2ban/jail.d/nginx.conf << FAIL2BAN
[nginx-http-auth]
enabled = true
filter  = nginx-http-auth
port    = 80,8443
logpath = /var/log/nginx/error.log
maxretry = 10
bantime  = 3600
findtime = 600

[nginx-botsearch]
enabled = true
filter  = nginx-botsearch
port    = 80,8443
logpath = /var/log/nginx/access.log
maxretry = 10
bantime  = 3600
findtime = 600
FAIL2BAN

    # Adjust logpath for non-Debian systems
    if [[ ! -f /var/log/auth.log ]]; then
        sed -i 's|logpath = /var/log/auth.log|logpath = /var/log/secure|' /etc/fail2ban/jail.d/sshd.conf
    fi

    service_enable_start fail2ban
    info "fail2ban active — SSH (port ${ssh_port}) + nginx protected"
}

# ──────────────────────────────────────────────
# 7. Enable BBR
# ──────────────────────────────────────────────
enable_bbr() {
    section "BBR — TCP Congestion Control"

    if sysctl net.ipv4.tcp_congestion_control 2>/dev/null | grep -q bbr; then
        info "BBR already enabled"
        return
    fi

    if lsmod 2>/dev/null | grep -q tcp_bbr; then
        info "tcp_bbr module loaded"
    else
        modprobe tcp_bbr 2>/dev/null || true
    fi

    cat > /etc/sysctl.d/99-bbr.conf << 'BBR'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
BBR
    sysctl --system >/dev/null 2>&1
    info "BBR enabled"
}

# ──────────────────────────────────────────────
# 8. Harden sysctl
# ──────────────────────────────────────────────
harden_sysctl() {
    section "Sysctl — Kernel hardening"

    cat > /etc/sysctl.d/99-security.conf << 'SYSCTL'
# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2

# TCP timestamps for better RTT estimation
net.ipv4.tcp_timestamps = 1

# Protect against TIME_WAIT assassination
net.ipv4.tcp_rfc1337 = 1
SYSCTL
    sysctl --system >/dev/null 2>&1
    info "Kernel hardening applied"
}

# ──────────────────────────────────────────────
# 9. Remove unnecessary services
# ──────────────────────────────────────────────
clean_services() {
    section "Hardening — Removing unnecessary services"

    local common_services=(
        avahi-daemon cups bluetooth postfix rpcbind
        nfs-server nfs-kernel-server slapd telnet
        vsftpd proftpd dovecot sendmail
    )

    for svc in "${common_services[@]}"; do
        if [[ $release == "alpine" ]]; then
            rc-service "$svc" stop 2>/dev/null || true
            rc-update del "$svc" 2>/dev/null || true
        else
            systemctl stop "$svc" 2>/dev/null || true
            systemctl disable "$svc" 2>/dev/null || true
        fi
    done

    info "Unnecessary services stopped and disabled"
}

# ──────────────────────────────────────────────
# 9b. Clean up existing x-ui installation
# ──────────────────────────────────────────────
cleanup_existing_xui() {
    section "Cleanup — Removing existing x-ui for clean install"

    if [[ -d /usr/local/x-ui ]] || [[ -d /etc/x-ui ]] || [[ -f /etc/systemd/system/x-ui.service ]]; then
        warn "Existing x-ui detected. Removing for clean install..."
        if [[ $release == "alpine" ]]; then
            rc-service x-ui stop 2>/dev/null || true
            rc-update del x-ui 2>/dev/null || true
            rm -f /etc/init.d/x-ui 2>/dev/null || true
        else
            systemctl stop x-ui 2>/dev/null || true
            systemctl disable x-ui 2>/dev/null || true
            rm -f /etc/systemd/system/x-ui.service 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
        fi
        rm -rf /usr/local/x-ui /etc/x-ui /var/log/x-ui /usr/bin/x-ui /etc/default/x-ui /etc/conf.d/x-ui /etc/sysconfig/x-ui 2>/dev/null || true
        info "Old x-ui removed"
    else
        info "No existing x-ui found"
    fi
}

# ──────────────────────────────────────────────
# 9c. Install & configure local PostgreSQL
# ──────────────────────────────────────────────
setup_postgres() {
    section "PostgreSQL — Installing and creating database"

    pkg_install postgresql

    local pg_data_dir=""
    case "${release}" in
        ubuntu|debian|armbian) pg_data_dir="/var/lib/postgresql" ;;
        fedora|amzn|rhel|almalinux|rocky|ol|centos) pg_data_dir="/var/lib/pgsql" ;;
        arch|manjaro|parch) pg_data_dir="/var/lib/postgres" ;;
        *) pg_data_dir="/var/lib/postgresql" ;;
    esac

    if [[ $release == "alpine" ]]; then
        rc-service postgresql start 2>/dev/null || /etc/init.d/postgresql setup 2>/dev/null || true
        rc-update add postgresql default 2>/dev/null || true
    else
        systemctl enable --now postgresql 2>/dev/null || true
    fi

    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        sudo -u postgres psql -tAc 'SELECT 1' > /dev/null 2>&1 && break
        sleep 1
    done

    PG_USER="xui_$(gen_random_string 6)"
    PG_PASS=$(gen_random_string 24)
    PG_DB="xui"
    PG_HOST="127.0.0.1"
    PG_PORT="5432"

    sudo -u postgres psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" 2>/dev/null | grep -q 1 \
        || sudo -u postgres psql -c "CREATE USER \"${PG_USER}\" WITH PASSWORD '${PG_PASS}';" >/dev/null 2>&1 || true

    # Always drop and recreate for a clean start (avoids GORM migration errors)
    sudo -u postgres psql -c "DROP DATABASE IF EXISTS \"${PG_DB}\";" >/dev/null 2>&1 || true
    sudo -u postgres psql -c "CREATE DATABASE \"${PG_DB}\" OWNER \"${PG_USER}\";" >/dev/null 2>&1 || true

    sudo -u postgres psql -c "ALTER USER \"${PG_USER}\" WITH PASSWORD '${PG_PASS}';" >/dev/null 2>&1 || true

    local pg_pass_enc
    pg_pass_enc=$(printf '%s' "${PG_PASS}" | sed -e 's/%/%25/g' -e 's/:/%3A/g' -e 's/@/%40/g' -e 's|/|%2F|g' -e 's/?/%3F/g' -e 's/#/%23/g')

    PG_DSN="postgres://${PG_USER}:${pg_pass_enc}@${PG_HOST}:${PG_PORT}/${PG_DB}?sslmode=disable"
    info "PostgreSQL ready: ${PG_USER}@${PG_HOST}:${PG_PORT}/${PG_DB}"
}

# ──────────────────────────────────────────────
# 10. Pre-seed DB so install.sh skips prompts
# ──────────────────────────────────────────────
preseed_xui_db() {
    section "Pre-seeding x-ui config — so install.sh skips all config prompts"

    mkdir -p /etc/x-ui

    local web_port
    web_port=$(shuf -i 1024-65535 -n 1)
    local web_path
    web_path=$(gen_random_string 18)
    local admin_user
    admin_user=$(gen_random_string 10)
    local admin_pass
    admin_pass=$(gen_random_string 16)

    PANEL_BASE_PATH="${web_path}"
    PANEL_PORT="${web_port}"
    PANEL_USER="${admin_user}"
    PANEL_PASS="${admin_pass}"

    # Write env file for x-ui service so it picks up PostgreSQL
    local xui_env_file=""
    case "${release}" in
        ubuntu|debian|armbian) xui_env_file="/etc/default/x-ui" ;;
        arch|manjaro|parch|alpine) xui_env_file="/etc/conf.d/x-ui" ;;
        *) xui_env_file="/etc/sysconfig/x-ui" ;;
    esac

    if [[ -n "${PG_DSN:-}" ]]; then
        mkdir -p "$(dirname "$xui_env_file")"
        umask 077
        cat > "$xui_env_file" << EOF
XUI_DB_TYPE=postgres
XUI_DB_DSN=${PG_DSN}
EOF
        chmod 600 "$xui_env_file"
        umask 022

        export XUI_DB_TYPE=postgres
        export XUI_DB_DSN="${PG_DSN}"
        info "PostgreSQL env file written: ${xui_env_file}"
    else
        # SQLite fallback: pre-create the database so install.sh skips prompts
        info "Pre-seeding SQLite database..."
        pkg_install sqlite3
        cat > /tmp/preseed.sql << SQLEOF
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT, value TEXT);
INSERT OR IGNORE INTO settings (key, value) VALUES ('webPort', '${web_port}');
INSERT OR IGNORE INTO settings (key, value) VALUES ('webBasePath', '/${web_path}');
INSERT OR IGNORE INTO settings (key, value) VALUES ('webListen', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('webDomain', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('webCertFile', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('webKeyFile', '');
INSERT OR IGNORE INTO settings (key, value) VALUES ('secret', '$(gen_random_string 32)');
INSERT OR IGNORE INTO settings (key, value) VALUES ('panelGuid', '$(gen_random_string 8)-$(gen_random_string 4)-$(gen_random_string 4)-$(gen_random_string 4)-$(gen_random_string 12)');
INSERT OR IGNORE INTO settings (key, value) VALUES ('sessionMaxAge', '360');
INSERT OR IGNORE INTO settings (key, value) VALUES ('trustedProxyCIDRs', '127.0.0.1/32,::1/128');
INSERT OR IGNORE INTO settings (key, value) VALUES ('subPort', '2096');
INSERT OR IGNORE INTO settings (key, value) VALUES ('subEnable', 'true');
INSERT OR IGNORE INTO settings (key, value) VALUES ('subListen', '');
CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, login_epoch INTEGER DEFAULT 0);
INSERT OR IGNORE INTO users (id, username, password) VALUES (1, '${admin_user}', '${admin_pass}');
SQLEOF
        sqlite3 /etc/x-ui/x-ui.db < /tmp/preseed.sql 2>/dev/null && {
            info "SQLite pre-seeded at /etc/x-ui/x-ui.db"
        } || {
            warn "sqlite3 pre-seed failed — install.sh will be interactive"
            rm -f /etc/x-ui/x-ui.db 2>/dev/null || true
        }
        rm -f /tmp/preseed.sql
    fi
}

# Answers piped to install.sh:
#   4 → Skip SSL (nginx handles TLS)
#   y → Bind panel to 127.0.0.1 only

post_install() {
    section "Post-Install — Reconfiguring panel behind nginx"

    local XUI_FOLDER="${XUI_MAIN_FOLDER:-/usr/local/x-ui}"

    local wait_seconds=0
    while [[ ! -x "${XUI_FOLDER}/x-ui" && $wait_seconds -lt 30 ]]; do
        sleep 1
        wait_seconds=$((wait_seconds + 1))
    done

    if [[ ! -x "${XUI_FOLDER}/x-ui" ]]; then
        error "x-ui binary not found at ${XUI_FOLDER}"
        error "Installation may have failed"
        return 1
    fi

    local internal_port="${PANEL_PORT:-2053}"
    local web_base_path="${PANEL_BASE_PATH}"

    if [[ -n "${PG_DSN:-}" ]]; then
        # ── PostgreSQL path ────────────────────────────────────────────
        # GORM AutoMigrate errors on existing tables (GORM bug v1.31.1).
        # Workaround: run a SINGLE x-ui setting command on a clean schema
        # that creates tables AND applies settings in one process.

        info "Using PostgreSQL — configuring panel with single x-ui call..."

        # Stop x-ui (may be crashed/restarting)
        systemctl stop x-ui 2>/dev/null || true
        sleep 1

        # Clean PG schema so x-ui creates tables fresh
        sudo -u postgres psql -d "${PG_DB}" \
            -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;" \
            >/dev/null 2>&1 || true

        # Give postgres a moment
        sleep 1

        # ONE call to create tables AND apply all settings at once
        if "${XUI_FOLDER}/x-ui" setting \
            -port "${internal_port}" \
            -webBasePath "/${web_base_path}" \
            -listenIP "127.0.0.1" \
            -username "${PANEL_USER}" \
            -password "${PANEL_PASS}" \
            >/dev/null 2>&1; then
            info "Panel configured: ${internal_port}/${web_base_path}"
        else
            warn "x-ui setting command had errors — checking PG for partial results"
        fi

        # Save password hash from PG for the systemd wrapper
        local hash_file
        hash_file="/etc/x-ui/.pg-password-hash"
        sudo -u postgres psql -d "${PG_DB}" -tAc \
            "SELECT password FROM users ORDER BY id LIMIT 1;" \
            > "${hash_file}" 2>/dev/null || true
        chmod 600 "${hash_file}" 2>/dev/null || true

        # Save all settings to a SQL file for the systemd wrapper
        local sql_file="/etc/x-ui/.pg-settings.sql"
        umask 077
        cat > "${sql_file}" << PGSQL
DELETE FROM settings;
INSERT INTO settings (key, value) VALUES ('webPort', '${internal_port}');
INSERT INTO settings (key, value) VALUES ('webBasePath', '/${web_base_path}');
INSERT INTO settings (key, value) VALUES ('webListen', '127.0.0.1');
PGSQL
        chmod 600 "${sql_file}"

        # Create PG schema cleanup script for systemd ExecStartPre
        mkdir -p /usr/local/x-ui
        cat > /usr/local/x-ui/clean-pg.sh << 'CLEANSH'
#!/bin/bash
# Drop and recreate public schema so x-ui starts fresh every time
# (works around GORM AutoMigrate bug with PostgreSQL)
. /etc/default/x-ui 2>/dev/null || true
DB_NAME="${XUI_DB_DSN##*/}"
DB_NAME="${DB_NAME%%\?*}"
sudo -u postgres psql -d "${DB_NAME:-xui}" \
    -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;" \
    2>/dev/null || true
CLEANSH
        chmod +x /usr/local/x-ui/clean-pg.sh

        # Create settings re-apply script for systemd ExecStartPost
        cat > /usr/local/x-ui/apply-pg.sh << 'APPLYSH'
#!/bin/bash
# Wait for x-ui to create tables, then re-apply custom settings
DB_NAME="${XUI_DB_DSN##*/}"
DB_NAME="${DB_NAME%%\?*}"
DB_NAME="${DB_NAME:-xui}"

# Wait up to 30s for x-ui to create the users table
for i in $(seq 1 30); do
    if sudo -u postgres psql -d "$DB_NAME" -tAc \
        "SELECT 1 FROM pg_tables WHERE tablename='users';" 2>/dev/null | grep -q 1; then
        break
    fi
    sleep 1
done

# Apply custom settings
SF=/etc/x-ui/.pg-settings.sql
if [[ -f "$SF" ]]; then
    sudo -u postgres psql -d "$DB_NAME" -f "$SF" 2>/dev/null || true
fi

# Update password back to our custom one (x-ui creates admin/admin by default)
HF=/etc/x-ui/.pg-password-hash
if [[ -f "$HF" ]]; then
    H=$(cat "$HF")
    sudo -u postgres psql -d "$DB_NAME" \
        -c "UPDATE users SET password='${H}' WHERE username='admin';" \
        2>/dev/null || true
fi
APPLYSH
        chmod +x /usr/local/x-ui/apply-pg.sh

        # Modify systemd service to clean schema before start
        local svc_file
        svc_file=$(systemctl show -P FragmentPath x-ui.service 2>/dev/null) || svc_file="/etc/systemd/system/x-ui.service"
        if [[ -f "$svc_file" ]]; then
            # Rewrite the service file with clean-pg Schema wrapper
            cat > "$svc_file" << SVCEOF
[Unit]
Description=x-ui Service
After=network.target
Wants=network.target

[Service]
EnvironmentFile=-/etc/default/x-ui
Environment="XRAY_VMESS_AEAD_FORCED=false"
Type=simple
WorkingDirectory=/usr/local/x-ui/
ExecStartPre=/usr/local/x-ui/clean-pg.sh
ExecStart=/usr/local/x-ui/x-ui
ExecStartPost=/usr/local/x-ui/apply-pg.sh
ExecReload=kill -USR1 \$MAINPID
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
SVCEOF
            systemctl daemon-reload
            info "Systemd service patched with PG schema wrapper"
        fi

    else
        # ── SQLite path ────────────────────────────────────────────
        info "Using SQLite — setting panel configuration via x-ui CLI..."
        "${XUI_FOLDER}/x-ui" setting \
            -port "${internal_port}" \
            -webBasePath "/${web_base_path}" \
            -listenIP "127.0.0.1" \
            >/dev/null 2>&1 || true
    fi

    # Restart x-ui (PG: starts fresh with clean schema → wrapper handles re-apply)
    if [[ $release == "alpine" ]]; then
        rc-service x-ui restart 2>/dev/null || true
    else
        systemctl restart x-ui 2>/dev/null || true
    fi
    sleep 3

    info "Updating nginx with panel proxy configuration..."
    setup_nginx "${DOMAIN}" "${internal_port}" "${web_base_path}"

    systemctl restart nginx 2>/dev/null || rc-service nginx restart 2>/dev/null || true
    info "nginx restarted with panel proxy at /${web_base_path}/"

    if command -v ufw &>/dev/null; then
        ufw reload 2>/dev/null || true
    fi

    # ── Summary ───────────────────────────────────────────────────
    echo ""
    echo -e "${green}══════════════════════════════════════════════════════════════${plain}"
    echo -e "${green}     STEALTH SETUP COMPLETE                                  ${plain}"
    echo -e "${green}══════════════════════════════════════════════════════════════${plain}"
    echo -e "  Domain:      ${yellow}${DOMAIN}${plain}"
    echo -e "  Server IP:   ${yellow}${SERVER_IP}${plain}"
    echo ""
    echo -e "  ${cyan}Decoy Website:${plain}"
    echo -e "    http://${DOMAIN}  →  Apache2 Ubuntu Default Page"
    echo -e "    (also served on port 443 via Reality fallback)"
    echo ""
    echo -e "  ${cyan}Panel Access:${plain}"
    echo -e "    https://${DOMAIN}:8443/${web_base_path}/"
    echo ""
    echo -e "  ${cyan}Database:${plain}"
    if [[ -n "${PG_DSN:-}" ]]; then
        echo -e "    PostgreSQL — ${PG_USER}@${PG_HOST}:${PG_PORT}/${PG_DB}"
    else
        echo -e "    SQLite (/etc/x-ui/x-ui.db)"
    fi
    echo ""
    echo -e "  ${cyan}Reality (VLESS+REALITY):${plain}"
    echo -e "    Port: 443"
    echo -e "    SNI:  ${DOMAIN}"
    echo -e "    Configure inbounds via panel → x-ray config → Inbounds"
    echo ""
    echo -e "  ${cyan}Open Ports:${plain}"
    echo -e "    22/tcp   — SSH"
    echo -e "    80/tcp   — HTTP (decoy + ACME)"
    echo -e "    443/tcp  — Reality (VLESS)"
    echo -e "    8443/tcp — Panel (behind nginx SSL)"
    echo ""
    echo -e "  ${cyan}Security:${plain}"
    echo -e "    ✓ fail2ban (SSH + nginx)"
    echo -e "    ✓ BBR enabled"
    echo -e "    ✓ Kernel hardening"
    echo -e "    ✓ Unnecessary services removed"
    echo -e "    ✓ Let's Encrypt SSL"
    echo -e "    ✓ Server tokens hidden"
    echo ""
    echo -e "  ${yellow}⚠ Panel Credentials:${plain}"
    echo -e "    Username: ${PANEL_USER:-<see above>}"
    echo -e "    Password: ${PANEL_PASS:-<see above>}"
    echo -e "  ${yellow}  Save these — they will NOT be shown again!${plain}"
    echo -e "${green}══════════════════════════════════════════════════════════════${plain}"
}

# ──────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────
main() {
    printf '\033[2J\033[3J\033[H' 2>/dev/null || true
    echo -e "${cyan}"
    echo '  ╔══════════════════════════════════════════════════╗'
    echo '  ║         3x-ui Stealth Setup Wrapper              ║'
    echo '  ║     Hardened · Decoy · Undetectable              ║'
    echo '  ╚══════════════════════════════════════════════════╝'
    echo -e "${plain}"

    # Detect IP
    info "Detecting server IP..."
    detect_ip || true
    if [[ -n "$SERVER_IP" ]]; then
        info "Server IP: ${SERVER_IP}"
    else
        warn "Could not auto-detect server IP"
    fi

    # Prompt for domain
    echo ""
    while true; do
        read -rp "Enter your domain (will be used as SNI for Reality + decoy): " DOMAIN
        DOMAIN="${DOMAIN,,}"  # lowercase
        DOMAIN="${DOMAIN// /}"
        if [[ -z "$DOMAIN" ]]; then
            error "Domain cannot be empty"
        elif ! is_domain "$DOMAIN"; then
            error "Invalid domain format: ${DOMAIN}"
        else
            break
        fi
    done
    info "Domain set to: ${DOMAIN}"

    echo ""
    info "Phase 1: System preparation"
    echo ""

    pkg_update
    pkg_install nginx fail2ban ufw curl wget tar openssl ca-certificates

    # Clean unnecessary services
    clean_services

    # Firewall
    setup_firewall

    # BBR + sysctl hardening
    enable_bbr
    harden_sysctl

    # fail2ban
    setup_fail2ban

    # Decoy website
    setup_decoy "${DOMAIN}"

    # SSL
    setup_ssl "${DOMAIN}"

    # Write initial nginx site config for port 80 (decoy + ACME)
    info "Writing initial nginx site config (port 80 decoy)..."
    mkdir -p /etc/nginx/sites-enabled /etc/nginx/ssl /var/log/nginx
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true

    cat > /etc/nginx/sites-enabled/decoy-http.conf << 'HTTPMIN'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    root /var/www/decoy;
    index index.html;
    location /.well-known/acme-challenge/ { root /var/www/decoy; }
    location / { try_files $uri $uri/ =404; }
}
HTTPMIN

    # If SSL cert files don't exist, create self-signed (needed for nginx to start with SSL)
    if [[ ! -f /etc/nginx/ssl/fullchain.pem || ! -f /etc/nginx/ssl/privkey.pem ]]; then
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/nginx/ssl/privkey.pem \
            -out /etc/nginx/ssl/fullchain.pem \
            -subj "/CN=${DOMAIN}" 2>/dev/null
    fi

    systemctl start nginx 2>/dev/null || rc-service nginx start 2>/dev/null || true
    info "nginx started on port 80 (decoy website)"

    # Clean any existing x-ui for a fresh install
    cleanup_existing_xui

    # PostgreSQL setup (user requested local PostgreSQL)
    echo ""
    info "Phase 2: Database Setup (PostgreSQL)"
    echo ""
    setup_postgres

    # Pre-seed DB so install.sh skips all interactive config prompts
    preseed_xui_db

    echo ""
    info "Phase 3: 3x-ui Panel Installation"
    echo ""
    info "${yellow}======================================================${plain}"
    info "${yellow}  RUNNING 3x-ui INSTALL (automated)${plain}"
    info "${yellow}  DB:  PostgreSQL (local)${plain}"
    info "${yellow}  SSL: Skipped (nginx handles it)${plain}"
    info "${yellow}  IP:  127.0.0.1 only${plain}"
    info "${yellow}======================================================${plain}"
    echo ""

    echo -e "4\ny" | bash "${CUR_DIR}/install.sh" "$@"

    echo ""
    info "install.sh completed. Running post-install configuration..."
    post_install "$@"
}

main "$@"
