#!/bin/bash

set -euo pipefail

# =============================================================================
#  3x-ui Stealth Setup Wrapper
#  Hardens server, sets up nginx decoy, fail2ban, firewall, SSL,
#  then installs 3x-ui panel behind reverse proxy.
#
#  Architecture:
#    Port 22:   SSH
#    Port 80:   nginx — decoy website + panel reverse proxy
#    Port 443:  xray — Reality (VLESS+REALITY, configured later in panel)
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
# 2. Firewall — allow ONLY 22, 80, 443
# ──────────────────────────────────────────────
setup_firewall() {
    section "Firewall — Locking down to ports 22, 80, 443"

    if command -v ufw &>/dev/null; then
        info "Using ufw"
        ufw --force reset
        ufw default deny incoming
        ufw default allow outgoing
        ufw allow 22/tcp comment 'SSH'
        ufw allow 80/tcp  comment 'HTTP (decoy + panel)'
        ufw allow 443/tcp comment 'Reality (VLESS)'
        ufw --force enable
        info "ufw active. Rules:"
        ufw status numbered
    elif command -v firewall-cmd &>/dev/null; then
        info "Using firewalld"
        firewall-cmd --set-default-zone=drop
        firewall-cmd --permanent --add-port=22/tcp
        firewall-cmd --permanent --add-port=80/tcp
        firewall-cmd --permanent --add-port=443/tcp
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
        ufw allow 80/tcp  comment 'HTTP (decoy + panel)'
        ufw allow 443/tcp comment 'Reality (VLESS)'
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

    section "nginx — Configuring decoy site + panel reverse proxy on port 80"

    mkdir -p /etc/nginx/sites-enabled
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true

    cat > /etc/nginx/sites-enabled/stealth.conf << NGINXCONF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    server_tokens off;

    root /var/www/decoy;
    index index.html;

    location /${web_base_path}/ {
        proxy_pass http://127.0.0.1:${panel_port}/;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cookie_path / /${web_base_path}/;
        proxy_redirect off;
        proxy_buffering off;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    location / {
        try_files \$uri \$uri/ =404;
    }
}
NGINXCONF

    info "nginx configured — port 80: decoy at /, panel at /${web_base_path}/"
}

# ──────────────────────────────────────────────
# 5. Self-signed SSL (needed for nginx, domain is for Reality SNI only)
# ──────────────────────────────────────────────
setup_selfsigned_ssl() {
    local domain="$1"
    section "Self-signed SSL — fallback cert for nginx"

    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/privkey.pem \
        -out /etc/nginx/ssl/fullchain.pem \
        -subj "/CN=${domain}" 2>/dev/null
    info "Self-signed certificate created (domain used as CN only)"
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
port    = 80
logpath = /var/log/nginx/error.log
maxretry = 10
bantime  = 3600
findtime = 600

[nginx-botsearch]
enabled = true
filter  = nginx-botsearch
port    = 80
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



post_install() {
    section "Post-Install — Configuring panel + nginx"

    local XUI_FOLDER="${XUI_MAIN_FOLDER:-/usr/local/x-ui}"
    local i=0
    while [[ ! -x "${XUI_FOLDER}/x-ui" && $i -lt 30 ]]; do
        sleep 1; i=$((i + 1))
    done
    if [[ ! -x "${XUI_FOLDER}/x-ui" ]]; then
        error "x-ui binary not found at ${XUI_FOLDER}"; return 1
    fi

    systemctl stop x-ui 2>/dev/null || true
    sleep 1

    local web_path
    web_path=$(gen_random_string 18)
    local admin_user
    admin_user=$(gen_random_string 10)
    local admin_pass
    admin_pass=$(gen_random_string 16)

    PANEL_BASE_PATH="${web_path}"
    PANEL_USER="${admin_user}"
    PANEL_PASS="${admin_pass}"

    if "${XUI_FOLDER}/x-ui" setting \
        -port "2053" \
        -webBasePath "/${web_path}" \
        -listenIP "127.0.0.1" \
        -username "${admin_user}" \
        -password "${admin_pass}" \
        >/dev/null 2>&1; then
        info "Panel settings applied"
    else
        warn "x-ui setting had errors"
    fi

    systemctl start x-ui 2>/dev/null || true
    sleep 3

    setup_nginx "${DOMAIN}" "2053" "${web_path}"
    systemctl restart nginx 2>/dev/null || true
    info "nginx serving decoy at / and panel at /${web_path}/"

    if command -v ufw &>/dev/null; then
        ufw reload 2>/dev/null || true
    fi

    echo ""
    echo -e "${green}══════════════════════════════════════════════════════════════${plain}"
    echo -e "${green}     STEALTH SETUP COMPLETE                                  ${plain}"
    echo -e "${green}══════════════════════════════════════════════════════════════${plain}"
    echo -e "  Domain:      ${yellow}${DOMAIN}${plain}  (SNI only — not for panel)"
    echo -e "  Server IP:   ${yellow}${SERVER_IP}${plain}"
    echo ""
    echo -e "  ${cyan}Decoy Website:${plain}"
    echo -e "    http://${SERVER_IP}  →  Apache2 Ubuntu Default Page"
    echo ""
    echo -e "  ${cyan}Panel Access:${plain}"
    echo -e "    ${yellow}http://${SERVER_IP}/${web_path}/${plain}"
    echo ""
    echo -e "  ${cyan}Panel Login:${plain}"
    echo -e "    Username: ${admin_user}"
    echo -e "    Password: ${admin_pass}"
    echo ""
    echo -e "  ${cyan}Database:${plain}"
    echo -e "    SQLite (/etc/x-ui/x-ui.db)"
    echo ""
    echo -e "  ${cyan}Reality (VLESS+REALITY):${plain}"
    echo -e "    Port: 443  |  SNI: ${DOMAIN}"
    echo -e "    Create an inbound via panel → Inbounds → Add VLESS+Reality"
    echo ""
    echo -e "  ${cyan}Open Ports:${plain}"
    echo -e "    22/tcp   — SSH"
    echo -e "    80/tcp   — HTTP (decoy + panel proxy)"
    echo -e "    443/tcp  — Reality"
    echo ""
    echo -e "  ${cyan}Security:${plain}"
    echo -e "    ✓ fail2ban  ✓ BBR  ✓ Kernel hardening  ✓ Server tokens hidden"
    echo -e ""
    echo -e "  ${yellow}⚠ Save credentials above — they will NOT be shown again!${plain}"
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

    # Self-signed SSL (CN uses domain but only for org purposes, no ACME)
    setup_selfsigned_ssl "${DOMAIN}"

    # Write initial nginx site config for port 80 (decoy only for now)
    info "Writing initial nginx site config (port 80 decoy)..."
    mkdir -p /etc/nginx/sites-enabled /var/log/nginx
    rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true

    cat > /etc/nginx/sites-enabled/stealth-http.conf << 'HTTPMIN'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    server_tokens off;
    root /var/www/decoy;
    index index.html;
    location / { try_files $uri $uri/ =404; }
}
HTTPMIN

    systemctl start nginx 2>/dev/null || rc-service nginx start 2>/dev/null || true
    info "nginx started on port 80 (decoy website)"

    # Clean any existing x-ui for a fresh install
    cleanup_existing_xui

    echo ""
    info "Phase 2: 3x-ui Panel Installation"
    echo ""
    info "${yellow}======================================================${plain}"
    info "${yellow}  RUNNING 3x-ui INSTALL (automated)${plain}"
    info "${yellow}  DB:  PostgreSQL (existing)${plain}"
    info "${yellow}  SSL: Skipped (no SSL needed)${plain}"
    info "${yellow}  IP:  127.0.0.1 only${plain}"
    info "${yellow}======================================================${plain}"
    echo ""

    local install_url="https://raw.githubusercontent.com/ndotvpn/3x-ui/master/install.sh"
    # Pipe answers to install.sh's config_after_install:
    #   "2"  → PostgreSQL
    #   "1"  → Install PostgreSQL locally
    #   ""   → Don't customize port (random)
    #   "4"  → Skip SSL
    #   "y"  → Bind to 127.0.0.1
    printf "2\n1\n\n4\ny\n" | bash <(curl -fsSL "$install_url") "$@"

    echo ""
    info "install.sh completed. Running post-install configuration..."
    post_install "$@"
}

main "$@"
