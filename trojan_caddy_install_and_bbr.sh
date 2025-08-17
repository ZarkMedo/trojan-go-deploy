#!/bin/bash
#=================================================
#	System Required: Debian 9+/Ubuntu 18.04+/Centos 7+
#	Description: Trojan & Caddy & BBR installation script
#	Version: 1.0.0
#	Author: ZarkMedo
#=================================================
# 使用方法：
# 1. 交互式安装: bash trojan_caddy_install_and_bbr.sh
# 2. 命令行参数安装: bash trojan_caddy_install_and_bbr.sh [域名] [Caddy端口] [Trojan端口] [密码]
#    例如: bash trojan_caddy_install_and_bbr.sh example.com 0 443 password
#    注意: 当Caddy端口设为0时，将随机生成一个端口
#=================================================
sh_ver="1.0.0"
#fonts color
RED="\033[0;31m"
NO_COLOR="\033[0m"
GREEN="\033[32m\033[01m"
FUCHSIA="\033[0;35m"
YELLOW="\033[33m"
BLUE="\033[0;36m"
GreenBG="\033[42;37m"
RedBG="\033[41;37m"
Font="\033[0m"
Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[提示]${Font_color_suffix}"
trojan_dir=/etc/trojan
trojan_bin_dir=${trojan_dir}/bin
trojan_conf_dir=${trojan_dir}/conf
trojan_conf_file=${trojan_conf_dir}/server.json
trojan_qr_config_file=${trojan_conf_dir}/qrconfig.json
trojan_systemd_file="/etc/systemd/system/trojan.service"
web_dir="/usr/wwwroot"
caddy_bin_dir="/usr/bin/caddy"
caddy_conf_dir="/etc/caddy"
caddy_conf="${caddy_conf_dir}/Caddyfile"
caddy_systemd_file="/lib/systemd/system/caddy.service"
static_website_file="intensify"

check_root() {
  [[ $EUID != 0 ]] && echo -e "${Error} ${RedBG} 当前非ROOT账号(或没有ROOT权限)，无法继续操作，请执行命令 ${Green_background_prefix}sudo -i${Font_color_suffix} 更换ROOT账号" && exit 1
}

set_SELINUX() {
  if [ -s /etc/selinux/config ] && grep 'SELINUX=enforcing' /etc/selinux/config; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    setenforce 0
  fi
}

check_sys() {
  if [[ -f /etc/redhat-release ]]; then
    release="centos"
  elif cat /etc/issue | grep -q -E -i "debian"; then
    release="debian"
  elif cat /etc/issue | grep -q -E -i "ubuntu"; then
    release="ubuntu"
  elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
  elif cat /proc/version | grep -q -E -i "debian"; then
    release="debian"
  elif cat /proc/version | grep -q -E -i "ubuntu"; then
    release="ubuntu"
  elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
    release="centos"
  fi
  bit=`uname -m`
}

sys_cmd(){
  if [[ ${release} == "centos" ]]; then
    cmd="yum"
  else
    cmd="apt"
  fi
}

sucess_or_fail() {
    if [[ 0 -eq $? ]]; then
        echo -e "${Info} ${GreenBG} $1 完成 ${Font}"
        sleep 1
    else
        echo -e "${Error} ${GreenBG}$1 失败${Font}"
        exit 1
    fi
}

install_dependency() {
  echo -e "${Info}开始升级系统，需要花费几分钟……"
  ${cmd} install apt-transport-https
  ${cmd} update -y
  sucess_or_fail "系统升级"
  echo -e "${Info}开始安装依赖……"
  if [[ ${cmd} == "apt" ]]; then
    apt -y install dnsutils
  else
    yum -y install bind-utils
  fi
  sucess_or_fail "DNS工具包安装"
  ${cmd} -y install wget
  sucess_or_fail "wget包安装"
  ${cmd} -y install unzip
  sucess_or_fail "unzip安装"
  ${cmd} -y install zip
  sucess_or_fail "zip安装"
  ${cmd} -y install curl
  sucess_or_fail "curl安装"
  ${cmd} -y install tar
  sucess_or_fail "tar安装"
  ${cmd} -y install git
  sucess_or_fail "git安装"
  ${cmd} -y install lsof
  sucess_or_fail "lsof安装"
  if [[ ${cmd} == "yum" ]]; then
    yum -y install crontabs
  else
    apt -y install cron
  fi
  sucess_or_fail "定时任务工具安装"
  ${cmd} -y install qrencode
  sucess_or_fail "qrencode安装"
  ${cmd} -y install bzip2
  sucess_or_fail "bzip2安装"
  if [[ ${cmd} == "yum" ]]; then
    yum install -y epel-release
  fi
  sucess_or_fail "epel-release安装"
  if [[ "${cmd}" == "yum" ]]; then
        ${cmd} -y groupinstall "Development tools"
    else
        ${cmd} -y install build-essential
  fi
  sucess_or_fail "编译工具包 安装"

  if [[ "${cmd}" == "yum" ]]; then
      ${cmd} -y install pcre pcre-devel zlib-devel epel-release
  else
      ${cmd} -y install libpcre3 libpcre3-dev zlib1g-dev dbus
  fi
  ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
}

close_firewall() {
  if systemctl status firewalld &>/dev/null; then
    systemctl stop firewalld.service
    systemctl disable firewalld.service
    echo -e "${Info} firewalld 已关闭 ${Font}"
  else
    echo -e "${Info} firewalld 服务未安装，无需关闭 ${Font}"
  fi
}

open_port() {
  if [[ ${release} != "centos" ]]; then
    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
    iptables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
    ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
    ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
    iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
    iptables -I INPUT -m state --state NEW -m udp -p udp --dport 443 -j ACCEPT
    ip6tables -I INPUT -m state --state NEW -m tcp -p tcp --dport 443 -j ACCEPT
    ip6tables -I INPUT -m state --state NEW -m udp -p udp --dport 443 -j ACCEPT
    iptables-save >/etc/iptables.rules.v4
		ip6tables-save >/etc/iptables.rules.v6
    netfilter-persistent save
    netfilter-persistent reload
  else
    firewall-cmd --zone=public --add-port=80/tcp --permanent
    firewall-cmd --zone=public --add-port=443/tcp --permanent
	fi
}

get_ip() {
  local_ip=$(curl -s https://ipinfo.io/ip)
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://api.ip.sb/ip)
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://api.ipify.org)
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://ip.seeip.org)
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://ifconfig.co/ip)
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s https://api.myip.com | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s icanhazip.com)
  [[ -z ${local_ip} ]] && ${local_ip}=$(curl -s myip.ipip.net | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}")
  [[ -z ${local_ip} ]] && echo -e "${Error}获取不到你vps的ip地址" && exit
}

check_domain() {
  if [ -n "$1" ]; then
    domain="$1"
    real_ip=$(ping "${domain}" -c 1 | sed '1{s/[^(]*(//;s/).*//;q}')
    if [ "${real_ip}" != "${local_ip}" ]; then
      echo -e "${Error}域名解析IP与本机IP不一致，请检查域名解析是否正确！"
      echo -e "域名解析IP：${real_ip}"
      echo -e "本机IP：${local_ip}"
      exit 1
    fi
  else
    echo -e "${Error}请输入要使用的域名"
    exit 1
  fi
}

# 安装Caddy
install_caddy() {
  echo -e "${Info}开始安装caddy……"
  [[ ! -d ${caddy_bin_dir} ]] && mkdir ${caddy_bin_dir}
  if [[ ! -f ${caddy_bin_dir}/caddy ]];then
    case  ${bit} in
    "x86_64")
      wget --no-check-certificate -O ${caddy_bin_dir}/caddy https://github.com/caddyserver/caddy/releases/download/v1.0.4/caddy_v1.0.4_linux_amd64
      sucess_or_fail "caddy下载"
      ;;    
    "i386" | "i686")
      wget --no-check-certificate -O ${caddy_bin_dir}/caddy https://github.com/caddyserver/caddy/releases/download/v1.0.4/caddy_v1.0.4_linux_386
      sucess_or_fail "caddy下载"
      ;;    
    "armv7l")
      wget --no-check-certificate -O ${caddy_bin_dir}/caddy https://github.com/caddyserver/caddy/releases/download/v1.0.4/caddy_v1.0.4_linux_arm7
      sucess_or_fail "caddy下载"
      ;;    
    *)
      echo -e "${Error}不支持 [${bit}] ! 请向开发者反馈[]中的名称，会及时添加支持。" && exit 1
      ;;    
    esac
    chmod +x ${caddy_bin_dir}/caddy
  else
    echo -e "${Info}caddy已存在，无需安装"
  fi
}

# 配置Caddy
config_caddy() {
  domain=$1
  caddy_trojan_port=$2
  mkdir -p ${web_dir}/${domain}
  mkdir -p ${caddy_conf_dir}
  cat >${caddy_conf} <<-EOF
${domain} {
  root * ${web_dir}/${domain}
  file_server
  tls /data/${domain}/fullchain.crt /data/${domain}/privkey.key
}
EOF
  systemctl restart caddy
  sucess_or_fail "Caddy配置"
}

# 安装Caddy服务
install_caddy_service() {
  touch ${caddy_systemd_file}
  cat >${caddy_systemd_file} <<-EOF
[Unit]
Description=Caddy HTTP/2 web server
Documentation=https://caddyserver.com/docs
After=network-online.target
Wants=network-online.target systemd-networkd-wait-online.service

[Service]
Restart=on-abnormal

; User and group the process will run as.
User=root
Group=root

; Letsencrypt-issued certificates will be written to this directory.
Environment=CADDYPATH=/data

; Always set "-root" to something safe in case it gets forgotten in the Caddyfile.
ExecStart=${caddy_bin_dir}/caddy -log stdout -agree=true -conf=${caddy_conf} -root=/var/tmp
ExecReload=${caddy_bin_dir}/caddy reload

; Use graceful shutdown with a reasonable timeout
KillMode=mixed
KillSignal=SIGQUIT
TimeoutStopSec=5s

; Limit the number of file descriptors; see 'man systemd.exec' for more limit settings.
LimitNOFILE=1048576
; Unmodified caddy is not expected to use more than that.
LimitNPROC=512

; Use private /tmp and /var/tmp, which are discarded after caddy stops.
PrivateTmp=true
; Use a minimal /dev (May bring additional security if switched to 'true', but it may not work on Raspberry Pi's or other devices, so it has been disabled in this dist.)
PrivateDevices=false
; Hide /home, /root, and /run/user. Nobody will steal your SSH-keys.
ProtectHome=true
; Make /usr, /boot, /etc and possibly some more folders read-only.
ProtectSystem=full
; … except /data, because we want Letsencrypt-certificates there. This merely retains r/w access rights, it does not add any new. Must still be writable on the host!
ReadWritePaths=/data

; The following additional security directives only work with systemd v229 or later.
; They further restrict privileges that can be gained by caddy. Uncomment if you like.
; Note that you may have to add capabilities required by any plugins in use.
;CapabilityBoundingSet=CAP_NET_BIND_SERVICE
;AmbientCapabilities=CAP_NET_BIND_SERVICE
;NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
sucess_or_fail "caddy后台管理服务安装"
}

# 卸载Caddy
uninstall_caddy() {
  if [[ -f ${caddy_bin_dir} ]] || [[ -f ${caddy_systemd_file} ]] || [[ -d ${caddy_conf_dir} ]] ; then
    echo -e "${Info}开始卸载Caddy……"
    [[ -f ${caddy_bin_dir} ]] && rm -f ${caddy_bin_dir}
    [[ -d ${caddy_conf_dir} ]] && rm -rf ${caddy_conf_dir}
    echo -e "${Info}Caddy卸载成功！"
  fi
}

# TLS证书生成脚本安装
tls_generate_script_install() {
    if [[ "${cmd}" == "yum" ]]; then
        ${cmd} install socat nc -y
    else
        ${cmd} install socat netcat-traditional -y
    fi
    sucess_or_fail "安装 tls 证书生成脚本依赖"

    curl https://get.acme.sh | sh
    sucess_or_fail "安装 tls 证书生成脚本"


    # 注册账号 , 你也可以切换到自己的邮箱， 但是没必要
    "$HOME"/.acme.sh/acme.sh --register-account  -m youremail@email.com --server zerossl
    sucess_or_fail "注册acme完成"
    source ~/.bashrc
}

# TLS证书生成
tls_generate() {
  if [[ -f "/data/${domain}/fullchain.crt" ]] && [[ -f "/data/${domain}/privkey.key" ]]; then
    echo -e "${Info}证书已存在……不需要再重新签发了……"
  else
    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force --test; then
        echo -e "${Info} TLS 证书测试签发成功，开始正式签发"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        sleep 2
    else
        echo -e "${Error}TLS 证书测试签发失败 "
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi

    if "$HOME"/.acme.sh/acme.sh --issue -d "${domain}" --standalone -k ec-256 --force; then
        echo -e "${Info} TLS 证书生成成功 "
        sleep 2
        [[ ! -d "/data" ]] && mkdir /data
        [[ ! -d "/data/${domain}" ]] && mkdir "/data/${domain}"
        if "$HOME"/.acme.sh/acme.sh --installcert -d "${domain}" --fullchainpath /data/${domain}/fullchain.crt --keypath /data/${domain}/privkey.key --ecc --force; then
            echo -e "${Info}证书配置成功 "
            sleep 2
        fi
    else
        echo -e "${Error} TLS 证书生成失败"
        rm -rf "$HOME/.acme.sh/${domain}_ecc"
        exit 1
    fi
  fi
}

# 下载安装Trojan-Go
download_install(){
  [[ ! -d ${trojan_dir} ]] && mkdir ${trojan_dir}
  [[ ! -d ${trojan_bin_dir} ]] && mkdir ${trojan_bin_dir}
  if [[ ! -f ${trojan_bin_dir}/trojan-go ]];then
      case  ${bit} in
      "x86_64")
        wget --no-check-certificate -O ${trojan_bin_dir}/trojan-go-linux-amd64.zip "https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-amd64.zip"
        sucess_or_fail "trojan-go下载"
        unzip -o -d ${trojan_bin_dir} ${trojan_bin_dir}/trojan-go-linux-amd64.zip
        sucess_or_fail "trojan-go解压"
        ;;
      "i386" | "i686")
        wget --no-check-certificate -O ${trojan_bin_dir}/trojan-go-linux-386.zip "https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-386.zip"
         sucess_or_fail "trojan-go下载"
        unzip -o -d ${trojan_bin_dir} ${trojan_bin_dir}/trojan-go-linux-386.zip
        sucess_or_fail "trojan-go解压"
        ;;
      "armv7l")
        wget --no-check-certificate -O ${trojan_bin_dir}/trojan-go-linux-armv7.zip "https://github.com/p4gefau1t/trojan-go/releases/download/v0.8.1/trojan-go-linux-armv7.zip"
         sucess_or_fail "trojan-go下载"
        unzip -o -d ${trojan_bin_dir} ${trojan_bin_dir}/trojan-go-linux-armv7.zip
        sucess_or_fail "trojan-go解压"
        ;;
      *)
        echo -e "${Error}不支持 [${bit}] ! 请向开发者反馈[]中的名称，会及时添加支持。" && exit 1
        ;;
      esac
      rm -f ${trojan_bin_dir}/trojan-go-linux-amd64.zip
      rm -f ${trojan_bin_dir}/trojan-go-linux-386.zip
      rm -f ${trojan_bin_dir}/trojan-go-linux-armv7.zip
  else
    echo -e "${Info}trojan-go已存在，无需安装"
  fi
}

# 卸载Trojan-Go
trojan_go_uninstall(){
  [[ -d ${trojan_dir} ]] && rm -rf ${trojan_dir} && echo -e "${Info}Trojan-go卸载成功"
}

# 设置端口
set_port() {
  port="$1"
  if [[ -n $2 ]]; then
    port_type="$2"
  else
    port_type="用户"
  fi
  echo -e "${Info}请输入${port_type}端口号 [1-65535],直接回车则使用默认端口: ${port}"
  read -rp "请输入端口号: " port_input
  [[ -n ${port_input} ]] && port=${port_input}
  if [[ ${port_input} -le 0 ]] || [[ ${port_input} -gt 65535 ]]; then
    echo -e "${Error}请输入正确的端口号！"
    exit 1
  fi
}

# 配置Trojan-Go
trojan_go_conf() {
  [[ ! -d ${trojan_conf_dir} ]] && mkdir ${trojan_conf_dir}
  [[ ! -f ${trojan_conf_file} ]] && touch ${trojan_conf_file}
  password="$1"
  if [[ -z $1 ]]; then
    password=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
  fi
  cat >${trojan_conf_file} <<-EOF
{
  "run_type": "server",
  "local_addr": "0.0.0.0",
  "local_port": ${trojanport},
  "remote_addr": "127.0.0.1",
  "remote_port": 80,
  "password": [
    "${password}"
  ],
  "ssl": {
    "cert": "/data/${domain}/fullchain.crt",
    "key": "/data/${domain}/privkey.key",
    "fallback_port": 80
  }
}
EOF
}

# 客户端配置
trojan_client_conf(){
  uuid=$(cat /proc/sys/kernel/random/uuid)
  touch ${web_dir}/${uuid}.json
  cat >${web_dir}/${uuid}.json <<EOF
  {
  "run_type": "client",
  "local_addr": "127.0.0.1",
  "local_port": ${trojanport},
  "remote_addr": "${domain}",
  "remote_port": ${webport},
  "log_level": 1,
  "log_file": "",
   "password": ["${password}"],
  "disable_http_check": false,
  "udp_timeout": 60,
  "ssl": {
    "verify": true,
    "verify_hostname": true,
    "cert": "/data/${domain}/fullchain.crt",
    "key": "/data/${domain}/privkey.key",
    "key_password": "",
    "cipher": "",
    "curves": "",
    "prefer_server_cipher": false,
    "sni": "",
    "alpn": [
      "http/1.1"
    ],
    "session_ticket": true,
    "reuse_session": true,
    "plain_http_response": "",
    "fallback_addr": "",
    "fallback_port": 0,
    "fingerprint": "firefox"
  },
  "tcp": {
    "no_delay": true,
    "keep_alive": true,
    "prefer_ipv4": false
  },
  "mux": {
    "enabled": false,
    "concurrency": 8,
    "idle_timeout": 60
  },
  "router": {
    "enabled": false,
    "bypass": [],
    "proxy": [],
    "block": [],
    "default_policy": "proxy",
    "domain_strategy": "as_is",
    "geoip": "$PROGRAM_DIR$/geoip.dat",
    "geosite": "$PROGRAM_DIR$/geosite.dat"
  },
  "websocket": {
    "enabled": false,
    "path": "",
    "host": ""
  },
  "shadowsocks": {
    "enabled": false,
    "method": "AES-128-GCM",
    "password": ""
  },
  "transport_plugin": {
    "enabled": false,
    "type": "",
    "command": "",
    "plugin_option": "",
    "arg": [],
    "env": []
  },
  "forward_proxy": {
    "enabled": false,
    "proxy_addr": "",
    "proxy_port": 0,
    "username": "",
    "password": ""
  },
  "mysql": {
    "enabled": false,
    "server_addr": "localhost",
    "server_port": 3306,
    "database": "",
    "username": "",
    "password": "",
    "check_rate": 60
  },
  "api": {
    "enabled": false,
    "api_addr": "",
    "api_port": 0,
    "ssl": {
      "enabled": false,
      "key": "",
      "cert": "",
      "verify_client": false,
      "client_cert": []
    }
  }
}
EOF
}

# Trojan-Go QR配置
trojan_go_qr_config(){
  touch ${trojan_qr_config_file}
  cat >${trojan_qr_config_file} <<-EOF
  "domain": "${domain}"
  "uuid": "${uuid}"
  "password": "${password}"
  "websocket_status":"${websocket_status}"
  "websocket_path":"${websocket_path}"
  "mux_status":"${mux_status}"
  "trojanport":"${trojanport}"
  "webport":"${webport}"
EOF
}

# Trojan-Go系统服务
trojan_go_systemd(){
  touch ${trojan_systemd_file}
  cat >${trojan_systemd_file} << EOF
[Unit]
Description=trojan
Documentation=https://github.com/p4gefau1t/trojan-go
After=network.target

[Service]
Type=simple
StandardError=journal
PIDFile=/usr/src/trojan/trojan/trojan.pid
ExecStart=/etc/trojan/bin/trojan-go -config /etc/trojan/conf/server.json
ExecReload=
ExecStop=/etc/trojan/bin/trojan-go
LimitNOFILE=51200
Restart=on-failure
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
}

# 下载伪装网站
download_website() {
  rm -rf ${web_dir}/${domain}/*
  wget -O ${web_dir}/${domain}/index.html https://raw.githubusercontent.com/ZarkMedo/trojan-go-deploy/main/trojan_go_tmpl.html
  sucess_or_fail "伪装网站下载"
}

# BBR相关函数
removeBbrSysctlConfig() {
    sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
    sed -i '/net.ipv4.tcp_ecn/d' /etc/sysctl.conf
}

# 使用默认选项启用BBR
enableBBRSysctlConfigDefault() {
    removeBbrSysctlConfig
    currentBBRText="bbr"
    currentQueueText="fq"
    currentECNValue="0"

    echo "net.core.default_qdisc=${currentQueueText}" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_congestion_control=${currentBBRText}" >> /etc/sysctl.conf
    echo "net.ipv4.tcp_ecn=${currentECNValue}" >> /etc/sysctl.conf

    isSysctlText=$(sysctl -p 2>&1 | grep "No such file")

    echo
    if [[ -z "$isSysctlText" ]]; then
        echo -e "${GREEN} 已成功开启 ${currentBBRText} + ${currentQueueText} ${Font}"
    else
        echo -e "${GREEN} 已成功开启 ${currentBBRText} ${Font}"
        echo -e "${RED} 但当前内核版本过低, 开启队列算法 ${currentQueueText} 失败! ${Font}"
    fi
    echo

    # 优化系统网络配置
    cat >> /etc/sysctl.conf <<-EOF

fs.file-max = 1000000
fs.inotify.max_user_instances = 8192

net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100

net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
EOF

    echo
    echo -e "${GREEN} 优化系统网络配置完成 ${Font}"
    echo
    sysctl -p
    echo
}

# 下载伪装网站模板
web_download() {
  [[ ! -d "${web_dir}" ]] && mkdir "${web_dir}"
  if [ -n "$1" ]; then
    aNum="$1"
    if [ "$aNum" -eq "0" ]; then
      aNum=$(shuf -i 1-15 -n 1)
      echo -e "${Info}随机选择网站模板编号: $aNum"
    fi
  else
    echo -e "${Tip}伪装网站未下载或下载失败,请选择下面的任意一个进行下载:
      ${Info}1. https://templated.co/intensify
      ${Info}2. https://templated.co/binary
      ${Info}3. https://templated.co/retrospect
      ${Info}4. https://templated.co/spatial
      ${Info}5. https://templated.co/monochromed
      ${Info}6. https://templated.co/transit
      ${Info}7. https://templated.co/interphase
      ${Info}8. https://templated.co/ion
      ${Info}9. https://templated.co/solarize
      ${Info}10. https://templated.co/phaseshift
      ${Info}11. https://templated.co/horizons
      ${Info}12. https://templated.co/grassygrass
      ${Info}13. https://templated.co/breadth
      ${Info}14. https://templated.co/undeviating
      ${Info}15. https://templated.co/lorikeet"
    read -rp "$(echo -e "${Tip}请输入你要下载的网站的数字:")" aNum
  fi
  case $aNum in
  1)
    static_website_file="intensify"
    echo ${static_website_file}
    ;;
  2)
    static_website_file="binary"
    echo ${static_website_file}
    ;;
  3)
    static_website_file="retrospect"
    echo ${static_website_file}
    ;;
  4)
    static_website_file="spatial"
    echo ${static_website_file}
    ;;
  5)
    static_website_file="monochromed"
    echo ${static_website_file}
    ;;
  6)
    static_website_file="transit"
    echo ${static_website_file}
    ;;
  7)
    static_website_file="interphase"
    echo ${static_website_file}
    ;;
  8)
    static_website_file="ion"
    echo ${static_website_file}
    ;;
  9)
    static_website_file="solarize"
    echo ${static_website_file}
    ;;
  10)
    static_website_file="phaseshift"
    echo ${static_website_file}
    ;;
  11)
    static_website_file="horizons"
    echo ${static_website_file}
    ;;
  12)
    static_website_file="grassygrass"
    echo ${static_website_file}
    ;;
  13)
    static_website_file="breadth"
    echo ${static_website_file}
    ;;
  14)
    static_website_file="undeviating"
    echo ${static_website_file}
    ;;
  15)
    static_website_file="lorikeet"
    echo ${static_website_file}
    ;;
  *)
    static_website_file="intensify"
    echo ${static_website_file}
    ;;
  esac
  wget -O ${web_dir}/web.zip --no-check-certificate "https://templated.co/download.php?filename=${static_website_file}"
  sucess_or_fail "伪装网站下载"
  unzip -o -d ${web_dir} ${web_dir}/web.zip
  sucess_or_fail "伪装网站解压"
  mv ${web_dir}/${static_website_file}/* ${web_dir}
}

# 生成Trojan-Go信息HTML页面
trojan_go_info_html() {
  cat >${web_dir}/${domain}/trojan.html <<-EOF
<!DOCTYPE html>
<html>
<head>
<title>Trojan-Go 安装信息</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
    body {
        font-family: Arial, sans-serif;
        line-height: 1.6;
        margin: 0;
        padding: 20px;
        background-color: #f5f5f5;
    }
    .container {
        max-width: 800px;
        margin: 0 auto;
        background-color: white;
        padding: 20px;
        border-radius: 5px;
        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    }
    h1 {
        color: #333;
        text-align: center;
    }
    .info-box {
        background-color: #f9f9f9;
        border-left: 4px solid #4CAF50;
        padding: 10px 15px;
        margin: 15px 0;
    }
    .qr-code {
        text-align: center;
        margin: 20px 0;
    }
    pre {
        background-color: #f4f4f4;
        padding: 10px;
        border-radius: 3px;
        overflow-x: auto;
    }
</style>
</head>
<body>
<div class="container">
    <h1>Trojan-Go 安装信息</h1>
    <div class="info-box">
        <p><strong>域名:</strong> ${domain}</p>
        <p><strong>端口:</strong> ${trojanport}</p>
        <p><strong>密码:</strong> ${password}</p>
    </div>
    <div class="qr-code">
        <img src="${uuid}.png" alt="Trojan-Go QR Code">
    </div>
    <h3>客户端配置:</h3>
    <pre id="config">${client_config}</pre>
</div>
</body>
</html>
EOF
}

# 显示Trojan-Go基本信息
trojan_go_basic_information() {
  {
echo -e "
${GREEN}=========================Trojan-go+tls 安装成功==============================
${FUCHSIA}=========================   Trojan-go 配置信息  =============================
${GREEN}地址：              ${domain}
${GREEN}端口：              ${trojanport}
${GREEN}密码：              ${password}
${GREEN}websocket状态：     ${websocket_status}
${GREEN}websocket路径：     ${websocket_path}
${GREEN}多路复用：          ${mux_status}
${FUCHSIA}=========================   客户端配置文件  ==========================================
${GREEN}详细信息: https://${domain}:${webport}/${uuid}.html${NO_COLOR}"
} | tee /etc/motd
}

# 下载trojan_mgr管理脚本
download_trojan_mgr() {
  cd /usr/local/bin || exit
  wget -N --no-check-certificate https://raw.githubusercontent.com/ZarkMedo/trojan-go-deploy/main/trojan_mgr.sh
  chmod +x trojan_mgr.sh
  ln -sf /usr/local/bin/trojan_mgr.sh /usr/local/bin/trojan
  sucess_or_fail "Trojan-Go管理脚本下载"
}

# 卸载trojan_mgr管理脚本
remove_trojan_mgr() {
  rm -rf /usr/local/bin/trojan_mgr.sh
  rm -rf /usr/local/bin/trojan
  echo -e "${Info}Trojan-Go管理脚本卸载成功！"
}

# 卸载所有组件
uninstall_all() {
  echo -e "${Info}开始卸载Trojan-Go和Caddy..."
  trojan_go_uninstall
  uninstall_caddy
  remove_trojan_mgr
  rm -rf ${web_dir}
  echo -e "${Info}卸载完成！"
}

open_websocket(){
  sed -i "53c    \"enabled\": true," ${trojan_conf_file}
  sed -i "53c    \"enabled\": true," ${web_dir}/"${uuid}".json
  sed -i "54c    \"path\": \"/trojan\"," ${trojan_conf_file}
  sed -i "54c    \"path\": \"/trojan\"," ${web_dir}/"${uuid}".json
  websocket_path="/trojan"
  websocket_status="开启"
  ;;
}

# 主函数
main() {
  check_root
  check_sys
  sys_cmd
  set_SELINUX
  get_ip

  echo -e "${GREEN}欢迎使用Trojan-Go一键安装脚本${Font}"
  echo -e "${GREEN}==================================${Font}"
  
  # 检查是否有命令行参数
  if [ $# -ge 1 ]; then
    # 通过命令行参数直接部署
    # 参数1: 域名
    domain=$1
    check_domain "${domain}"
    echo -e "${Info}域名: ${domain}"
    
    # 参数2: Caddy端口，如果为0则随机生成
    if [ -n "$2" ]; then
      caddy_trojan_port=$2
      if [ "$caddy_trojan_port" -eq 0 ]; then
        caddy_trojan_port=$(shuf -i 10000-65000 -n 1)
        echo -e "${Info}随机生成Caddy端口: ${caddy_trojan_port}"
      fi
    else
      caddy_trojan_port=80
    fi
    echo -e "${Info}参数2: Caddy端口=> caddy_trojan_port: ${caddy_trojan_port}"
    
    # 参数3: Trojan端口
    if [ -n "$3" ]; then
      trojanport=$3
    else
      trojanport=$(shuf -i 10000-65000 -n 1)
        echo -e "${Info}随机生成trojan端口: ${trojanport}"
    fi
    echo -e "${Info}参数3: Trojan端口=> trojanport: ${trojanport}"
    
    # 参数4: 密码
    if [ -n "$4" ]; then
      password=$4
    else
      password=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
      echo -e "${Info}随机生成密码: ${password}"
    fi
    echo -e "${Info}参数4: 密码=> password: ${password}"
    
    webport=$caddy_trojan_port
    
    # 安装依赖
    install_dependency
    close_firewall
    open_port
    
    # 安装TLS证书
    tls_generate_script_install
    tls_generate
    
    # 安装Caddy
    install_caddy
    install_caddy_service
    
    # 安装Trojan-Go
    download_install
    trojan_go_conf
    trojan_go_systemd
    
    # 下载伪装网站
    mkdir -p ${web_dir}/${domain}
    web_download 1
    # 移动网站文件到域名目录
    mv ${web_dir}/* ${web_dir}/${domain}/ 2>/dev/null
    [[ -f ${web_dir}/${domain}/web.zip ]] && rm -rf ${web_dir}/${domain}/web.zip
    
    # 配置Caddy
    config_caddy
    
    # 生成客户端配置
    client_config=$(cat ${trojan_conf_file} | sed 's/\n/\\n/g')
    trojan_client_conf
    trojan_go_qr_config
    
    # 生成二维码
    cd ${web_dir}/${domain} || exit
    qrencode -o ${uuid}.png -s 8 "trojan://${password}@${domain}:${trojanport}"
    
    # 生成信息页面
    trojan_go_info_html
    
    # 下载管理脚本
    download_trojan_mgr
    
    # 启动服务
    systemctl enable trojan.service
    systemctl start trojan.service
    systemctl enable caddy.service
    systemctl start caddy.service
    
    # 启用BBR
    enableBBRSysctlConfigDefault
    
    # 显示安装信息
    trojan_go_basic_information
  else
    # 交互式菜单
    echo -e "1. 安装Trojan-Go + Caddy + BBR"
    echo -e "=================================="
    
    # 设置域名
    read -rp "请输入你的域名(必须已解析到本机IP): " domain
    [[ -z ${domain} ]] && domain="example.com"
    check_domain "${domain}"
    
    # 设置端口
    trojanport=443
    webport=80
    set_port ${trojanport} "Trojan-Go"
    trojanport=${port}
    
    # 设置密码
    read -rp "请输入Trojan-Go密码(留空则随机生成): " password
    [[ -z ${password} ]] && password=$(cat /dev/urandom | head -1 | md5sum | head -c 8)
    
    # 安装依赖
    install_dependency
    close_firewall
    open_port
    
    # 安装TLS证书
    tls_generate_script_install
    tls_generate
    
    # 安装Caddy
    install_caddy
    install_caddy_service
    
    # 安装Trojan-Go
    download_install
    trojan_go_conf
    trojan_go_systemd
    
    # 下载伪装网站
    mkdir -p ${web_dir}/${domain}
    web_download 1
    # 移动网站文件到域名目录
    mv ${web_dir}/* ${web_dir}/${domain}/ 2>/dev/null
    [[ -f ${web_dir}/${domain}/web.zip ]] && rm -rf ${web_dir}/${domain}/web.zip
    
    # 配置Caddy
    config_caddy
    
    # 生成客户端配置
    client_config=$(cat ${trojan_conf_file} | sed 's/\n/\\n/g')
    trojan_client_conf
    open_websocket
    trojan_go_qr_config
    
    # 生成二维码
    cd ${web_dir}/${domain} || exit
    qrencode -o ${uuid}.png -s 8 "trojan://${password}@${domain}:${trojanport}"
    
    # 生成信息页面
    trojan_go_info_html
    
    # 下载管理脚本
    download_trojan_mgr
    
    # 启动服务
    systemctl enable trojan.service
    systemctl start trojan.service
    systemctl enable caddy.service
    systemctl start caddy.service
    
    # 启用BBR
    enableBBRSysctlConfigDefault
    
    # 显示安装信息
    trojan_go_basic_information
  fi
}

# 执行主函数
main "$@"