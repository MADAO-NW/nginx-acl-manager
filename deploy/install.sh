#!/usr/bin/env bash

set -Eeuo pipefail

GITHUB_REPO="MADAO-NW/nginx-acl-manager"
SERVICE_NAME="nginx-acl-manager"
SERVICE_USER="nginx-acl-manager"
BINARY_PATH="/usr/local/bin/nginx-acl-manager"
CONFIG_DIR="/etc/nginx-acl-manager"
DATA_DIR="/var/lib/nginx-acl-manager"
CONFIG_PATH="${CONFIG_DIR}/config.json"
AUTH_PATH="${CONFIG_DIR}/auth.json"
CANDIDATE_PATH="${DATA_DIR}/staging/nginx-profile-candidate.json"
UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
PROFILE_APPLY_UNIT_PATH="/etc/systemd/system/nginx-acl-manager-profile-apply.service"
PUBLISH_UNIT_PATH="/etc/systemd/system/nginx-acl-manager-publish.service"
RECOVER_UNIT_PATH="/etc/systemd/system/nginx-acl-manager-recover.service"
AUTH_APPLY_UNIT_PATH="/etc/systemd/system/nginx-acl-manager-auth-apply.service"
SUDOERS_PATH="/etc/sudoers.d/nginx-acl-manager"

ACTION="install"
REQUESTED_VERSION=""
PORT="7582"
PORT_PROVIDED="false"
NGINX_BIN=""
NGINX_CONF=""
NGINX_PREFIX=""
NGINX_SERVICE="nginx.service"
NGINX_HTTP_INCLUDE="/etc/nginx/conf.d/50-nginx-acl-manager.conf"
NGINX_REAL_IP_SNIPPET="/etc/nginx/snippets/cloudflare-real-ip.conf"
NGINX_BIN_PROVIDED="false"
NGINX_CONF_PROVIDED="false"
TEMP_DIR=""
OS=""
ARCH=""

log() {
    printf '[nginx-acl-manager] %s\n' "$*"
}

fail() {
    printf '[nginx-acl-manager] 错误: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
用法:
  install.sh [install] [安装参数]
  install.sh upgrade
  install.sh install-version <vX.Y.Z>
  install.sh uninstall

安装参数:
  --port <1-65535>                 管理页面端口，默认 7582
  --nginx-bin <绝对路径>           Nginx 二进制候选值
  --nginx-conf <绝对路径>          Nginx 主配置候选值
  --nginx-prefix <绝对路径>        Nginx prefix 候选值
  --nginx-service <名称.service>   Nginx systemd service 候选值
  --nginx-http-include <绝对路径>  管理器 http include 候选值
  --nginx-real-ip-snippet <路径>   real IP snippet 候选值

示例:
  curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh | sudo bash
  curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh | sudo bash -s -- --port 17582
EOF
}

cleanup() {
    if [ -n "$TEMP_DIR" ] && [ -d "$TEMP_DIR" ]; then
        rm -rf -- "$TEMP_DIR"
    fi
}

trap cleanup EXIT

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        fail "请使用 sudo 或 root 权限运行"
    fi
}

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        fail "缺少必要命令: $1"
    fi
}

validate_port() {
    if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
        fail "端口必须是 1 到 65535 之间的整数"
    fi
}

require_absolute_path() {
    local label="$1"
    local value="$2"
    if [[ "$value" != /* ]] || [[ "$value" == *$'\n'* ]] || [[ "$value" == *$'\r'* ]]; then
        fail "${label}必须是无换行的绝对路径"
    fi
}

parse_arguments() {
    if [ "$#" -gt 0 ]; then
        case "$1" in
            install|upgrade|uninstall)
                ACTION="$1"
                shift
                ;;
            install-version)
                ACTION="$1"
                shift
                if [ "$#" -eq 0 ]; then
                    fail "install-version 缺少版本号"
                fi
                REQUESTED_VERSION="$1"
                shift
                ;;
            --help|-h)
                usage
                exit 0
                ;;
        esac
    fi

    while [ "$#" -gt 0 ]; do
        case "$1" in
            --port)
                [ "$#" -ge 2 ] || fail "--port 缺少值"
                PORT="$2"
                PORT_PROVIDED="true"
                shift 2
                ;;
            --nginx-bin)
                [ "$#" -ge 2 ] || fail "--nginx-bin 缺少值"
                NGINX_BIN="$2"
                NGINX_BIN_PROVIDED="true"
                shift 2
                ;;
            --nginx-conf)
                [ "$#" -ge 2 ] || fail "--nginx-conf 缺少值"
                NGINX_CONF="$2"
                NGINX_CONF_PROVIDED="true"
                shift 2
                ;;
            --nginx-prefix)
                [ "$#" -ge 2 ] || fail "--nginx-prefix 缺少值"
                NGINX_PREFIX="$2"
                shift 2
                ;;
            --nginx-service)
                [ "$#" -ge 2 ] || fail "--nginx-service 缺少值"
                NGINX_SERVICE="$2"
                shift 2
                ;;
            --nginx-http-include)
                [ "$#" -ge 2 ] || fail "--nginx-http-include 缺少值"
                NGINX_HTTP_INCLUDE="$2"
                shift 2
                ;;
            --nginx-real-ip-snippet)
                [ "$#" -ge 2 ] || fail "--nginx-real-ip-snippet 缺少值"
                NGINX_REAL_IP_SNIPPET="$2"
                shift 2
                ;;
            --help|-h)
                usage
                exit 0
                ;;
            *)
                fail "未知参数: $1"
                ;;
        esac
    done
}

detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    [ "$OS" = "linux" ] || fail "当前安装脚本只支持 Linux"

    case "$(uname -m)" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            fail "不支持的 CPU 架构: $(uname -m)"
            ;;
    esac
}

normalize_version() {
    local value="$1"
    if [[ "$value" != v* ]]; then
        value="v${value}"
    fi
    if ! [[ "$value" =~ ^v[0-9][0-9A-Za-z.-]*$ ]]; then
        fail "版本号格式无效: $value"
    fi
    printf '%s\n' "$value"
}

latest_version() {
    local effective_url
    effective_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${GITHUB_REPO}/releases/latest")" || fail "无法获取最新 Release"
    normalize_version "${effective_url##*/}"
}

download_release() {
    local version="$1"
    local version_number="${version#v}"
    local archive="nginx-acl-manager_${version_number}_${OS}_${ARCH}.tar.gz"
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${version}"

    TEMP_DIR="$(mktemp -d)"
    log "下载 ${archive}"
    curl -fL --retry 3 --connect-timeout 10 --max-time 300 "${base_url}/${archive}" -o "${TEMP_DIR}/${archive}"
    curl -fL --retry 3 --connect-timeout 10 --max-time 60 "${base_url}/checksums.txt" -o "${TEMP_DIR}/checksums.txt"

    local expected
    local actual
    expected="$(awk -v archive="$archive" '$2 == archive { print $1 }' "${TEMP_DIR}/checksums.txt")"
    [ -n "$expected" ] || fail "checksums.txt 中缺少 ${archive}"
    actual="$(sha256sum "${TEMP_DIR}/${archive}" | awk '{ print $1 }')"
    [ "$expected" = "$actual" ] || fail "Release 文件 SHA-256 校验失败"

    tar -xzf "${TEMP_DIR}/${archive}" -C "$TEMP_DIR"
    [ -f "${TEMP_DIR}/nginx-acl-manager" ] || fail "Release 压缩包缺少 nginx-acl-manager"
    chmod 0755 "${TEMP_DIR}/nginx-acl-manager"
    local binary_version
    binary_version="$("${TEMP_DIR}/nginx-acl-manager" --version)"
    [ "$binary_version" = "$version" ] || fail "二进制版本 ${binary_version} 与 Release ${version} 不一致"
}

ensure_service_user_and_directories() {
    if ! id "$SERVICE_USER" >/dev/null 2>&1; then
        local nologin_shell
        nologin_shell="$(command -v nologin || true)"
        [ -n "$nologin_shell" ] || fail "找不到 nologin shell"
        useradd --system --user-group --home-dir "$DATA_DIR" --shell "$nologin_shell" "$SERVICE_USER"
    fi

    install -d -m 0750 -o root -g "$SERVICE_USER" "$CONFIG_DIR"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$DATA_DIR"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "${DATA_DIR}/staging"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "${DATA_DIR}/auth"
    install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "${DATA_DIR}/drafts/projects"
    install -d -m 0750 -o root -g "$SERVICE_USER" "${DATA_DIR}/results"
    install -d -m 0755 -o root -g root "/etc/nginx/access-control/releases"
}

write_service_unit() {
    cat >"$UNIT_PATH" <<EOF
# managed-by: nginx-acl-manager
[Unit]
Description=Nginx ACL Manager
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
ExecStart=${BINARY_PATH} serve
Restart=on-failure
RestartSec=5s
UMask=0027
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=${DATA_DIR}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "$UNIT_PATH"
    chown root:root "$UNIT_PATH"
}

write_privileged_units_and_sudoers() {
    local managed_path
    for managed_path in "$PROFILE_APPLY_UNIT_PATH" "$PUBLISH_UNIT_PATH" "$RECOVER_UNIT_PATH" "$AUTH_APPLY_UNIT_PATH" "$SUDOERS_PATH"; do
        if [ -e "$managed_path" ] && ! grep -qx '# managed-by: nginx-acl-manager' "$managed_path"; then
            fail "目标文件已存在且不属于本工具: ${managed_path}"
        fi
    done
    cat >"$PROFILE_APPLY_UNIT_PATH" <<EOF
# managed-by: nginx-acl-manager
[Unit]
Description=Validate and apply Nginx ACL Manager profile
After=${SERVICE_NAME}.service

[Service]
Type=oneshot
User=root
Group=root
UMask=0027
ExecStart=${BINARY_PATH} profile apply-candidate
EOF

    cat >"$PUBLISH_UNIT_PATH" <<EOF
# managed-by: nginx-acl-manager
[Unit]
Description=Publish Nginx ACL Manager rules
After=${SERVICE_NAME}.service

[Service]
Type=oneshot
User=root
Group=root
UMask=0027
ExecStart=${BINARY_PATH} publish
EOF

    cat >"$RECOVER_UNIT_PATH" <<EOF
# managed-by: nginx-acl-manager
[Unit]
Description=Recover unfinished Nginx ACL Manager publish

[Service]
Type=oneshot
User=root
Group=root
UMask=0027
ExecStart=${BINARY_PATH} recover
EOF

    cat >"$AUTH_APPLY_UNIT_PATH" <<EOF
# managed-by: nginx-acl-manager
[Unit]
Description=Apply Nginx ACL Manager authentication changes
After=${SERVICE_NAME}.service

[Service]
Type=oneshot
User=root
Group=root
UMask=0027
ExecStart=${BINARY_PATH} auth apply-candidate
EOF

    cat >"$SUDOERS_PATH" <<EOF
# managed-by: nginx-acl-manager
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start nginx-acl-manager-profile-apply.service
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start nginx-acl-manager-publish.service
${SERVICE_USER} ALL=(root) NOPASSWD: /usr/bin/systemctl start nginx-acl-manager-auth-apply.service
EOF
    chmod 0644 "$PROFILE_APPLY_UNIT_PATH" "$PUBLISH_UNIT_PATH" "$RECOVER_UNIT_PATH" "$AUTH_APPLY_UNIT_PATH"
    chown root:root "$PROFILE_APPLY_UNIT_PATH" "$PUBLISH_UNIT_PATH" "$RECOVER_UNIT_PATH" "$AUTH_APPLY_UNIT_PATH"
    chmod 0440 "$SUDOERS_PATH"
    chown root:root "$SUDOERS_PATH"
    visudo -cf "$SUDOERS_PATH" >/dev/null || fail "sudoers 配置校验失败"
}

detect_nginx_candidate() {
    if [ -z "$NGINX_BIN" ]; then
        NGINX_BIN="$(command -v nginx || true)"
    fi
    if [ -n "$NGINX_BIN" ]; then
        if [[ "$NGINX_BIN" != /* ]]; then
            if [ "$NGINX_BIN_PROVIDED" = "true" ]; then
                fail "Nginx 二进制必须是绝对路径"
            fi
            NGINX_BIN=""
        fi
    fi

    if [ -z "$NGINX_CONF" ] && [ -n "$NGINX_BIN" ] && [ -x "$NGINX_BIN" ]; then
        NGINX_CONF="$("$NGINX_BIN" -V 2>&1 | sed -n 's/.*--conf-path=\([^ ]*\).*/\1/p' | head -n 1)"
    fi
    if [ -n "$NGINX_CONF" ] && [[ "$NGINX_CONF" != /* ]]; then
        if [ "$NGINX_CONF_PROVIDED" = "true" ]; then
            fail "Nginx 主配置必须是绝对路径"
        fi
        NGINX_CONF=""
    fi
}

seed_nginx_candidate() {
    detect_nginx_candidate
    if [ -z "$NGINX_BIN" ] || [ -z "$NGINX_CONF" ]; then
        log "未探测到完整 Nginx 路径，首次登录后请在 Web 页面填写"
        return
    fi

    require_absolute_path "Nginx 主配置" "$NGINX_CONF"
    require_absolute_path "Nginx http include" "$NGINX_HTTP_INCLUDE"
    require_absolute_path "Nginx real IP snippet" "$NGINX_REAL_IP_SNIPPET"
    local arguments=(
        profile seed-candidate
        --output "$CANDIDATE_PATH"
        --nginx-bin "$NGINX_BIN"
        --nginx-conf "$NGINX_CONF"
        --nginx-service "$NGINX_SERVICE"
        --nginx-http-include "$NGINX_HTTP_INCLUDE"
        --nginx-real-ip-snippet "$NGINX_REAL_IP_SNIPPET"
    )
    if [ -n "$NGINX_PREFIX" ]; then
        require_absolute_path "Nginx prefix" "$NGINX_PREFIX"
        arguments+=(--nginx-prefix "$NGINX_PREFIX")
    fi
    "$BINARY_PATH" "${arguments[@]}"
    chown "$SERVICE_USER:$SERVICE_USER" "$CANDIDATE_PATH"
    chmod 0600 "$CANDIDATE_PATH"
}

fresh_install() {
    local reuse_existing="false"
    if [ -e "$CONFIG_PATH" ] || [ -e "$AUTH_PATH" ]; then
        if [ ! -f "$CONFIG_PATH" ] || [ ! -f "$AUTH_PATH" ]; then
            fail "检测到不完整的保留配置，请先检查 ${CONFIG_DIR}"
        fi
        if [ "$PORT_PROVIDED" = "true" ]; then
            fail "重新安装会保留原端口；请安装后使用 config set-port 修改"
        fi
        reuse_existing="true"
    fi

    local version
    if [ -n "$REQUESTED_VERSION" ]; then
        version="$(normalize_version "$REQUESTED_VERSION")"
    else
        version="$(latest_version)"
    fi
    download_release "$version"
    ensure_service_user_and_directories
    install -m 0755 -o root -g root "${TEMP_DIR}/nginx-acl-manager" "$BINARY_PATH"

    if [ "$reuse_existing" = "true" ]; then
        log "检测到卸载后保留的配置和管理员凭据，将直接复用"
    else
        "$BINARY_PATH" config init --output "$CONFIG_PATH" --port "$PORT"
        log "请设置唯一管理员账号，密码不会回显"
        "$BINARY_PATH" admin init --output "$AUTH_PATH"
    fi
    chown "root:$SERVICE_USER" "$CONFIG_PATH" "$AUTH_PATH"
    chmod 0640 "$CONFIG_PATH" "$AUTH_PATH"
    if [ -f "${CONFIG_DIR}/nginx-profile.json" ]; then
        chown "root:$SERVICE_USER" "${CONFIG_DIR}/nginx-profile.json"
        chmod 0640 "${CONFIG_DIR}/nginx-profile.json"
    fi

    if [ -f "$CANDIDATE_PATH" ]; then
        chown "$SERVICE_USER:$SERVICE_USER" "$CANDIDATE_PATH"
        chmod 0600 "$CANDIDATE_PATH"
    else
        seed_nginx_candidate
    fi
    write_service_unit
    write_privileged_units_and_sudoers
    systemctl daemon-reload
    if ! systemctl enable --now "${SERVICE_NAME}.service"; then
        systemctl status "${SERVICE_NAME}.service" --no-pager || true
        fail "服务启动失败"
    fi

    log "安装完成，版本 ${version}"
    if [ "$reuse_existing" = "true" ]; then
        log "服务监听端口沿用 ${CONFIG_PATH} 中的保留值"
    else
        log "服务监听 0.0.0.0:${PORT}，请通过防火墙或反向代理限制访问范围"
    fi
}

upgrade_install() {
    [ -x "$BINARY_PATH" ] || fail "尚未安装 nginx-acl-manager"
    [ -f "$CONFIG_PATH" ] || fail "缺少现有服务配置"
    local version
    if [ "$ACTION" = "install-version" ]; then
        version="$(normalize_version "$REQUESTED_VERSION")"
    else
        version="$(latest_version)"
    fi

    local current_version
    current_version="$("$BINARY_PATH" --version 2>/dev/null || true)"
    if [ "$current_version" = "$version" ]; then
        log "当前已经是 ${version}"
        return
    fi

    download_release "$version"
    ensure_service_user_and_directories
    cp -p "$BINARY_PATH" "${TEMP_DIR}/nginx-acl-manager.previous"
    systemctl stop "${SERVICE_NAME}.service"
    install -m 0755 -o root -g root "${TEMP_DIR}/nginx-acl-manager" "$BINARY_PATH"
    write_service_unit
    write_privileged_units_and_sudoers
    systemctl daemon-reload
    if ! systemctl start "${SERVICE_NAME}.service"; then
        install -m 0755 -o root -g root "${TEMP_DIR}/nginx-acl-manager.previous" "$BINARY_PATH"
        systemctl start "${SERVICE_NAME}.service" || true
        fail "新版本启动失败，已恢复 ${current_version}"
    fi
    log "已从 ${current_version} 更新到 ${version}"
}

uninstall_manager() {
    printf '将停止服务并删除二进制、systemd unit 和系统用户；配置与数据会保留。继续？[y/N] ' >/dev/tty
    local answer
    read -r answer </dev/tty
    case "$answer" in
        y|Y|yes|YES)
            ;;
        *)
            log "已取消卸载"
            return
            ;;
    esac

    systemctl disable --now "${SERVICE_NAME}.service" >/dev/null 2>&1 || true
    local active_profile="${CONFIG_DIR}/nginx-profile.json"
    if [ -f "$active_profile" ]; then
        local active_nginx_service
        active_nginx_service="$(sed -n 's/^[[:space:]]*"serviceName":[[:space:]]*"\([A-Za-z0-9_.@-]*\.service\)"[,]*[[:space:]]*$/\1/p' "$active_profile" | head -n 1)"
        if [[ "$active_nginx_service" =~ ^[A-Za-z0-9_.@-]+\.service$ ]]; then
            local managed_drop_in="/etc/systemd/system/${active_nginx_service}.d/50-nginx-acl-manager-recover.conf"
            if [ -f "$managed_drop_in" ] && grep -qx '# managed-by: nginx-acl-manager' "$managed_drop_in" && grep -qx 'Requires=nginx-acl-manager-recover.service' "$managed_drop_in"; then
                rm -f -- "$managed_drop_in"
                rmdir -- "/etc/systemd/system/${active_nginx_service}.d" >/dev/null 2>&1 || true
            fi
        fi
    fi
    rm -f -- "$UNIT_PATH"
    rm -f -- "$PROFILE_APPLY_UNIT_PATH" "$PUBLISH_UNIT_PATH" "$RECOVER_UNIT_PATH" "$AUTH_APPLY_UNIT_PATH" "$SUDOERS_PATH"
    rm -f -- "$BINARY_PATH"
    systemctl daemon-reload
    if id "$SERVICE_USER" >/dev/null 2>&1; then
        userdel "$SERVICE_USER"
    fi
    log "已卸载程序；${CONFIG_DIR} 和 ${DATA_DIR} 已保留"
}

main() {
    parse_arguments "$@"
    require_root

    if [ "$ACTION" = "uninstall" ]; then
        require_command systemctl
        require_command userdel
        uninstall_manager
        return
    fi

    validate_port
    detect_platform
    for command in curl tar sha256sum install mktemp systemctl visudo; do
        require_command "$command"
    done

    case "$ACTION" in
        install)
            require_command useradd
            require_command stty
            fresh_install
            ;;
        upgrade|install-version)
            upgrade_install
            ;;
        *)
            fail "不支持的操作: $ACTION"
            ;;
    esac
}

main "$@"
