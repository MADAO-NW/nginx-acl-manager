# nginx-acl-manager

单机 Nginx URL 访问控制管理工具。项目采用 Go 单二进制、服务端渲染页面和 systemd 部署，管理页面固定监听回环地址，默认端口为 `7582`。

## 当前实现状态

当前版本已经包含：

- 单管理员 Argon2id 凭据初始化与登录；
- 内存 Session、CSRF 和 Host 校验；
- 管理端口配置；
- Nginx Profile 候选配置页面、结构校验和原子保存；
- Linux `amd64/arm64` GitHub Release 自动构建；
- 一键安装、升级、指定版本升级/回退和卸载脚本。

规则管理、root Profile apply、Nginx 配置发布与历史恢复仍按[技术方案](./技术方案.md)继续实现。当前页面可以登录并维护候选 Nginx Profile，但“验证并应用”尚不可用。

## 一键安装

前提条件：Linux、systemd，以及已经安装并运行的 Nginx。安装脚本不会安装、升级或改写 Nginx。

```bash
curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh | sudo bash
```

脚本会完成以下操作：

1. 识别 `amd64` 或 `arm64`；
2. 从 GitHub Releases 下载最新预编译包并强制校验 SHA-256；
3. 安装二进制到 `/usr/local/bin/nginx-acl-manager`；
4. 创建专用非 root 系统用户、配置目录和数据目录；
5. 通过本机 TTY 设置唯一管理员用户名和密码；
6. 探测 Nginx 路径并保存候选 Profile；
7. 注册并启动 `nginx-acl-manager.service`。

服务只监听 `127.0.0.1:7582`，不会开放防火墙。远程访问时使用 SSH 隧道：

```bash
ssh -L 7582:127.0.0.1:7582 <user>@<server>
```

然后访问 `http://127.0.0.1:7582`。

### 安装参数

覆盖管理端口：

```bash
curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh \
  | sudo bash -s -- --port 17582
```

覆盖 Nginx 候选配置：

```bash
curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh \
  | sudo bash -s -- \
      --nginx-bin /opt/nginx/sbin/nginx \
      --nginx-conf /opt/nginx/conf/nginx.conf \
      --nginx-prefix /opt/nginx \
      --nginx-service custom-nginx.service \
      --nginx-http-include /opt/nginx/conf/http.d/50-nginx-acl-manager.conf \
      --nginx-real-ip-snippet /opt/nginx/conf/snippets/cloudflare-real-ip.conf
```

这些参数只用于预填候选 Profile，不会绕过 Web 登录和后续 root 强校验，也不会在安装阶段修改现有 Nginx 配置。

### 维护命令

```bash
# 修改管理员用户名
sudo nginx-acl-manager admin set-username

# 修改管理员密码
sudo nginx-acl-manager admin set-password

# 同时重置用户名和密码
sudo nginx-acl-manager admin reset

# 修改管理页面端口
sudo nginx-acl-manager config set-port --port 17582

# 升级到最新 Release
curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh \
  | sudo bash -s -- upgrade

# 将已有安装升级或回退到指定版本
curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh \
  | sudo bash -s -- install-version v0.1.0

# 卸载程序，保留配置与数据
curl -fsSL https://raw.githubusercontent.com/MADAO-NW/nginx-acl-manager/main/deploy/install.sh \
  | sudo bash -s -- uninstall
```

管理员密码始终从 `/dev/tty` 交互读取且不回显，不支持通过命令参数或环境变量传入。

## 发布版本

推送 `v*` 标签后，[Release workflow](./.github/workflows/release.yml) 会先运行 `go test ./...` 和 `go vet ./...`，然后构建 Linux `amd64/arm64` 静态二进制、生成 `checksums.txt` 并创建 GitHub Release。

```bash
git tag -a v0.1.0 -m "v0.1.0"
git push origin v0.1.0
```

工作流只使用仓库自动提供的 `GITHUB_TOKEN`，不需要额外配置 Release Token。

## 本地开发

```bash
go test ./...
go vet ./...
go build ./cmd/nginx-acl-manager
```
