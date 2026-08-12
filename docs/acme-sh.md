# acme.sh 使用指南

本文档说明如何在 macOS、Linux 和 Windows 环境安装 `acme.sh`，并为指定域名申请、部署及续期 SSL/TLS 证书。

> CertKeeper 的服务端镜像已内置 `acme.sh`。本指南适用于直接在主机上使用 `acme.sh`，或为反向代理等其他服务签发证书。

---

## 前置条件

- 域名的 DNS 记录已解析到验证所用的服务器，或拥有该域名 DNS 服务商的 API 凭据。
- 使用 HTTP-01 验证时，公网可以访问域名的 `80` 端口。
- 申请通配符证书（如 `*.example.com`）必须使用 DNS-01 验证。
- 申请服务需要可访问 [Let's Encrypt](https://letsencrypt.org/) 或所配置的其他 ACME CA。

`acme.sh` 默认签发 ECC 证书；除非有旧客户端兼容需求，建议继续使用默认值。

---

## 安装 acme.sh

### macOS

macOS 默认 Shell 为 `zsh`。执行以下命令安装，并将邮箱替换为实际地址：

```bash
curl https://get.acme.sh | sh -s email=you@example.com
```

重新打开终端，或加载 Shell 配置后确认安装：

```bash
source ~/.zshrc
acme.sh --version
```

程序默认安装在 `~/.acme.sh/acme.sh`。

### Linux

在 Debian、Ubuntu、RHEL、CentOS、Fedora、Alpine 等发行版中均可执行：

```bash
curl https://get.acme.sh | sh -s email=you@example.com
```

重新登录终端，或加载 Shell 配置后确认安装：

```bash
source ~/.bashrc
acme.sh --version
```

若系统尚未安装 `curl`，可按发行版安装：

```bash
# Debian / Ubuntu
sudo apt update && sudo apt install -y curl

# RHEL / CentOS / Fedora
sudo dnf install -y curl

# Alpine
sudo apk add curl
```

### Windows

`acme.sh` 是 Shell 脚本，不建议在纯 `cmd` 或 PowerShell 中直接运行。建议通过 Windows Subsystem for Linux（WSL）安装和使用。

以管理员身份打开 PowerShell：

```powershell
wsl --install
```

重启后完成 Ubuntu 初始化并创建 Linux 用户，打开 Ubuntu 终端执行：

```bash
sudo apt update
sudo apt install -y curl
curl https://get.acme.sh | sh -s email=you@example.com
source ~/.bashrc
acme.sh --version
```

证书会保存在 WSL 的 Linux 文件系统 `~/.acme.sh/` 中。若 Web 服务运行在 Windows 宿主机，建议使用 DNS-01 验证；使用 HTTP-01 时，需确保验证请求能够到达 WSL 中运行的验证服务。

---

## 常用命令

| 操作 | 命令 | 说明 |
|---|---|---|
| 查看版本 | `acme.sh --version` | 查看当前安装版本 |
| 查看帮助 | `acme.sh --help` | 查看所有命令和参数 |
| 查看证书列表 | `acme.sh --list` | 列出 acme.sh 管理的证书 |
| 查看证书详情 | `acme.sh --info -d example.com --ecc` | 查看签发方式、CA 和下次续期时间等信息 |
| 手动续期 | `acme.sh --renew -d example.com --ecc` | 未到续期时间时会自动跳过 |
| 强制续期 | `acme.sh --renew -d example.com --ecc --force` | 忽略续期时间并重新签发 |
| 执行续期检查 | `acme.sh --cron --home "$HOME/.acme.sh"` | 手动执行一次定时续期检查 |
| 设置默认 CA | `acme.sh --set-default-ca --server letsencrypt` | 将后续新证书的默认 CA 设置为 Let's Encrypt |
| 吊销证书 | `acme.sh --revoke -d example.com --ecc` | 通知签发 CA 吊销该证书 |
| 停止管理证书 | `acme.sh --remove -d example.com --ecc` | 停止自动续期，不吊销也不删除磁盘文件 |
| 更新 acme.sh | `acme.sh --upgrade` | 更新到最新版本 |
| 开启自动更新 | `acme.sh --upgrade --auto-upgrade` | 允许 acme.sh 自动更新自身 |
| 关闭自动更新 | `acme.sh --upgrade --auto-upgrade 0` | 停止自动更新自身 |
| 输出调试日志 | `acme.sh --renew -d example.com --ecc --debug 2` | 排查签发或续期失败原因 |

默认签发的是 ECC 证书，操作默认 ECC 证书时需要保留 `--ecc`；如果签发时通过 `--keylength 2048` 等参数创建了 RSA 证书，则应移除 `--ecc`。不要频繁执行带 `--force` 的续期命令，否则可能触发 CA 的签发频率限制。

---

## 申请证书

以下示例以 `example.com` 为域名。申请根域名和 `www` 子域名时，请同时传入两个 `-d` 参数。

### 独立模式（HTTP-01）

适用于服务器未运行 Web 服务，或可以在申请期间释放 `80` 端口的场景。执行前停止占用该端口的服务：

```bash
sudo systemctl stop nginx

# 单域名
acme.sh --issue -d example.com --standalone

# 根域名和 www
acme.sh --issue -d example.com -d www.example.com --standalone

sudo systemctl start nginx
```

macOS 没有 `systemctl`，请按实际服务管理方式停止和启动 Web 服务。

### Webroot 模式（HTTP-01）

适用于 Nginx、Apache 等 Web 服务已运行，且已知站点根目录。以下示例的站点根目录为 `/var/www/example.com`：

```bash
acme.sh --issue -d example.com -d www.example.com -w /var/www/example.com
```

验证文件由 `acme.sh` 自动生成，不需要手工创建。验证过程如下：

1. CA 为本次申请返回一个随机的 Challenge Token。
2. `acme.sh` 在 `<Webroot>/.well-known/acme-challenge/` 下创建以 Token 命名的临时文件。
3. 文件内容是由 Token 和 ACME 账户密钥计算得到的 Key Authorization。
4. CA 通过 HTTP 请求读取文件，内容匹配后确认申请者控制该域名。
5. 验证完成后，`acme.sh` 清理本次创建的临时文件。

对应的文件和访问地址为：

```text
文件：/var/www/example.com/.well-known/acme-challenge/<Token>
地址：http://example.com/.well-known/acme-challenge/<Token>
```

运行 `acme.sh` 的用户必须对 Webroot 下的 `.well-known/acme-challenge/` 目录有写权限。以 Nginx 为例，可以显式放行验证路径：

```nginx
location ^~ /.well-known/acme-challenge/ {
    root /var/www/example.com;
    default_type text/plain;
    try_files $uri =404;
}
```

申请前可以创建普通测试文件，确认 Webroot 路径映射正确：

```bash
sudo mkdir -p /var/www/example.com/.well-known/acme-challenge
sudo chown -R "$USER":"$(id -gn)" /var/www/example.com/.well-known
printf 'ok\n' > /var/www/example.com/.well-known/acme-challenge/check
curl http://example.com/.well-known/acme-challenge/check
rm /var/www/example.com/.well-known/acme-challenge/check
```

请求返回 `ok` 后再申请证书。证书中每个 `-d` 域名都必须能访问对应的验证路径；鉴权、CDN 规则和全局跳转不能拦截该路径。

### Nginx 自动模式（HTTP-01）

适用于已配置域名对应 `server_name` 的 Nginx：

```bash
acme.sh --issue -d example.com -d www.example.com --nginx
```

`acme.sh` 会临时调整 Nginx 配置以完成验证。生产环境中，优先使用 Webroot 或 DNS API 模式，减少对现有 Nginx 配置的影响。

### 手工 DNS 模式（DNS-01）

DNS 服务商没有可用 API 时，可以手工添加 TXT 记录完成验证：

```bash
acme.sh --issue --dns -d example.com -d '*.example.com'
```

命令不会立即完成签发，而是输出需要添加的记录名和值，例如：

```text
Domain: _acme-challenge.example.com
TXT value: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

在 DNS 服务商控制台添加对应记录：

| 类型 | 记录名 | 记录值 |
|---|---|---|
| TXT | `_acme-challenge.example.com` | `acme.sh` 输出的 TXT value |

等待 DNS 记录生效，并通过公共 DNS 服务器检查：

```bash
dig +short TXT _acme-challenge.example.com @1.1.1.1
```

查询结果包含 `acme.sh` 输出的值后，继续完成签发：

```bash
acme.sh --renew -d example.com --ecc
```

手工 DNS 模式需要注意：

- `example.com` 和 `*.example.com` 的验证记录名都是 `_acme-challenge.example.com`，一次申请可能要求在同一记录名下同时保留多个 TXT 值。
- `www.example.com` 对应的记录名是 `_acme-challenge.www.example.com`。
- TXT 值由 CA 为每次验证生成，不能自行构造或重复使用旧值。
- 所有要求的 TXT 值都应保留到本次验证完成后再删除。
- 手工模式无法无人值守自动续期，每次续期都需要重新添加新的 TXT 记录，生产环境应优先使用 DNS API 模式。

### DNS API 模式（DNS-01）

DNS API 模式适用于通配符证书、无法开放 `80` 端口、域名经 CDN 代理或需要自动续期的场景。`acme.sh` 会调用 DNS 服务商 API 创建 TXT 记录，验证成功后通常会自动清理记录。

通用签发格式如下，其中 `<插件名>` 需要替换为实际 DNS 插件：

```bash
acme.sh --issue --dns <插件名> -d example.com -d '*.example.com'
```

首次成功调用后，`acme.sh` 会将 DNS API 配置保存到自身配置目录，供定时续期使用。API 凭据应属于专用账号并限制到最小权限，同时确保 `~/.acme.sh/` 目录只有运行用户可以访问。

本文档覆盖以下常用 DNS 服务商：

| DNS 服务商 | 插件名 | 主要配置变量 |
|---|---|---|
| Cloudflare | `dns_cf` | `CF_Token`、`CF_Account_ID`，可选 `CF_Zone_ID` |
| 阿里云 DNS | `dns_ali` | `Ali_Key`、`Ali_Secret` |
| DNSPod 独立账号 | `dns_dp` | `DP_Id`、`DP_Key` |
| AWS Route 53 | `dns_aws` | `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` |
| 腾讯云 DNSPod | `dns_tencent` | `Tencent_SecretId`、`Tencent_SecretKey` |
| 华为云 DNS | `dns_huaweicloud` | `HUAWEICLOUD_Username`、`HUAWEICLOUD_Password`、`HUAWEICLOUD_DomainName`，可选 `HUAWEICLOUD_Region` |
| Azure DNS | `dns_azure` | `AZUREDNS_SUBSCRIPTIONID`、`AZUREDNS_TENANTID`、`AZUREDNS_APPID`、`AZUREDNS_CLIENTSECRET` |
| Google Cloud DNS | `dns_gcloud` | 使用 `gcloud` 登录，可选 `CLOUDSDK_ACTIVE_CONFIG_NAME` |

#### Cloudflare

建议创建仅允许管理目标 Zone 的 API Token，并授予 `Zone:DNS:Edit` 和 `Zone:Zone:Read` 权限：

```bash
export CF_Token='你的 Cloudflare API Token'
export CF_Account_ID='你的 Cloudflare Account ID'

# 已知 Zone ID 时可以设置，避免自动查找 Zone
export CF_Zone_ID='你的 Cloudflare Zone ID'

acme.sh --issue --dns dns_cf -d example.com -d '*.example.com'
```

`CF_Zone_ID` 是可选变量。不要使用权限覆盖整个账号的 Global API Key，除非现有环境确实无法使用 API Token。

#### 阿里云 DNS

创建独立 RAM 用户和 AccessKey：

```bash
export Ali_Key='你的 AccessKey ID'
export Ali_Secret='你的 AccessKey Secret'

acme.sh --issue --dns dns_ali -d example.com -d '*.example.com'
```

可以直接授予 RAM 用户 `AliyunDNSFullAccess`；若使用自定义最小权限策略，至少应允许 `alidns:DescribeDomainRecords`、`alidns:AddDomainRecord` 和 `alidns:DeleteDomainRecord`，并将资源范围限制到目标域名。

#### DNSPod 独立账号

`dns_dp` 使用 DNSPod API Token 的 ID 和 Token，不使用腾讯云的 SecretId/SecretKey：

```bash
export DP_Id='你的 DNSPod API Token ID'
export DP_Key='你的 DNSPod API Token'

acme.sh --issue --dns dns_dp -d example.com -d '*.example.com'
```

应为证书签发创建独立 API Token；如果当前 DNSPod 产品支持权限范围限制，应只授权目标域名，否则应使用专用低权限账号隔离凭据。

#### AWS Route 53

使用 IAM 用户的访问密钥：

```bash
export AWS_ACCESS_KEY_ID='你的 AWS Access Key ID'
export AWS_SECRET_ACCESS_KEY='你的 AWS Secret Access Key'

acme.sh --issue --dns dns_aws -d example.com -d '*.example.com'
```

推荐使用以下最小权限策略，并将 `HOSTED_ZONE_ID` 替换为实际 Hosted Zone ID：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "route53:ListHostedZones",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListResourceRecordSets",
        "route53:ChangeResourceRecordSets"
      ],
      "Resource": "arn:aws:route53:::hostedzone/HOSTED_ZONE_ID"
    }
  ]
}
```

运行在带有 IAM Role 的 EC2 或 ECS 环境时，`dns_aws` 也可以使用实例或容器角色，无需配置长期访问密钥。

#### 腾讯云 DNSPod

腾讯云账号应使用新版 `dns_tencent` 插件：

```bash
export Tencent_SecretId='你的腾讯云 SecretId'
export Tencent_SecretKey='你的腾讯云 SecretKey'

acme.sh --issue --dns dns_tencent -d example.com -d '*.example.com'
```

可以为专用子账号授予 `QcloudDNSPodFullAccess`。使用自定义策略时，需要允许查询域名和记录，以及创建、查询和删除 TXT 记录；不要使用主账号永久密钥。

#### 华为云 DNS

华为云插件使用 IAM 用户名和密码获取临时 Token：

```bash
export HUAWEICLOUD_Username='你的 IAM 用户名'
export HUAWEICLOUD_Password='你的 IAM 用户密码'
export HUAWEICLOUD_DomainName='你的华为云账号名称'
export HUAWEICLOUD_Region='cn-north-4'

acme.sh --issue --dns dns_huaweicloud -d example.com -d '*.example.com'
```

`HUAWEICLOUD_DomainName` 是 IAM 用户所属的华为云账号名称，不是申请证书的域名。`HUAWEICLOUD_Region` 可选，但建议明确设置 DNS Zone 所在区域。IAM 用户需要目标项目的 DNS Zone 和记录集查询、创建、修改及删除权限，可以使用 `DNS FullAccess` 或更严格的自定义策略。

#### Azure DNS

推荐创建服务主体，并在目标 DNS Zone 范围授予 `DNS Zone Contributor`：

```bash
az ad sp create-for-rbac \
  --name acme-dns \
  --role 'DNS Zone Contributor' \
  --scopes '/subscriptions/<订阅ID>/resourceGroups/<资源组>/providers/Microsoft.Network/dnszones/example.com'
```

将 Azure 订阅 ID，以及命令输出的租户、应用和密码信息配置为环境变量：

```bash
export AZUREDNS_SUBSCRIPTIONID='你的 Subscription ID'
export AZUREDNS_TENANTID='你的 Tenant ID'
export AZUREDNS_APPID='服务主体的 App ID'
export AZUREDNS_CLIENTSECRET='服务主体的 Client Secret'

acme.sh --issue --dns dns_azure -d example.com -d '*.example.com'
```

在支持 Azure Managed Identity 的资源中，也可以设置 `AZUREDNS_SUBSCRIPTIONID` 和 `AZUREDNS_MANAGEDIDENTITY=true`，避免使用长期 Client Secret。

#### Google Cloud DNS

`dns_gcloud` 通过本机安装的 `gcloud` 命令管理记录。创建服务账号后，为其授予 `roles/dns.admin`，并激活对应配置：

```bash
gcloud auth activate-service-account --key-file=/path/service-account.json
gcloud config set project PROJECT_ID
export CLOUDSDK_ACTIVE_CONFIG_NAME='default'

acme.sh --issue --dns dns_gcloud -d example.com -d '*.example.com'
```

`CLOUDSDK_ACTIVE_CONFIG_NAME` 是可选变量；如果使用的就是当前活动配置，可以不设置。服务账号密钥文件应限制为仅运行用户可读。

acme.sh 支持的 DNS 服务商会随版本变化，其他厂商及最新配置请查阅官方文档：

- [DNS API 文档（第一部分）](https://github.com/acmesh-official/acme.sh/wiki/dnsapi)
- [DNS API 文档（第二部分）](https://github.com/acmesh-official/acme.sh/wiki/dnsapi2)

---

## 部署证书

新签发的证书默认位于：

```text
~/.acme.sh/example.com_ecc/
```

不要让 Nginx、Apache 或应用直接读取该目录中的文件。应通过 `--install-cert` 将证书部署到服务的正式证书路径；续期成功时，`acme.sh` 会自动再次执行该部署命令。

Nginx 示例：

```bash
sudo mkdir -p /etc/nginx/ssl/example.com
sudo chown "$USER":"$(id -gn)" /etc/nginx/ssl/example.com

acme.sh --install-cert -d example.com --ecc \
  --key-file /etc/nginx/ssl/example.com/key.pem \
  --fullchain-file /etc/nginx/ssl/example.com/fullchain.pem \
  --reloadcmd 'sudo systemctl reload nginx'
```

Nginx 配置：

```nginx
ssl_certificate     /etc/nginx/ssl/example.com/fullchain.pem;
ssl_certificate_key /etc/nginx/ssl/example.com/key.pem;
```

若签发的是 RSA 证书，请从部署命令中移除 `--ecc`。运行 `acme.sh` 的用户必须能写入证书目录；`--reloadcmd` 中的 `sudo` 也必须能在定时任务中无交互执行，否则续期后 Nginx 无法自动加载新证书。

---

## Docker 部署的 Nginx

Nginx 使用 Docker 部署时，需要额外处理验证目录共享、证书目录挂载、宿主机端口占用，以及证书续期后的容器重载。

推荐按以下优先级选择验证方式：

1. **DNS API 模式**：不依赖 Nginx、`80` 端口或验证目录，最适合 Docker 环境。
2. **Webroot 模式**：Nginx 容器持续运行，但宿主机与容器必须共享验证目录。
3. **独立模式**：必须停止 Nginx 容器以释放宿主机 `80` 端口，会造成短暂服务中断。

宿主机上的 `acme.sh --nginx` 通常无法访问容器内的 Nginx 程序和配置，因此不建议对 Docker Nginx 使用 Nginx 自动模式。

### Webroot 共享目录

以下示例将宿主机的验证目录和证书目录只读挂载到 Nginx 容器：

```yaml
services:
  nginx:
    image: nginx:alpine
    container_name: nginx
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /opt/nginx/acme-webroot:/var/www/acme:ro
      - /opt/nginx/certs:/etc/nginx/ssl:ro
      - /opt/nginx/nginx.conf:/etc/nginx/conf.d/default.conf:ro
```

Nginx 的 HTTP 配置需要放行 ACME Challenge 路径：

```nginx
server {
    listen 80;
    server_name example.com www.example.com;

    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type text/plain;
        try_files $uri =404;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}
```

在宿主机上创建共享目录，并确认公网可以访问测试文件：

```bash
sudo mkdir -p /opt/nginx/acme-webroot/.well-known/acme-challenge
sudo chown -R "$USER":"$(id -gn)" /opt/nginx/acme-webroot
printf 'ok\n' > /opt/nginx/acme-webroot/.well-known/acme-challenge/check
curl http://example.com/.well-known/acme-challenge/check
rm /opt/nginx/acme-webroot/.well-known/acme-challenge/check
```

返回 `ok` 后，在宿主机执行签发。`-w` 必须使用宿主机路径，而不是容器内路径：

```bash
acme.sh --issue \
  -d example.com \
  -d www.example.com \
  -w /opt/nginx/acme-webroot
```

验证文件的路径对应关系如下：

```text
宿主机：/opt/nginx/acme-webroot/.well-known/acme-challenge/<Token>
容器内：/var/www/acme/.well-known/acme-challenge/<Token>
公网地址：http://example.com/.well-known/acme-challenge/<Token>
```

使用 HTTP-01 时，还需要确保宿主机防火墙和云安全组已放行 `80/tcp`，并且 Compose 已将宿主机 `80` 端口发布到 Nginx 容器。

### 部署并挂载证书

不要将 `~/.acme.sh/` 直接挂载给 Nginx。应将证书部署到独立目录，再把整个目录挂载到容器：

```bash
sudo mkdir -p /opt/nginx/certs/example.com
sudo chown -R "$USER":"$(id -gn)" /opt/nginx/certs

acme.sh --install-cert -d example.com --ecc \
  --key-file /opt/nginx/certs/example.com/key.pem \
  --fullchain-file /opt/nginx/certs/example.com/fullchain.pem \
  --reloadcmd 'docker exec nginx nginx -t && docker exec nginx nginx -s reload'
```

`nginx` 是示例容器名，需替换为实际名称。Nginx 容器内使用挂载后的路径：

```nginx
ssl_certificate     /etc/nginx/ssl/example.com/fullchain.pem;
ssl_certificate_key /etc/nginx/ssl/example.com/key.pem;
```

建议挂载整个 `/opt/nginx/certs` 目录，不要分别挂载 `key.pem` 和 `fullchain.pem`。续期时证书文件可能被替换，单文件挂载可能导致容器继续引用旧文件。

### 使用 Docker Compose 重载

`--reloadcmd` 会保存到域名配置中，并在后续成功续期后自动执行。使用 Docker Compose 时，应指定 Compose 文件的绝对路径，并在定时任务中使用 `-T` 禁用伪终端：

```bash
acme.sh --install-cert -d example.com --ecc \
  --key-file /opt/nginx/certs/example.com/key.pem \
  --fullchain-file /opt/nginx/certs/example.com/fullchain.pem \
  --reloadcmd '/usr/bin/docker compose -f /opt/nginx/compose.yaml exec -T nginx nginx -t && /usr/bin/docker compose -f /opt/nginx/compose.yaml exec -T nginx nginx -s reload'
```

执行 `acme.sh` 定时任务的用户必须有权限访问 Docker。若命令依赖 `sudo`，需要配置无需交互的权限；否则续期成功后可能无法重载 Nginx。

### 首次启动 HTTPS

Nginx 配置引用的证书文件不存在时，容器会启动失败。首次部署建议按以下顺序操作：

1. 使用仅包含 HTTP 的 Nginx 配置启动容器。
2. 通过 Webroot 或 DNS API 模式签发并部署证书。
3. 添加 HTTPS 配置和证书路径。
4. 执行 `nginx -t` 检查配置，然后重载容器。

也可以预置临时自签名证书，但不能使用空的 `key.pem` 或 `fullchain.pem` 文件代替有效证书。

### 独立模式的端口冲突

Nginx 容器发布宿主机 `80` 端口后，宿主机上的 `acme.sh --standalone` 无法监听同一端口。必须先停止 Nginx 容器：

```bash
docker compose -f /opt/nginx/compose.yaml stop nginx
acme.sh --issue -d example.com --standalone
docker compose -f /opt/nginx/compose.yaml start nginx
```

该方式会造成服务中断，并且签发失败后仍需确保 Nginx 能恢复启动。生产环境应优先使用 Webroot 或 DNS API 模式。

### 权限与安全

- Nginx 必须能读取证书私钥，但不要将私钥设置为所有用户可读的 `0644`。非 root Nginx 镜像可通过文件所有者或用户组授予 `0640` 读取权限。
- DNS API 凭据不要写入 Dockerfile、镜像或提交到 Git，应使用专用账号和最小权限。
- 不建议仅为执行重载命令而给 acme.sh 容器挂载 `/var/run/docker.sock`，该权限接近宿主机 root 权限。更安全的方式是在宿主机运行续期任务并执行容器重载。
- CDN、访问鉴权和全局跳转不能拦截 `/.well-known/acme-challenge/` 路径。
- 续期后应先执行容器内的 `nginx -t`，检查通过后再重载 Nginx。

---

## 续期与验证

安装程序会自动创建定时任务，每天检查证书，在接近过期时自动续期。查看已管理的证书：

```bash
acme.sh --list
```

手动强制续期测试：

```bash
acme.sh --renew -d example.com --ecc --force
```

检查线上服务当前使用的证书：

```bash
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -issuer -subject -dates
```

---

## 常见问题

### HTTP-01 验证失败

确认域名 A/AAAA 记录正确、服务器防火墙和云安全组已放行 `80/tcp`，并检查 CDN 是否代理或拦截 `/.well-known/acme-challenge/` 路径。

### 无法签发通配符证书

HTTP-01 不支持通配符证书。请切换到 DNS API 模式，并为 DNS 服务商配置相应 API 凭据。

### 续期后服务未加载新证书

部署证书时应通过 `--reloadcmd` 配置服务重载命令，并确认该命令可由执行 `acme.sh` 的用户成功运行。

### 使用 CertKeeper 时如何管理 acme.sh

CertKeeper 服务端已负责调用、部署和续期 `acme.sh` 证书。具体的证书配置、DNS Secret 管理和客户端拉取流程请参考项目 [README](../README.md)。
