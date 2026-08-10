# CertKeeper 证书管家

一个使用 acme.sh 统一配置签发证书的服务。目标：**只在一处（服务端）安装并配置 acme.sh**，所有目标机器通过客户端调用服务端申请/续签证书，避免在每个节点维护 acme.sh + DNS Secret。

## 设计

- **服务端（`certk-server`）**：Go 编写，包装 acme.sh 完成签发与续签，对外暴露 HTTP API；SQLite 持久化（证书配置、token、DNS Secret、客户端、申请日志）；最终以 Docker 镜像运行。
- **服务端 CLI（`certk-server-cli`）**：直接读取服务端配置、SQLite 和证书目录，在服务端主机或容器内执行管理操作，不依赖 HTTP 或 HMAC 凭据。
- **客户端（`certk-client`）**：单二进制 Go 程序，可手动或 cron 调用；与服务端鉴权通信，下载证书到本地，可选执行 verify / reload 命令使证书立即生效。

### 两种使用模式

| 模式 | 说明 | 触发方式 |
|---|---|---|
| 方式1（服务端预置） | 管理员在服务端预先配置好域名的 challenge 模式、DNS provider、Keylength 等；客户端只发 `domain` 即可申请/续签 | `client apply -d example.com` |
| 方式2（客户端推参） | 客户端请求时携带 `challenge_mode`、`dns_provider` 等；**DNS Secret 仍只存服务端**；推参申请需 admin token | `client apply -d example.com --mode dns_api --dns-provider dns_cf` |

### 安全模型

- 多 token：每个 token 含 `id`、`secret`、`备注`、`启用/停用`、`是否 admin`。
- 请求签名：`HMAC-SHA256(method + path + ? + query + ts + nonce + bodySHA256, secret)`，通过请求头 `X-CK-Token-Id / X-CK-Timestamp / X-CK-Nonce / X-CK-BodyHash / X-CK-Signature` 携带。
- 防重放：每个 nonce 在 SQLite 表中保留至 TTL 过期，重复使用即拒绝。
- 时钟窗口：默认 ±300 秒，可在配置中调整。
- 方式2 推参申请需 admin token，普通 token 只能申请服务端已预置的域名。
- DNS Secret 用 AES-256-GCM 加密后入库，主密钥来自配置或 `CK_ENCRYPTION_KEY` 环境变量。

## 服务端 API

### 客户端 API（需 client token）

| 方法 | 路径 | 用途 |
|---|---|---|
| `POST` | `/api/v1/certs/apply` | 申请/续签证书 |
| `GET`  | `/api/v1/certs/:domain/files/:name` | 下载单个证书文件（cert/key/fullchain/ca/time.log） |
| `GET`  | `/api/v1/certs/:domain/status` | 查询证书状态（有效期、文件清单） |
| `POST` | `/api/v1/client/register` | 注册客户端（hostname、os_info） |
| `POST` | `/api/v1/client/heartbeat` | 心跳更新 last_seen |
| `GET`  | `/api/v1/ping` | 连通性测试 |

### 管理 API（需 admin token）

| 方法 | 路径 | 用途 |
|---|---|---|
| `GET/POST` | `/api/v1/admin/tokens` | 列出 / 创建 token |
| `GET/PUT/DELETE` | `/api/v1/admin/tokens/:id` | 查 / 改 / 删 token |
| `GET/POST` | `/api/v1/admin/certs` | 列出 / 创建证书配置 |
| `DELETE` | `/api/v1/admin/certs/:domain` | 删除证书配置 |
| `GET` | `/api/v1/admin/certs/status` | 所有证书有效期总览 |
| `POST` | `/api/v1/admin/certs/:domain/reissue` | 手动触发重签 |
| `GET/POST` | `/api/v1/admin/secrets` | 列出 / 添加 DNS Secret |
| `DELETE` | `/api/v1/admin/secrets/:id` 或 `/:provider/:env_key` | 删除 Secret |
| `GET` | `/api/v1/admin/providers` | 列出 acme.sh 支持的 DNS provider（含是否已配置标记） |
| `GET` | `/api/v1/admin/providers/:provider/parameters` | 查询指定 provider 已配置参数（值已脱敏） |
| `GET` | `/api/v1/admin/clients` | 客户端列表 |
| `GET` | `/api/v1/admin/logs?domain=&client=&success=&limit=` | 申请日志 |

### 请求示例（带签名）

```bash
TS=$(date +%s); NONCE=$(openssl rand -hex 16)
BODY_HASH=$(printf '{"domain":"example.com"}' | openssl dgst -sha256 -hex | awk '{print $2}')
SIG=$(printf '%s\n%s\n%d\n%s\n%s' POST /api/v1/certs/apply $TS $NONCE $BODY_HASH \
        | openssl dgst -sha256 -hmac "$SECRET" -hex | awk '{print $2}')
curl -X POST "https://ck.example.com:8443/api/v1/certs/apply" \
  -H "X-CK-Token-Id: $TOKEN_ID" -H "X-CK-Timestamp: $TS" -H "X-CK-Nonce: $NONCE" \
  -H "X-CK-BodyHash: $BODY_HASH" -H "X-CK-Signature: $SIG" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com"}'
```

## 服务端 CLI

`certk-server-cli` 与服务端共享同一份配置和 SQLite 数据库，适合在服务端主机上直接维护证书配置、Token、DNS Secret 和申请日志。默认配置路径为 `/data/config/config.yaml`，也可以通过全局 `-c/--config` 指定。

```bash
# Docker 容器内执行
docker compose exec certkeeper certk-server-cli cert-config list
docker compose exec certkeeper certk-server-cli cert status-all

# 本地源码执行
go run ./cmd/server-cli --config deploy/config.local.example.yaml cert-config list
```

支持的命令包括：

- `cert apply/status/status-all/file/list/reissue`
- `token list/get/create/update/delete`
- `cert-config list/set/delete`
- `secret list/set/delete`
- `provider list/parameters`
- `client list`
- `log list`

默认输出为表格，脚本调用可使用 `--output json`。全局参数必须放在资源命令之前：

```bash
certk-server-cli --config /data/config/config.yaml --output json token list
certk-server-cli --config /data/config/config.yaml cert-config set \
  -d example.com --mode dns_api --dns-provider dns_cf
certk-server-cli --config /data/config/config.yaml cert apply -d example.com
```

DNS Secret 建议通过标准输入传入，避免出现在 shell 历史中：

```bash
printf '%s\n' '<your_cf_key>' | certk-server-cli \
  --config /data/config/config.yaml secret set \
  --provider dns_cf --env-key CF_Key --value-stdin
```

CLI 与服务端进程共享 ACME 文件锁，同一时间只允许一个进程调用 acme.sh。

## 快速开始

### 1. 构建

```bash
cd extra-tools/cert-keeper
./scripts/build.sh          # 当前平台
./scripts/build.sh all      # 跨平台
./scripts/build.sh docker   # Docker 镜像（certkeeper/certk-server:latest / certkeeper/certk-client:latest）
```

### 2. 本地源码调试（不发布、不依赖 Docker）

无需构建二进制或镜像，直接用 `go run` 启动服务端和客户端。本地持久化目录在工作区 `./.local/data`，已加入 `.gitignore`。

```bash
# 终端1：启动服务端（首次启动会在日志输出 admin token secret，仅显示一次）
go run ./cmd/server -config deploy/config.local.example.yaml
```

```bash
# 终端2：编辑 deploy/client.local.example.yaml，填入服务端日志输出的 admin secret
#         随后可直接用 -c 指定该配置运行客户端
go run ./cmd/client -c deploy/client.local.example.yaml test
go run ./cmd/client -c deploy/client.local.example.yaml register
go run ./cmd/client -c deploy/client.local.example.yaml apply -d example.com --out-dir ./.local/certs
```

仅调试 API、SQLite、鉴权与客户端通信时，无需安装 `acme.sh`；真实签发证书仍需本机安装 [acme.sh](https://get.acme.sh)。本机调试可配合 Delve 断点：

```bash
go install github.com/go-delve/delve/cmd/dlv@latest
dlv debug ./cmd/server -- -config deploy/config.local.example.yaml
dlv debug ./cmd/client -- -c deploy/client.local.example.yaml test
```

### 3. 启动服务端（Docker）

```bash
cd deploy
# 生成加密密钥（首次）
docker run --rm certkeeper/certk-server:latest --gen-encryption-key > .env
echo "CK_ENCRYPTION_KEY=$(cat .env)" > .env
docker compose up -d
# 首次启动会在日志输出 admin token secret，仅显示一次
docker compose logs certkeeper | grep "已创建 admin token"
```

### 4. 配置证书（方式1）

```bash
# 1. 添加 DNS Secret（以 CloudFlare 为例）
curl -X POST .../api/v1/admin/secrets \
  -d '{"provider":"dns_cf","env_key":"CF_Key","env_value":"<your_cf_key>"}'
curl -X POST .../api/v1/admin/secrets \
  -d '{"provider":"dns_cf","env_key":"CF_Email","env_value":"you@example.com"}'

# 2. 创建证书配置
curl -X POST .../api/v1/admin/certs \
  -d '{"domain":"example.com","challenge_mode":"dns_api","dns_provider":"dns_cf","renew_days":30}'

# 3. 为目标机器创建 client token
curl -X POST .../api/v1/admin/tokens \
  -d '{"note":"web-01","auto_gen":true,"enabled":true}'
```

### 5. 客户端使用

```bash
# 部署客户端二进制
sudo install -m 0755 certk-client /usr/local/bin/certkeeper-client
sudo mkdir -p /etc/certkeeper
sudo cp client.example.yaml /etc/certkeeper/client.yaml
# 编辑 /etc/certkeeper/client.yaml 填入 server / token_id / token_secret

# 注册
certkeeper-client register

# 手动申请/续签
certkeeper-client apply -d example.com

# 配置 crontab（每天凌晨 3 点检查）
echo "0 3 * * * /usr/local/bin/certkeeper-client apply -d example.com --quiet" | sudo crontab -
```

## 目录结构

```
extra-tools/cert-keeper/
├── cmd/
│   ├── server/main.go          服务端入口
│   ├── server-cli/main.go      服务端本地管理 CLI
│   └── client/main.go          客户端入口
├── internal/
│   ├── config/                  配置加载
│   ├── store/                  SQLite + 迁移 + tokens/certs/secrets/clients/logs/nonces
│   ├── acme/                   acme.sh 包装器 + 证书解析
│   ├── lock/                   ACME 跨进程文件锁
│   ├── service/                API 与 CLI 共用的业务操作
│   ├── api/                    HTTP handler + auth 中间件 + admin/client 接口
│   └── client/                 客户端逻辑（签名、下载、部署）
├── pkg/ckauth/                 签名 / 随机数 / 防重放工具
├── deploy/
│   ├── Dockerfile              多阶段构建（server + client）
│   ├── docker-compose.yml
│   ├── entrypoint-server.sh
│   ├── config.example.yaml
│   ├── client.example.yaml
│   ├── config.local.example.yaml  本地源码调试（go run）
│   └── client.local.example.yaml  本地源码调试（go run）
└── scripts/build.sh            本地 / 跨平台 / Docker 构建
```

## 持久化目录布局（容器内）

```
/data/
├── db/certkeeper.db            SQLite（tokens / certs / secrets / clients / logs / nonces）
├── acme/                       acme.sh 主目录（账户、CA 配置、原始证书）
├── certs/<domain>/             最终证书产物
│   ├── cert.pem  key.pem  fullchain.pem  ca.pem  time.log
├── logs/certkeeper.log
└── config/config.yaml
```

`time.log` 内容为 Unix 时间戳，每次成功签发/续签后由服务端写入，客户端可据此判断是否需要重新下载（兼容 acmeDeliver 客户端的思路）。

## ACME Challenge 模式

| 模式 | 说明 | 必填参数 |
|---|---|---|
| `dns_api` | DNS API 自动验证，可签发通配符证书（推荐） | `dns_provider`（如 `dns_cf`） |
| `standalone` | 服务端临时占用 80 端口 HTTP-01 | 服务端 80 端口可达 |
| `webroot` | 通过已有 Web 服务器目录验证 | `webroot_path` |
| `dns_manual` | 手动加 TXT 记录，无自动续签，仅一次性签发 | — |

DNS Secret 由服务端按 `provider` 名分组加密存储；acme.sh 调用时临时解密注入子进程环境变量，不落盘、不回传客户端。

## 续签流程

1. 客户端 cron 调用 `apply -d <domain>`。
2. 服务端读取该域名预置配置（或方式2 客户端推参）。
3. 解析现有 `fullchain.pem` 的 `NotAfter`：若距到期日大于 `renew_days`，直接返回当前文件清单，不重新签发。
4. 若需要续签：解密 DNS Secret 注入环境变量，调用 `acme.sh --issue` + `--install-cert`，更新 `time.log`。
5. 客户端按返回的文件 SHA256 逐个下载，与本地 `.bak` 备份；若服务端 `time.log` 未变则跳过下载。
6. 下载完成执行 `verify_cmd`（如 `nginx -t`），失败则回滚证书；通过后执行 `reload_cmd`（如 `systemctl reload nginx`），失败不回滚（证书已更新，不应因 reload 失败回退证书）。

## 与参考项目 acmeDeliver 的差异

| 维度 | acmeDeliver | CertKeeper |
|---|---|---|
| 签发职责 | 不调 acme.sh，只分发已签好的证书 | 服务端包装 acme.sh 完成签发/续签 |
| 持久化 | 无（仅文件 + 内存 timedmap） | SQLite，含 token / 客户端 / 日志 |
| 鉴权 | 单一全局密码 + MD5 | 多 token + HMAC-SHA256 + nonce 防重放 |
| 客户端 | Bash，仅下载 | Go 单二进制，申请/续签/下载/部署/reload |
| DNS Secret | 不涉及 | 服务端加密存储管理 |
| 客户端管理 | 不记录 | 注册 + 心跳 + 日志可查 |
| 部署 | systemd | Docker / docker-compose |

## 限制

- 当前版本无 Web UI，所有管理通过 HTTP API。
- 方式2 推参申请默认要求 admin token，避免普通客户端签发任意域名。
- 服务端自身 TLS 证书建议由反向代理（nginx/Caddy）终止；如需服务端直接暴露 HTTPS，在配置中开启 `tls` 并指定证书路径（可先用 acme.sh 为服务端自身域名签一张）。
- DNS 手动模式（`dns_manual`）无自动续签，仅用于一次性签发。

## 相关文档

- [发布指南](docs/releasing.md)

## 许可

随主仓库协议。
