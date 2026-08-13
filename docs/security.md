# CertKeeper v2 安全模型

本文档概述 v2 版本的安全设计，供部署与审计参考。实现细节以 `internal/`、`pkg/` 源码为准。

## 请求认证：HMAC + 正文哈希

- 每个 token 持有 `id` 与 `secret`，签名算法为
  `HMAC-SHA256(method + path + ? + query + ts + nonce + bodySHA256, secret)`。
- 请求头携带 `X-CK-Token-Id / X-CK-Timestamp / X-CK-Nonce / X-CK-BodyHash / X-CK-Signature`。
- `X-CK-BodyHash` 是请求正文的 SHA256 十六进制摘要并纳入签名，任何对 body 的篡改都会使签名校验失败。
- 防重放：nonce 在 SQLite 中保留至 TTL 过期（默认 300 秒），重复使用即拒绝；时间戳窗口默认 ±300 秒，可通过 `auth.timestamp_window_sec` / `auth.nonce_ttl_sec` 调整。
- 密钥永不入日志；v2 错误响应不向调用方泄露内部路径或存储细节（500 仅返回通用消息）。

## 授权：deny-by-default grant

- v2 API（`/api/v2/certs/...`、`/api/v2/jobs/...`）要求 client token 鉴权；写操作不强制 admin。
- 授权按 `(token, domain, permission)` 三元组在 service 层逐次检查，**未授权即拒绝（403），admin 也不绕过域名 grant 检查**。
- 权限集合：`apply / status / read_cert / read_private_key / force`；`force` 强制重签还需 admin 身份 + `force` grant 双重条件。
- grant 由管理员通过 `certk-server-cli grant add/remove/list` 显式维护（见 [operations.md](operations.md)）。
- 内置 `system` token 仅供服务端调度器执行协调使用，secret 为随机值，不用于 HTTP 认证。

## 密钥与凭据存储

- **Token 加密存储**：token secret 以 AES-256-GCM 加密后入库（`secret_ciphertext`，带版本号），AAD 绑定 token ID；旧明文列在轮换后清空。常规列表与 JSON 输出不含 secret。
- **DNS Secret 加密存储**：同样使用 AES-256-GCM，AAD 绑定 `provider/profile/env_key`；主密钥来自配置 `storage.encryption_key` 或环境变量 `CK_ENCRYPTION_KEY`。
- 主密钥必须显式提供（compose 中无默认值）；轮换主密钥会导致已存密文无法解密，需提前重新录入 Secret。

## 服务端 generation 原子发布

- 证书产物按不可变 generation 存储：`<certs_dir>/<domain>/generations/<generation>/`，当前版本由 `current` 指针文件标识。
- 发布流程：staging 目录校验（证书链完整、私钥与叶子证书匹配、SAN 覆盖、未过期、文件集合恰好为固定五个文件）→ 原子 rename → `current` 指针以临时文件 + rename 方式原子切换，并 fsync 目录。
- 拒绝符号链接、路径穿越与未知文件；generation ID 由服务端生成，客户端不可指定发布路径。

## 客户端原子部署与回滚

- 客户端输出目录采用 `releases/<generation>/` + `current` 布局，与服务端 generation 一一对应。
- 下载到 staging 后按 manifest 校验每个文件的大小与 SHA256，再解析校验证书链与私钥，然后原子切换 `current`。
- `verify_cmd`（如 `nginx -t`）失败时自动恢复 previous `current`；`reload_cmd` 失败不回滚（证书已生效），按可重试错误处理。
- 全程持有 flock 部署锁，目录/文件权限收紧（0700/0600），拒绝符号链接。
- 部署结果通过 `POST /api/v2/certs/{domain}/deployments` 回报服务端。

## DNS 凭据零持久化

- 每次签发/续期使用独立的 acme 临时 config-home（`0700` 权限临时目录），操作结束后删除。
- DNS 凭据仅在内存中解密并注入 acme.sh 子进程环境变量，不写入 acme home、证书目录等持久位置。
- 操作前后对持久目录做 canary 扫描：一旦发现凭据残留即报错（错误信息不含凭据值）。

## 审计事件

- v2 关键操作（`reconcile_v2`、`deployment_report_v2` 等）写入审计事件表，包含操作者 token、域名、动作、结果与有限细节。
- 审计内容绝不包含明文机密、ACME 原始输出或内部路径。
- 查询：`certk-server-cli audit list [--domain D] [--actor T] [--limit N]`。

## 传输与边界

- 服务端自身 TLS 建议由反向代理终止；直接暴露时开启 `server.tls` 并配置证书。
- `/readyz`、`/metrics` 不含机密信息，但仍建议仅对监控网络暴露（可用 `observability` 配置段关闭）。
- v2 仅支持 `dns_api` 挑战模式，standalone/webroot/dns_manual 场景请使用 v1 流程。
