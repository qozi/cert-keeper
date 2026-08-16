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
- 生产根密钥必须通过 `CK_ENCRYPTION_KEY` 显式提供（compose 中无默认值）。配置中的
  `storage.encryption_key` 可用但不建议生产使用，因为它会把密钥写入配置文件。
- 旧版本可能在 SQLite 旁生成 `<sqlite_path>.kek`（通常是
  `/data/db/certkeeper.db.kek`）。首次以 `CK_ENCRYPTION_KEY` 启动时，程序将 `.db.kek` 作为迁移
  回退密钥，自动把旧 token/DNS 密文重加密到当前根密钥，并清空旧 token 明文列。
- 迁移前必须同时备份数据库、`.db.kek` 与新 `CK_ENCRYPTION_KEY`；启动后等待 `/readyz`
  的 `store_encryption` 检查通过，再验证 profile secret 和 token 可用。不要先删除 `.db.kek`，
  也不要只替换根密钥后丢弃旧密钥。内置 backup 会在文件存在时收入 `.db.kek`，但环境注入的
  `CK_ENCRYPTION_KEY` 必须由外部密钥系统单独备份。

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

## ACME 状态与 DNS 凭据隔离

- `acme.home` 是持久 config-home，保存 ACME 账户、CA 与域名续期状态。它必须与数据库和证书
  仓储一起持久化和备份，否则恢复后可能丢失账户/续期上下文。
- 每次 issue/renew/install 流程创建权限为 `0700` 的临时目录和独立 `accountconf`。DNS Secret
  只在内存中解密、注入 acme.sh 子进程环境，并允许 DNS 插件把 `SAVED_*` 写入这份临时
  accountconf；同一流程的步骤复用它，流程结束后删除。
- 账户注册直接使用持久 config-home，不使用临时 accountconf。持久 config-home 和证书仓储
  会执行凭据残留扫描；检测到泄漏时操作失败，错误信息不会包含凭据值。

## 审计事件

- v2 关键操作（`reconcile_v2`、`deployment_report_v2` 等）写入审计事件表，包含操作者 token、域名、动作、结果与有限细节。
- 审计内容绝不包含明文机密、ACME 原始输出或内部路径。
- 查询：`certk-server-cli audit list [--domain D] [--actor T] [--limit N]`。

## 传输与边界

- `server.tls_mode` 只有 `direct`、`proxy`、`development`。生产 direct 模式必须配置证书和
  私钥；proxy 模式应只监听回环地址，或显式设置 `trusted_proxies` 后再由网络层限制后端端口。
  `development` 允许明文 HTTP，只用于本地调试。
- `auth.legacy_api_enabled` 生产必须为 `false`；客户端 v2 请求失败时不得以 `--v1` 重试。
- `/readyz`、`/metrics` 不含机密信息，但仍建议仅对监控网络暴露（可用 `observability` 配置段关闭）。
- v2 仅支持 `dns_api`。生产不应为其他 challenge 模式重新开启 v1；需迁移到 DNS API profile。
