# CertKeeper v2 运维手册

本文档面向服务端运维：调度、监控、授权管理、备份与升级。安全设计见 [security.md](security.md)。

## 续期调度器

- 由 `scheduler` 配置段控制：`enabled`（默认 true）、`interval`（默认 12h）、`jitter`（默认 1h，必须小于 interval）。
- 每轮对全部预置证书执行 v2 reconcile：距到期超过 `renew_days` 的域名会跳过，不重复签发。
- 调度以内置 `system` token 身份执行，不绕过域名 grant；启动时会自动为预置证书补齐调度所需 grant。
- 关闭信号到达时调度器先于 HTTP 服务停止，避免关闭过程中仍在签发。
- 临时关闭自动续期：将 `scheduler.enabled` 设为 `false` 并重启。

## 监控与就绪检查

- `/readyz`（`observability.ready_enabled`，默认开启）：聚合数据库连通性与关键目录可写检查，任一失败返回 503。docker-compose 的 healthcheck 即使用该端点。
- `/metrics`（`observability.metrics_enabled`，默认开启）：Prometheus 文本格式，包含：
  - `certkeeper_requests_total{method,status}` HTTP 请求计数
  - `certkeeper_acme_operations_total{operation,status}` ACME 操作计数
  - `certkeeper_jobs_total{job,status}` 后台任务计数（含 `scheduler_reconcile`）
  - `certkeeper_deployments_total{status}` 部署回报计数
  - `certkeeper_readiness{check}` 各就绪检查状态（成功为 1）
- 指标不含 token、secret、原始域名等高基数敏感标签；建议仅对监控网络暴露这两个端点。

## grant 授权管理（v2 必需）

v2 客户端调用 reconcile/status/下载前，必须为 token 授予对应域名的权限（deny-by-default，admin 同样不绕过）：

```bash
# 授权：apply 申请/续期，status 查状态，read_cert 读证书，read_private_key 读私钥，force 强制重签
docker compose exec certkeeper certk-server-cli grant add \
  --token web-01 --domain example.com --permission apply
docker compose exec certkeeper certk-server-cli grant add \
  --token web-01 --domain example.com --permission read_private_key

# 查看与回收
certk-server-cli grant list --token web-01
certk-server-cli grant remove --token web-01 --domain example.com --permission apply
```

## 任务与审计排查

```bash
certk-server-cli job list [--domain D] [--status failed]     # 证书任务列表
certk-server-cli job show --id <job_id>                      # 任务详情
certk-server-cli generation list --domain example.com        # generation 列表（不含私钥引用）
certk-server-cli generation deployments --id <N>             # 某 generation 的部署回报
certk-server-cli audit list [--domain D] [--actor T]         # 审计事件
```

## 备份建议

- 需要备份的全部状态都在 `/data` 卷内：
  - `db/certkeeper.db`：SQLite，含 token（密文）、证书配置、DNS Secret（密文）、grant、任务与审计。
  - `acme/`：ACME 账户与 CA 配置；丢失后可重新注册账户，但建议备份。
  - `certs/`：证书产物（generation 仓储）。
  - `config/config.yaml` 与 `.env` 中的 `CK_ENCRYPTION_KEY`：**主密钥丢失则所有密文无法解密，必须与数据库一起离线保存**。
- SQLite 备份：先 `docker compose stop certkeeper` 再整体打包 `/data`；在线备份请使用
  `sqlite3 /data/db/certkeeper.db ".backup '/data/db/backup.db'"`，避免直接复制写入中的库文件。
- 恢复：还原 `/data` 与同一主密钥后启动即可；客户端按 `current` generation 续用。

## 升级注意

- 服务端启动时**不再自动升级 acme.sh**。acme.sh 版本固定在镜像构建期（`deploy/Dockerfile` 的
  `ACMESH_VERSION` + `ACMESH_SHA256`），升级方式是修改 Dockerfile 并重建镜像；
  应急手动升级：`docker compose exec certkeeper acme.sh --upgrade --home /data/acme`。
- 服务端升级流程：备份 `/data` → `docker compose pull && docker compose up -d`（数据库迁移自动执行）。
- 客户端 `apply` 默认走 v2；对接旧服务端时自动回退 v1，也可用 `--v1` 强制。
- 从 v1 升级后注意：v2 只支持 `dns_api` 预置证书；其余挑战模式继续使用 v1 流程。
- 加密主密钥不可随意更换；轮换会导致已存 token secret 与 DNS Secret 无法解密。
