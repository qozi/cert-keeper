# CertKeeper v2 运维手册

本文档面向服务端运维：调度、监控、授权管理、备份与升级。安全设计见 [security.md](security.md)。

## 续期调度器

- 由 `scheduler` 配置段控制：`enabled`（默认 true）、`interval`（默认 12h）、`jitter`（默认 1h，必须小于 interval）。
- 每轮对全部预置证书执行 v2 reconcile：距到期超过 `renew_days` 的域名会跳过，不重复签发。
- `certk-server` 同一进程内运行持久 worker：客户端 reconcile 返回 `202` 后，任务先写入
  SQLite，再由 worker claim、续租和执行；服务重启后可继续领取未完成或过期 lease 的任务。
- `scheduler.interval/jitter` 控制扫描预置证书候选的周期；持久任务队列 polling 当前固定为
  5 秒，不是 YAML 配置字段。客户端对 `202 Location` 的 polling 也由客户端内置。
- 调度以内置 `system` 身份执行；HTTP 客户端仍必须具备域名 grant，admin 不绕过 grant。
- 关闭信号到达时调度器先于 HTTP 服务停止，避免关闭过程中仍在签发。
- 临时关闭自动续期：将 `scheduler.enabled` 设为 `false` 并重启。

## 监控与就绪检查

- `/readyz`（`observability.ready_enabled`，默认开启）：聚合 SQLite 连通性、全部密文可解密、
  ACME/证书目录可写、ACME 配置、worker 首轮 heartbeat 与可恢复任务查询；任一失败返回 503。
  Compose healthcheck 使用容器内 HTTP 地址，即使公网由 direct/proxy TLS 提供。
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

客户端 `apply` 收到 `202 Accepted` 会轮询 job URL 直到 `succeeded/failed/cancelled`。服务异常时
应保留客户端输出目录中的 `.client-state.json`，它保存幂等键与待补发 deployment report；不要
删除状态后用新请求反复强签。任务失败先用 `job show` 查看公开错误，再排查 worker 日志、DNS
profile 与 `/readyz`。

## 证书生命周期操作

三个命令语义不同，均需明确的本地 actor/grant 参数并写审计：

- `cert revoke -d example.com`：调用 ACME CA 吊销证书；不会自动删除本地 current generation。
- `cert remove -d example.com`：从持久 ACME 状态移除域名，并清理非 current generation 元数据；
  不等于 CA 吊销，current 仍受保护。
- `cert delete -d example.com`：删除生命周期记录；存在 current generation 时会拒绝，避免无法
  原子删除当前证书。它不替代 revoke/remove，也不会隐式完成二者。

执行破坏性操作前先备份，并按目标分别完成吊销、从消费端下线、清理 current，再执行后续清理。

## 备份与恢复

- `certk-server-cli backup create --destination /data/backup/<唯一目录>` 在线创建 SQLite 一致性
  快照，并复制 `certs/` generation 仓储、持久 `acme/` config-home 和存在的 `.db.kek`。
  目标目录必须不存在。随后用 `backup verify --path ...` 校验 manifest、SHA256 与 SQLite 完整性。
- 内置备份不包含环境变量中的 `CK_ENCRYPTION_KEY`、前端代理/direct TLS 私钥或宿主机配置。
  这些必须由外部密钥/备份系统保存。完整恢复集至少包含数据库、当前根密钥、旧 `.db.kek`
  （若存在）、ACME state、证书仓储和 TLS 证书私钥。
- `/data/backup` 使用独立持久卷只是暂存，仍需复制到异地或离线存储。不要直接复制正在写入的
  SQLite 文件，也不要把唯一备份留在业务主机。

恢复步骤：

1. 停止 `certk-server`，确保没有 worker、CLI 或其他进程打开目标 SQLite/ACME/证书目录。
2. 从离线介质还原备份目录和原 `CK_ENCRYPTION_KEY`；先运行 `backup verify --path <目录>`。
3. 在不会打开数据库的 restore 模式执行
   `certk-server-cli --config /etc/certkeeper/server.yaml backup restore --path <目录> --confirm-dangerous-restore`。
4. 恢复代理/direct TLS 证书与私钥，确认目录属主、目录 `0700`、敏感文件 `0600`。
5. 启动服务，等待 `/readyz` 返回 200；检查 `store_encryption`、worker heartbeat、profile、job 和
   generation current。再运行一次客户端 apply，验证稳定 `current` 路径及 reload。

`backup restore` 会替换数据库、证书仓储和 ACME 状态。不能通过 `docker compose exec` 在运行中
恢复，因为服务端已打开数据库；应使用停止服务后的临时容器或主机 CLI。

## 升级注意

- 服务端启动时**不升级 acme.sh**。版本固定在镜像构建期（`deploy/Dockerfile` 的
  `ACMESH_VERSION` + `ACMESH_SHA256`），升级方式是发布并验证新镜像；不要在运行容器中执行
  `acme.sh --upgrade`，否则二进制与镜像版本不可复现。
- 服务端升级流程：备份 `/data` → `docker compose pull && docker compose up -d`（数据库迁移自动执行）。
- 客户端 `apply/status/download` 默认走 v2且不会自动回退；生产不要使用 `--v1`。
- 从 v1 升级时先迁移为 `dns_api` profile、补齐 grant，验证 v2 后设置
  `auth.legacy_api_enabled: false`。不要长期并行暴露 v1。
- 从 `.db.kek` 迁移到 `CK_ENCRYPTION_KEY` 时按 [安全模型](security.md) 保留双份密钥并等待
  `store_encryption` 就绪检查通过；未经迁移流程直接轮换根密钥会使旧密文不可读。
