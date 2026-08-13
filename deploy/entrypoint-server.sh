#!/bin/sh
set -e

# 配置、数据库与证书均属敏感数据，统一按属主私有权限创建
umask 077

# 准备持久化目录，并在挂载目录没有配置时生成默认配置
mkdir -p /data/config /data/db /data/acme /data/certs /data/logs
if [ ! -f /data/config/config.yaml ]; then
    cat > /data/config/config.yaml <<'EOF'
server:
  listen: ":8443"
  tls: false
  base_url: "https://CK_SERVER_HOST:8443"
auth:
  timestamp_window_sec: 300
  nonce_ttl_sec: 300
  admin_token_id: "admin"
storage:
  sqlite_path: "/data/db/certkeeper.db"
  # 留空时从 CK_ENCRYPTION_KEY 环境变量读取
  encryption_key: ""
acme:
  home: "/data/acme"
  certs_dir: "/data/certs"
  default_ca: "letsencrypt"
  default_keylength: "ec-256"
  default_renew_days: 30
  issue_timeout: 300s
  auto_upgrade: true
  acme_sh_path: "/root/.acme.sh/acme.sh"
log:
  level: "info"
  file: "/data/logs/certkeeper.log"
  max_size_mb: 10
  max_backups: 3
EOF
    echo "[entrypoint] 已生成默认配置 /data/config/config.yaml，请按需修改"
fi

# 启动时不再自动升级 acme.sh（升级属运维操作，请显式执行，例如：
#   docker compose exec certkeeper acme.sh --upgrade --home /data/acme）

echo "[entrypoint] 启动 certk-server"
exec /usr/local/bin/certk-server "$@"
