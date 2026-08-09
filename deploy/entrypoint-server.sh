#!/bin/sh
set -e

# 复制默认配置（如果挂载目录没有）
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

# 自动升级 acme.sh
if [ -x /root/.acme.sh/acme.sh ]; then
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade --home /data/acme 2>&1 | sed 's/^/[acme-upgrade] /' || true
fi

echo "[entrypoint] 启动 ck-server $@"
exec /usr/local/bin/ck-server "$@"
