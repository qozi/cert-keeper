# CertKeeper — Agent 指南

## 技术栈

纯 Go 项目，单一 module（`github.com/siidoo/certkeeper`），无 monorepo，无前端。
三个二进制：`certk-server`、`certk-server-cli`、`certk-client`，共用 `internal/` 包。
SQLite 使用 `modernc.org/sqlite`（纯 Go），全程 `CGO_ENABLED=0`，无需 C 工具链，可直接交叉编译。

## 代码规范

- **所有代码注释、package doc、错误信息使用中文**（现有代码如此，必须保持一致）
- `gofmt` 零容忍（CI 强制）：`gofmt -l .` 必须无输出
- `go vet ./...`（CI 强制）
- shell 脚本需通过 `shellcheck`
- YAML 文件需通过 `yamllint==1.37.1`（固定版本，CI 用此版本）

## 开发命令

```bash
# 本地调试（go run，无需构建）
go run ./cmd/server -config deploy/config.local.example.yaml
go run ./cmd/client test -c deploy/client.local.example.yaml
go run ./cmd/server-cli --config deploy/config.local.example.yaml token list

# 构建（输出到 dist/）
./scripts/build.sh          # 当前平台
./scripts/build.sh all      # 全平台交叉编译
./scripts/build.sh docker   # Docker 镜像

# 裸构建（需加 ldflags，否则版本显示 dev/unknown）
CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o dist/certk-server ./cmd/server
```

## 测试

```bash
go test ./...               # 全量（含单元、集成）
go test -race ./...         # 带 race 检测
go test ./test/e2e          # 端到端（无需真实 CA，使用 fakeV2Issuer）

# 运行单个包 / 单个函数
go test ./internal/store
go test -run TestV2HappyPath ./test/e2e
```

E2E 测试完全自包含：`fakeV2Issuer` 生成自签证书，每个测试用 `t.TempDir()` 隔离 SQLite，不需要外部服务。
Pebble 验收测试（`.github/workflows/pebble-acceptance.yml`）需手动触发，不在普通 CI 中运行。

## Lint 顺序（CI 串行）

```
gofmt → go vet → shellcheck → yamllint → actionlint → govulncheck → go test
```

发布门禁：`test` job 必须通过后才能运行 `build` 和 `publish-images`。

## 架构要点

- **迁移自动执行**：`store.Open()` 启动时自动跑 `internal/store/migrations/`，不需要手动执行迁移命令
- **v2 异步流程是生产唯一流程**：`POST /reconcile` → `202` + `Location` header → 轮询 job → 下载 manifest → 原子更新 `current`；`auth.legacy_api_enabled` 默认 `false`，v1 路由在生产中关闭
- **版本信息通过 ldflags 注入** `internal/version` 包，裸 `go build` 不加 ldflags 会得到 `dev`/`unknown`
- **acme.sh 仅真实签发时需要**，本地调试 API/鉴权/SQLite 逻辑不依赖它

## 环境变量覆盖

可覆盖 yaml 配置中的对应字段：

```
CK_ENCRYPTION_KEY   ← 生产必须显式注入，无默认值
CK_LISTEN / CK_BASE_URL / CK_SQLITE_PATH
CK_ACME_HOME / CK_CERTS_DIR / CK_ACME_SH_PATH
CK_LOG_FILE / CK_LOG_LEVEL
```

## 本地开发注意

- 调试数据存放在 `./.local/data/`（已加入 .gitignore），不污染仓库
- 服务端首次启动自动生成 admin token，**secret 仅在 stderr 输出一次**，需立即保存后填入 client 配置
- DNS Secret 通过 stdin 传入避免泄露到 shell history：
  ```bash
  printf '%s\n' '<secret>' | certk-server-cli secret set ... --value-stdin
  ```
