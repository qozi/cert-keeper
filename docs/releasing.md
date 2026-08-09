# CertKeeper 发布指南

本文档说明代码修改后如何提交、打 tag、发布版本，包括 GitHub Release 产物和 Docker 镜像。

## 概述

CertKeeper 采用 **GitHub Actions + GoReleaser** 自动发布：

- 推送形如 `v*` 的 git tag → 自动触发 `.github/workflows/release.yml`
- GoReleaser 构建多平台二进制（server / client）并创建 GitHub Release
- 同时构建 `server` 和 `client` 两个 Docker 镜像，推送到 `ghcr.io`

整个过程无需手动操作，打 tag 后等待 CI 完成即可。

---

## 前置条件

- 对仓库有 **写权限**（可推送 tag + 创建 Release）
- `GITHUB_TOKEN` 由 Actions 自动提供，无需额外配置
- 本地需安装 Go 1.26+、git；如需本地验证 Docker 镜像则需安装 Docker

---

## 提交规范（建议）

项目**不强制**提交信息格式，但建议采用 **Conventional Commits**：

```
feat: 新增 xxx 功能
fix: 修复 xxx 问题
docs: 更新文档
chore: 构建/依赖变更
test: 添加测试
refactor: 重构
```

提示：`.goreleaser.yml` 的 changelog 会**过滤** `docs:` / `chore:` / `test:` 前缀的提交，这些变更不会出现在 Release Notes 中。

---

## 版本号规范

采用**语义化版本**（Semantic Versioning）：

| 变更类型 | 版本格式 | 示例 | 说明 |
|---|---|---|---|
| 破坏性变更 | `vX+1.0.0` | `v2.0.0` | API 不兼容改动、数据库 schema 不兼容变更 |
| 新功能（向后兼容） | `vX.Y+1.0` | `v1.1.0` | 新增 API、新命令 |
| Bug 修复 / 补丁 | `vX.Y.Z+1` | `v1.1.1` | 修复已有功能 |

预发布版本使用 `rc` / `beta` 后缀（如 `v1.1.0-rc1`），GoReleaser 的 `prerelease: auto` 会自动识别。

---

## 发布步骤

### 1. 确保 main 分支最新

```bash
git checkout main
git pull origin main
```

### 2. 本地测试（发布前必做）

发布前务必在本地验证构建和功能正常，所有产物输出到本地 `dist/` 和 Docker 镜像，不会影响远端。

```bash
# 构建当前平台的 server + client 二进制（输出到 dist/）
scripts/build.sh native

# 跨平台构建（输出到 dist/，发布前可选）
scripts/build.sh all

# 构建本地 Docker 镜像
scripts/build.sh docker

# 启动服务端容器验证
cd deploy
cp config.example.yaml data/config/config.yaml && vim data/config/config.yaml
docker compose up
```

本地测试通过后再进入下一步。

### 3. 打 tag

```bash
# 格式：vX.Y.Z（无前缀）
git tag -a v1.0.0 -m "release v1.0.0"
```

### 4. 推送 tag 触发 CI

```bash
git push origin v1.0.0
```

### 5. 监控 CI

前往 [GitHub Actions](https://github.com/qozi/cert-keeper/actions) 查看进度，包含以下 jobs：

- `goreleaser` — 构建多平台二进制 + 创建 GitHub Release
- `docker-server` — 构建并推送服务端 Docker 镜像
- `docker-client` — 构建并推送客户端 Docker 镜像

三个 job 并行执行，全部通过后即发布完成。

---

## 发布产物清单

### GitHub Release 二进制

GoReleaser 自动上传到 [Releases 页面](https://github.com/qozi/cert-keeper/releases)，产物如下：

| 产物 | 平台 | 格式 |
|---|---|---|
| `certk-server_linux_amd64` | Linux x86_64 | tar.gz |
| `certk-server_linux_arm64` | Linux ARM64 | tar.gz |
| `certk-server_linux_arm` | Linux ARM v7 | tar.gz |
| `certk-server_darwin_amd64` | macOS x86_64 | tar.gz |
| `certk-server_darwin_arm64` | macOS Apple Silicon | tar.gz |
| `certk-client_linux_amd64` | Linux x86_64 | tar.gz |
| `certk-client_linux_arm64` | Linux ARM64 | tar.gz |
| `certk-client_linux_arm` | Linux ARM v7 | tar.gz |
| `certk-client_darwin_amd64` | macOS x86_64 | tar.gz |
| `certk-client_darwin_arm64` | macOS Apple Silicon | tar.gz |
| `checksums.txt` | — | SHA256 校验和 |

同时自动生成 [changelog](https://github.com/qozi/cert-keeper/releases)（基于 Conventional Commits，过滤 `docs` / `chore` / `test`）。

### Docker 镜像

| 镜像 | 用途 | 平台 | Registry |
|---|---|---|---|
| `ghcr.io/qozi/cert-keeper/server` | 服务端（含 acme.sh） | linux/amd64, linux/arm64 | GitHub Container Registry |
| `ghcr.io/qozi/cert-keeper/client` | 客户端（最小化运行时） | linux/amd64, linux/arm64 | GitHub Container Registry |

**镜像标签**（每次发布自动生成）：

| 标签 | 示例 | 说明 |
|---|---|---|
| 完整版本号 | `v1.0.0` | 精确版本，推荐生产使用 |
| 主次版本 | `1.0` | 跟随 minor 更新 |
| 主版本 | `1` | 跟随 major 更新 |
| `latest` | `latest` | 始终指向最新正式版 |
| commit SHA | `sha-a1b2c3d` | 指向构建时的 commit |

---

## 拉取和使用 Docker 镜像

```bash
# 拉取最新版
docker pull ghcr.io/qozi/cert-keeper/server:latest
docker pull ghcr.io/qozi/cert-keeper/client:latest

# 拉取指定版本
docker pull ghcr.io/qozi/cert-keeper/server:v1.0.0

# 使用 docker-compose 启动服务端
cp deploy/config.example.yaml deploy/data/config/config.yaml  # 按需修改
cp deploy/docker-compose.yml .
docker compose up -d
```

---

## 常见问题

### tag 打错了怎么办？

```bash
# 删除本地 tag
git tag -d v1.0.0

# 删除远程 tag
git push --delete origin v1.0.0
```

> 注意：远程删除 tag 后，对应的 GitHub Release 需要手动在页面上删除。

**不建议**对已发布的版本在旧 tag 上强推。正确做法是升一个 patch 版本号重新发布：

```bash
git tag -a v1.0.1 -m "fix: 修正 v1.0.0 的 xxx 问题"
git push origin v1.0.1
```

### CI 触发了但 Docker 镜像没推上去？

检查 Actions 是否有 `packages: write` 权限（`release.yml` 已声明）。若使用 fork 仓库，需在 Settings → Actions → General 中确认 **Workflow permissions** 设为 `Read and write permissions`。

### 如何只发布二进制不发布 Docker 镜像？

在 GitHub Actions 手动触发 Release 时，可以在 Release 页面选择性跳过（但标准流程中三个 job 都会运行）。如需精确控制，建议修改 workflow 添加 `inputs` 控制。

---

## 附录：发布流程图

```
本地构建与测试（scripts/build.sh）
        │
        ▼
   测试通过
        │
        ▼
git push origin v1.0.0
         │
         ▼
  GitHub Actions 触发
  ┌──────────┬──────────────┐
  │          │              │
  ▼          ▼              ▼
goreleaser  docker-server  docker-client
  │          │              │
  │          │              │
  ▼          ▼              ▼
GitHub     ghcr.io/       ghcr.io/
Release    server         client
```
