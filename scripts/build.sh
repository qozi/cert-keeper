#!/usr/bin/env bash
set -euo pipefail

# CertKeeper 构建脚本
# 用法：
#   ./build.sh            构建当前平台 server + server-cli + client
#   ./build.sh all        跨平台构建到 dist/
#   ./build.sh docker     构建 docker 镜像

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"

# 版本信息（构建时注入）
VERSION=$(git -C "$ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w \
  -X github.com/siidoo/certkeeper/internal/version.Version=${VERSION} \
  -X github.com/siidoo/certkeeper/internal/version.GitCommit=${COMMIT} \
  -X github.com/siidoo/certkeeper/internal/version.BuildDate=${DATE}"

build_native() {
    mkdir -p "$DIST"
    cd "$ROOT"
    echo "==> 构建 certk-server ($(go env GOOS)/$(go env GOARCH))  version=${VERSION} commit=${COMMIT}"
    CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "$DIST/certk-server" ./cmd/server
    echo "==> 构建 certk-server-cli ($(go env GOOS)/$(go env GOARCH))"
    CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "$DIST/certk-server-cli" ./cmd/server-cli
    echo "==> 构建 certk-client ($(go env GOOS)/$(go env GOARCH))"
    CGO_ENABLED=0 go build -trimpath -ldflags="${LDFLAGS}" -o "$DIST/certk-client" ./cmd/client
    echo "==> 完成: $DIST"
}

build_all() {
    mkdir -p "$DIST"
    cd "$ROOT"
    local targets=(
        "linux/amd64"
        "linux/arm64"
        "linux/arm"
        "darwin/amd64"
        "darwin/arm64"
    )
    for t in "${targets[@]}"; do
        local os="${t%/*}"
        local arch="${t#*/}"
        local out="$DIST/certk-server-${os}-${arch}"
        echo "==> 构建 certk-server $os/$arch"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="${LDFLAGS}" -o "$out" ./cmd/server
        local out_cli="$DIST/certk-server-cli-${os}-${arch}"
        echo "==> 构建 certk-server-cli $os/$arch"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="${LDFLAGS}" -o "$out_cli" ./cmd/server-cli
        local outc="$DIST/certk-client-${os}-${arch}"
        echo "==> 构建 certk-client $os/$arch"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="${LDFLAGS}" -o "$outc" ./cmd/client
    done
    echo "==> 完成: $DIST"
}

build_docker() {
    cd "$ROOT"
    docker build -f deploy/Dockerfile -t certkeeper/certk-server:latest --target server .
    docker build -f deploy/Dockerfile -t certkeeper/certk-client:latest --target client .
    echo "==> Docker 镜像构建完成"
}

case "${1:-native}" in
    native|"") build_native ;;
    all)       build_all ;;
    docker)    build_docker ;;
    *) echo "未知子命令: $1"; echo "用法: $0 [native|all|docker]"; exit 1 ;;
esac
