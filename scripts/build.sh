#!/usr/bin/env bash
set -euo pipefail

# CertKeeper 构建脚本
# 用法：
#   ./build.sh            构建当前平台 server + client
#   ./build.sh all        跨平台构建到 dist/
#   ./build.sh docker     构建 docker 镜像

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"

build_native() {
    mkdir -p "$DIST"
    cd "$ROOT"
    echo "==> 构建 ck-server ($(go env GOOS)/$(go env GOARCH))"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$DIST/ck-server" ./cmd/server
    echo "==> 构建 ck-client ($(go env GOOS)/$(go env GOARCH))"
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$DIST/ck-client" ./cmd/client
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
        local out="$DIST/ck-server-${os}-${arch}"
        echo "==> 构建 ck-server $os/$arch"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$out" ./cmd/server
        local outc="$DIST/ck-client-${os}-${arch}"
        echo "==> 构建 ck-client $os/$arch"
        CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags="-s -w" -o "$outc" ./cmd/client
    done
    echo "==> 完成: $DIST"
}

build_docker() {
    cd "$ROOT"
    docker build -f deploy/Dockerfile -t certkeeper/server:latest --target server .
    docker build -f deploy/Dockerfile -t certkeeper/client:latest --target client .
    echo "==> Docker 镜像构建完成"
}

case "${1:-native}" in
    native|"") build_native ;;
    all)       build_all ;;
    docker)    build_docker ;;
    *) echo "未知子命令: $1"; echo "用法: $0 [native|all|docker]"; exit 1 ;;
esac
