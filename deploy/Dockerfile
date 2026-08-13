# 阶段1: 构建 Go 二进制
FROM golang:1.26.5-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/certk-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/certk-server-cli ./cmd/server-cli \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/certk-client ./cmd/client

# 阶段2: 服务端运行时（含 acme.sh + 必要工具）
FROM alpine:3.20 AS server
# acme.sh 固定到具体 release tag 并校验 tarball sha256，避免 get.acme.sh 在线安装引入供应链漂移。
# 升级方法：修改 ACMESH_VERSION 为目标 tag（3.x tag 不带 v 前缀），并重新计算 sha256：
#   curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/<TAG>.tar.gz" | shasum -a 256
# 注意：GitHub 自动生成的归档 tarball 理论上可复现，但官方曾调整过压缩参数；
# 若构建时校验失败，先按上式重新计算哈希再更新 ACMESH_SHA256。
ARG ACMESH_VERSION=3.1.1
ARG ACMESH_SHA256=c5d623ac0af400e83cd676aefaf045228f60e9fc597fea5db4c3a5bd7f6bfcf4
RUN apk add --no-cache socat curl openssl ca-certificates tzdata bash \
 && mkdir -p /root/.acme.sh \
 && curl -fsSL -o /tmp/acme.sh.tar.gz "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACMESH_VERSION}.tar.gz" \
 && echo "${ACMESH_SHA256}  /tmp/acme.sh.tar.gz" | sha256sum -c - \
 && tar -xzf /tmp/acme.sh.tar.gz -C /tmp \
 && cd /tmp/acme.sh-${ACMESH_VERSION} \
 && ./acme.sh --install --home /root/.acme.sh \
 && cd / \
 && rm -rf /tmp/acme.sh.tar.gz /tmp/acme.sh-${ACMESH_VERSION} \
 && ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
COPY --from=builder /out/certk-server /usr/local/bin/certk-server
COPY --from=builder /out/certk-server-cli /usr/local/bin/certk-server-cli
COPY deploy/entrypoint-server.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--config", "/data/config/config.yaml"]

# 阶段3: 客户端运行时（最小化）
FROM alpine:3.20 AS client
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/certk-client /usr/local/bin/certk-client
ENTRYPOINT ["/usr/local/bin/certk-client"]
