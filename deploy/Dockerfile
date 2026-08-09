# 阶段1: 构建 Go 二进制
FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ck-server ./cmd/server \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/ck-client ./cmd/client

# 阶段2: 服务端运行时（含 acme.sh + 必要工具）
FROM alpine:3.20 AS server
RUN apk add --no-cache socat curl openssl ca-certificates tzdata bash \
 && mkdir -p /root/.acme.sh \
 && curl -fsSL https://get.acme.sh | sh \
 && ln -sf /root/.acme.sh/acme.sh /usr/local/bin/acme.sh
COPY --from=builder /out/ck-server /usr/local/bin/ck-server
COPY deploy/entrypoint-server.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
VOLUME ["/data"]
EXPOSE 8443
ENTRYPOINT ["/entrypoint.sh"]
CMD ["--config", "/data/config/config.yaml"]

# 阶段3: 客户端运行时（最小化）
FROM alpine:3.20 AS client
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /out/ck-client /usr/local/bin/ck-client
ENTRYPOINT ["/usr/local/bin/ck-client"]
