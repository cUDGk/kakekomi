# kakekomi 用 ハードン済み Dockerfile
#
# Multi-stage build:
#   1. golang:alpine で静的バイナリをビルド (CGO 無効、netgo+osusergo)
#   2. distroless/static で実行 (シェルなし、パッケージマネージャなし、libc なし)
#
# Build:   docker build -f deploy/docker/Dockerfile -t kakekomi:latest .
# Run:     docker run --rm -it \
#            --read-only \
#            --cap-drop=ALL \
#            --security-opt=no-new-privileges \
#            --security-opt=seccomp=deploy/docker/seccomp.json \
#            --tmpfs /tmp:rw,noexec,nosuid,size=64m \
#            -v $(pwd)/data:/data \
#            -v /run/kakekomi:/run/kakekomi \
#            kakekomi:latest

# ──────────────────────────────────────────────────
# Build stage
# ──────────────────────────────────────────────────
FROM golang:1.22-alpine AS build

WORKDIR /src

# 依存先に確定
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# ソース全体
COPY . .

# 再現可能ビルド (trimpath, no buildid)
ARG VERSION=dev
ENV CGO_ENABLED=0 \
    GOFLAGS="-trimpath -buildvcs=true" \
    GOOS=linux

RUN go build \
      -trimpath \
      -buildvcs=true \
      -ldflags="-s -w -buildid= -X main.version=${VERSION}" \
      -tags 'netgo osusergo' \
      -o /out/kakekomi \
      ./cmd/kakekomi

# air-gap viewer (別バイナリ)
RUN go build \
      -trimpath \
      -buildvcs=true \
      -ldflags="-s -w -buildid=" \
      -tags 'netgo osusergo airgap' \
      -o /out/kakekomi-viewer \
      ./cmd/viewer || true

# バイナリ強度確認
RUN apk add --no-cache file && file /out/kakekomi

# ──────────────────────────────────────────────────
# Runtime stage: distroless static (nonroot)
# ──────────────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="kakekomi"
LABEL org.opencontainers.image.description="anonymous tipline (hardened)"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.source="https://github.com/<TBD>/kakekomi"

COPY --from=build /out/kakekomi /kakekomi
COPY --from=build /out/kakekomi-viewer /kakekomi-viewer

# nonroot user (UID 65532) を使う
USER nonroot:nonroot

# 内部 HTTP port (tor が proxy する)
# ※ Unix socket 運用なら EXPOSE は不要
EXPOSE 8080

ENTRYPOINT ["/kakekomi"]
CMD ["run", "--data-dir=/data"]
