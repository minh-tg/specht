FROM docker.io/library/node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS frontend-builder
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY frontend/ .
RUN pnpm run build

FROM docker.io/library/golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS builder
ARG VERSION=dev
ARG COMMIT=unknown
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /src/frontend/dist/ ./cmd/server/dist/dist/
RUN CGO_ENABLED=0 go build \
    -ldflags "-X github.com/minh-tg/specht/internal/version.Version=${VERSION} -X github.com/minh-tg/specht/internal/version.Commit=${COMMIT}" \
    -o /bin/server ./cmd/server

FROM docker.io/library/alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
# Install runtime deps without hard-pinning patch versions: pinning an exact
# Alpine package version (e.g. tzdata=2026b-r0) breaks the image build the
# moment the distro bumps the rebuild (2026b -> 2026c), which is not what a
# build should fail on. ca-certificates and tzdata are stable interfaces; the
# Go binary is what we want reproducible, and go.mod already pins that.
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /bin/server /usr/local/bin/specht
COPY --from=builder /src/migrations /migrations
RUN addgroup -S specht && adduser -S -G specht specht
USER specht
# The binary probes itself, so the image needs no HTTP client of its own.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["specht", "healthcheck"]
EXPOSE 8080
ENTRYPOINT ["specht"]
