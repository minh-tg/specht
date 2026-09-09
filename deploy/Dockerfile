FROM node:22-alpine AS frontend-builder
WORKDIR /src/frontend
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/pnpm-workspace.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile
COPY frontend/ .
RUN pnpm run build

FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=frontend-builder /src/frontend/dist/ ./cmd/server/dist/dist/
RUN CGO_ENABLED=0 go build -o /bin/server ./cmd/server

FROM alpine:3.21
# Install runtime deps without hard-pinning patch versions: pinning an exact
# Alpine package version (e.g. tzdata=2026b-r0) breaks the image build the
# moment the distro bumps the rebuild (2026b -> 2026c), which is not what a
# build should fail on. ca-certificates and tzdata are stable interfaces; the
# Go binary is what we want reproducible, and go.mod already pins that.
RUN apk add --no-cache ca-certificates tzdata curl
COPY --from=builder /bin/server /usr/local/bin/specht
COPY --from=builder /src/migrations /migrations
RUN addgroup -S specht && adduser -S -G specht specht
USER specht
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -fsS http://localhost:8080/api/v1/health || exit 1
EXPOSE 8080
ENTRYPOINT ["specht"]
