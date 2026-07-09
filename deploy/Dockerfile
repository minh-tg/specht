FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /bin/server ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache \
    ca-certificates=20260413-r0 \
    tzdata=2026b-r0
COPY --from=builder /bin/server /usr/local/bin/specht
COPY --from=builder /src/migrations /migrations
EXPOSE 8080
ENTRYPOINT ["specht"]
