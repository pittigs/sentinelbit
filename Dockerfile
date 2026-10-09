# Multi-Stage Build: Kompiliert statisches Go-Binary für jede Plattform (x86_64, ARM64 / Pi 5)
FROM --platform=$BUILDPLATFORM golang:alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

# Abhängigkeiten cachen
COPY go.mod go.sum ./
RUN go mod download

# Quellcode kopieren
COPY . .

# Argumente für Multi-Architektur Cross-Compilation
ARG TARGETOS
ARG TARGETARCH

# Statische, CGO-freie Binaries kompilieren
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o sentinelbit ./cmd/server
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o sentinelbit-cli ./cmd/cli

# -------------------------------------------------------------
# Minimales Produktiv-Image
# -------------------------------------------------------------
FROM alpine:3.20

# TLS-Zertifikate für sichere externe Anfragen & Zeitzonen
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Binärdateien und statische Assets kopieren
COPY --from=builder /app/sentinelbit /app/sentinelbit
COPY --from=builder /app/sentinelbit-cli /usr/local/bin/sentinelbit-cli
COPY --from=builder /app/static /app/static

# Datenverzeichnis für SQLite & Backups
VOLUME /data
ENV SENTINELBIT_DATA_DIR=/data
ENV SENTINELBIT_PORT=8000
ENV SENTINELBIT_HOST=0.0.0.0
ENV SENTINELBIT_DISABLE_REGISTRATION=false
ENV SENTINELBIT_LOG_LEVEL=info

EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8000/api/health || exit 1

# Startbefehl
CMD ["/app/sentinelbit"]
