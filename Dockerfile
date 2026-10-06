# Multi-Stage Build: Kompiliert statisches Go-Binary für jede Plattform (x86_64, ARM64 / Pi 5)
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

WORKDIR /app

# Abhängigkeiten cachen
COPY go.mod go.sum ./
RUN go mod download

# Quellcode kopieren
COPY . .

# Argumente für Multi-Architektur Cross-Compilation
ARG TARGETOS
ARG TARGETARCH

# Statisches, CGO-freies Binary kompilieren
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -o sentinelbit ./cmd/server

# -------------------------------------------------------------
# Minimales Produktiv-Image (Alpine oder Scratch)
# -------------------------------------------------------------
FROM alpine:3.20

# TLS-Zertifikate für sichere externe Anfragen (z.B. HIBP) & Zeitzonen
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

# Nur die Binärdatei und statische Frontend-Dateien kopieren
COPY --from=builder /app/sentinelbit /app/sentinelbit
COPY --from=builder /app/static /app/static

# Datenverzeichnis für SQLite & Backups
VOLUME /data
ENV SENTINELBIT_DATA_DIR=/data
ENV SENTINELBIT_PORT=8000

EXPOSE 8000

# Docker Healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://127.0.0.1:8000/ || exit 1

# Startbefehl
CMD ["/app/sentinelbit"]

