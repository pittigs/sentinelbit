# ==============================================================================
# Sentinelbit - Makefile (100% Go Single-Binary Stack)
# ==============================================================================

BINARY_NAME=sentinelbit
CLI_NAME=sentinelbit-cli
CMD_PATH=./cmd/server
CLI_PATH=./cmd/cli
BUILD_DIR=./bin
LDFLAGS=-s -w

.PHONY: all build build-server build-cli run test clean docker docker-run build-pi build-linux build-windows

all: build

## build: Kompiliert Server und CLI
build: build-server build-cli

## build-server: Kompiliert das Go-Server-Binary für das aktuelle System
build-server:
	@echo "🔨 Kompiliere $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "✅ Erfolgreich gebaut: $(BUILD_DIR)/$(BINARY_NAME)"

## build-cli: Kompiliert das administrative CLI-Tool
build-cli:
	@echo "🔨 Kompiliere $(CLI_NAME)..."
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(CLI_NAME) $(CLI_PATH)
	@echo "✅ Erfolgreich gebaut: $(BUILD_DIR)/$(CLI_NAME)"

## run: Startet Sentinelbit Server direkt aus dem Quellcode
run:
	@echo "🚀 Starte Sentinelbit Server..."
	go run $(CMD_PATH)

## test: Führt alle Tests aus
test:
	@echo "🧪 Führe Go-Tests aus..."
	go test -v ./...

## build-pi: Cross-Compilation für Raspberry Pi (ARM64 / aarch64)
build-pi:
	@echo "🥧 Kompiliere statisches Binary für Raspberry Pi (Linux ARM64)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-arm64 $(CMD_PATH)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(CLI_NAME)-arm64 $(CLI_PATH)
	@echo "✅ Fertig: $(BUILD_DIR)/$(BINARY_NAME)-arm64"

## build-linux: Kompiliert statisches Binary für Linux x86_64
build-linux:
	@echo "🐧 Kompiliere statisches Binary für Linux x86_64..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(CLI_NAME)-linux-amd64 $(CLI_PATH)
	@echo "✅ Fertig: $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

## build-windows: Kompiliert Binary für Windows x86_64
build-windows:
	@echo "🪟 Kompiliere Binary für Windows (x86_64)..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME).exe $(CMD_PATH)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(BUILD_DIR)/$(CLI_NAME).exe $(CLI_PATH)
	@echo "✅ Fertig: $(BUILD_DIR)/$(BINARY_NAME).exe"

## docker: Erstellt das schlanke Docker-Image
docker:
	@echo "🐳 Erstelle Docker-Image 'sentinelbit:latest'..."
	docker build -t sentinelbit:latest .

## docker-run: Startet den Docker-Container
docker-run:
	@echo "🐳 Starte Container via Docker Compose..."
	docker compose up -d

## clean: Löscht kompilierte Binärdateien
clean:
	@echo "🧹 Bereinige Build-Artefakte..."
	rm -rf $(BUILD_DIR)
	@echo "✅ Bereinigt."
