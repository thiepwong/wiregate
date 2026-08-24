SHELL := /bin/sh
WORKSPACE_DIR := $(abspath $(CURDIR)/..)
BUILD_DIR := $(WORKSPACE_DIR)/build
TOOLS_DIR := $(BUILD_DIR)/tools/bin
BUF_CACHE_DIR := $(BUILD_DIR)/cache/buf
GOMODCACHE := $(BUILD_DIR)/cache/go-mod
GOCACHE := $(BUILD_DIR)/cache/go-build
BIN_DIR := $(BUILD_DIR)/bin
GO_FILES := $(shell find cmd internal gen -name '*.go' -type f 2>/dev/null)
PROTOC_GEN_GO_VERSION := v1.36.11
PROTOC_GEN_GO_GRPC_VERSION := v1.6.2
export BUF_CACHE_DIR GOMODCACHE GOCACHE

.PHONY: tools deps generate fmt lint test build check bundle clean

tools: $(TOOLS_DIR)/protoc-gen-go $(TOOLS_DIR)/protoc-gen-go-grpc

$(TOOLS_DIR)/protoc-gen-go:
	mkdir -p $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install google.golang.org/protobuf/cmd/protoc-gen-go@$(PROTOC_GEN_GO_VERSION)

$(TOOLS_DIR)/protoc-gen-go-grpc:
	mkdir -p $(TOOLS_DIR)
	GOBIN=$(TOOLS_DIR) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@$(PROTOC_GEN_GO_GRPC_VERSION)

deps:
	go mod tidy

generate: tools
	buf generate

fmt:
	gofmt -w $(GO_FILES)

lint:
	buf lint
	go vet ./...

test:
	go test ./...

build:
	mkdir -p $(BIN_DIR)
	go build -trimpath -o $(BIN_DIR)/wiregate-agent ./cmd/wiregate-agent
	go build -trimpath -o $(BIN_DIR)/wiregate-web ./cmd/wiregate-web

check: generate fmt lint test build

bundle: check
	./scripts/build-bundle.sh

clean:
	rm -rf $(BIN_DIR) gen/wiregate
