# Exalm Makefile
#
# Common targets:
#   make build           — build the binary to ./bin/exalm
#   make build-linux     — build a Linux ELF binary regardless of host OS
#   make test            — run all unit tests
#   make test-redact     — run redaction tests verbosely (run before any redact change)
#   make lint            — gofmt + go vet
#   make run             — build + run with --help
#   make clean           — remove build artifacts
#
# Container & chart targets:
#   make image           — docker build → exalm:dev
#   make image-push      — docker build + push to $IMAGE_REPO:$VERSION
#   make chart-lint      — helm lint the exalm-agent chart
#   make chart-template  — render every example values file (smoke test)
#   make chart-package   — produce ./bin/exalm-agent-<ver>.tgz

BINARY      := exalm
PKG         := github.com/exalm-ai/exalm
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Container image
IMAGE_REPO  ?= ghcr.io/exalm-ai/exalm
IMAGE_TAG   ?= $(VERSION)

# Helm chart
CHART_DIR   := deploy/helm/exalm-agent

LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) \
           -X $(PKG)/internal/version.Commit=$(COMMIT) \
           -X $(PKG)/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: build build-linux test test-redact lint run clean tidy \
        image image-push chart-lint chart-template chart-package

build:
	@mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/exalm

# build-linux produces a Linux ELF binary regardless of host OS.
# Use this from WSL so that `export EXALM_LLM_MODEL=...` is inherited.
build-linux:
	@mkdir -p bin
	GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/exalm

test:
	go test ./...

test-redact:
	go test -v -run . ./internal/redact

lint:
	gofmt -s -l . | tee /dev/stderr | (! grep .)
	go vet ./...

run: build
	./bin/$(BINARY) --help

tidy:
	go mod tidy

clean:
	rm -rf bin/

# -----------------------------------------------------------------------------
# Container image
# -----------------------------------------------------------------------------
image:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t exalm:dev \
		-t $(IMAGE_REPO):$(IMAGE_TAG) \
		.

image-push: image
	docker push $(IMAGE_REPO):$(IMAGE_TAG)

# -----------------------------------------------------------------------------
# Helm chart
# -----------------------------------------------------------------------------
chart-lint:
	helm lint $(CHART_DIR)

chart-template:
	@echo "→ default (ollama, no key)"
	@helm template test $(CHART_DIR) >/dev/null
	@echo "→ claude provider with inline secret"
	@helm template test $(CHART_DIR) --set llm.provider=claude --set llm.apiKey=sk-ant-EXAMPLE >/dev/null
	@echo "→ openrouter provider"
	@helm template test $(CHART_DIR) --set llm.provider=openrouter --set llm.model=qwen/qwen-2.5-0.5b-instruct --set llm.apiKey=sk-or-EXAMPLE >/dev/null
	@echo "→ openai with existing secret"
	@helm template test $(CHART_DIR) --set llm.provider=openai --set llm.existingSecret=my-secret >/dev/null
	@echo "→ rbac.allowApply=true"
	@helm template test $(CHART_DIR) --set rbac.allowApply=true >/dev/null
	@echo "→ SLO + Prometheus"
	@helm template test $(CHART_DIR) --set slo.enabled=true --set slo.specConfigMap=my-slos --set slo.prometheusURL=http://prom:9090 >/dev/null
	@echo "✓ all chart render scenarios passed"

chart-package:
	@mkdir -p bin
	helm package $(CHART_DIR) --destination bin/
