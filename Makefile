VERSION ?=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_SYMBOL := github.com/venslabs/vens/cmd/vens/version.Version

export CGO_ENABLED ?= 0

GO ?= go
GO_LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"
# Bump by hand when a newer golangci-lint v2 lands: Dependabot tracks the
# action SHA and go modules, not this pin, so it will otherwise go stale silently.
GOLANGCI_VERSION ?= v2.12.2
GOPATH_BIN := $(shell $(GO) env GOBIN)
ifeq ($(GOPATH_BIN),)
GOPATH_BIN := $(shell $(GO) env GOPATH)/bin
endif

.PHONY: all
all: binaries

.PHONY: binaries
binaries: _output/bin/vens

.PHONY: test
test:
	$(GO) test -v ./...

.PHONY: test-integration
test-integration:
	$(GO) test -v ./cmd/vens/... -run TestScript

.PHONY: fmt
fmt:
	@PATH="$(GOPATH_BIN):$$PATH" command -v goimports >/dev/null 2>&1 || $(GO) install golang.org/x/tools/cmd/goimports@latest
	gofmt -s -w .
	PATH="$(GOPATH_BIN):$$PATH" goimports -w .

.PHONY: lint
lint:
	@PATH="$(GOPATH_BIN):$$PATH" command -v golangci-lint >/dev/null 2>&1 || $(GO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)
	PATH="$(GOPATH_BIN):$$PATH" golangci-lint run --timeout=10m --verbose

.PHONY: print-golangci-version
print-golangci-version:
	@echo $(GOLANGCI_VERSION)

.PHONY: _output/bin/vens
_output/bin/vens:
	$(GO_BUILD) -o $@ ./cmd/vens

.PHONY: artifacts
artifacts:
	@mkdir -p _output
	@for os in linux darwin; do \
		for arch in amd64 arm64; do \
			ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
			echo "Building vens-$$os-$$arch$$ext"; \
			GOOS=$$os GOARCH=$$arch $(GO_BUILD) -o _output/vens$$ext ./cmd/vens; \
			tar -czf _output/vens-$(VERSION)-$$os-$$arch.tar.gz -C _output vens$$ext; \
			rm _output/vens$$ext; \
		done; \
	done

.PHONY: quickstart-run
quickstart-run:
    # Before executing this target, make sure to set the --llm flag and export the required environment variables (e.g., API_KEY)
	@mkdir -p _output
	go run ./cmd/vens generate \
	  --config-file examples/quickstart/config.yaml \
	  --llm openai \
	  examples/quickstart/reports/python-slim.trivy.json \
	  _output/vex_quickstart.json

.PHONY: quickstart-enrich
quickstart-enrich:
	@mkdir -p _output
	go run ./cmd/vens enrich \
	  --vex _output/vex_quickstart.json \
	  --output _output/enriched_trivy.json \
	  examples/quickstart/trivy.json

.PHONY: install-plugin
install-plugin:
	$(GO_BUILD) -o vens ./cmd/vens
	-trivy plugin uninstall vens
	trivy plugin install .