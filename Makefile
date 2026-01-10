VERSION ?=$(shell git describe --match 'v[0-9]*' --dirty='.m' --always --tags)
VERSION_SYMBOL := github.com/fahedouch/vens/cmd/vens/version.Version

GO ?= go
GO_LDFLAGS ?= -s -w -X $(VERSION_SYMBOL)=$(VERSION)
GO_BUILD ?= $(GO) build -trimpath -ldflags="$(GO_LDFLAGS)"

.PHONY: all
all: binaries

.PHONY: binaries
binaries: _output/bin/vens

.PHONY: test
test:
	$(GO) test -v ./...

.PHONY: _output/bin/vens
_output/bin/vens:
	$(GO_BUILD) -o $@ ./cmd/vens

.PHONY: quickstart-run
quickstart-run:
    # Before executing this target, make sure to set the --llm flag and export the required environment variables (e.g., API_KEY)
	@mkdir -p _output
	go run ./cmd/vens generate \
	  --config-file examples/quickstart/config.yaml \
	  --llm openai \
	  --sboms examples/quickstart/sbom.cdx.json \
	  examples/quickstart/trivy.json \
	  _output/vex_quickstart.json

.PHONY: quickstart-enrich
quickstart-enrich:
	@mkdir -p _output
	go run ./cmd/vens enrich \
	  --vex _output/vex_quickstart.json \
	  --output _output/enriched_trivy.json \
	  examples/quickstart/trivy.json