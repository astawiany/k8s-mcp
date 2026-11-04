include versions.env
export

.PHONY: build lint test vuln integration
.DEFAULT_GOAL := test

# VERSION is stamped into the binary with -ldflags "-X main.version=..."
# (k8s-mcp --version prints it). Override: make build VERSION=v1.2.3
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Static, reproducible-path build of the server into bin/k8s-mcp.
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)" -o bin/k8s-mcp ./cmd/k8s-mcp

lint:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	@if command -v yamllint >/dev/null 2>&1; then yamllint --strict . ; \
	else echo "yamllint not installed locally: skipping (CI installs yamllint==$(YAMLLINT_VERSION))"; fi

test:
	go test ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...

# kind integration tests (Docker, kind, kubectl, curl required): creates the
# throwaway cluster k8s-mcp-it, runs test/integration with -tags integration
# and always deletes the cluster. See test/integration/run.sh.
integration:
	test/integration/run.sh
