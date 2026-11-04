include versions.env
export

.PHONY: lint test vuln
.DEFAULT_GOAL := test

lint:
	@out="$$(gofmt -l .)"; if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...
	@if command -v yamllint >/dev/null 2>&1; then yamllint -d relaxed . ; \
	else echo "yamllint not installed locally: skipping (CI installs yamllint==$(YAMLLINT_VERSION))"; fi

test:
	go test ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION) ./...
