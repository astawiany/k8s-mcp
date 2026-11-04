# k8s-mcp

A read-only [Model Context Protocol](https://modelcontextprotocol.io) server for Kubernetes, written in Go.

Status: scaffold. See [LICENSE](LICENSE) (MIT).

## Development

- `make lint` - gofmt check, `go vet`, staticcheck, yamllint
- `make test` - `go test ./...`
- `make vuln` - govulncheck

Tool versions are pinned in [versions.env](versions.env).
