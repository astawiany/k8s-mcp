# Release image of k8s-mcp: one static binary on distroless static nonroot.
# Base images are pinned by digest (tag kept for readability; the builder's Go version equals
# GO_VERSION in versions.env and the toolchain line of go.mod). The build is deterministic for a given
# source: no VCS stamping, read-only module graph (go.sum is authoritative), stripped paths.
# release.yml also passes SOURCE_DATE_EPOCH, so a rebuild of the same commit yields the same image
# config (the scanned image and the pushed image are compared by config digest).
# Local build: docker build --build-arg VERSION=v0.0.0-dev -t k8s-mcp:dev .
FROM golang:1.26.10-alpine@sha256:a2012b4a1d1f9f7e9f44e0d39b805a901e856b1dd80b4e6ee4338db547050308 AS build
ARG VERSION=dev
ENV CGO_ENABLED=0 GOFLAGS=-mod=readonly GOTOOLCHAIN=local
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY cmd/ cmd/
COPY internal/ internal/
# VERSION ends up in -ldflags: refuse anything that could add linker flags.
RUN case "$VERSION" in ""|*[!A-Za-z0-9._+-]*) echo "invalid VERSION '$VERSION'" >&2; exit 1 ;; esac \
    && go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=${VERSION}" -o /out/k8s-mcp ./cmd/k8s-mcp

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
# OCI labels; release.yml sets the real values. The source label also links the GHCR package to the repo.
ARG VERSION=dev
ARG REVISION=unknown
ARG SOURCE=https://github.com/astawiany/k8s-mcp
LABEL org.opencontainers.image.title="k8s-mcp" \
      org.opencontainers.image.description="Read-only Kubernetes MCP server (stdio)" \
      org.opencontainers.image.source="${SOURCE}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /out/k8s-mcp /k8s-mcp
USER 65532:65532
ENTRYPOINT ["/k8s-mcp"]
