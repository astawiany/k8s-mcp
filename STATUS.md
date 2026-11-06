# Status

This file records, with dates, what has and has not been exercised outside
the local test suite. It is not part of the release archives; update it when
something changes.

As of 2026-11-06:

- **Unit, protocol, injection-corpus and built-binary tests** (`make test`,
  `go test -race ./...`) pass locally.
- **kind integration tests** (`make integration`) passed locally on a
  throwaway kind cluster during development (about 75 seconds) and passed on
  GitHub Actions in the first `validate` run on `main` (about 3.5 minutes).
- **GitHub workflows**: `validate.yml` ran on GitHub for the first time on
  2026-11-05 (push to `main`): `lint`, `test`, `integration` and `security`
  all passed (`test` took about 8 minutes). Branch protection, the `release`
  Environment and the `release-tags` ruleset were applied the same day with
  `scripts/protect-branch.sh`. `release.yml` is covered by static tests
  (`test/release_test.go`) and actionlint, and its first run on GitHub was the
  `v0.1.0` release on 2026-11-05 (all seven jobs passed, with both `release`
  Environment approvals given by the owner). The design follows the sibling
  project fleet-in-a-repo, whose release workflow also ran on GitHub.
- **Release `v0.1.0`** (2026-11-05): verified independently afterwards, using
  only public access and an empty Docker config, with the commands in
  [docs/security.md](docs/security.md): the signatures of `SHA256SUMS` and of
  all four archives verify with the exact identity
  `.../release.yml@refs/tags/v0.1.0`, the checksums match, the macOS binary
  prints `v0.1.0`, and the image `ghcr.io/astawiany/k8s-mcp` verifies by
  digest (`sha256:b5e2b30f...ca934f`), carries an SBOM and provenance, and
  pulls anonymously. The image is linux/amd64 only. This is point-in-time
  evidence about those artefacts, not a guarantee about future releases.
- **Acceptance run** (a Claude Code session troubleshooting a deliberately
  broken workload in the fleet-in-a-repo fleet): not yet done.
- **Behavioural eval** (`test/injection/eval/`): not yet run against a real
  model and cluster. Results will be recorded here with model and date.
