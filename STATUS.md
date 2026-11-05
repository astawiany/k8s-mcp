# Status

This file records, with dates, what has and has not been exercised outside
the local test suite. It is not part of the release archives; update it when
something changes.

As of 2026-11-05:

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
  (`test/release_test.go`) and actionlint, and the release image build, scan
  and file listing were run locally; its first run on GitHub is the `v0.1.0`
  release. The design follows the sibling project fleet-in-a-repo, whose
  release workflow ran on GitHub.
- **Behavioural eval** (`test/injection/eval/`): not yet run against a real
  model and cluster. Results will be recorded here with model and date.
