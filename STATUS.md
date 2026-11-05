# Status

This file records, with dates, what has and has not been exercised outside
the local test suite. It is not part of the release archives; update it when
something changes.

As of 2026-11-05:

- **Unit, protocol, injection-corpus and built-binary tests** (`make test`,
  `go test -race ./...`) pass locally.
- **kind integration tests** (`make integration`) passed when last run
  locally on a throwaway kind cluster during development (about 75 seconds);
  they were not re-run after the final round of fixes.
- **GitHub workflows**: `validate.yml` and `release.yml` are covered by
  static tests (`test/workflows_test.go`, `test/release_test.go`) and
  actionlint in CI, and the release image build, scan and file listing were
  run locally. Neither workflow has run on GitHub yet, and no release has
  been published. The design follows the sibling project fleet-in-a-repo,
  whose release workflow did run on GitHub.
- **Behavioural eval** (`test/injection/eval/`): not yet run against a real
  model and cluster. Results will be recorded here with model and date.
