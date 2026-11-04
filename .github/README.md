# GitHub setup

What lives here: `workflows/validate.yml` (the only workflow), `CODEOWNERS` (`* @astawiany`) and
this file. Nothing here publishes anything; a release workflow, if one is added later, must reuse
the `release` Environment and the `v*` tag rules described below.

## The validate workflow

Runs on pushes to `main`, on every pull request (including the integration job) and on manual
dispatch. Superseded pull-request runs are cancelled. Permissions are `contents: read` for the
whole workflow, every job has a timeout, and no job reads a secret.

| Job | Required | What it does |
| --- | --- | --- |
| `lint` | yes | `make lint` (gofmt, go vet, pinned staticcheck, `yamllint --strict`), shellcheck on `scripts/*.sh` and `test/integration/run.sh`, actionlint |
| `test` | yes | `go test -race ./...` |
| `integration` | yes | `make integration`: a throwaway kind cluster (`k8s-mcp-it`) with Flux and the fixtures; Docker comes with the ubuntu runner |
| `security` | no | `make vuln` (govulncheck) and `trivy fs` (fixable HIGH/CRITICAL fail, secrets fail) |

`security` is deliberately not a required check: it downloads vulnerability databases at run time,
so an upstream outage or a newly published CVE must not block unrelated merges. It still runs and
shows red when it finds something; treat that as a to-do, not as noise.

Go, kind, kubectl, Trivy and actionlint are installed by `scripts/ci-install-tools.sh` from
official release archives whose sha256 is pinned in `versions.env` (a mismatch aborts the job).
The Go version is the `go` line of `go.mod` (a test keeps them equal), and `GOTOOLCHAIN=local`
stops the go command from fetching another toolchain. The only third-party action is
`actions/checkout`.

## Action pinning (no Dependabot)

Every `uses:` is pinned by commit SHA with a version comment (`@<40 hex> # v4.2.2`);
`test/workflows_test.go` fails on anything else. There is no Dependabot: bumps are manual.
Recipe for an action `owner/repo` at a release tag `vX.Y.Z` that is at least two weeks old:

```sh
gh api repos/owner/repo/git/ref/tags/vX.Y.Z --jq .object.sha   # lightweight tag: this is the commit
# annotated tag: the sha above is the tag object; dereference it
gh api repos/owner/repo/git/tags/<that sha> --jq .object.sha
```

Replace the SHA and the comment in `validate.yml`, read the release notes, run `make test`. The
current `actions/checkout` pin (v4.2.2) was copied from the sibling project fleet-in-a-repo and
re-checked with the first command above. Tool pins in `versions.env` carry their own lookup notes.

## Settings the repository needs

1. Settings > Actions > General: workflow permissions "Read repository contents and packages
   permissions" (read-only default token); leave "Allow GitHub Actions to create and approve pull
   requests" off, nothing here needs it. The token is `GITHUB_TOKEN` only, read-only, never given
   to PR code with write access. The workflow has no `pull_request_target` trigger, so pull
   requests from forks run without secrets.
2. Branch protection, the `release` Environment and the tag ruleset, applied by one script. Preview:

   ```sh
   scripts/protect-branch.sh --dry-run --repo astawiany/k8s-mcp
   ```

   Drop `--dry-run` to apply (needs `gh auth login` with admin rights on the repository). Without
   `--repo` it refuses to run, dry run included. Options:

   - `--approvals N` (0-6, default 0): approving reviews required. With 1 or more, code-owner
     review is required too.
   - `--enforce-admins`: apply the rules to admins as well (off by default).
   - `--no-protect-tags`: skip the tag ruleset (prints a warning).

   What it sets:
   - `main`: pull request required, status checks `lint`, `test`, `integration` required and up to
     date (strict). `security` is not listed.
   - Environment `release`: required reviewer is the repository owner, deployments only from `v*`
     tags (a deployment tag policy). Use it in the `environment:` of any future publishing job.
   - Ruleset `release-tags` (Settings > Rules > Rulesets): only repository admins may create, move
     or delete `v*` tags, because a pushed tag runs the workflows of the tagged commit. Re-running
     updates it. Rulesets need a public repository or a paid plan.
   - Read-back: after applying, the script reads the release tag policy, the ruleset and the
     branch protection back and exits 1 if any is missing.
3. Settings > Code security: enable private vulnerability reporting and secret scanning with push
   protection if the plan offers them.

## Solo maintainer

GitHub never lets an author approve their own pull request, so with one maintainer keep
`--approvals 0` (merges are still gated by the three required checks; code-owner review is then
off) and leave `--enforce-admins` off, or you lock yourself out of `main`. You can still be the
`release` Environment reviewer: unless "Prevent self-review" is enabled on the Environment, you can
approve your own deployment. Add a second maintainer before raising either setting.
