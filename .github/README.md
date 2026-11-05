# GitHub setup

What lives here: `workflows/validate.yml` (the gate for `main`), `workflows/release.yml` (publishes
signed binaries and a signed image on a `v*` tag), `CODEOWNERS` (`* @astawiany`) and this file.

## The release workflow

`release.yml` runs only on pushed `v*` tags. Workflow-level permissions are `{}`; each job gets its
own. `verify` (tag is exactly `vX.Y.Z`, commit is on `origin/main`, version absent from GHCR and from
the Releases) gates `build` (four static binaries, govulncheck per platform), `image` (scan before
push, push by digest with SBOM and provenance, cosign sign and verify, then tag) and `release`
(`cosign sign-blob` bundles, `verify-blob`, `gh release create`). `image` and `release` run in the
`release` Environment, so each waits for a reviewer. Consumer verification, threat model and the
release procedure: [docs/security.md](../docs/security.md#verifying-releases). Its third-party actions
are `actions/checkout`, `actions/upload-artifact` and `actions/download-artifact` (SHA from
`gh api repos/actions/download-artifact/git/ref/tags/v8.0.2`, released 2026-10-07; v8 fails on an
artifact digest mismatch by default). cosign, Trivy, BuildKit and the SBOM scanner are pinned in
`versions.env`.

## The validate workflow

Runs on pushes to `main`, on every pull request (including the integration job) and on manual
dispatch. Superseded pull-request runs are cancelled. Permissions are `contents: read` for the
whole workflow, every job has a timeout, and no job reads a secret.

| Job | Required | What it does |
| --- | --- | --- |
| `lint` | yes | `make lint` (gofmt, go vet, pinned staticcheck, `yamllint --strict`), shellcheck on `scripts/*.sh` and `test/integration/run.sh`, actionlint |
| `test` | yes | `go test -race ./...` |
| `integration` | yes | `make integration`: a throwaway kind cluster (`k8s-mcp-it`) with Flux and the fixtures; Docker comes with the ubuntu runner. On failure `run.sh` writes diagnostics (pods, events, flux-system logs, `kind export logs`; never Secrets, files with a canary, token or JWT are deleted) before deleting the cluster, and the workflow uploads them with `actions/upload-artifact` as `integration-diagnostics` (7 days) |
| `security` | no | `make vuln` (govulncheck) and `trivy fs` (fixable HIGH/CRITICAL fail, secrets fail) |

`security` is deliberately not a required check: it downloads vulnerability databases at run time,
so an upstream outage or a newly published CVE must not block unrelated merges. It still runs and
shows red when it finds something; treat that as a to-do, not as noise.

### Failure diagnostics artifact

When `integration` fails, the `integration-diagnostics` artifact contains exactly:

- `pods-events.txt`: `kubectl get pods,events -A -o wide`;
- `describe-<ns>-<pod>.txt`: `describe` of the pods that are not ready;
- `flux-logs/`: the last 200 log lines of each `flux-system` pod;
- `kind/`, an allow-listed reduction of `kind export logs`: the top-level `kind-version.txt` and
  `docker-info.txt`, and per node only `kubelet.log`, `containerd.log`, `journal.log`, `inspect.json`,
  `kubernetes-version.txt` and the pod-log directories `pods/kube-system_*`, `pods/flux-system_*` and
  `pods/local-path-storage_*`. Everything else kind copies from the node's `/var/log` is deleted
  (`containers/`, the pod logs of every other namespace, in particular the `log-injection` fixture with
  its intentional fake credentials, apt and alternatives logs, ...), as are symlinks. Deletion never
  follows symlinks.

Secrets and kubeconfigs are never dumped. Files containing the real canary value, a minted
ServiceAccount token or any JWT are deleted with an error message, and a final sweep deletes any
remaining file holding the fixture's fake credentials; neither changes the exit code of the run. For a
public repository the artifact is downloadable by anyone signed in to GitHub, so treat its content as
public. It expires after 7 days (`retention-days: 7`).

Go, kind, kubectl, Trivy and actionlint are installed by `scripts/ci-install-tools.sh` from
official release archives whose sha256 is pinned in `versions.env` (a mismatch aborts the job).
The Go version is the `toolchain` line of `go.mod` (a test keeps them equal; the `go` line stays the
language floor, and the pin is a current patch because govulncheck checks the stdlib it runs on), and `GOTOOLCHAIN=local`
stops the go command from fetching another toolchain. The third-party actions are
`actions/checkout` and, for failure diagnostics, `actions/upload-artifact` (SHA from
`gh api repos/actions/upload-artifact/git/ref/tags/v7.0.2`, released 2026-10-07).

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
   - Environment `release`: required reviewer is the repository owner (added as `type: User` with the
     owner's id, so for an organization-owned repository add a team reviewer by hand), deployments only from `v*`
     tags (a deployment tag policy). Use it in the `environment:` of any future publishing job.
   - Ruleset `release-tags` (Settings > Rules > Rulesets): only repository admins may create, move
     or delete `v*` tags, because a pushed tag runs the workflows of the tagged commit. Re-running
     updates it. Rulesets need a public repository or a paid plan.
   - Read-back: after applying, the script reads the release tag policy, the ruleset and the
     branch protection back (strict and the exact required contexts) and exits 1 if any is missing or
     wrong. If the rulesets API is unavailable (private repository on a free plan) it stops before
     changing anything and tells you to use `--no-protect-tags`.
3. Settings > Code security: enable private vulnerability reporting and secret scanning with push
   protection if the plan offers them.

## Solo maintainer

GitHub never lets an author approve their own pull request, so with one maintainer keep
`--approvals 0` (merges are still gated by the three required checks; code-owner review is then
off) and leave `--enforce-admins` off, or you lock yourself out of `main`. You can still be the
`release` Environment reviewer: unless "Prevent self-review" is enabled on the Environment, you can
approve your own deployment. Add a second maintainer before raising either setting.
