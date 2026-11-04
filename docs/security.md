# Security

- How k8s-mcp limits what a model can do with cluster data, the tests behind
  each control and the residual risks: [threat-model.md](threat-model.md).
- A read-only identity for the server:
  [deploy/rbac/readonly-clusterrole.yaml](../deploy/rbac/readonly-clusterrole.yaml)
  and the README section "A read-only identity".

## Verifying releases

Added in Task 17 of the stage 1 plan, together with the signed release
pipeline: how to verify the cosign signatures, SBOM and provenance of the
binaries and the container image. No release has been published yet.
