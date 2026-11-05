---
name: vulnops-iac
description: VulnOps specialist lens for infrastructure-as-code, CI/CD, container, and deployment security issues
---

# IaC Lens

Focus on:
- Public exposure: `0.0.0.0/0`, public buckets, open security groups, unauthenticated ingress.
- Overbroad IAM/RBAC: wildcard actions, cluster-admin, broad service accounts.
- Secrets in manifests, CI variables, Dockerfiles, Helm values, Terraform variables, and workflow logs.
- Privileged containers, host networking, hostPath mounts, missing read-only roots, missing security contexts.
- Supply-chain risks in CI: unpinned actions, shelling untrusted inputs, checkout of attacker-controlled refs.

False-positive traps:
- Example manifests and documentation snippets.
- Wildcards scoped to non-sensitive read-only resources.
- Local developer compose files not used in deployment.

Required evidence:
- Deployment path or workflow path.
- Risky permission/exposure.
- A principal, network boundary, or runtime that can be abused.
