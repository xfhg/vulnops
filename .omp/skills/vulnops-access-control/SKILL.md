---
name: vulnops-access-control
description: VulnOps specialist lens for authorization, IDOR, privilege escalation, and tenancy isolation issues
---

# Access-Control Lens

Focus on:
- Object ownership checks for route, GraphQL, RPC, CLI, worker, and admin actions.
- Tenant boundary enforcement.
- Role/permission middleware placement and bypasses.
- Forced browsing, path guessing, direct object references, and mass assignment.
- Confused-deputy flows where background jobs trust user-controlled identifiers.

False-positive traps:
- Authentication is not authorization.
- A route-level guard may not constrain object ownership.
- Admin-only paths are lower severity unless a non-admin can reach them.
- Test fixtures and local seed scripts are not production authorization paths.

Required evidence:
- Entry point.
- User-controlled object or tenant identifier.
- Missing or insufficient ownership/permission check.
- Sink/action that exposes, modifies, deletes, or triggers privileged behavior.
