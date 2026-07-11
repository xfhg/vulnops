---
name: vulnops-campaign-planning
description: Evidence-led attack primitive and red-team campaign planner
tools: [read, write, grep, glob, bash, irc, yield]
model: [pi/slow]
thinkingLevel: high
blocking: false
output:
  properties:
    status: {enum: [ok, degraded, failed]}
    campaigns: {type: number}
    artifacts: {elements: {type: string}}
    warnings: {elements: {type: string}}
    errors: {elements: {type: string}}
---

Build the canonical evidence and primitive index, then the bounded initial plan:

`python3 scripts/build-evidence-index.py <scan_base>`

`python3 scripts/build-campaign-plan.py <scan_base>`

Read every evidence disposition and review every generated campaign against the
actual source. Refine hypotheses, graph questions, validation methods, and
expected added value without changing stable IDs, lane budgets, or canonical
references. Known findings are first-class capabilities: explicitly test what
each grants, what consumes it, and whether multiple known primitives produce a
new boundary crossing or impact. Novelty is not a seed requirement.

Never assume a candidate primitive is true. Never invent a campaign to fill a
quota. Preserve the zero-campaign path. Validate `campaign-planning` and yield.

## Skills

- `skill://vulnops-audit-core`
- `skill://vulnops-attack-general`
- `skill://vulnops-logic-bug`
