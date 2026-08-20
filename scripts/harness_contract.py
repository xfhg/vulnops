#!/usr/bin/env python3
"""Compute the canonical harness contract fingerprint used for safe resume."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path


CONTRACT_VERSION = "canonical-redteam-v2-offline-install-package-v6"
CONTRACT_FILES = (
    "config/attack-taxonomy-v2.json",
    "config/osv-snapshot.lock.json",
    "config/offline-pack.linux_amd64.lock.json",
    "config/offline-pack.darwin_arm64.lock.json",
    "schemas/v2/campaign-plan.schema.json",
    "schemas/v2/evidence-index.schema.json",
    "schemas/v2/threat-model.schema.json",
    "schemas/v2/hunt-plan.schema.json",
    "schemas/v2/hunt-result.schema.json",
    "schemas/v2/candidate-finding.schema.json",
    "schemas/v2/coverage-ledger.schema.json",
    "schemas/v2/run-manifest.schema.json",
    "schemas/v2/tool-collection.schema.json",
    "schemas/v2/tool-receipt.schema.json",
    "schemas/v2/dependency-limitations.schema.json",
    "schemas/v2/report.schema.json",
    "schemas/v2/operator-context.schema.json",
    "schemas/v2/recon-research.schema.json",
    "schemas/v2/synthesis-findings.schema.json",
    "schemas/v2/final-findings.schema.json",
    ".omp/guards/target-readonly.ts",
    "scripts/agent-shell.sh",
    "scripts/agent-shell-isolator.sh",
    "scripts/artifact_policy.py",
    "scripts/build-campaign-plan.py",
    "scripts/build-evidence-index.py",
    "scripts/build-hunt-plan.py",
    "scripts/bootstrap-omp.sh",
    "scripts/close-interrupted-run.py",
    "scripts/harness_contract.py",
    "scripts/dependency_contract.py",
    "scripts/collect-tools.py",
    "scripts/run-wraith.sh",
    "scripts/normalize-wraith.py",
    "scripts/merge-wraith.py",
    "scripts/finalize-tool-collection.py",
    "scripts/render-report.py",
    "scripts/osv_snapshot.py",
    "scripts/offline_package.py",
    "scripts/operator_context.py",
    "scripts/probe-agent-isolation.sh",
    "scripts/probe-bubblewrap.sh",
    "scripts/run-safe-reproduction.sh",
    "scripts/safe-reproduction-backend.sh",
    "scripts/init-run.py",
    "scripts/phase_seal.py",
    "scripts/recover-run.py",
    "scripts/resume-run.py",
    "scripts/run-audit.sh",
    "scripts/finalize-sast.py",
    "scripts/finalize-recon.py",
    "scripts/sast_contract.py",
    "scripts/validate-json.py",
    "scripts/validate-omp-agents.py",
    "scripts/validate-phase-v2.py",
    "scripts/validate-scan-v2.py",
    "scripts/update-run-state.py",
    "scripts/probe-verifier-model.py",
    "run.sh",
    ".omp/agents/vulnops-threatmodel.md",
    ".omp/agents/vulnops-deepdive-chunk.md",
    ".omp/agents/vulnops-sast-lead.md",
    ".omp/agents/vulnops-independent-verify-one.md",
    ".omp/agents/vulnops-recon.md",
    ".omp/agents/vulnops-recon-overview.md",
    ".omp/agents/vulnops-recon-trust.md",
    ".omp/agents/vulnops-recon-inputs.md",
    ".omp/agents/vulnops-campaign-planning.md",
    ".omp/agents/vulnops-intrusion-campaign.md",
    ".omp/agents/vulnops-synthesis.md",
)
DEFAULT_SAST_BUDGETS = {
    "quick": {"max_concurrency": 4, "max_hunt_tasks": 12, "max_hunt_questions": 24, "max_gapfill_rounds": 1, "max_attempts": 2},
    "balanced": {"max_concurrency": 8, "max_hunt_tasks": 32, "max_hunt_questions": 64, "max_gapfill_rounds": 2, "max_attempts": 2},
    "full": {"max_concurrency": 16, "max_hunt_tasks": 64, "max_hunt_questions": 128, "max_gapfill_rounds": 3, "max_attempts": 2},
}


def resolved_sast_budget(depth: str) -> dict[str, int]:
    defaults = DEFAULT_SAST_BUDGETS[depth]
    prefix = f"VULNOPS_SAST_{depth.upper()}"
    return {
        "max_concurrency": defaults["max_concurrency"],
        "max_hunt_tasks": int(os.environ.get(f"{prefix}_MAX_HUNT_TASKS", defaults["max_hunt_tasks"])),
        "max_hunt_questions": int(os.environ.get(f"{prefix}_MAX_HUNT_QUESTIONS", defaults["max_hunt_questions"])),
        "max_gapfill_rounds": int(os.environ.get(f"{prefix}_MAX_GAPFILL_ROUNDS", defaults["max_gapfill_rounds"])),
        "max_attempts": int(os.environ.get(f"{prefix}_MAX_ATTEMPTS", defaults["max_attempts"])),
        "context_packet_bytes": int(os.environ.get("VULNOPS_SAST_CONTEXT_PACKET_BYTES", "65536")),
    }


def harness_contract_sha256(root: Path) -> str:
    digest = hashlib.sha256()
    digest.update(CONTRACT_VERSION.encode("utf-8"))
    digest.update(b"\0")
    for relative in CONTRACT_FILES:
        path = root / relative
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def main() -> int:
    print(harness_contract_sha256(Path(__file__).resolve().parent.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
