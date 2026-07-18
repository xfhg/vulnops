#!/usr/bin/env python3
"""Fingerprint the sole linked-remediation implementation contract."""

from __future__ import annotations

import hashlib
from pathlib import Path


CONTRACT_VERSION = "linked-remediation-v2-production-patches-v1"
CONTRACT_FILES = (
    "schemas/v2/remediation-manifest.schema.json",
    "schemas/v2/remediation-plan.schema.json",
    "schemas/v2/remediation-packet.schema.json",
    "schemas/v2/remediation-worker-result.schema.json",
    "schemas/v2/remediation-patch-receipt.schema.json",
    "schemas/v2/remediation.schema.json",
    "scripts/harness-lib.sh",
    "scripts/remediation_common.py",
    "scripts/remediation_contract.py",
    "scripts/init-remediation.py",
    "scripts/update-remediation-state.py",
    "scripts/build-remediation-plan.py",
    "scripts/prepare-remediation-work.py",
    "scripts/publish-remediation-patch.py",
    "scripts/finalize-remediation.py",
    "scripts/validate-remediation.py",
    "scripts/close-interrupted-remediation.py",
    "scripts/run-remediation.sh",
    "scripts/remediation-status.sh",
    "remediate.sh",
    ".omp/main/vulnops-remediation-main.md",
    ".omp/agents/vulnops-remediation.md",
    ".omp/agents/vulnops-remediate-one.md",
)


def remediation_contract_sha256(root: Path) -> str:
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
    print(remediation_contract_sha256(Path(__file__).resolve().parent.parent))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
