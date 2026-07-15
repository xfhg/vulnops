#!/usr/bin/env python3
"""Canonical OMP selector identity helpers.

Thinking effort changes execution cost, not model diversity. Only a recognized
trailing OMP effort suffix is removed; colons that are part of a model ID stay
intact.
"""

from __future__ import annotations


THINKING_EFFORTS = {
    "off",
    "minimal",
    "low",
    "medium",
    "high",
    "xhigh",
    "max",
    "auto",
}


def model_identity(selector: str) -> str:
    value = str(selector or "").strip()
    head, separator, suffix = value.rpartition(":")
    if separator and suffix.lower() in THINKING_EFFORTS:
        return head
    return value


def model_diversity(primary: str, verifier: str) -> bool:
    return model_identity(primary) != model_identity(verifier)
