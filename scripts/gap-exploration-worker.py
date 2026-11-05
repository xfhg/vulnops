#!/usr/bin/env python3
"""Deterministic supplementary phase worker entrypoint."""
from gap_exploration_contract import cli

if __name__ == "__main__":
    raise SystemExit(cli("worker"))
