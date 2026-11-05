#!/usr/bin/env python3
"""Remove only the current native Advantage invocation's disposable resources."""
from advantage_lifecycle import main

if __name__ == "__main__":
    raise SystemExit(main("cleanup"))
