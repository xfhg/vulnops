#!/usr/bin/env python3
"""Initialize Advantage directly or from the owning interactive OMP launch."""
import json
import os
from pathlib import Path
import sys

from advantage_lifecycle import main

if __name__ == "__main__":
    if sys.argv[1:] == ["--from-launcher"]:
        try:
            request = json.loads(os.environ["VULNOPS_ADVANTAGE_LAUNCH_REQUEST"])
            session = os.environ["VULNOPS_ADVANTAGE_LAUNCHER_SESSION_ID"]
            if (not isinstance(request, dict)
                    or set(request) != {"argv", "cwd", "launcher_session_id"}
                    or not session or request["launcher_session_id"] != session
                    or not isinstance(request["argv"], list) or not request["argv"]
                    or any(not isinstance(value, str) or "\0" in value for value in request["argv"])
                    or not isinstance(request["cwd"], str)
                    or not Path(request["cwd"]).is_absolute()):
                raise ValueError("invalid launcher request")
            # OMP runs at the harness root; source and patch paths retain the
            # operator's original working-directory semantics.
            os.chdir(request["cwd"])
            sys.argv[1:] = request["argv"]
        except (KeyError, OSError, ValueError, TypeError):
            print("[advantage] invalid or missing session-owned launch request", file=sys.stderr)
            raise SystemExit(2)
    raise SystemExit(main('init'))
