"""Acceptance gate for the CVE-2026-2699 ShareFile SZC gateway config guard."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "gateway/tests"],
        cwd=ROOT,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        print(
            "gateway config guard tests failed; block unauthenticated access to restricted SZC config pages",
            file=sys.stderr,
        )
        return completed.returncode
    print("gateway config guard tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
