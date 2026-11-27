#!/usr/bin/env python3
"""Measure a real cold download and offline warm archive installs locally.

Actions cache transfer/scheduling is measured separately by setup-zig in CI.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="0.16.0")
    parser.add_argument("--warm-runs", type=int, default=3)
    args = parser.parse_args()
    if args.warm_runs < 1:
        parser.error("--warm-runs must be positive")
    installer = Path(__file__).with_name("install-zig.sh").resolve()
    # Never change the caller's PATH file or an existing development toolchain.
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_PATH"}
    results = []
    with tempfile.TemporaryDirectory(prefix="benchmark-zig-") as work:
        command = ["sh", str(installer), args.version, work]
        for index in range(args.warm_runs + 1):
            started = time.perf_counter()
            subprocess.run(command, check=True, env=env, stdout=subprocess.DEVNULL)
            results.append(round(time.perf_counter() - started, 3))
    print(json.dumps({
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "system": platform.system(),
        "release": platform.release(),
        "architecture": platform.machine(),
        "zig_version": args.version,
        "cold_seconds": results[0],
        "warm_seconds": results[1:],
        "warm_median_seconds": statistics.median(results[1:]),
        "scope": "installer only; excludes GitHub Actions cache transfer and step scheduling",
    }, indent=2))


if __name__ == "__main__":
    main()
