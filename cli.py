from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, Optional

from docker_scanner.findings import Finding, Severity, write_finding
from docker_scanner.scanner import DockerExposureConfig, run_docker_exposure


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="docker-exposure-scan",
        description="Probe for exposed Docker endpoints (2375) and registries (5000).",
    )
    p.add_argument(
        "--targets",
        nargs="+",
        required=True,
        help="IP/CIDR/host targets to probe (e.g. 1.2.3.4 10.0.0.0/24).",
    )
    p.add_argument("--timeout", type=float, default=0.7, help="Per-connection timeout seconds.")
    p.add_argument("--concurrency", type=int, default=256, help="Concurrent probes.")
    p.add_argument(
        "--inspect",
        action="store_true",
        help="If Docker API appears open, query read-only endpoints and scan env for secrets.",
    )
    p.add_argument(
        "--jsonl",
        type=Path,
        default=None,
        help="Optional path to write findings as JSON Lines.",
    )
    p.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity],
        default=None,
        help="Exit non-zero if any finding at/above severity appears.",
    )
    return p.parse_args(argv)


def _severity_rank(sev: Severity) -> int:
    order = {Severity.LOW: 1, Severity.MEDIUM: 2, Severity.HIGH: 3, Severity.CRITICAL: 4}
    return order[sev]


def _should_fail(findings: Iterable[Finding], fail_on: Optional[str]) -> bool:
    if not fail_on:
        return False
    threshold = Severity(fail_on)
    t = _severity_rank(threshold)
    return any(_severity_rank(f.severity) >= t for f in findings)


def main(argv: Optional[list[str]] = None) -> int:
    ns = _parse_args(sys.argv[1:] if argv is None else argv)

    out_fh = None
    if ns.jsonl is not None:
        ns.jsonl.parent.mkdir(parents=True, exist_ok=True)
        out_fh = ns.jsonl.open("a", encoding="utf-8")

    findings: list[Finding] = []
    cfg = DockerExposureConfig(
        targets=list(ns.targets),
        timeout=float(ns.timeout),
        concurrency=int(ns.concurrency),
        inspect=bool(ns.inspect),
    )

    try:
        for f in run_docker_exposure(cfg):
            findings.append(f)
            write_finding(f, out_fh=out_fh)
    finally:
        if out_fh is not None:
            out_fh.close()

    if _should_fail(findings, ns.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
