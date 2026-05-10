#!/usr/bin/env python3
"""
Chain read-only Aureon probes into one JSON bundle (explicit consent preserved).

Runs device_remediate_phase2.py subcommands plus optional heuristic .ovpn audit.
Does not replace antivirus, EDR, or formal assurance.

Example::

  python3 contrib/aureon-hardening/aureon_doctor.py \\
      --ack-readonly-inventory --configs site.ovpn --json
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path


def _here() -> Path:
    return Path(__file__).resolve().parent


def _meta_flags(args: argparse.Namespace) -> list[str]:
    flags: list[str] = []
    if args.run_id:
        flags += ["--run-id", args.run_id]
    if args.host_label:
        flags += ["--host-label", args.host_label]
    if args.tenant:
        flags += ["--tenant", args.tenant]
    return flags


def _run_phase2(extra: list[str], timeout: float) -> dict:
    cmd = [sys.executable, str(_here() / "device_remediate_phase2.py")] + extra
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "argv": cmd}
    row: dict = {"returncode": p.returncode, "argv": cmd, "stderr_tail": p.stderr[-4000:]}
    if p.stdout.strip():
        try:
            row["json"] = json.loads(p.stdout)
        except json.JSONDecodeError:
            row["stdout_head"] = p.stdout[:12_000]
    return row


def _run_audit(paths: list[str], timeout: float) -> dict:
    if not paths:
        return {"skipped": True}
    cmd = [sys.executable, str(_here() / "audit_ovpn_config.py")] + paths
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "argv": cmd}
    return {"returncode": p.returncode, "argv": cmd, "stderr": p.stderr[-8000:], "stdout": p.stdout[-4000:]}


def _run_health(args: argparse.Namespace, timeout: float) -> dict:
    cmd = [
        sys.executable,
        str(_here() / "device_health_scan.py"),
        "--ack-readonly-inventory",
        "--json",
    ]
    if args.roots:
        cmd.extend(["--roots"] + args.roots)
    cmd.extend(_meta_flags(args))
    cmd.extend(["--max-files", str(args.max_files)])
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"error": "timeout", "argv": cmd}
    row: dict = {"returncode": p.returncode, "argv": cmd}
    if p.stderr:
        row["stderr_tail"] = p.stderr[-2000:]
    if p.stdout.strip():
        try:
            row["json"] = json.loads(p.stdout)
        except json.JSONDecodeError:
            row["stdout_head"] = p.stdout[:8000]
    return row


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--ack-readonly-inventory",
        action="store_true",
        help="Forwarded to device_health_scan (mandatory unless --skip-health)",
    )
    ap.add_argument("--skip-health", action="store_true", help="Skip device_health_scan")
    ap.add_argument(
        "--roots",
        nargs="*",
        default=[],
        help="device_health_scan --roots PATH ... (omit to scan user home)",
    )
    ap.add_argument("--configs", nargs="*", default=[], metavar="CFG.ovpn")
    ap.add_argument(
        "--max-files",
        type=int,
        default=50_000,
        help="device_health_scan file cap when health run is enabled",
    )
    ap.add_argument("--run-id")
    ap.add_argument("--host-label")
    ap.add_argument("--tenant")
    ap.add_argument(
        "--json",
        action="store_true",
        help="Emit single JSON envelope on stdout",
    )
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when any subprocess reports a non-zero return code (skipped steps ignored)",
    )
    ap.add_argument("--timeout-phase2", type=float, default=120.0)
    ap.add_argument("--timeout-health", type=float, default=900.0)
    ap.add_argument("--timeout-audit", type=float, default=60.0)

    args = ap.parse_args()
    meta = _meta_flags(args)

    if not args.skip_health and not args.ack_readonly_inventory:
        sys.stderr.write("Refusing: pass --ack-readonly-inventory or --skip-health\n")
        return 2

    bundle = {
        "schema": "aureon.doctor.bundle.v1",
        "emitter": "aureon_doctor.py",
        "reports": {},
    }

    mf = meta + []

    bundle["reports"]["wifi"] = _run_phase2(["wifi"] + mf, args.timeout_phase2)
    bundle["reports"]["metrics"] = _run_phase2(["metrics"] + mf, args.timeout_phase2)
    bundle["reports"]["dns_probe"] = _run_phase2(
        ["dns-probe", "--query", "example.com"] + mf, args.timeout_phase2
    )

    bundle["reports"]["audit_ovpn_configs"] = _run_audit(list(args.configs), args.timeout_audit)

    if not args.skip_health:
        bundle["reports"]["device_health_scan"] = _run_health(args, args.timeout_health)
    else:
        bundle["reports"]["device_health_scan"] = {"skipped": True}

    if args.json:
        json.dump(bundle, sys.stdout, indent=2)
        sys.stdout.write("\n")

    errs: list[str] = []
    for k, v in bundle["reports"].items():
        if not isinstance(v, dict):
            continue
        if v.get("skipped"):
            continue
        if v.get("error"):
            errs.append(k)
            continue
        rc = v.get("returncode")
        if rc is not None and rc != 0:
            errs.append(k)
    if args.strict and errs:
        sys.stderr.write("strict mode: failures in: {}\n".format(", ".join(errs)))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
