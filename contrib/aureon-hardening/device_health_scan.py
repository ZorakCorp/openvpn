#!/usr/bin/env python3
"""
Read-only endpoint inventory scanner (stdlib only).

Aureon posture: explicit consent flag, bounded work, structured output,
no covert exfiltration, honest limits stated in --help and reports.

This is NOT antivirus/EDR. It cannot "find all viruses." Optional integration
runs ClamAV if installed, or invokes Windows Defender only when explicitly
requested (platform-specific behaviour applies).
"""

from __future__ import annotations

import argparse
import heapq
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

_PKG = Path(__file__).resolve().parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))
from report_meta import build_report_meta


@dataclass
class ScanLimits:
    max_files: int


@dataclass
class FileMeta:
    path: str
    size: int
    mtime_ns: int
    atime_ns: int


def _now_ts() -> float:
    return time.time()


def _parse_roots(raw: list[str]) -> list[Path]:
    out: list[Path] = []
    for r in raw:
        p = Path(os.path.expandvars(os.path.expanduser(r))).resolve()
        if p.exists():
            out.append(p)
        else:
            sys.stderr.write(f"skip missing root: {r!r}\n")
    return out


def prune_dirnames(dirnames: list[str], *, skip_git: bool, skip_node_modules: bool) -> None:
    if skip_git and ".git" in dirnames:
        dirnames.remove(".git")
    if skip_node_modules and "node_modules" in dirnames:
        dirnames.remove("node_modules")


def _add_dir_ancestors(
    file_path: Path, root: Path, size: int, dir_bytes: dict[str, int]
) -> None:
    cur = file_path.parent
    root = root.resolve()
    while True:
        dir_bytes[str(cur)] += size
        if cur == root or cur == cur.parent:
            break
        cur = cur.parent


def collect_inventory(
    roots: list[Path],
    limits: ScanLimits,
    *,
    skip_git: bool,
    skip_node_modules: bool,
) -> tuple[list[FileMeta], dict[str, int], list[str], bool]:
    files: list[FileMeta] = []
    dir_bytes: dict[str, int] = defaultdict(int)
    errors: list[str] = []
    count = 0
    capped = False

    for root in roots:
        root = root.resolve()
        for dirpath, dirnames, filenames in os.walk(
            root, topdown=True, followlinks=False
        ):
            prune_dirnames(
                dirnames, skip_git=skip_git, skip_node_modules=skip_node_modules
            )
            dp = Path(dirpath)
            try:
                for name in filenames:
                    if count >= limits.max_files:
                        capped = True
                        return files, dir_bytes, errors, capped
                    fp = dp / name
                    try:
                        lst = fp.lstat()
                    except OSError as e:
                        errors.append(f"lstat({fp}): {e}")
                        continue
                    mode = lst.st_mode
                    if stat.S_ISSOCK(mode) or stat.S_ISFIFO(mode):
                        continue
                    at_ns = getattr(lst, "st_atime_ns", int(lst.st_atime * 1e9))
                    mtime_ns = getattr(lst, "st_mtime_ns", int(lst.st_mtime * 1e9))
                    meta = FileMeta(
                        path=str(fp),
                        size=lst.st_size,
                        mtime_ns=mtime_ns,
                        atime_ns=at_ns,
                    )
                    files.append(meta)
                    count += 1
                    _add_dir_ancestors(fp, root, lst.st_size, dir_bytes)
            except OSError as e:
                errors.append(f"walk({dp}): {e}")
    return files, dir_bytes, errors, capped


def stale_candidates(
    files: list[FileMeta],
    *,
    days: float,
    prefer_atime: bool,
    now_ts: float,
) -> list[dict]:
    thresh = now_ts - days * 86400.0
    rows: list[dict] = []
    for f in files:
        ts_ns = f.atime_ns if prefer_atime else f.mtime_ns
        ts_sec = ts_ns / 1e9
        if ts_sec <= thresh:
            rows.append({"path": f.path, "size": f.size, "stamp_sec": ts_sec})
    rows.sort(key=lambda x: x["stamp_sec"])
    return rows[:8000]


def run_clamav(target: Path, *, timeout: int, clamscan: str) -> dict:
    if not shutil.which(clamscan):
        return {"ok": False, "error": f"{clamscan!r} not found in PATH"}
    try:
        r = subprocess.run(
            [clamscan, "--recursive=yes", "-i", str(target)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return {
            "ok": True,
            "returncode": r.returncode,
            "infected_lines_sample": (r.stdout or "")[-8000:],
            "stderr_tail": (r.stderr or "")[-2000:] if r.stderr else "",
            "clam_note": "returncode 0=clean subtree; 1=virus(es) reported by ClamAV",
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"clamscan exceeded {timeout}s"}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def run_windows_defender_quick(*, timeout: int) -> dict:
    base = Path(os.environ.get("PROGRAMFILES", r"C:\Program Files"))
    exe = base / "Windows Defender" / "MpCmdRun.exe"
    if not exe.is_file():
        return {"triggered": False, "note": "MpCmdRun.exe not located"}
    flags = 0
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        flags = subprocess.CREATE_NO_WINDOW
    try:
        r = subprocess.run(
            [str(exe), "-Scan", "-ScanType", "2"],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=flags,
        )
        return {
            "triggered": True,
            "returncode": r.returncode,
            "stdout_tail": (r.stdout or "")[-2000:],
            "stderr_tail": (r.stderr or "")[-2000:],
        }
    except OSError as e:
        return {"triggered": True, "error": str(e)}
    except subprocess.TimeoutExpired:
        return {"triggered": True, "error": f"timed out ({timeout}s)"}


def posture_hints() -> list[str]:
    h: list[str] = []
    sysname = platform.system()
    if sysname == "Windows":
        h.append(
            "Windows: confirm Windows Security (real-time protection) is on; enforce "
            "BitLocker/Device Encryption where laptops leave the facility."
        )
    elif sysname == "Linux":
        h.append(
            "Linux: vendor security repos + unattended upgrades; minimise open listening "
            "services; firewall default-deny egress for server roles where applicable."
        )
    elif sysname == "Darwin":
        h.append(
            "macOS: align Gatekeeper/FileVault/mobile device policies with organisational MDM."
        )
    else:
        h.append("Generalise: OS & firmware patching on a contractual cadence.")
    h.extend(
        [
            "Backups immutable or offline-tested; restore drills beat promises.",
            "Use approved EDR for malware behavioural verdicts—not this enumerator.",
            "Review unusually large installers / scripts in Downloads with suspicion.",
            "Enumerate USB policies and autorun equivalents for your fleet.",
        ]
    )
    return h


def main() -> int:
    p = argparse.ArgumentParser(
        description="Read-only storage & staleness inventory (Aureon baseline). "
        "Never replaces antivirus/EDR."
    )
    p.add_argument(
        "--ack-readonly-inventory",
        action="store_true",
        required=True,
        help="Mandatory consent flag acknowledging an authorised READ-ONLY crawl.",
    )
    p.add_argument(
        "--roots",
        nargs="+",
        default=[],
        metavar="PATH",
        help="Directories to analyse (omit to use user home)",
    )
    p.add_argument("--max-files", type=int, default=500_000, help="Stop after N regular files")
    p.add_argument("--top-files", type=int, default=40, help="Report N largest files")
    p.add_argument("--top-dirs", type=int, default=25, help="Report N directories by summed size")
    p.add_argument(
        "--stale-days",
        type=float,
        default=0.0,
        help="When >0, include oldest cohort by chosen timestamp",
    )
    p.add_argument(
        "--stale-by",
        choices=("atime", "mtime"),
        default="mtime",
        help="atime unreliable on relatime/noatime filesystems — prefer mtime for planning",
    )
    p.add_argument("--skip-git", action="store_true", default=True)
    p.add_argument(
        "--no-skip-git", action="store_true", help="Include .git trees (heavy)"
    )
    p.add_argument("--skip-node-modules", action="store_true", default=True)
    p.add_argument(
        "--no-skip-node-modules", action="store_true", help="Include node_modules (very heavy)"
    )
    p.add_argument("--json", action="store_true", help="JSON report on stdout")

    clam = p.add_argument_group("optional malware scanners (explicit opt-in)")
    clam.add_argument(
        "--clamav-invoke",
        metavar="DIR",
        help="Run clamscan recursively on DIR (slow; binary must exist)",
    )
    clam.add_argument("--clamscan-bin", default="clamscan")
    clam.add_argument("--clamav-timeout", type=int, default=3600)

    wd = p.add_argument_group("Windows-only optional hook")
    wd.add_argument(
        "--windows-defender-quick-scan",
        action="store_true",
        help="Spawn MpCmdRun quick scan — policy/elevation varies by tenant",
    )
    wd.add_argument("--wd-timeout", type=int, default=7200)

    env = p.add_argument_group("report envelope (JSON output)")
    env.add_argument("--run-id", default=None, help="Correlation id")
    env.add_argument("--host-label", default=None, help="Endpoint label")
    env.add_argument("--tenant", default=None, help="Tenant / fleet bucket")

    args = p.parse_args()
    skip_git = not args.no_skip_git
    skip_nm = not args.no_skip_node_modules

    home = Path.home()
    roots = (
        _parse_roots(args.roots)
        if args.roots
        else ([home.resolve()] if home.exists() else [])
    )
    if not roots:
        sys.stderr.write("No valid roots after expansion.\n")
        return 2

    limits = ScanLimits(max_files=args.max_files)
    sys.stderr.write(
        f"aureon device_health_scan: roots={[str(r) for r in roots]} max_files={args.max_files}\n"
    )

    files, dirsz, errs, capped = collect_inventory(
        roots, limits, skip_git=skip_git, skip_node_modules=skip_nm
    )

    largest_files = heapq.nlargest(args.top_files, files, key=lambda f: f.size)
    hottest_dirs = heapq.nlargest(args.top_dirs, dirsz.items(), key=lambda kv: kv[1])

    now = _now_ts()
    stale_rows: list[dict] = []
    if args.stale_days > 0:
        stale_rows = stale_candidates(
            files,
            days=args.stale_days,
            prefer_atime=args.stale_by == "atime",
            now_ts=now,
        )

    clam_rep: dict | None = None
    if args.clamav_invoke:
        tgt = Path(args.clamav_invoke).expanduser().resolve()
        if tgt.exists():
            clam_rep = run_clamav(
                tgt,
                timeout=args.clamav_timeout,
                clamscan=args.clamscan_bin,
            )
        else:
            clam_rep = {"ok": False, "error": f"missing clamav root {tgt}"}

    wd_rep: dict | None = None
    if args.windows_defender_quick_scan:
        wd_rep = run_windows_defender_quick(timeout=args.wd_timeout)

    report_meta = build_report_meta(
        "device_health_scan.py",
        run_id=args.run_id,
        host_label=args.host_label,
        tenant=args.tenant,
    )
    report = {
        "schema": "aureon.device_health_scan.v1",
        "utc": datetime.now(timezone.utc).isoformat(),
        "report_meta": report_meta,
        "platform": platform.platform(),
        "roots": [str(r) for r in roots],
        "hit_file_cap": capped,
        "files_scanned": len(files),
        "errors_sample": errs[:120],
        "error_count": len(errs),
        "largest_files": [asdict(f) for f in largest_files],
        "largest_dirs": [{"path": k, "bytes": v} for k, v in hottest_dirs],
        "stale_cutoff_days": args.stale_days if args.stale_days > 0 else None,
        "stale_by": args.stale_by if args.stale_days > 0 else None,
        "stale_candidates_count": len(stale_rows),
        "stale_sample": stale_rows[:200],
        "clamav_optional": clam_rep,
        "windows_defender_optional": wd_rep,
        "posture_hints": posture_hints(),
        "limitations": [
            "Does NOT detect all malicious code — heuristic + signature engines live in antivirus/MDR stacks.",
            "Access-time 'staleness' is meaningless on many Linux/macOS relatime installs — default to mtime for planning migrations.",
            "Permission denied on system paths is normal without elevation — rerun scoped roots if noisy.",
            "Cloud placeholder / dedup files may distort observed size.",
            "This tool never quarantines, deletes, or remediates — human or EDR workflow required.",
        ],
    }

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print("=== Aureon device health (READ-ONLY enumerator) ===")
        print(f"Files enumerated: {len(files)}  hit_cap={capped}")
        print("\n-- Largest files --")
        for f in largest_files[:20]:
            print(f"{f.size:13d}  {f.path}")
        print("\n-- Heaviest directories --")
        for path, nbytes in hottest_dirs[:20]:
            print(f"{nbytes:13d}  {path}")
        if stale_rows:
            label = args.stale_by
            print(
                f"\n-- Oldest {label} cohort (≥ {args.stale_days}d) sample ({len(stale_rows)} rows) --"
            )
            for row in stale_rows[:20]:
                when = datetime.fromtimestamp(row["stamp_sec"], tz=timezone.utc)
                print(f"{when.isoformat()}  {row['path']}")
        if clam_rep:
            print("\n-- ClamAV (optional external engine) --")
            print(json.dumps(clam_rep, indent=2)[:8000])
        if wd_rep:
            print("\n-- Windows Defender quick hook (optional) --")
            print(json.dumps(wd_rep, indent=2)[:4000])
        print("\n-- Posture reminders --")
        for h in report["posture_hints"]:
            print(f"• {h}")
        print("\n-- Limits / honesty clause --")
        for L in report["limitations"]:
            print(f"• {L}")

    return 3 if capped else 0


if __name__ == "__main__":
    raise SystemExit(main())
