#!/usr/bin/env python3
"""
Phase-2 Aureon remediation helper (guided, manifest-based).

Destructive flows require reviewed JSON + matching --execute-ack tokens.
Companion to device_health_scan.py (read-only inventory).

See contrib/aureon-hardening/GUIDE.rst §11–12 for scope boundaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_PKG = Path(__file__).resolve().parent
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))
from report_meta import build_report_meta

SCHEMA_CLEANUP_V1 = "aureon.remediation.cleanup.v1"
SCHEMA_APPX_V1 = "aureon.remediation.appx.v1"
SCHEMA_DUPES_V1 = "aureon.remediation.dupes.v1"
SCHEMA_FLATPAK_V1 = "aureon.remediation.flatpak.v1"


def _spawn(cmd: list[str], timeout: float, *, shell: bool = False) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            shell=shell,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except OSError as e:
        return -2, "", str(e)


def audit_log_append(
    path: str | None,
    record: dict[str, Any],
    *,
    envelope: dict[str, Any] | None = None,
) -> None:
    if not path:
        return
    base: dict[str, Any] = {"utc": datetime.now(timezone.utc).isoformat()}
    if envelope:
        base.update(envelope)
    base.update(record)
    line = json.dumps(base, sort_keys=True) + "\n"
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(line)


def _audit_env(args: argparse.Namespace) -> dict[str, Any] | None:
    return getattr(args, "report_envelope", None)


def _with_meta(blob: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    out = dict(blob)
    rm = getattr(args, "report_envelope", None)
    if rm:
        out["report_meta"] = rm
    return out


# --- wifi / metrics (existing) ---


def cmd_wifi_scan() -> dict:
    sysname = platform.system()
    if sysname == "Windows":
        code, out, err = _spawn(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"], 60
        )
        return {"ok": code == 0, "output": out + ("\n" + err if err else ""), "tool": "netsh"}
    if sysname == "Linux":
        for tool in (
            ["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY", "dev", "wifi"],
            ["iw", "dev", "wlan0", "scan"],
        ):
            code, out, err = _spawn(tool, 45)
            if code == 0 and out.strip():
                return {"ok": True, "output": out, "tool": " ".join(tool[:2])}
        return {"ok": False, "output": "Install nmcli / configure iw iface", "tool": None}
    if sysname == "Darwin":
        path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
        if os.path.isfile(path):
            code, out, err = _spawn([path, "-s"], 45)
            return {"ok": code == 0, "output": out + err, "tool": "airport"}
        return {"ok": False, "output": "airport binary unavailable", "tool": None}
    return {"ok": False, "output": f"wifi scan N/A on {sysname}", "tool": None}


def cmd_metrics() -> dict:
    out: dict = {"platform": platform.platform(), "utc": datetime.now(timezone.utc).isoformat()}
    sysname = platform.system()
    out["cpu_logical"] = os.cpu_count()
    if sysname == "Windows":
        ps = (
            "Get-CimInstance Win32_OperatingSystem | "
            "Select-Object FreePhysicalMemory,TotalVisibleMemorySize;"
            "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | "
            "Select-Object DeviceID,FreeSpace,Size"
        )
        code, so, se = _spawn(["powershell", "-NoProfile", "-Command", ps], 60)
        out["powershell_memory_disk"] = {"returncode": code, "stdout": so[:8000], "stderr": se[:2000]}
        code2, top, _ = _spawn(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 "
                "ProcessName,Id,CPU,WorkingSet | Format-Table -AutoSize | Out-String -Width 200",
            ],
            45,
        )
        out["top_cpu_processes"] = {"returncode": code2, "text": top[:6000]}
    elif sysname == "Linux":
        code, so, _ = _spawn(["df", "-h"], 15)
        out["df"] = so[:4000]
        if Path("/proc/meminfo").is_file():
            out["meminfo_head"] = Path("/proc/meminfo").read_text(encoding="utf-8", errors="replace")[
                :2000
            ]
        code2, top, _ = _spawn(["ps", "aux", "--sort=-%cpu"], 10)
        out["ps_head"] = top[:4000]
    elif sysname == "Darwin":
        code, so, _ = _spawn(["df", "-h"], 15)
        out["df"] = so[:4000]
        code2, vm, _ = _spawn(["vm_stat"], 10)
        out["vm_stat"] = vm[:4000]
    du = shutil.disk_usage(Path.home())
    out["home_volume"] = {
        "total": du.total,
        "used": du.used,
        "free": du.free,
        "free_percent": round(100.0 * du.free / max(du.total, 1), 2),
    }
    return out


def _heuristic_slowness_hint(m: dict) -> list[str]:
    hints: list[str] = []
    hv = m.get("home_volume") or {}
    fp = hv.get("free_percent")
    if isinstance(fp, (int, float)) and fp < 10:
        hints.append(
            "Low free space — swap/OS stability risk; offload bulk user data safely."
        )
    if fp and fp < 20:
        hints.append("Review caches/downloads after browser-cache-scan + cleanup-plan.")
    hints.append("Baseline CPU outliers against browser tabs & AV scan windows.")
    hints.append("Prefer Ethernet for jitter-sensitive workloads.")
    hints.append(
        "If DNS/trace show loss or spikes, escalate to ISP/IT—this tool doesn't fix RF physics."
    )
    return hints


# --- idea list: network ---


def dns_probe_dict(args: argparse.Namespace) -> dict:
    host = args.query
    res: dict = {"resolver_tests": [], "query": host}
    if platform.system() == "Windows":
        for srv in args.servers.split(","):
            srv = srv.strip()
            code, so, se = _spawn(["nslookup", host, srv], 12)
            res["resolver_tests"].append({"server": srv, "code": code, "out": so[:2500], "err": se[:500]})
    else:
        dig = shutil.which("dig")
        getent_done = False
        for srv in args.servers.split(","):
            srv = srv.strip()
            if not srv:
                continue
            if dig:
                code, so, se = _spawn([dig, f"@{srv}", "+time=2", "+tries=1", host], 10)
                res["resolver_tests"].append(
                    {"server": srv, "code": code, "out": so[:2500], "err": se[:500]}
                )
            elif shutil.which("nslookup"):
                code, so, se = _spawn(["nslookup", host, srv], 12)
                res["resolver_tests"].append(
                    {"server": srv, "code": code, "out": so[:2500], "err": se[:500]}
                )
            else:
                # getent hosts is not resolver-specific; record once to avoid duplicate rows.
                if not getent_done:
                    code, so, se = _spawn(["getent", "hosts", host], 5)
                    res["resolver_tests"].append(
                        {
                            "fallback": "getent_hosts",
                            "note": "Install dig or nslookup for per-resolver checks",
                            "code": code,
                            "out": so[:500],
                            "err": se[:500],
                        }
                    )
                    getent_done = True
                break
    return res


def cmd_dns_probe(args: argparse.Namespace) -> int:
    print(json.dumps(_with_meta(dns_probe_dict(args), args), indent=2))
    return 0


def cmd_trace_lite(args: argparse.Namespace) -> int:
    hops = str(args.max_hops)
    if platform.system() == "Windows":
        code, out, err = _spawn(["tracert", "-d", "-h", hops, args.target], args.timeout_s)
        tool = "tracert"
    else:
        if shutil.which("traceroute"):
            code, out, err = _spawn(["traceroute", "-n", "-m", hops, args.target], args.timeout_s)
            tool = "traceroute"
        else:
            code, out, err = _spawn(["tracepath", args.target], args.timeout_s)
            tool = "tracepath"
    print(
        json.dumps(
            _with_meta({"ok": code == 0 or code == 1, "tool": tool, "output": out + err}, args),
            indent=2,
        )
    )
    return 0


def arp_snapshot_dict() -> dict:
    if platform.system() == "Windows":
        code1, so1, _ = _spawn(["arp", "-a"], 15)
        code2, so2, se2 = _spawn(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-NetNeighbor | Select-Object IPAddress,State,LinkLayerAddress,ifIndex "
                "| ConvertTo-Csv -NoTypeInformation",
            ],
            30,
        )
        blob: dict[str, Any] = {
            "arp_ascii": {"code": code1, "text": so1[:8000]},
            "net_neighbor_csv": {"code": code2, "text": (so2 + se2)[:8000]},
        }
    elif platform.system() == "Linux":
        code, so, err = _spawn(["ip", "neigh"], 15)
        if code != 0:
            code, so, err = _spawn(["ip", "-s", "neigh"], 15)
        blob = {"ip_neigh": {"code": code, "text": (so + err)[:12000]}}
    else:
        code, so, err = _spawn(["arp", "-an"], 15)
        blob = {"arp_an": {"code": code, "text": so + err}}
    blob["honesty"] = "Snapshot only—not ARP spoofing IDS; escalate anomalies with netsec tooling."
    return blob


def cmd_arp_snapshot(args: argparse.Namespace) -> int:
    print(json.dumps(_with_meta(arp_snapshot_dict(), args), indent=2))
    return 0


# --- idea list: performance / laptop ---


def cmd_disk_bench(args: argparse.Namespace) -> int:
    if args.execute_ack != "EXECUTE_PHASE2_DISK_BENCH":
        sys.stderr.write("Refusing: requires --execute-ack EXECUTE_PHASE2_DISK_BENCH\n")
        return 2
    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        sys.stderr.write("root must exist\n")
        return 2
    sz = args.mebibytes * 1024 * 1024
    timings: dict[str, Any] = {}
    fh, path = tempfile.mkstemp(prefix="aureon-bench-", dir=root, text=False)
    os.close(fh)
    p = Path(path)
    chunk = bytes(1024 * 1024)
    try:
        t0 = time.perf_counter()
        with open(p, "wb", buffering=0) as wf:
            for _ in range(args.mebibytes):
                wf.write(chunk)
        timings["seq_write_mb_s"] = round(args.mebibytes / max(time.perf_counter() - t0, 1e-6), 2)
        t1 = time.perf_counter()
        with open(p, "rb") as rf:
            while rf.read(1024 * 1024):
                pass
        timings["seq_read_mb_s"] = round(args.mebibytes / max(time.perf_counter() - t1, 1e-6), 2)
    finally:
        try:
            p.unlink(missing_ok=True)
        except OSError:
            pass
    audit_log_append(
        getattr(args, "audit_log", None),
        {"action": "disk_bench", "root": str(root), "timing": timings},
        envelope=_audit_env(args),
    )
    print(
        json.dumps(
            _with_meta(
                {"root": str(root), "mebibytes": args.mebibytes, "timing": timings},
                args,
            ),
            indent=2,
        )
    )
    return 0


def cmd_battery_report(args: argparse.Namespace) -> int:
    if platform.system() != "Windows":
        sys.stderr.write("battery-report only wired for Windows powercfg.\n")
        return 2
    out = Path(args.out).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    code, so, err = _spawn(["powercfg", "/batteryreport", "/output", str(out)], 120)
    print(
        json.dumps(
            _with_meta({"code": code, "path": str(out), "stdout": so, "stderr": err}, args),
            indent=2,
        )
    )
    audit_log_append(
        getattr(args, "audit_log", None),
        {"action": "battery_report", "path": str(out), "code": code},
        envelope=_audit_env(args),
    )
    return 0 if code == 0 else 1


# --- startup / browser caches ---


def startup_inventory_dict() -> dict:
    ps = (
        "Get-CimInstance Win32_StartupCommand | "
        "Select-Object Name,Command,Location,User | ConvertTo-Json -Depth 3;"
        "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | "
        "Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 3"
    )
    code, out, err = _spawn(["powershell", "-NoProfile", "-Command", ps], 180)
    return {"code": code, "payload": out[:120000], "stderr": err[:2000]}


def cmd_startup_inventory(args: argparse.Namespace) -> int:
    if platform.system() != "Windows":
        sys.stderr.write(
            "startup-inventory WMI export targets Windows — on Linux enumerate systemd:user units.\n"
        )
        return 2
    blob = startup_inventory_dict()
    print(json.dumps(_with_meta(blob, args), indent=2))
    return 0 if blob["code"] == 0 else 1


def systemd_user_units_hints(args: argparse.Namespace) -> int:
    if platform.system() != "Linux":
        sys.stderr.write("Linux-only informational hint runner.\n")
        return 2
    lines = []
    for cmd in (
        ["systemctl", "--user", "list-unit-files"],
        ["systemctl", "--user", "list-timers", "--no-pager"],
    ):
        c, so, err = _spawn(cmd, 20)
        lines.append({"cmd": cmd, "code": c, "out_head": so[:16000], "err": err[:2000]})
    print(
        json.dumps(
            _with_meta({"note": "read-only systemd --user snapshots", "blocks": lines}, args),
            indent=2,
        )
    )
    return 0


def _dir_size_limit(path: Path, max_entries: int) -> tuple[int, int]:
    total = 0
    seen = 0
    try:
        for dp, _, fns in os.walk(path):
            if seen >= max_entries:
                break
            for n in fns:
                seen += 1
                fp = Path(dp) / n
                try:
                    total += fp.stat().st_size
                except OSError:
                    pass
                if seen >= max_entries:
                    break
    except OSError:
        pass
    return total, seen


def browser_cache_scan_dict() -> dict:
    rows: list[dict] = []
    if platform.system() == "Windows":
        la = Path(os.environ.get("LOCALAPPDATA", ""))
        cands = [
            la / "Google/Chrome/User Data/Default/Cache",
            la / "Google/Chrome/User Data/Default/Cache/Cache_Data",
            la / "Microsoft/Edge/User Data/Default/Cache",
            la / "Microsoft/Edge/User Data/Default/Cache/Cache_Data",
            la / "Mozilla/Firefox/Profiles",
        ]
        for d in cands:
            if d.is_dir():
                b, cnt = _dir_size_limit(d, 250_000)
                rows.append({"path": str(d), "estimated_bytes_under_cap": b, "file_samples": cnt})
    elif platform.system() == "Linux":
        home = Path.home()
        for d in [
            home / ".cache/google-chrome",
            home / ".cache/mozilla/firefox",
            home / ".cache/msedge",
        ]:
            if d.is_dir():
                b, cnt = _dir_size_limit(d, 250_000)
                rows.append({"path": str(d), "estimated_bytes_under_cap": b, "file_samples": cnt})
    elif platform.system() == "Darwin":
        home = Path.home()
        for d in [
            home / "Library/Caches/Google/Chrome",
            home / "Library/Caches/com.apple.Safari",
        ]:
            if d.is_dir():
                b, cnt = _dir_size_limit(d, 250_000)
                rows.append({"path": str(d), "estimated_bytes_under_cap": b, "file_samples": cnt})
    hint = (
        "Sizes capped — run cleanup-plan on selected cache dirs only after validating nothing "
        "sensitive will be harmed."
    )
    return {"dirs": rows, "note": hint}


def cmd_browser_cache_scan(args: argparse.Namespace) -> int:
    print(json.dumps(_with_meta(browser_cache_scan_dict(), args), indent=2))
    return 0


# --- cleanup / dupes ---


def _walk_large_files(roots: list[Path], *, max_files: int, min_bytes: int) -> list[dict]:
    rows: list[dict] = []
    n = 0
    for root in roots:
        root = root.resolve()
        if not root.is_dir():
            continue
        for dp, _, filenames in os.walk(root, topdown=True, followlinks=False):
            if n >= max_files:
                return rows
            for name in filenames:
                if n >= max_files:
                    return rows
                fp = Path(dp) / name
                try:
                    st = fp.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_size >= min_bytes:
                    rows.append(
                        {
                            "path": str(fp),
                            "bytes": st.st_size,
                            "approved": False,
                            "reason": "large_file_candidate",
                        }
                    )
                if stat.S_ISREG(st.st_mode):
                    n += 1
    return rows


def cmd_cleanup_plan(args: argparse.Namespace) -> int:
    roots = [Path(p).expanduser().resolve() for p in args.roots]
    rows = _walk_large_files(roots, max_files=args.max_files, min_bytes=args.min_size_mb * 1024 * 1024)
    expect = hashlib.sha256()
    blob = json.dumps(rows, sort_keys=True).encode()
    expect.update(blob)
    doc = {
        "schema": SCHEMA_CLEANUP_V1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "allowed_roots": [str(r) for r in roots],
        "execute_ack_required": "EXECUTE_PHASE2_DELETE",
        "instructions": (
            "Set approved:true per path only after review; run cleanup-apply with matching ack "
            "and optional --manifest-sha256 on this canonical JSON ordering."
        ),
        "canonical_items_sha256": expect.hexdigest(),
        "items": rows,
    }
    txt = json.dumps(doc, indent=2)
    Path(args.out).write_text(txt, encoding="utf-8")
    mf = hashlib.sha256(txt.encode()).hexdigest()
    print(f"Wrote plan {len(rows)} rows -> {args.out}\nmanifest_file_sha256={mf}")
    return 0


def _path_allowed(target: Path, roots: list[Path]) -> bool:
    t = target.resolve()
    for r in roots:
        try:
            t.relative_to(r.resolve())
            return True
        except ValueError:
            continue
    return False


def cmd_cleanup_apply(args: argparse.Namespace) -> int:
    if args.execute_ack != "EXECUTE_PHASE2_DELETE":
        sys.stderr.write("Refusing cleanup-apply acknowledgement.\n")
        return 2
    dry = getattr(args, "dry_run", False)
    raw = Path(args.manifest).read_text(encoding="utf-8")
    if getattr(args, "manifest_sha256", None):
        if hashlib.sha256(raw.encode()).hexdigest() != args.manifest_sha256:
            sys.stderr.write("manifest SHA256 mismatch — refuse apply.\n")
            return 2
    doc = json.loads(raw)
    if doc.get("schema") != SCHEMA_CLEANUP_V1:
        sys.stderr.write("Invalid cleanup schema.\n")
        return 2
    roots = [Path(p).resolve() for p in doc["allowed_roots"]]
    deleted = 0
    errors = 0
    for item in doc.get("items", []):
        if not item.get("approved"):
            continue
        p = Path(item["path"]).expanduser().resolve()
        if not _path_allowed(p, roots):
            sys.stderr.write(f"skip outside roots {p}\n")
            errors += 1
            continue
        if not p.exists():
            continue
        try:
            if dry:
                print(f"[dry-run] would remove: {p}")
                deleted += 1
                audit_log_append(
                    getattr(args, "audit_log", None),
                    {"would_delete": str(p), "dry_run": True},
                    envelope=_audit_env(args),
                )
            else:
                if p.is_file():
                    p.unlink()
                else:
                    shutil.rmtree(p)
                deleted += 1
                audit_log_append(
                    getattr(args, "audit_log", None),
                    {"deleted": str(p)},
                    envelope=_audit_env(args),
                )
        except OSError as e:
            sys.stderr.write(f"delete error {p}: {e}\n")
            errors += 1
    audit_log_append(
        getattr(args, "audit_log", None),
        {
            "action": "cleanup_apply_finished",
            "deleted": deleted,
            "errors": errors,
            "dry_run": dry,
        },
        envelope=_audit_env(args),
    )
    print(f"deleted={deleted} errors={errors} dry_run={dry}")
    return 0 if errors == 0 else 1


def _file_digest(path: Path, limit: int) -> str | None:
    h = hashlib.sha256()
    n = 0
    try:
        with path.open("rb") as fh:
            while True:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                h.update(block)
                n += len(block)
                if limit > 0 and n >= limit:
                    break
        return h.hexdigest()
    except OSError:
        return None


def cmd_dupes_plan(args: argparse.Namespace) -> int:
    roots = [Path(p).expanduser().resolve() for p in args.roots]
    grouped: dict[tuple[int, str], list[str]] = {}
    seen_files = 0
    hash_cap = args.max_hash_mib * 1024 * 1024

    def consider(fp: Path, st_sz: int) -> None:
        nonlocal seen_files
        if st_sz < args.min_size_kb * 1024 or st_sz > args.max_size_mib * 1024 * 1024:
            return
        if seen_files >= args.max_files_scan:
            return
        dg = _file_digest(fp, hash_cap if st_sz <= hash_cap else 64 * 1024)
        seen_files += 1
        if not dg:
            return
        key = (st_sz, dg if st_sz <= hash_cap else dg + ":partial-prefix")
        grouped.setdefault(key, []).append(str(fp.resolve()))

    for root in roots:
        if not root.is_dir():
            continue
        for dp, _, fns in os.walk(root, topdown=True, followlinks=False):
            if seen_files >= args.max_files_scan:
                break
            for name in fns:
                fp = Path(dp) / name
                try:
                    lst = fp.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(lst.st_mode):
                    continue
                consider(fp, lst.st_size)
        if seen_files >= args.max_files_scan:
            break

    dup_groups = [{"size": k[0], "digest_marker": k[1], "paths": v} for k, v in grouped.items() if len(v) > 1]

    packs = []
    for g in dup_groups:
        keep = g["paths"][0]
        removals = [{"path": p, "approved": False} for p in g["paths"][1:]]

        packs.append(
            {
                "size": g["size"],
                "digest_marker": g["digest_marker"],
                "keep_path": keep,
                "delete_duplicates": removals,
                "approved_delete_duplicates": False,
                "instructions": (
                    "Set approved:true on removals you approve; optionally set "
                    "approved_delete_duplicates:true for whole group shortcut after review "
                    "(still requires EXECUTE_PHASE2_DELETE_DUPES)."
                ),
            }
        )

    doc = {
        "schema": SCHEMA_DUPES_V1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "allowed_roots": [str(r) for r in roots],
        "execute_ack_required": "EXECUTE_PHASE2_DELETE_DUPES",
        "max_hash_mib": args.max_hash_mib,
        "caution": "Partial hashing for gigantic files marks digest_marker suffix :partial-prefix",
        "groups": packs,
    }
    Path(args.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"duplicate groups detected={len(packs)} -> {args.out}")
    return 0


def cmd_dupes_apply(args: argparse.Namespace) -> int:
    if args.execute_ack != "EXECUTE_PHASE2_DELETE_DUPES":
        sys.stderr.write("Refusing: pass --execute-ack EXECUTE_PHASE2_DELETE_DUPES\n")
        return 2
    dry = getattr(args, "dry_run", False)
    raw = Path(args.manifest).read_text(encoding="utf-8")
    if getattr(args, "manifest_sha256", None):
        if hashlib.sha256(raw.encode()).hexdigest() != args.manifest_sha256:
            sys.stderr.write("dupes manifest SHA256 mismatch\n")
            return 2
    doc = json.loads(raw)
    if doc.get("schema") != SCHEMA_DUPES_V1:
        return 2
    roots = [Path(p).resolve() for p in doc["allowed_roots"]]
    n = err = 0
    for g in doc["groups"]:
        bulk = bool(g.get("approved_delete_duplicates"))
        dels = []
        if bulk:
            dels = [
                Path(x["path"])
                for x in g["delete_duplicates"]
                if isinstance(x, dict) and isinstance(x.get("path"), str)
            ]
        else:
            dels = []
            for x in g.get("delete_duplicates", []):
                if isinstance(x, dict) and x.get("approved"):
                    dels.append(Path(x["path"]))
        for pth in dels:
            pth = pth.expanduser().resolve()
            if not _path_allowed(pth, roots):
                sys.stderr.write(f"outside roots {pth}\n")
                err += 1
                continue
            try:
                if pth.samefile(Path(str(g["keep_path"])).resolve()):
                    continue
            except OSError:
                continue
            try:
                if dry:
                    print(f"[dry-run] would remove duplicate: {pth}")
                    n += 1
                    audit_log_append(
                        getattr(args, "audit_log", None),
                        {"would_dup_remove": str(pth), "dry_run": True},
                        envelope=_audit_env(args),
                    )
                elif pth.is_file():
                    pth.unlink()
                    n += 1
                    audit_log_append(
                        getattr(args, "audit_log", None),
                        {"dup_removed": str(pth)},
                        envelope=_audit_env(args),
                    )
                elif pth.is_dir():
                    shutil.rmtree(pth)
                    n += 1
                    audit_log_append(
                        getattr(args, "audit_log", None),
                        {"dup_removed": str(pth)},
                        envelope=_audit_env(args),
                    )
            except OSError as e:
                sys.stderr.write(f"{pth}: {e}\n")
                err += 1
    audit_log_append(
        getattr(args, "audit_log", None),
        {"action": "dupes_apply", "removed_files": n, "errors": err, "dry_run": dry},
        envelope=_audit_env(args),
    )
    print(f"removed_duplicate_files≈{n} errors={err} dry_run={dry}")
    return 0 if err == 0 else 1


# --- flatpak (Linux) ---


def cmd_flatpak_plan(args: argparse.Namespace) -> int:
    if platform.system() != "Linux":
        sys.stderr.write("flatpak-plan is Linux-specific.\n")
        return 2
    fk = shutil.which("flatpak")
    if not fk:
        sys.stderr.write("flatpak CLI missing.\n")
        return 2
    code, out, err = _spawn([fk, "list", "--app", "--columns=application"], 60)
    if code != 0:
        sys.stderr.write(err + out)
        return 1
    rows = []
    for line in out.splitlines():
        app = line.strip()
        if not app or app.lower().startswith("no installed"):
            continue
        rows.append({"application_id": app, "approved_uninstall": False})
    doc = {
        "schema": SCHEMA_FLATPAK_V1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "execute_ack_required": "EXECUTE_PHASE2_FLATPAK_RM",
        "items": rows,
    }
    Path(args.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"wrote flatpak catalogue lines={len(rows)} -> {args.out}")
    return 0


def cmd_flatpak_apply(args: argparse.Namespace) -> int:
    if platform.system() != "Linux" or args.execute_ack != "EXECUTE_PHASE2_FLATPAK_RM":
        sys.stderr.write("Wrong platform or acknowledgement.\n")
        return 2
    fk = shutil.which("flatpak")
    if not fk:
        return 2
    dry = getattr(args, "dry_run", False)
    raw = Path(args.manifest).read_text(encoding="utf-8")
    if getattr(args, "manifest_sha256", None):
        if hashlib.sha256(raw.encode()).hexdigest() != args.manifest_sha256:
            sys.stderr.write("flatpak manifest SHA256 mismatch\n")
            return 2
    doc = json.loads(raw)
    if doc.get("schema") != SCHEMA_FLATPAK_V1:
        return 2
    ok = bad = 0
    for it in doc.get("items", []):
        if not it.get("approved_uninstall"):
            continue
        app = it.get("application_id") or ""
        base = [
            fk,
            "uninstall",
            "-y",
        ]
        if app:
            if dry:
                print(f"[dry-run] would flatpak uninstall: {app}")
                ok += 1
                audit_log_append(
                    getattr(args, "audit_log", None),
                    {"would_flatpak_remove": app, "dry_run": True},
                    envelope=_audit_env(args),
                )
            else:
                code, _, _ = _spawn(base + [app], 300)
                if code == 0:
                    ok += 1
                    audit_log_append(
                        getattr(args, "audit_log", None),
                        {"flatpak_removed": app},
                        envelope=_audit_env(args),
                    )
                else:
                    bad += 1
    audit_log_append(
        getattr(args, "audit_log", None),
        {"action": "flatpak_apply", "ok": ok, "bad": bad, "dry_run": dry},
        envelope=_audit_env(args),
    )
    print(f"flatpak uninstall ok={ok} fail={bad} dry_run={dry}")
    return 0 if bad == 0 else 1


def cmd_manifest_hash(args: argparse.Namespace) -> int:
    raw = Path(args.file).read_bytes()
    hf = hashlib.sha256(raw).hexdigest()
    print(json.dumps(_with_meta({"sha256": hf, "path": args.file}, args)))
    return 0


def cmd_apps_plan(args: argparse.Namespace) -> int:
    if platform.system() != "Windows":
        sys.stderr.write("apps-plan is Windows-only.\n")
        return 2
    ps = (
        "Get-AppxPackage | Where-Object {$_.IsFramework -eq $false} | "
        "Select-Object Name,PackageFullName,Version,Publisher | ConvertTo-Json -Depth 3"
    )
    code, out, err = _spawn(["powershell", "-NoProfile", "-Command", ps], 120)
    if code != 0:
        sys.stderr.write(err + out)
        return 1
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        rows = [{"raw": out[:4000]}]
    else:
        rows = data if isinstance(data, list) else [data]
    doc = {
        "schema": SCHEMA_APPX_V1,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "execute_ack_required": "EXECUTE_PHASE2_UNINSTALL_APPX",
        "items": [
            {
                "name": r.get("Name"),
                "package_full_name": r.get("PackageFullName"),
                "version": r.get("Version"),
                "publisher": r.get("Publisher"),
                "approved": False,
            }
            for r in rows
            if isinstance(r, dict) and r.get("PackageFullName")
        ],
    }
    Path(args.out).write_text(json.dumps(doc, indent=2), encoding="utf-8")
    print(f"appx catalogue={len(doc['items'])} -> {args.out}")
    return 0


def cmd_apps_apply(args: argparse.Namespace) -> int:
    if platform.system() != "Windows" or args.execute_ack != "EXECUTE_PHASE2_UNINSTALL_APPX":
        sys.stderr.write("apps-apply precondition failed.\n")
        return 2
    dry = getattr(args, "dry_run", False)
    raw = Path(args.manifest).read_text(encoding="utf-8")
    if getattr(args, "manifest_sha256", None):
        if hashlib.sha256(raw.encode()).hexdigest() != args.manifest_sha256:
            sys.stderr.write("appx manifest SHA256 mismatch\n")
            return 2
    doc = json.loads(raw)
    if doc.get("schema") != SCHEMA_APPX_V1:
        return 2
    ok = bad = 0
    for item in doc.get("items", []):
        if not item.get("approved"):
            continue
        pfn = item.get("package_full_name")
        if not pfn:
            bad += 1
            continue
        pfn_esc = pfn.replace("'", "''")
        ps = (
            "Get-AppxPackage -PackageFullName '{0}' "
            "| Remove-AppxPackage".format(pfn_esc)
        )
        if dry:
            print(f"[dry-run] would Remove-AppxPackage: {pfn}")
            ok += 1
            audit_log_append(
                getattr(args, "audit_log", None),
                {"would_appx_remove": pfn, "dry_run": True},
                envelope=_audit_env(args),
            )
            continue
        code, _, err = _spawn(["powershell", "-NoProfile", "-Command", ps], 180)
        audit_log_append(
            getattr(args, "audit_log", None),
            {"appx_remove": pfn, "code": code, "stderr": err[:500]},
            envelope=_audit_env(args),
        )
        if code == 0:
            ok += 1
        else:
            bad += 1
    print(f"appx remove ok={ok} fail={bad} dry_run={dry}")
    return 0 if bad == 0 else 1


def _audit_arg(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--audit-log",
        help="Append JSONL audit rows for destructive/consent-heavy actions",
    )


# --- gui ---


def run_gui() -> int:
    try:
        import tkinter as tk
        import tkinter.simpledialog as tksd
        from tkinter import filedialog, messagebox, scrolledtext
    except ImportError:
        sys.stderr.write("tkinter unavailable.\n")
        return 2

    root = tk.Tk()
    root.title("House of Asher · Aureon Phase 2")
    root.geometry("900x620")
    txt = scrolledtext.ScrolledText(root, height=28, wrap="word")
    txt.pack(fill="both", expand=True, padx=8, pady=6)

    def dump(obj: object) -> None:
        txt.delete("1.0", "end")
        txt.insert("end", json.dumps(obj, indent=2, default=str))

    def bn_wifi():
        dump(cmd_wifi_scan())

    def bn_metrics():
        m = cmd_metrics()
        m["hints"] = _heuristic_slowness_hint(m)
        dump(m)

    def bn_dns():
        dns_args = argparse.Namespace(query=" mozilla.org ".strip(), servers="8.8.8.8,1.1.1.1")
        dump(dns_probe_dict(dns_args))

    def bn_arp():
        dump(arp_snapshot_dict())

    def bn_trace():
        tr = argparse.Namespace(target="one.one.one.one", max_hops=8, timeout_s=35)
        if platform.system() == "Windows":
            code, out, err = _spawn(["tracert", "-d", "-h", "8", tr.target], tr.timeout_s)
            dump({"tracert_exit": code, "output": (out + err)[:24000]})
        elif shutil.which("traceroute"):
            code, out, err = _spawn(["traceroute", "-n", "-m", "8", tr.target], tr.timeout_s)
            dump({"tool": "traceroute", "exit": code, "output": (out + err)[:24000]})
        else:
            dump({"hint": "install traceroute or use CLI trace-lite"})

    def bn_startup():
        if platform.system() == "Windows":
            dump(startup_inventory_dict())
        else:
            dump({"os": platform.system(), "hint": "use systemd-units CLI on Linux"})

    def bn_browser():
        dump(browser_cache_scan_dict())

    def plan_stub():
        home = Path.home()
        path = filedialog.asksaveasfilename(
            defaultextension=".json", initialfile="aureon-cleanup-plan.json"
        )
        if not path:
            return
        tmp = argparse.Namespace(
            roots=[str(home / "Downloads"), str(Path(os.environ.get("TEMP", str(home))))],
            max_files=55_000,
            min_size_mb=150,
            out=path,
        )
        cmd_cleanup_plan(tmp)
        messagebox.showinfo("Plan saved", path)

    def apply_stub():
        mpath = filedialog.askopenfilename(filetypes=[("JSON", "*.json")])
        if not mpath:
            return
        tok = tksd.askstring("Ack", "Type: EXECUTE_PHASE2_DELETE", parent=root)
        if tok != "EXECUTE_PHASE2_DELETE":
            messagebox.showerror("Denied", "Token mismatch.")
            return
        code = cmd_cleanup_apply(
            argparse.Namespace(manifest=mpath, execute_ack=tok, manifest_sha256=None, audit_log=None)
        )
        messagebox.showinfo("Exit", str(code))

    bar = tk.Frame(root)
    bar.pack(fill="x", pady=4)
    for lbl, cb in (
        ("Wi‑Fi", bn_wifi),
        ("Metrics", bn_metrics),
        ("DNS", bn_dns),
        ("ARP/neigh", bn_arp),
        ("Traceroute‑lite", bn_trace),
        ("Startup/tasks", bn_startup),
        ("Browser caches", bn_browser),
        ("Plan downloads+TEMP", plan_stub),
        ("Apply cleanup…", apply_stub),
    ):
        tk.Button(bar, text=lbl, command=cb).pack(side="left", padx=2)
    tk.Label(bar, text="Manifest + typed token still required for deletes.", fg="#555").pack(
        side="left", padx=12
    )
    root.mainloop()
    return 0


def add_apply_audit_flags(p: argparse.ArgumentParser) -> None:
    p.add_argument("--manifest-sha256", help="Verify manifest blob hash before destructive apply")
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate manifest and print would-do actions; no deletes or uninstalls",
    )
    _audit_arg(p)


def cmd_tasks_snapshot(args: argparse.Namespace) -> int:
    if platform.system() != "Windows":
        sys.stderr.write("tasks-snapshot uses schtasks (Windows only).\n")
        return 2
    code, out, err = _spawn(["schtasks", "/query", "/fo", "CSV", "/v"], 120)
    blob = {
        "code": code,
        "format": "schtasks_csv",
        "text_head": (out + err)[:120000],
        "stderr_tail": err[-4000:],
    }
    print(json.dumps(_with_meta(blob, args), indent=2))
    return 0 if code == 0 else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    env = p.add_argument_group(
        "report envelope (attached to JSON outputs and audit-log context)"
    )
    env.add_argument("--run-id", default=None, help="Correlation id for pipelines / SIEM")
    env.add_argument("--host-label", default=None, help="Human-readable endpoint label")
    env.add_argument("--tenant", default=None, help="Optional tenant / fleet bucket")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("wifi", help="WLAN / wireless sweep")
    sub.add_parser("metrics", help="Slowness-related quick metrics")

    dn = sub.add_parser("dns-probe", help="Resolver sanity (nslookup / dig)")
    dn.add_argument("--query", default="example.com")
    dn.add_argument("--servers", default="8.8.8.8,1.1.1.1")
    dn.set_defaults(func=cmd_dns_probe)

    tl = sub.add_parser("trace-lite", help="Short traceroute/tracepath probe")
    tl.add_argument("target")
    tl.add_argument("--max-hops", type=int, default=8)
    tl.add_argument("--timeout-s", type=int, default=45)
    tl.set_defaults(func=cmd_trace_lite)

    sub.add_parser("arp-snapshot", help="Layer-2-ish neighbour listings (honest banner)")

    db = sub.add_parser("disk-bench", help="Controlled seq read/write throughput sample")
    db.add_argument("--root", required=True, help="Directory for temp workload file")
    db.add_argument("--mebibytes", type=int, default=32)
    db.add_argument("--execute-ack", required=True)
    _audit_arg(db)
    db.set_defaults(func=cmd_disk_bench)

    br = sub.add_parser("battery-report", help="(Windows) powercfg /batteryreport")
    br.add_argument("--out", default="battery-report.html")
    _audit_arg(br)
    br.set_defaults(func=cmd_battery_report)

    sub.add_parser("startup-inventory", help="Windows startup + filtered scheduled tasks dump")
    sub.add_parser(
        "systemd-user-hints",
        help="Linux: systemctl --user list snapshots (informational)",
    )

    sub.add_parser(
        "tasks-snapshot",
        help="Windows: schtasks /query CSV (truncated)—Microsoft tasks only; use startup-inventory for WMI detail",
    )

    sub.add_parser("browser-cache-scan", help="Estimate Chromium/Edge/Fx cache footprint")

    cp = sub.add_parser("cleanup-plan", help="Large-file JSON plan (approve per row)")
    cp.add_argument("--roots", nargs="+", required=True)
    cp.add_argument("--min-size-mb", type=int, default=180)
    cp.add_argument("--max-files", type=int, default=120_000)
    cp.add_argument("--out", required=True)
    cp.set_defaults(func=cmd_cleanup_plan)

    ca = sub.add_parser("cleanup-apply", help="Deletes approved cleanup manifest rows")
    ca.add_argument("--manifest", required=True)
    ca.add_argument("--execute-ack", required=True)
    add_apply_audit_flags(ca)
    ca.set_defaults(func=cmd_cleanup_apply)

    dp = sub.add_parser("dupes-plan", help="Grouped duplicate-ish files via hashed cohorts")
    dp.add_argument("--roots", nargs="+", required=True)
    dp.add_argument("--min-size-kb", type=int, default=32)
    dp.add_argument("--max-size-mib", type=int, default=96)
    dp.add_argument("--max-files-scan", type=int, default=60_000)
    dp.add_argument("--max-hash-mib", type=int, default=64)
    dp.add_argument("--out", required=True)
    dp.set_defaults(func=cmd_dupes_plan)

    da = sub.add_parser("dupes-apply", help="Deletes duplicate manifests after acknowledgement")
    da.add_argument("--manifest", required=True)
    da.add_argument("--execute-ack", required=True)
    add_apply_audit_flags(da)
    da.set_defaults(func=cmd_dupes_apply)

    fp = sub.add_parser("flatpak-plan", help="(Linux) list flatpak apps for manifest approval")
    fp.add_argument("--out", required=True)
    fp.set_defaults(func=cmd_flatpak_plan)

    fa = sub.add_parser("flatpak-apply", help="flatpak uninstall -y manifest-approved ids")
    fa.add_argument("--manifest", required=True)
    fa.add_argument("--execute-ack", required=True)
    add_apply_audit_flags(fa)
    fa.set_defaults(func=cmd_flatpak_apply)

    ph = sub.add_parser("manifest-sha256", help="Print SHA-256 digest of arbitrary file")
    ph.add_argument("file")
    ph.set_defaults(func=cmd_manifest_hash)

    ap = sub.add_parser("apps-plan", help="(Windows) appx enumeration")
    ap.add_argument("--out", required=True)
    ap.set_defaults(func=cmd_apps_plan)

    aa = sub.add_parser("apps-apply", help="(Windows) appx removals")
    aa.add_argument("--manifest", required=True)
    aa.add_argument("--execute-ack", required=True)
    add_apply_audit_flags(aa)
    aa.set_defaults(func=cmd_apps_apply)

    sub.add_parser("gui", help="Tkinter cockpit for read-heavy checks + plan stubs")

    return p


def main() -> int:
    p = build_parser()
    args = p.parse_args()
    args.report_envelope = build_report_meta(
        "device_remediate_phase2.py",
        run_id=args.run_id,
        host_label=args.host_label,
        tenant=args.tenant,
    )
    if args.cmd == "metrics":
        m = cmd_metrics()
        m["hints"] = _heuristic_slowness_hint(m)
        m["report_meta"] = args.report_envelope
        print(json.dumps(m, indent=2))
        return 0
    if args.cmd == "wifi":
        w = cmd_wifi_scan()
        w["report_meta"] = args.report_envelope
        print(json.dumps(w, indent=2))
        return 0
    if args.cmd == "gui":
        return run_gui()
    if args.cmd == "arp-snapshot":
        return cmd_arp_snapshot(args)
    if args.cmd == "browser-cache-scan":
        return cmd_browser_cache_scan(args)
    if args.cmd == "startup-inventory":
        return cmd_startup_inventory(args)
    if args.cmd == "systemd-user-hints":
        return systemd_user_units_hints(args)
    if args.cmd == "tasks-snapshot":
        return cmd_tasks_snapshot(args)
    result = args.func(args)
    return int(result)


if __name__ == "__main__":
    raise SystemExit(main())

