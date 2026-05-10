/**
 * Phase-2 remediation helper — mirrors device_remediate_phase2.py (GUI: use Python `gui` subcommand).
 */

import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  takeFlag,
  takeInt,
  takeManyAfterFlag,
} from "./lib/args.js";
import { spawnCmd } from "./lib/spawn.js";

const SCHEMA_CLEANUP = "aureon.remediation.cleanup.v1";
const SCHEMA_APPX = "aureon.remediation.appx.v1";
const SCHEMA_DUPES = "aureon.remediation.dupes.v1";
const SCHEMA_FLATPAK = "aureon.remediation.flatpak.v1";

interface StatFsLike {
  bavail?: number;
  blocks?: number;
  bsize?: number;
  frsize?: number;
}

export function auditLogAppend(
  file: string | undefined,
  record: Record<string, unknown>
): void {
  if (!file) return;
  const line =
    JSON.stringify({ utc: new Date().toISOString(), ...record }) + "\n";
  try {
    fs.mkdirSync(path.dirname(path.resolve(file)), { recursive: true });
    fs.appendFileSync(file, line, "utf8");
  } catch {
    /* ignore */
  }
}

function which(bin: string): string | null {
  const ext = process.platform === "win32" ? ".exe" : "";
  const pathVar = process.env["PATH"] ?? "";
  const sep = process.platform === "win32" ? ";" : ":";
  for (const dir of pathVar.split(sep)) {
    const candidate = path.join(dir, bin + ext);
    if (fs.existsSync(candidate)) return candidate;
  }
  return null;
}

/** Match Python json.dumps(sort_keys=True) for hashing. */
function sortKeysDeep(val: unknown): unknown {
  if (Array.isArray(val)) return val.map(sortKeysDeep);
  if (val !== null && typeof val === "object" && val.constructor === Object) {
    const o = val as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(o).sort()) out[k] = sortKeysDeep(o[k]);
    return out;
  }
  return val;
}

export function cmdWifiScan(): Record<string, unknown> {
  const sys = process.platform;
  if (sys === "win32") {
    const r = spawnCmd(["netsh", "wlan", "show", "networks", "mode=Bssid"], 60_000);
    return {
      ok: r.code === 0,
      output: r.stdout + (r.stderr ? "\n" + r.stderr : ""),
      tool: "netsh",
    };
  }
  if (sys === "linux") {
    const tries = [
      ["nmcli", "-t", "-f", "ACTIVE,SSID,SIGNAL,SECURITY", "dev", "wifi"],
      ["iw", "dev", "wlan0", "scan"],
    ] as const;
    for (const tool of tries) {
      const r = spawnCmd([...tool], 45_000);
      if (r.code === 0 && r.stdout.trim()) {
        return { ok: true, output: r.stdout, tool: tool.slice(0, 2).join(" ") };
      }
    }
    return { ok: false, output: "Install nmcli / configure iw iface", tool: null };
  }
  if (sys === "darwin") {
    const ap =
      "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport";
    if (fs.existsSync(ap)) {
      const r = spawnCmd([ap, "-s"], 45_000);
      return { ok: r.code === 0, output: r.stdout + r.stderr, tool: "airport" };
    }
    return { ok: false, output: "airport binary unavailable", tool: null };
  }
  return { ok: false, output: `wifi scan N/A on ${sys}`, tool: null };
}

export function heuristicSlownessHint(m: Record<string, unknown>): string[] {
  const hints: string[] = [];
  const hv = (m["home_volume"] as Record<string, unknown> | undefined) ?? {};
  const fp = hv["free_percent"];
  if (typeof fp === "number" && fp < 10) {
    hints.push(
      "Low free space — swap/OS stability risk; offload bulk user data safely."
    );
  }
  if (typeof fp === "number" && fp < 20) {
    hints.push("Review caches/downloads after browser-cache-scan + cleanup-plan.");
  }
  hints.push(
    "Baseline CPU outliers against browser tabs & AV scan windows.",
    "Prefer Ethernet for jitter-sensitive workloads.",
    "If DNS/trace show loss or spikes, escalate to ISP/IT—this tool doesn't fix RF physics."
  );
  return hints;
}

function diskUsageHome(home: string): { total: number; free: number } {
  const fss = (
    fs as typeof fs & { statfsSync?: (p: string) => StatFsLike }
  ).statfsSync;
  if (typeof fss === "function") {
    try {
      const st = fss(home);
      const frag = Number(st.frsize ?? st.bsize ?? 4096);
      const free = Number(st.bavail ?? 0) * frag;
      const total = Number(st.blocks ?? 0) * frag;
      if (total > 0 && free >= 0) return { total, free };
    } catch {
      /* fall through */
    }
  }
  if (process.platform === "win32") {
    const drive = path.parse(path.resolve(home)).root.replace(/\\/g, "");
    const letter = drive.replace(":", "").charAt(0);
    const ps =
      `$d = '${letter}:'.Replace(':',''); ` +
      `Get-PSDrive $d | Select-Object Used,Free | ConvertTo-Json`;
    const r = spawnCmd(["powershell", "-NoProfile", "-Command", ps], 30_000);
    try {
      const row = JSON.parse(r.stdout.trim() || "{}") as {
        Used?: number;
        Free?: number;
      };
      const free = Number(row.Free ?? 0);
      const used = Number(row.Used ?? 0);
      if (used + free > 0) return { total: used + free, free };
    } catch {
      /* ignore */
    }
  }
  return { total: 1, free: 1 };
}

export function cmdMetrics(): Record<string, unknown> {
  const out: Record<string, unknown> = {
    platform: `${os.platform()} ${os.release()} ${os.version()}`,
    utc: new Date().toISOString(),
  };
  const sys = process.platform;
  out["cpu_logical"] = Math.max(os.cpus().length, 1);
  if (sys === "win32") {
    const ps =
      "Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize;" +
      'Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" | Select-Object DeviceID,FreeSpace,Size';
    const r = spawnCmd(["powershell", "-NoProfile", "-Command", ps], 60_000);
    out["powershell_memory_disk"] = {
      returncode: r.code,
      stdout: r.stdout.slice(0, 8000),
      stderr: r.stderr.slice(0, 2000),
    };
    const ps2 =
      "Get-Process | Sort-Object CPU -Descending | Select-Object -First 15 ProcessName,Id,CPU,WorkingSet | Format-Table -AutoSize | Out-String -Width 200";
    const r2 = spawnCmd(["powershell", "-NoProfile", "-Command", ps2], 45_000);
    out["top_cpu_processes"] = {
      returncode: r2.code,
      text: r2.stdout.slice(0, 6000),
    };
  } else if (sys === "linux") {
    const r = spawnCmd(["df", "-h"], 15_000);
    out["df"] = r.stdout.slice(0, 4000);
    const meminfo = "/proc/meminfo";
    if (fs.existsSync(meminfo)) {
      try {
        out["meminfo_head"] = fs.readFileSync(meminfo, "utf8").slice(0, 2000);
      } catch {
        /* ignore */
      }
    }
    const r2 = spawnCmd(["ps", "aux", "--sort=-%cpu"], 10_000);
    out["ps_head"] = r2.stdout.slice(0, 4000);
  } else if (sys === "darwin") {
    const r = spawnCmd(["df", "-h"], 15_000);
    out["df"] = r.stdout.slice(0, 4000);
    const r2 = spawnCmd(["vm_stat"], 10_000);
    out["vm_stat"] = r2.stdout.slice(0, 4000);
  }
  const home = os.homedir();
  const { total, free } = diskUsageHome(path.resolve(home));
  const freePct = Math.round((10_000 * free) / Math.max(total, 1)) / 100;
  out["home_volume"] = {
    total,
    used: total - free,
    free,
    free_percent: freePct,
  };
  return out;
}

export function dnsProbeDict(query: string, serversCsv: string): Record<string, unknown> {
  const resolver_tests: Record<string, unknown>[] = [];
  const res: Record<string, unknown> = {
    resolver_tests,
    query,
  };
  const servers = serversCsv
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  const dig = which("dig");
  const nslookup = which("nslookup");
  if (process.platform === "win32") {
    for (const srv of servers) {
      const r = spawnCmd(["nslookup", query, srv], 12_000);
      resolver_tests.push({
        server: srv,
        code: r.code,
        out: r.stdout.slice(0, 2500),
        err: r.stderr.slice(0, 500),
      });
    }
    return res;
  }
  let getentDone = false;
  for (const srv of servers) {
    if (dig) {
      const r = spawnCmd([dig, `@${srv}`, "+time=2", "+tries=1", query], 10_000);
      resolver_tests.push({
        server: srv,
        code: r.code,
        out: r.stdout.slice(0, 2500),
        err: r.stderr.slice(0, 500),
      });
    } else if (nslookup) {
      const r = spawnCmd(["nslookup", query, srv], 12_000);
      resolver_tests.push({
        server: srv,
        code: r.code,
        out: r.stdout.slice(0, 2500),
        err: r.stderr.slice(0, 500),
      });
    } else if (!getentDone) {
      const r = spawnCmd(["getent", "hosts", query], 5000);
      resolver_tests.push({
        fallback: "getent_hosts",
        note: "Install dig or nslookup for per-resolver checks",
        code: r.code,
        out: r.stdout.slice(0, 500),
        err: r.stderr.slice(0, 500),
      });
      getentDone = true;
      break;
    }
  }
  return res;
}

export function traceLite(
  target: string,
  maxHops: number,
  timeoutMs: number
): number {
  const hops = String(maxHops);
  if (process.platform === "win32") {
    const r = spawnCmd(["tracert", "-d", "-h", hops, target], timeoutMs);
    process.stdout.write(
      JSON.stringify({
        ok: r.code === 0 || r.code === 1,
        tool: "tracert",
        output: r.stdout + r.stderr,
      })
    );
    process.stdout.write("\n");
    return 0;
  }
  const trBin = which("traceroute");
  if (trBin) {
    const r = spawnCmd([trBin, "-n", "-m", hops, target], timeoutMs);
    process.stdout.write(
      JSON.stringify({
        ok: r.code === 0 || r.code === 1,
        tool: "traceroute",
        output: r.stdout + r.stderr,
      })
    );
    process.stdout.write("\n");
    return 0;
  }
  const r = spawnCmd(["tracepath", target], timeoutMs);
  process.stdout.write(
    JSON.stringify({
      ok: r.code === 0 || r.code === 1,
      tool: "tracepath",
      output: r.stdout + r.stderr,
    })
  );
  process.stdout.write("\n");
  return 0;
}

export function arpSnapshot(): Record<string, unknown> {
  if (process.platform === "win32") {
    const r1 = spawnCmd(["arp", "-a"], 15_000);
    const ps =
      "Get-NetNeighbor | Select-Object IPAddress,State,LinkLayerAddress,ifIndex | ConvertTo-Csv -NoTypeInformation";
    const r2 = spawnCmd(["powershell", "-NoProfile", "-Command", ps], 30_000);
    return {
      arp_ascii: { code: r1.code, text: r1.stdout.slice(0, 8000) },
      net_neighbor_csv: {
        code: r2.code,
        text: (r2.stdout + r2.stderr).slice(0, 8000),
      },
      honesty:
        "Snapshot only—not ARP spoofing IDS; escalate anomalies with netsec tooling.",
    };
  }
  if (process.platform === "linux") {
    let r = spawnCmd(["ip", "neigh"], 15_000);
    if (r.code !== 0) r = spawnCmd(["ip", "-s", "neigh"], 15_000);
    return {
      ip_neigh: { code: r.code, text: (r.stdout + r.stderr).slice(0, 12_000) },
      honesty:
        "Snapshot only—not ARP spoofing IDS; escalate anomalies with netsec tooling.",
    };
  }
  const r = spawnCmd(["arp", "-an"], 15_000);
  return {
    arp_an: { code: r.code, text: r.stdout + r.stderr },
    honesty:
      "Snapshot only—not ARP spoofing IDS; escalate anomalies with netsec tooling.",
  };
}

function pathAllowed(target: string, roots: string[]): boolean {
  const t = path.resolve(target);
  for (const r of roots) {
    const root = path.resolve(r);
    const rel = path.relative(root, t);
    if (rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel)) return true;
  }
  return false;
}

function takeExecuteAck(argv: string[]): string {
  const i = argv.indexOf("--execute-ack");
  if (i === -1 || i + 1 >= argv.length) return "";
  return argv[i + 1]!;
}

function takeManifestSha(argv: string[]): string | undefined {
  return takeFlag(argv, "--manifest-sha256");
}

function diskBench(argv: string[]): number {
  const ack = takeExecuteAck(argv);
  const root = takeFlag(argv, "--root");
  const mebibytes = takeInt(argv, "--mebibytes", 32);
  const auditLog = takeFlag(argv, "--audit-log");
  if (ack !== "EXECUTE_PHASE2_DISK_BENCH") {
    process.stderr.write("Refusing: requires --execute-ack EXECUTE_PHASE2_DISK_BENCH\n");
    return 2;
  }
  if (!root || !fs.existsSync(root) || !fs.statSync(root).isDirectory()) {
    process.stderr.write("root must exist\n");
    return 2;
  }
  const resolved = path.resolve(root);
  const tmp = path.join(
    resolved,
    `aureon-bench-${process.pid}-${Date.now()}-${Math.random().toString(16).slice(2)}.dat`
  );
  const chunk = Buffer.alloc(1024 * 1024, 0x41);
  const timings: Record<string, number> = {};
  try {
    const t0 = performance.now();
    const fh = fs.openSync(tmp, "w");
    try {
      for (let i = 0; i < mebibytes; i++) {
        fs.writeSync(fh, chunk);
      }
    } finally {
      fs.closeSync(fh);
    }
    timings["seq_write_mb_s"] =
      Math.round(
        (mebibytes / Math.max((performance.now() - t0) / 1000, 1e-6)) * 100
      ) / 100;
    const t1 = performance.now();
    const rf = fs.openSync(tmp, "r");
    try {
      const buf = Buffer.alloc(1024 * 1024);
      for (;;) {
        const n = fs.readSync(rf, buf, 0, buf.length, undefined);
        if (n === 0) break;
      }
    } finally {
      fs.closeSync(rf);
    }
    timings["seq_read_mb_s"] =
      Math.round(
        (mebibytes / Math.max((performance.now() - t1) / 1000, 1e-6)) * 100
      ) / 100;
  } finally {
    try {
      fs.unlinkSync(tmp);
    } catch {
      /* ignore */
    }
  }
  auditLogAppend(auditLog, {
    action: "disk_bench",
    root: resolved,
    timing: timings,
  });
  process.stdout.write(
    JSON.stringify({ root: resolved, mebibytes, timing: timings }, null, 2) + "\n"
  );
  return 0;
}

function batteryReport(argv: string[]): number {
  if (process.platform !== "win32") {
    process.stderr.write("battery-report only wired for Windows powercfg.\n");
    return 2;
  }
  const outPathRaw =
    takeFlag(argv, "--out") ?? path.join(process.cwd(), "battery-report.html");
  const outPath = path.resolve(
    outPathRaw.replace(/^~(?=$|[\\/])/, os.homedir())
  );
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  const r = spawnCmd(["powercfg", "/batteryreport", "/output", outPath], 120_000);
  const auditLog = takeFlag(argv, "--audit-log");
  auditLogAppend(auditLog, {
    action: "battery_report",
    path: outPath,
    code: r.code,
  });
  process.stdout.write(
    JSON.stringify(
      { code: r.code, path: outPath, stdout: r.stdout, stderr: r.stderr },
      null,
      2
    ) + "\n"
  );
  return r.code === 0 ? 0 : 1;
}

function startupInventory(): Record<string, unknown> {
  const ps =
    "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Depth 3;" +
    "Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\\\Microsoft\\\\*'} | Select-Object TaskName,TaskPath,State | ConvertTo-Json -Depth 3";
  const r = spawnCmd(["powershell", "-NoProfile", "-Command", ps], 180_000);
  return {
    code: r.code,
    payload: r.stdout.slice(0, 120_000),
    stderr: r.stderr.slice(0, 2000),
  };
}

function systemdUserHints(): number {
  if (process.platform !== "linux") {
    process.stderr.write("Linux-only informational hint runner.\n");
    return 2;
  }
  const blocks: unknown[] = [];
  for (const cmd of [
    ["systemctl", "--user", "list-unit-files"],
    ["systemctl", "--user", "list-timers", "--no-pager"],
  ] as const) {
    const r = spawnCmd([...cmd], 20_000);
    blocks.push({
      cmd,
      code: r.code,
      out_head: r.stdout.slice(0, 16_000),
      err: r.stderr.slice(0, 2000),
    });
  }
  process.stdout.write(
    JSON.stringify(
      { note: "read-only systemd --user snapshots", blocks },
      null,
      2
    ) + "\n"
  );
  return 0;
}

function dirSizeLimit(p: string, maxEntries: number): { bytes: number; seen: number } {
  let total = 0;
  let seen = 0;
  const stack = [p];
  try {
    while (stack.length && seen < maxEntries) {
      const d = stack.pop()!;
      let names: string[];
      try {
        names = fs.readdirSync(d);
      } catch {
        continue;
      }
      for (const n of names) {
        if (seen >= maxEntries) break;
        const fp = path.join(d, n);
        let st: fs.Stats;
        try {
          st = fs.lstatSync(fp);
        } catch {
          continue;
        }
        if (st.isDirectory()) stack.push(fp);
        else if (st.isFile()) {
          seen += 1;
          total += st.size;
        }
      }
    }
  } catch {
    /* ignore */
  }
  return { bytes: total, seen };
}

export function browserCacheScan(): Record<string, unknown> {
  const rows: unknown[] = [];
  const sys = process.platform;
  if (sys === "win32") {
    const la = process.env["LOCALAPPDATA"] ?? "";
    const cands = [
      path.join(la, "Google/Chrome/User Data/Default/Cache"),
      path.join(la, "Google/Chrome/User Data/Default/Cache/Cache_Data"),
      path.join(la, "Microsoft/Edge/User Data/Default/Cache"),
      path.join(la, "Microsoft/Edge/User Data/Default/Cache/Cache_Data"),
      path.join(la, "Mozilla/Firefox/Profiles"),
    ];
    for (const d of cands) {
      if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
        const { bytes, seen } = dirSizeLimit(d, 250_000);
        rows.push({
          path: d,
          estimated_bytes_under_cap: bytes,
          file_samples: seen,
        });
      }
    }
  } else if (sys === "linux") {
    const home = os.homedir();
    for (const d of [
      path.join(home, ".cache/google-chrome"),
      path.join(home, ".cache/mozilla/firefox"),
      path.join(home, ".cache/msedge"),
    ]) {
      if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
        const { bytes, seen } = dirSizeLimit(d, 250_000);
        rows.push({
          path: d,
          estimated_bytes_under_cap: bytes,
          file_samples: seen,
        });
      }
    }
  } else if (sys === "darwin") {
    const home = os.homedir();
    for (const d of [
      path.join(home, "Library/Caches/Google/Chrome"),
      path.join(home, "Library/Caches/com.apple.Safari"),
    ]) {
      if (fs.existsSync(d) && fs.statSync(d).isDirectory()) {
        const { bytes, seen } = dirSizeLimit(d, 250_000);
        rows.push({
          path: d,
          estimated_bytes_under_cap: bytes,
          file_samples: seen,
        });
      }
    }
  }
  return {
    dirs: rows,
    note:
      "Sizes capped — run cleanup-plan on selected cache dirs only after validating nothing sensitive will be harmed.",
  };
}

type CleanupRow = {
  path: string;
  bytes: number;
  approved: boolean;
  reason: string;
};

function walkLargeFiles(
  roots: string[],
  maxFiles: number,
  minBytes: number
): CleanupRow[] {
  const rows: CleanupRow[] = [];
  let n = 0;
  for (const root of roots) {
    const r = path.resolve(root);
    if (!fs.existsSync(r) || !fs.statSync(r).isDirectory()) continue;
    const stack = [r];
    while (stack.length > 0) {
      if (n >= maxFiles) return rows;
      const dirpath = stack.pop()!;
      let names: string[];
      try {
        names = fs.readdirSync(dirpath);
      } catch {
        continue;
      }
      for (const name of names) {
        if (n >= maxFiles) return rows;
        const fp = path.join(dirpath, name);
        let st: fs.Stats;
        try {
          st = fs.lstatSync(fp);
        } catch {
          continue;
        }
        if (st.isDirectory()) stack.push(fp);
        else if (st.isFile()) {
          if (st.size >= minBytes) {
            rows.push({
              path: fp,
              bytes: st.size,
              approved: false,
              reason: "large_file_candidate",
            });
          }
          n += 1;
        }
      }
    }
  }
  return rows;
}

function cleanupPlan(argv: string[]): number {
  const roots = takeManyAfterFlag(argv, "--roots").map((p) =>
    path.resolve(p.replace(/^~(?=$|[\\/])/, os.homedir()))
  );
  const minMb = takeInt(argv, "--min-size-mb", 180);
  const maxFiles = takeInt(argv, "--max-files", 120_000);
  const out = takeFlag(argv, "--out");
  if (!out || roots.length === 0) {
    process.stderr.write("cleanup-plan requires --roots ... and --out\n");
    return 2;
  }
  const rows = walkLargeFiles(roots, maxFiles, minMb * 1024 * 1024);
  const canon = Buffer.from(
    JSON.stringify(sortKeysDeep(rows) as CleanupRow[]),
    "utf8"
  );
  const canonHash = createHash("sha256").update(canon).digest("hex");
  const doc = {
    schema: SCHEMA_CLEANUP,
    generated_utc: new Date().toISOString(),
    allowed_roots: roots,
    execute_ack_required: "EXECUTE_PHASE2_DELETE",
    instructions:
      "Set approved:true per path only after review; run cleanup-apply with matching ack and optional --manifest-sha256 on this canonical JSON ordering.",
    canonical_items_sha256: canonHash,
    items: rows,
  };
  const txt = JSON.stringify(doc, null, 2);
  fs.writeFileSync(out, txt, "utf8");
  const mf = createHash("sha256").update(txt).digest("hex");
  process.stdout.write(
    `Wrote plan ${rows.length} rows -> ${out}\nmanifest_file_sha256=${mf}\n`
  );
  return 0;
}

function cleanupApply(argv: string[]): number {
  if (takeExecuteAck(argv) !== "EXECUTE_PHASE2_DELETE") {
    process.stderr.write("Refusing cleanup-apply acknowledgement.\n");
    return 2;
  }
  const mfPath = takeFlag(argv, "--manifest");
  const shaExp = takeManifestSha(argv);
  const auditLog = takeFlag(argv, "--audit-log");
  if (!mfPath) return 2;
  const raw = fs.readFileSync(mfPath, "utf8");
  if (shaExp && createHash("sha256").update(raw).digest("hex") !== shaExp) {
    process.stderr.write("manifest SHA256 mismatch — refuse apply.\n");
    return 2;
  }
  const doc = JSON.parse(raw) as {
    schema?: string;
    allowed_roots?: string[];
    items?: Array<{ path: string; approved?: boolean }>;
  };
  if (doc.schema !== SCHEMA_CLEANUP || !doc.allowed_roots) {
    process.stderr.write("Invalid cleanup schema.\n");
    return 2;
  }
  const roots = doc.allowed_roots.map((p) => path.resolve(p));
  let deleted = 0;
  let errors = 0;
  for (const item of doc.items ?? []) {
    if (!item.approved) continue;
    let pth = path.resolve(item.path.replace(/^~(?=$|[\\/])/, os.homedir()));
    if (!pathAllowed(pth, roots)) {
      process.stderr.write(`skip outside roots ${pth}\n`);
      errors += 1;
      continue;
    }
    if (!fs.existsSync(pth)) continue;
    try {
      const st = fs.lstatSync(pth);
      if (st.isFile()) {
        fs.unlinkSync(pth);
      } else if (st.isDirectory()) {
        fs.rmSync(pth, { recursive: true, force: true });
      } else continue;
      deleted += 1;
      auditLogAppend(auditLog, { deleted: pth });
    } catch (e) {
      process.stderr.write(`delete error ${pth}: ${String(e)}\n`);
      errors += 1;
    }
  }
  auditLogAppend(auditLog, {
    action: "cleanup_apply_finished",
    deleted,
    errors,
  });
  process.stdout.write(`deleted=${deleted} errors=${errors}\n`);
  return errors === 0 ? 0 : 1;
}

function fileDigest(file: string, limit: number): string | null {
  const h = createHash("sha256");
  try {
    const fd = fs.openSync(file, "r");
    let n = 0;
    try {
      const buf = Buffer.alloc(1024 * 1024);
      for (;;) {
        const read = fs.readSync(fd, buf, 0, buf.length);
        if (read <= 0) break;
        h.update(buf.subarray(0, read));
        n += read;
        if (limit > 0 && n >= limit) break;
      }
    } finally {
      fs.closeSync(fd);
    }
    return h.digest("hex");
  } catch {
    return null;
  }
}

function sameFileDeviceInode(a: string, b: string): boolean {
  try {
    const sa = fs.statSync(a);
    const sb = fs.statSync(b);
    return (
      sa.ino === sb.ino &&
      (sa.dev as unknown) === (sb.dev as unknown)
    );
  } catch {
    return false;
  }
}

function dupesPlan(argv: string[]): number {
  const roots = takeManyAfterFlag(argv, "--roots").map((p) =>
    path.resolve(p.replace(/^~(?=$|[\\/])/, os.homedir()))
  );
  const minKb = takeInt(argv, "--min-size-kb", 32);
  const maxSizeMib = takeInt(argv, "--max-size-mib", 96);
  const maxFilesScan = takeInt(argv, "--max-files-scan", 60_000);
  const maxHashMib = takeInt(argv, "--max-hash-mib", 64);
  const out = takeFlag(argv, "--out");
  if (!out || roots.length === 0) {
    process.stderr.write("dupes-plan requires --roots ... and --out\n");
    return 2;
  }
  const grouped = new Map<string, string[]>();
  let seenFiles = 0;
  const hashCap = maxHashMib * 1024 * 1024;

  function consider(fp: string, stSz: number): void {
    if (seenFiles >= maxFilesScan) return;
    if (stSz < minKb * 1024 || stSz > maxSizeMib * 1024 * 1024) return;
    seenFiles += 1;
    const cap = stSz <= hashCap ? hashCap : 64 * 1024;
    const dg = fileDigest(fp, cap);
    if (!dg) return;
    const marker =
      stSz <= hashCap ? dg : dg + ":partial-prefix";
    const key = `${stSz}:${marker}`;
    const existing = grouped.get(key) ?? [];
    existing.push(path.resolve(fp));
    grouped.set(key, existing);
  }

  outer: for (const root of roots) {
    const r = path.resolve(root);
    if (!fs.existsSync(r) || !fs.statSync(r).isDirectory()) continue;
    const stack = [r];
    while (stack.length > 0) {
      if (seenFiles >= maxFilesScan) break outer;
      const dirpath = stack.pop()!;
      let names: string[];
      try {
        names = fs.readdirSync(dirpath);
      } catch {
        continue;
      }
      for (const name of names) {
        if (seenFiles >= maxFilesScan) break outer;
        const fp = path.join(dirpath, name);
        let st: fs.Stats;
        try {
          st = fs.lstatSync(fp);
        } catch {
          continue;
        }
        if (st.isDirectory()) stack.push(fp);
        else if (st.isFile()) consider(fp, st.size);
      }
    }
  }

  const fixedPacks = [];
  for (const [kStr, plist] of grouped) {
    if (plist.length < 2) continue;
    plist.sort();
    const sep = kStr.indexOf(":");
    const sz = Number(kStr.slice(0, sep));
    const marker = kStr.slice(sep + 1);
    fixedPacks.push({
      size: sz,
      digest_marker: marker,
      keep_path: plist[0],
      delete_duplicates: plist.slice(1).map((p) => ({
        path: p,
        approved: false,
      })),
      approved_delete_duplicates: false,
      instructions:
        "Set approved:true on removals you approve; optionally set approved_delete_duplicates:true for whole group shortcut after review (still requires EXECUTE_PHASE2_DELETE_DUPES).",
    });
  }

  const doc = {
    schema: SCHEMA_DUPES,
    generated_utc: new Date().toISOString(),
    allowed_roots: roots,
    execute_ack_required: "EXECUTE_PHASE2_DELETE_DUPES",
    max_hash_mib: maxHashMib,
    caution:
      "Partial hashing for gigantic files marks digest_marker suffix :partial-prefix",
    groups: fixedPacks,
  };
  fs.writeFileSync(out, JSON.stringify(doc, null, 2), "utf8");
  process.stdout.write(
    `duplicate groups detected=${fixedPacks.length} -> ${out}\n`
  );
  return 0;
}

function dupesApply(argv: string[]): number {
  if (takeExecuteAck(argv) !== "EXECUTE_PHASE2_DELETE_DUPES") {
    process.stderr.write(
      "Refusing: pass --execute-ack EXECUTE_PHASE2_DELETE_DUPES\n"
    );
    return 2;
  }
  const mfPath = takeFlag(argv, "--manifest");
  const shaExp = takeManifestSha(argv);
  const auditLog = takeFlag(argv, "--audit-log");
  if (!mfPath) return 2;
  const raw = fs.readFileSync(mfPath, "utf8");
  if (shaExp && createHash("sha256").update(raw).digest("hex") !== shaExp) {
    process.stderr.write("dupes manifest SHA256 mismatch\n");
    return 2;
  }
  const doc = JSON.parse(raw) as {
    schema?: string;
    allowed_roots?: string[];
    groups?: Array<{
      keep_path?: string;
      approved_delete_duplicates?: boolean;
      delete_duplicates?: Array<{ path: string; approved?: boolean }>;
    }>;
  };
  if (doc.schema !== SCHEMA_DUPES) return 2;
  const roots = (doc.allowed_roots ?? []).map((p) => path.resolve(p));
  let n = 0;
  let err = 0;
  for (const g of doc.groups ?? []) {
    const keepPath = path.resolve(String(g.keep_path ?? ""));
    const bulk = Boolean(g.approved_delete_duplicates);
    const dels: string[] = bulk
      ? (g.delete_duplicates ?? []).map((x) => String(x?.path ?? ""))
      : (g.delete_duplicates ?? []).filter((x) => x?.approved).map((x) => String(x.path));
    for (let pRaw of dels) {
      let pth = path.resolve(pRaw.replace(/^~(?=$|[\\/])/, os.homedir()));
      if (!pathAllowed(pth, roots)) {
        process.stderr.write(`outside roots ${pth}\n`);
        err += 1;
        continue;
      }
      if (sameFileDeviceInode(pth, keepPath)) continue;
      try {
        const st = fs.lstatSync(pth);
        if (st.isFile()) {
          fs.unlinkSync(pth);
          n += 1;
          auditLogAppend(auditLog, { dup_removed: pth });
        } else if (st.isDirectory()) {
          fs.rmSync(pth, { recursive: true, force: true });
          n += 1;
        }
      } catch (e) {
        process.stderr.write(`${pth}: ${String(e)}\n`);
        err += 1;
      }
    }
  }
  auditLogAppend(auditLog, {
    action: "dupes_apply",
    removed_files: n,
    errors: err,
  });
  process.stdout.write(`removed_duplicate_files≈${n} errors=${err}\n`);
  return err === 0 ? 0 : 1;
}

function flatpakPlan(argv: string[]): number {
  if (process.platform !== "linux") {
    process.stderr.write("flatpak-plan is Linux-specific.\n");
    return 2;
  }
  const fk = which("flatpak");
  if (!fk) {
    process.stderr.write("flatpak CLI missing.\n");
    return 2;
  }
  const out = takeFlag(argv, "--out");
  if (!out) return 2;
  const r = spawnCmd([fk, "list", "--app", "--columns=application"], 60_000);
  if (r.code !== 0) {
    process.stderr.write(r.stderr + r.stdout);
    return 1;
  }
  const rows = [];
  for (const line of r.stdout.split(/\r?\n/)) {
    const app = line.trim();
    if (!app || app.toLowerCase().startsWith("no installed")) continue;
    rows.push({ application_id: app, approved_uninstall: false });
  }
  const doc = {
    schema: SCHEMA_FLATPAK,
    generated_utc: new Date().toISOString(),
    execute_ack_required: "EXECUTE_PHASE2_FLATPAK_RM",
    items: rows,
  };
  fs.writeFileSync(out, JSON.stringify(doc, null, 2), "utf8");
  process.stderr.write(`wrote flatpak catalogue lines=${rows.length} -> ${out}\n`);
  return 0;
}

function flatpakApply(argv: string[]): number {
  if (process.platform !== "linux") {
    process.stderr.write("Wrong platform.\n");
    return 2;
  }
  if (takeExecuteAck(argv) !== "EXECUTE_PHASE2_FLATPAK_RM") return 2;
  const fk = which("flatpak");
  if (!fk) return 2;
  const mfPath = takeFlag(argv, "--manifest");
  const shaExp = takeManifestSha(argv);
  const auditLog = takeFlag(argv, "--audit-log");
  if (!mfPath) return 2;
  const raw = fs.readFileSync(mfPath, "utf8");
  if (shaExp && createHash("sha256").update(raw).digest("hex") !== shaExp) {
    process.stderr.write("flatpak manifest SHA256 mismatch\n");
    return 2;
  }
  const doc = JSON.parse(raw) as {
    schema?: string;
    items?: Array<{ application_id?: string; approved_uninstall?: boolean }>;
  };
  if (doc.schema !== SCHEMA_FLATPAK) return 2;
  let ok = 0;
  let bad = 0;
  for (const it of doc.items ?? []) {
    if (!it.approved_uninstall) continue;
    const app = String(it.application_id ?? "");
    if (!app) {
      bad += 1;
      continue;
    }
    const r = spawnCmd([fk, "uninstall", "-y", app], 300_000);
    if (r.code === 0) {
      ok += 1;
      auditLogAppend(auditLog, { flatpak_removed: app });
    } else bad += 1;
  }
  auditLogAppend(auditLog, { action: "flatpak_apply", ok, bad });
  process.stdout.write(`flatpak uninstall ok=${ok} fail=${bad}\n`);
  return bad === 0 ? 0 : 1;
}

function manifestHashCli(argv: string[]): number {
  const file = argv[0];
  if (!file) return 2;
  const raw = fs.readFileSync(file);
  const hf = createHash("sha256").update(raw).digest("hex");
  process.stdout.write(JSON.stringify({ sha256: hf, path: file }) + "\n");
  return 0;
}

function appsPlan(argv: string[]): number {
  if (process.platform !== "win32") {
    process.stderr.write("apps-plan is Windows-only.\n");
    return 2;
  }
  const out = takeFlag(argv, "--out");
  if (!out) return 2;
  const ps =
    "Get-AppxPackage | Where-Object {$_.IsFramework -eq $false} | Select-Object Name,PackageFullName,Version,Publisher | ConvertTo-Json -Depth 3";
  const r = spawnCmd(["powershell", "-NoProfile", "-Command", ps], 120_000);
  if (r.code !== 0) {
    process.stderr.write(r.stderr + r.stdout);
    return 1;
  }
  let rowsRaw: unknown;
  try {
    rowsRaw = JSON.parse(r.stdout);
  } catch {
    rowsRaw = [{ raw: r.stdout.slice(0, 4000) }];
  }
  const arr = Array.isArray(rowsRaw) ? rowsRaw : [rowsRaw];
  const doc = {
    schema: SCHEMA_APPX,
    generated_utc: new Date().toISOString(),
    execute_ack_required: "EXECUTE_PHASE2_UNINSTALL_APPX",
    items: arr
      .filter((row): row is Record<string, unknown> => !!row && typeof row === "object")
      .filter((row) => typeof row.PackageFullName === "string")
      .map((r) => ({
        name: r.Name,
        package_full_name: r.PackageFullName,
        version: r.Version,
        publisher: r.Publisher,
        approved: false,
      })),
  };
  fs.writeFileSync(out, JSON.stringify(doc, null, 2), "utf8");
  process.stdout.write(`appx catalogue=${doc.items.length} -> ${out}\n`);
  return 0;
}

function appsApply(argv: string[]): number {
  if (process.platform !== "win32") return 2;
  if (takeExecuteAck(argv) !== "EXECUTE_PHASE2_UNINSTALL_APPX") return 2;
  const mfPath = takeFlag(argv, "--manifest");
  const shaExp = takeManifestSha(argv);
  const auditLog = takeFlag(argv, "--audit-log");
  if (!mfPath) return 2;
  const raw = fs.readFileSync(mfPath, "utf8");
  if (shaExp && createHash("sha256").update(raw).digest("hex") !== shaExp) {
    process.stderr.write("appx manifest SHA256 mismatch\n");
    return 2;
  }
  const doc = JSON.parse(raw) as {
    schema?: string;
    items?: Array<{ approved?: boolean; package_full_name?: string }>;
  };
  if (doc.schema !== SCHEMA_APPX) return 2;
  let ok = 0;
  let bad = 0;
  for (const item of doc.items ?? []) {
    if (!item.approved) continue;
    const pfn = item.package_full_name;
    if (!pfn) {
      bad += 1;
      continue;
    }
    const pfnEsc = pfn.replace(/'/g, "''");
    const ps = `Get-AppxPackage -PackageFullName '${pfnEsc}' | Remove-AppxPackage`;
    const r = spawnCmd(["powershell", "-NoProfile", "-Command", ps], 180_000);
    auditLogAppend(auditLog, {
      appx_remove: pfn,
      code: r.code,
      stderr: r.stderr.slice(0, 500),
    });
    if (r.code === 0) ok += 1;
    else bad += 1;
  }
  process.stdout.write(`appx remove ok=${ok} fail=${bad}\n`);
  return bad === 0 ? 0 : 1;
}

function positionalAfterSubcmd(argv: string[], sub: string): string[] {
  const i = argv.indexOf(sub);
  return i >= 0 ? argv.slice(i + 1) : argv;
}

export function runPhase2(argv: string[]): number {
  const sub = argv[0];
  if (!sub) {
    process.stderr.write(
      'Usage: phase2 <wifi|metrics|dns-probe|trace-lite|arp-snapshot|...> (see contrib/aureon-hardening/ts)\n'
    );
    return 2;
  }
  const tail = argv.slice(1);

  if (sub === "wifi") {
    process.stdout.write(JSON.stringify(cmdWifiScan(), null, 2) + "\n");
    return 0;
  }
  if (sub === "metrics") {
    const m = cmdMetrics();
    m["hints"] = heuristicSlownessHint(m);
    process.stdout.write(JSON.stringify(m, null, 2) + "\n");
    return 0;
  }
  if (sub === "dns-probe") {
    const query = takeFlag(tail, "--query") ?? "example.com";
    const servers = takeFlag(tail, "--servers") ?? "8.8.8.8,1.1.1.1";
    process.stdout.write(JSON.stringify(dnsProbeDict(query, servers), null, 2) + "\n");
    return 0;
  }
  if (sub === "trace-lite") {
    const rest = positionalAfterSubcmd(argv, sub);
    const target = rest[0];
    if (!target) {
      process.stderr.write("trace-lite requires target host\n");
      return 2;
    }
    const maxHops = takeInt(tail, "--max-hops", 8);
    const timeoutS = takeInt(tail, "--timeout-s", 45);
    return traceLite(target, maxHops, timeoutS * 1000);
  }
  if (sub === "arp-snapshot") {
    process.stdout.write(JSON.stringify(arpSnapshot(), null, 2) + "\n");
    return 0;
  }
  if (sub === "disk-bench") return diskBench(tail);
  if (sub === "battery-report") return batteryReport(tail);
  if (sub === "startup-inventory") {
    if (process.platform !== "win32") {
      process.stderr.write(
        "startup-inventory WMI export targets Windows — use systemd-user-hints on Linux.\n"
      );
      return 2;
    }
    const blob = startupInventory();
    process.stdout.write(JSON.stringify(blob, null, 2) + "\n");
    return blob.code === 0 ? 0 : 1;
  }
  if (sub === "systemd-user-hints") return systemdUserHints();
  if (sub === "browser-cache-scan") {
    process.stdout.write(JSON.stringify(browserCacheScan(), null, 2) + "\n");
    return 0;
  }
  if (sub === "cleanup-plan") return cleanupPlan(tail);
  if (sub === "cleanup-apply") return cleanupApply(tail);
  if (sub === "dupes-plan") return dupesPlan(tail);
  if (sub === "dupes-apply") return dupesApply(tail);
  if (sub === "flatpak-plan") return flatpakPlan(tail);
  if (sub === "flatpak-apply") return flatpakApply(tail);
  if (sub === "manifest-sha256") return manifestHashCli(argv.slice(1));
  if (sub === "apps-plan") return appsPlan(tail);
  if (sub === "apps-apply") return appsApply(tail);
  if (sub === "gui") {
    process.stderr.write(
      "Tk GUI is implemented in Python: python3 contrib/aureon-hardening/device_remediate_phase2.py gui\n"
    );
    return 0;
  }

  process.stderr.write(`unknown phase2 subcommand: ${sub}\n`);
  return 2;
}
