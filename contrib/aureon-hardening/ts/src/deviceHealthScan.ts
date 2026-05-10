/**
 * Read-only inventory — mirrors device_health_scan.py (bounded walk, JSON schema v1).
 */

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  hasFlag,
  takeFlag,
  takeFloat,
  takeInt,
  takeManyAfterFlag,
} from "./lib/args.js";
import { spawnCmd } from "./lib/spawn.js";

export interface FileMeta {
  path: string;
  size: number;
  mtime_ns: number;
  atime_ns: number;
}

function expandRoot(raw: string): string | null {
  const p = path.resolve(path.normalize(raw.replace(/^~(?=$|[\\/])/, os.homedir())));
  try {
    if (fs.existsSync(p) && fs.statSync(p).isDirectory()) return p;
  } catch {
    /* ignore */
  }
  process.stderr.write(`skip missing root: ${JSON.stringify(raw)}\n`);
  return null;
}

function pruneDirnames(
  names: string[],
  skipGit: boolean,
  skipNm: boolean
): void {
  if (skipGit) {
    const i = names.indexOf(".git");
    if (i >= 0) names.splice(i, 1);
  }
  if (skipNm) {
    const j = names.indexOf("node_modules");
    if (j >= 0) names.splice(j, 1);
  }
}

function addDirAncestors(
  filePath: string,
  root: string,
  size: number,
  dirBytes: Map<string, number>
): void {
  let cur = path.dirname(filePath);
  const rootAbs = path.resolve(root);
  for (;;) {
    dirBytes.set(cur, (dirBytes.get(cur) ?? 0) + size);
    if (cur === rootAbs || path.dirname(cur) === cur) break;
    cur = path.dirname(cur);
  }
}

export function collectInventory(
  roots: string[],
  maxFiles: number,
  skipGit: boolean,
  skipNm: boolean
): {
  files: FileMeta[];
  dirBytes: Map<string, number>;
  errors: string[];
  capped: boolean;
} {
  const files: FileMeta[] = [];
  const dirBytes = new Map<string, number>();
  const errors: string[] = [];
  let count = 0;
  let capped = false;

  const stack: string[] = [...roots.map((r) => path.resolve(r))];

  outer: while (stack.length > 0) {
    const dirpath = stack.pop()!;
    let names: string[];
    try {
      names = fs.readdirSync(dirpath);
    } catch (e) {
      errors.push(`readdir(${dirpath}): ${String(e)}`);
      continue;
    }
    pruneDirnames(names, skipGit, skipNm);

    for (const name of names) {
      const fp = path.join(dirpath, name);
      let lst: fs.Stats;
      try {
        lst = fs.lstatSync(fp);
      } catch (e) {
        errors.push(`lstat(${fp}): ${String(e)}`);
        continue;
      }
      if (lst.isDirectory()) {
        stack.push(fp);
      } else if (lst.isFile()) {
        if (count >= maxFiles) {
          capped = true;
          break outer;
        }
        const atNs = lst.atimeNs ?? Math.round(lst.atimeMs * 1e6);
        const mtNs = lst.mtimeNs ?? Math.round(lst.mtimeMs * 1e6);
        files.push({
          path: fp,
          size: lst.size,
          mtime_ns: mtNs,
          atime_ns: atNs,
        });
        count += 1;
        let rootForAncestors = roots.find((rr) => {
          const rrAbs = path.resolve(rr);
          const rel = path.relative(rrAbs, fp);
          return rel !== "" && !rel.startsWith("..") && !path.isAbsolute(rel);
        });
        if (!rootForAncestors && roots.length === 1) rootForAncestors = roots[0];
        if (rootForAncestors)
          addDirAncestors(fp, path.resolve(rootForAncestors), lst.size, dirBytes);
      }
    }
  }

  return { files, dirBytes, errors, capped };
}

function staleCandidates(
  files: FileMeta[],
  days: number,
  preferAtime: boolean,
  nowSec: number
): Array<{ path: string; size: number; stamp_sec: number }> {
  const thresh = nowSec - days * 86400;
  const rows = files
    .map((f) => ({
      path: f.path,
      size: f.size,
      stamp_sec: (preferAtime ? f.atime_ns : f.mtime_ns) / 1e9,
    }))
    .filter((r) => r.stamp_sec <= thresh)
    .sort((a, b) => a.stamp_sec - b.stamp_sec);
  return rows.slice(0, 8000);
}

function runClam(target: string, timeoutS: number, clamscanBin: string): Record<string, unknown> {
  const r = spawnSync(clamscanBin, ["--recursive=yes", "-i", target], {
    encoding: "utf8",
    timeout: timeoutS * 1000,
    windowsHide: true,
  });
  if ((r.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT") {
    return { ok: false, error: `${JSON.stringify(clamscanBin)} not found in PATH` };
  }
  return {
    ok: true,
    returncode: r.status ?? -1,
    infected_lines_sample: ((r.stdout as string) ?? "").slice(-8000),
    stderr_tail: (((r.stderr as string) ?? "") as string).slice(-2000),
    clam_note: "returncode 0=clean subtree; 1=virus(es) reported by ClamAV",
  };
}

function runWindowsDefenderQuick(timeoutS: number): Record<string, unknown> {
  const base = process.env["PROGRAMFILES"] ?? "C:\\Program Files";
  const exe = path.join(base, "Windows Defender", "MpCmdRun.exe");
  if (!fs.existsSync(exe)) {
    return { triggered: false, note: "MpCmdRun.exe not located" };
  }
  const r = spawnCmd([exe, "-Scan", "-ScanType", "2"], timeoutS * 1000);
  return {
    triggered: true,
    returncode: r.code,
    stdout_tail: r.stdout.slice(-2000),
    stderr_tail: r.stderr.slice(-2000),
  };
}

function postureHints(): string[] {
  const sys = os.platform();
  const h: string[] = [];
  if (sys === "win32") {
    h.push(
      "Windows: confirm Windows Security (real-time protection) is on; enforce BitLocker/Device Encryption where laptops leave the facility."
    );
  } else if (sys === "linux") {
    h.push(
      "Linux: vendor security repos + unattended upgrades; minimise open listening services; firewall default-deny egress for server roles where applicable."
    );
  } else if (sys === "darwin") {
    h.push(
      "macOS: align Gatekeeper/FileVault/mobile device policies with organisational MDM."
    );
  } else {
    h.push("Generalise: OS & firmware patching on a contractual cadence.");
  }
  h.push(
    "Backups immutable or offline-tested; restore drills beat promises.",
    "Use approved EDR for malware behavioural verdicts—not this enumerator.",
    "Review unusually large installers / scripts in Downloads with suspicion.",
    "Enumerate USB policies and autorun equivalents for your fleet."
  );
  return h;
}

export function runDeviceHealthScan(argv: string[]): number {
  if (!hasFlag(argv, "--ack-readonly-inventory")) {
    process.stderr.write(
      "Refusing: device health scan requires --ack-readonly-inventory (explicit consent).\n"
    );
    return 2;
  }

  const rootsArg = takeManyAfterFlag(argv, "--roots");
  const maxFiles = takeInt(argv, "--max-files", 500_000);
  const topFiles = takeInt(argv, "--top-files", 40);
  const topDirs = takeInt(argv, "--top-dirs", 25);
  const staleDays = takeFloat(argv, "--stale-days", 0);
  const staleBy = (takeFlag(argv, "--stale-by") as "atime" | "mtime" | null) ?? "mtime";
  const skipGit = !hasFlag(argv, "--no-skip-git");
  const skipNm = !hasFlag(argv, "--no-skip-node-modules");
  const jsonOut = hasFlag(argv, "--json");

  const clamRoot = takeFlag(argv, "--clamav-invoke");
  const clamBin = takeFlag(argv, "--clamscan-bin") ?? "clamscan";
  const clamTimeout = takeInt(argv, "--clamav-timeout", 3600);
  const wdQuick = hasFlag(argv, "--windows-defender-quick-scan");
  const wdTimeout = takeInt(argv, "--wd-timeout", 7200);

  let roots: string[];
  if (rootsArg.length > 0) {
    roots = rootsArg.map(expandRoot).filter((x): x is string => x !== null);
  } else {
    const home = os.homedir();
    roots = home && fs.existsSync(home) ? [path.resolve(home)] : [];
  }
  if (roots.length === 0) {
    process.stderr.write("No valid roots after expansion.\n");
    return 2;
  }

  process.stderr.write(
    `aureon device_health_scan: roots=${JSON.stringify(roots)} max_files=${maxFiles}\n`
  );

  const { files, dirBytes, errors, capped } = collectInventory(
    roots,
    maxFiles,
    skipGit,
    skipNm
  );

  const largestFiles = [...files].sort((a, b) => b.size - a.size).slice(0, topFiles);
  const hottestDirs = [...dirBytes.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, topDirs);

  const now = Date.now() / 1000;
  let staleRows: ReturnType<typeof staleCandidates> = [];
  if (staleDays > 0) {
    staleRows = staleCandidates(files, staleDays, staleBy === "atime", now);
  }

  let clamRep: Record<string, unknown> | null = null;
  if (clamRoot) {
    const tgt = path.resolve(path.normalize(clamRoot.replace(/^~(?=$|[\\/])/, os.homedir())));
    if (fs.existsSync(tgt)) {
      clamRep = runClam(tgt, clamTimeout, clamBin);
    } else {
      clamRep = { ok: false, error: `missing clamav root ${tgt}` };
    }
  }

  let wdRep: Record<string, unknown> | null = null;
  if (wdQuick) {
    wdRep = runWindowsDefenderQuick(wdTimeout);
  }

  const report = {
    schema: "aureon.device_health_scan.v1",
    utc: new Date().toISOString(),
    platform: `${os.platform()} ${os.release()}`,
    roots,
    hit_file_cap: capped,
    files_scanned: files.length,
    errors_sample: errors.slice(0, 120),
    error_count: errors.length,
    largest_files: largestFiles,
    largest_dirs: hottestDirs.map(([k, v]) => ({ path: k, bytes: v })),
    stale_cutoff_days: staleDays > 0 ? staleDays : null,
    stale_by: staleDays > 0 ? staleBy : null,
    stale_candidates_count: staleRows.length,
    stale_sample: staleRows.slice(0, 200),
    clamav_optional: clamRep,
    windows_defender_optional: wdRep,
    posture_hints: postureHints(),
    limitations: [
      "Does NOT detect all malicious code — heuristic + signature engines live in antivirus/MDR stacks.",
      "Access-time 'staleness' is meaningless on many Linux/macOS relatime installs — default to mtime for planning migrations.",
      "Permission denied on system paths is normal without elevation — rerun scoped roots if noisy.",
      "Cloud placeholder / dedup files may distort observed size.",
      "This tool never quarantines, deletes, or remediates — human or EDR workflow required.",
    ],
  };

  if (jsonOut) {
    process.stdout.write(JSON.stringify(report, null, 2) + "\n");
  } else {
    process.stdout.write("=== Aureon device health (READ-ONLY enumerator) ===\n");
    process.stdout.write(`Files enumerated: ${files.length}  hit_cap=${capped}\n`);
    process.stdout.write("\n-- Largest files --\n");
    for (const f of largestFiles.slice(0, 20)) {
      process.stdout.write(`${String(f.size).padStart(13)}  ${f.path}\n`);
    }
    process.stdout.write("\n-- Heaviest directories --\n");
    for (const [p, nbytes] of hottestDirs.slice(0, 20)) {
      process.stdout.write(`${String(nbytes).padStart(13)}  ${p}\n`);
    }
    if (staleRows.length > 0) {
      process.stdout.write(
        `\n-- Oldest ${staleBy} cohort (≥ ${staleDays}d) sample (${staleRows.length} rows) --\n`
      );
      for (const row of staleRows.slice(0, 20)) {
        process.stdout.write(`${new Date(row.stamp_sec * 1000).toISOString()}  ${row.path}\n`);
      }
    }
    if (clamRep) {
      process.stdout.write("\n-- ClamAV (optional external engine) --\n");
      process.stdout.write(JSON.stringify(clamRep, null, 2).slice(0, 8000) + "\n");
    }
    if (wdRep) {
      process.stdout.write("\n-- Windows Defender quick hook (optional) --\n");
      process.stdout.write(JSON.stringify(wdRep, null, 2).slice(0, 4000) + "\n");
    }
    process.stdout.write("\n-- Posture reminders --\n");
    for (const h of report.posture_hints) {
      process.stdout.write(`• ${h}\n`);
    }
    process.stdout.write("\n-- Limits / honesty clause --\n");
    for (const L of report.limitations) {
      process.stdout.write(`• ${L}\n`);
    }
  }

  return capped ? 3 : 0;
}
