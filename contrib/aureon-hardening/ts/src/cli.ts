#!/usr/bin/env node
/**
 * Aureon tooling entrypoint (strict TypeScript, Node 18+).
 *
 * Commands:
 *   node dist/cli.js audit [CONFIG.ovpn ...]   # stdin when no paths
 *   node dist/cli.js health --ack-readonly-inventory ...
 *   node dist/cli.js phase2 <subcommand> ...
 */

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { auditText, worstExitFromFindings } from "./auditOvpnConfig.js";
import { runDeviceHealthScan } from "./deviceHealthScan.js";
import { runPhase2 } from "./phase2.js";

function printHelp(): void {
  process.stderr.write(`aureon-ts (strict TypeScript)
  audit [files...]
  health --ack-readonly-inventory [--roots PATH...] [--json] ...
  phase2 wifi|metrics|dns-probe|... (parity with contrib/aureon-hardening Python tools)
`);
}

function main(): number {
  const argv = process.argv.slice(2);
  const cmd = argv[0];

  if (!cmd || cmd === "--help" || cmd === "-h") {
    printHelp();
    return cmd ? 0 : 2;
  }

  if (cmd === "audit") {
    const paths = argv.slice(1).filter((a) => !a.startsWith("-"));
    const blobs: Array<{ label: string; text: string }> = [];
    if (paths.length === 0) {
      blobs.push({ label: "stdin", text: fs.readFileSync(0, "utf8") });
    } else {
      for (const p of paths) {
        const abs = path.resolve(p);
        let st: fs.Stats;
        try {
          st = fs.statSync(abs);
        } catch {
          process.stderr.write(`skip (cannot stat): ${abs}\n`);
          continue;
        }
        if (!st.isFile()) {
          process.stderr.write(`skip (not a regular file): ${abs}\n`);
          continue;
        }
        blobs.push({
          label: abs,
          text: fs.readFileSync(abs, { encoding: "utf8", flag: "r" }),
        });
      }
    }
    let worst = 0;
    let hadOutput = false;
    for (const { label, text } of blobs) {
      const hits = auditText(text);
      if (!hits.length) {
        process.stderr.write(`=== ${label}: OK (heuristic sweep) ===\n`);
        continue;
      }
      hadOutput = true;
      worst = Math.max(worst, worstExitFromFindings(hits));
      process.stderr.write(`=== ${label}: ${hits.length} finding(s) ===\n`);
      for (const h of hits) {
        const loc = `line ${h.line ?? "?"}`;
        process.stderr.write(`[${h.severity}] ${loc}: ${h.message}\n`);
      }
    }
    if (!hadOutput && paths.length === 0) {
      process.stderr.write("stdin was empty — nothing to audit\n");
    }
    return worst;
  }

  if (cmd === "health") {
    return runDeviceHealthScan(argv.slice(1));
  }

  if (cmd === "phase2") {
    return runPhase2(argv.slice(1));
  }

  printHelp();
  process.stderr.write(`unknown command: ${cmd}\n`);
  return 2;
}

process.exitCode = main();
