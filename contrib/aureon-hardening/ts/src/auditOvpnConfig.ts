/**
 * Heuristic OpenVPN configuration auditor — mirrors audit_ovpn_config.py (stdlib-parity logic).
 */

export type Severity = "CRITICAL" | "WARNING" | "INFO";

export interface Finding {
  severity: Severity;
  line: number | null;
  message: string;
}

function iterDirectives(text: string): Array<{ line: number; low: string }> {
  const out: Array<{ line: number; low: string }> = [];
  const lines = text.split(/\r?\n/);
  for (let lineno = 1; lineno <= lines.length; lineno++) {
    let line = lines[lineno - 1]!.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    let merged = "";
    let escaped = false;
    for (const ch of line) {
      if (escaped) {
        merged += ch;
        escaped = false;
        continue;
      }
      if (ch === "\\") {
        escaped = true;
        continue;
      }
      if (ch === "#") break;
      merged += ch;
    }
    merged = merged.trim().toLowerCase();
    if (merged) out.push({ line: lineno, low: merged });
  }
  return out;
}

const RULES_INLINE: Array<{ severity: Severity; rx: RegExp; message: string }> = [
  {
    severity: "CRITICAL",
    rx: /^\s*tls-version-min\s+(1\.0|1\.1)\b/,
    message:
      "tls-version-min permits TLS 1.0 or 1.1 — use tls-version-min 1.2 (or newer policy floor)",
  },
  {
    severity: "WARNING",
    rx: /^\s*verify-client-cert\s+none\b/,
    message:
      "verify-client-cert none — mutual TLS weakened; unacceptable for PKI-strong profiles",
  },
  {
    severity: "WARNING",
    rx: /\bauth\s+none\b/,
    message: "auth none disables data-channel auth tag usage — rarely appropriate",
  },
  {
    severity: "WARNING",
    rx: /^\s*client-cert-not-required\b/,
    message:
      "server allows sessions without client certificates — document compensating identity controls",
  },
  {
    severity: "WARNING",
    rx: /^\s*cipher\b.*\bbf-cbc\b/,
    message: "BF-CBC obsolete — migrate to negotiated AEAD (data-ciphers)",
  },
  {
    severity: "WARNING",
    rx: /^\s*cipher\b.*\b(des|cast5|idea)-/,
    message:
      "Legacy symmetric cipher directive — prefer AES-GCM / ChaCha20-Poly1305 class AEAD",
  },
  {
    severity: "WARNING",
    rx: /^\s*comp-lzo\b/,
    message:
      "comp-lzo is obsolete; remove unless isolated legacy enclave — see project guidance",
  },
];

function checkManagement(low: string, lineno: number): Finding[] {
  if (!low.startsWith("management ")) return [];
  const tokens = low.split(/\s+/).filter(Boolean);
  if (tokens.includes("unix")) return [];
  const bind = tokens[1] ?? "";
  if (bind === "127.0.0.1" || bind === "::1" || bind === "localhost") return [];
  if (bind === "tunnel") return [];
  return [
    {
      severity: "WARNING",
      line: lineno,
      message:
        "management appears network-bound — prefer unix socket / loopback plus password file",
    },
  ];
}

function checkDuplicateCn(low: string, lineno: number): Finding[] {
  if (/^\s*duplicate-cn\b/.test(low)) {
    return [
      {
        severity: "INFO",
        line: lineno,
        message:
          "duplicate-cn allows simultaneous sessions that share canonical cert identity — reconcile with accounting/policy",
      },
    ];
  }
  return [];
}

function checkTlsSecret(low: string, lineno: number): Finding[] {
  if (/^\s*(secret|tls-auth|tls-crypt)\b/.test(low)) {
    return [
      {
        severity: "INFO",
        line: lineno,
        message:
          "Static symmetric key material (tls-auth/tls-crypt/secret) — rotate using controlled procedure if disclosed",
      },
    ];
  }
  return [];
}

export function auditText(text: string): Finding[] {
  const findings: Finding[] = [];
  const rank: Record<string, number> = { CRITICAL: 4, WARNING: 3, INFO: 1 };
  for (const { line: lineno, low } of iterDirectives(text)) {
    for (const { severity, rx, message } of RULES_INLINE) {
      if (rx.test(low)) {
        findings.push({ severity, line: lineno, message });
        break;
      }
    }
    findings.push(...checkManagement(low, lineno));
    findings.push(...checkDuplicateCn(low, lineno));
    findings.push(...checkTlsSecret(low, lineno));
  }
  findings.sort(
    (a, b) =>
      (rank[b.severity] ?? 0) - (rank[a.severity] ?? 0) ||
      (a.line ?? 0) - (b.line ?? 0)
  );
  return findings;
}

export function worstExitFromFindings(findings: Finding[]): number {
  let worst = 0;
  for (const h of findings) {
    if (h.severity === "CRITICAL") worst = Math.max(worst, 2);
    else if (h.severity === "WARNING" && worst < 2) worst = Math.max(worst, 1);
  }
  return worst;
}
