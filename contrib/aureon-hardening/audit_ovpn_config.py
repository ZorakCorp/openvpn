#!/usr/bin/env python3
"""
Heuristic OpenVPN configuration auditor (stdlib only).

Flags likely misconfigurations; false positives possible — review warnings.
Invocation: audit_ovpn_config.py [CONFIG ...] or stdin with no paths.

Exit codes: 0 = no CRITICAL/WARNING, 1 = WARNING-only, 2 = at least one CRITICAL
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Iterable, Iterator, NamedTuple


class Finding(NamedTuple):
    severity: str
    line: int | None
    message: str


def iter_directives(text: str) -> Iterator[tuple[int, str]]:
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        merged = ""
        escaped = False
        for ch in line:
            if escaped:
                merged += ch
                escaped = False
                continue
            if ch == "\\":
                escaped = True
                continue
            if ch == "#":
                break
            merged += ch
        merged = merged.strip().lower()
        if merged:
            yield lineno, merged


_RULES_INLINE: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "CRITICAL",
        re.compile(r"^\s*tls-version-min\s+(1\.0|1\.1)\b"),
        "tls-version-min permits TLS 1.0 or 1.1 — use tls-version-min 1.2 (or newer policy floor)",
    ),
    (
        "WARNING",
        re.compile(r"^\s*verify-client-cert\s+none\b"),
        "verify-client-cert none — mutual TLS weakened; unacceptable for PKI-strong profiles",
    ),
    (
        "WARNING",
        re.compile(r"\bauth\s+none\b"),
        "auth none disables data-channel auth tag usage — rarely appropriate",
    ),
    (
        "WARNING",
        re.compile(r"^\s*client-cert-not-required\b"),
        "server allows sessions without client certificates — document compensating identity controls",
    ),
    (
        "WARNING",
        re.compile(r"^\s*cipher\b.*\bbf-cbc\b"),
        "BF-CBC obsolete — migrate to negotiated AEAD (data-ciphers)",
    ),
    (
        "WARNING",
        re.compile(r"^\s*cipher\b.*\b(des|cast5|idea)-"),
        "Legacy symmetric cipher directive — prefer AES-GCM / ChaCha20-Poly1305 class AEAD",
    ),
    (
        "WARNING",
        re.compile(r"^\s*comp-lzo\b"),
        "comp-lzo is obsolete; remove unless isolated legacy enclave — see project guidance",
    ),
    (
        "WARNING",
        re.compile(r"^\s*tls-ciphers\s+.+\b(3des|des-|rc4|md5|null|anon)\b"),
        "tls-ciphers lists weak or obsolete patterns — prefer tls-ciphersuites + modern AEAD posture",
    ),
    (
        "WARNING",
        re.compile(
            r"^\s*data-ciphers\s+.+\b(bf-cbc|des-|3des|cast5|rc4|md5)\b"
        ),
        "data-ciphers includes legacy patterns — prefer negotiated AES-GCM / ChaCha20-Poly1305 class AEAD",
    ),
)


def _check_management(low: str, lineno: int) -> Iterable[Finding]:
    if not low.startswith("management "):
        return ()
    tokens = low.split()
    # forms: management <path|IP> <unix|[port]> ... or tunnel client mode
    if "unix" in tokens:
        return ()
    bind = tokens[1] if len(tokens) > 1 else ""
    if bind in ("127.0.0.1", "::1", "localhost"):
        return ()
    if bind == "tunnel":
        return ()
    return (
        Finding(
            "WARNING",
            lineno,
            "management appears network-bound — prefer unix socket / loopback plus password file (see doc/man-sections/management-options.rst)",
        ),
    )


def _check_duplicate_cn(low: str, lineno: int) -> Iterable[Finding]:
    if re.match(r"^\s*duplicate-cn\b", low):
        return (
            Finding(
                "INFO",
                lineno,
                "duplicate-cn allows simultaneous sessions that share canonical cert identity — reconcile with accounting/policy",
            ),
        )
    return ()


def _check_tls_secret(low: str, lineno: int) -> Iterable[Finding]:
    if re.match(r"^\s*(secret|tls-auth|tls-crypt|tls-crypt-v2)\b", low):
        return (
            Finding(
                "INFO",
                lineno,
                "Static symmetric key material (tls-auth/tls-crypt*/secret) — rotate using controlled procedure if disclosed",
            ),
        )
    return ()


def _check_crypto_material_paths(low: str, lineno: int) -> Iterable[Finding]:
    if re.match(
        r"^\s*(ca|cert|key|dh|extra-certs|pkcs12|pkcs15)\s+\S",
        low,
    ):
        return (
            Finding(
                "INFO",
                lineno,
                "Referenced CA/cert/key/material path — verify host filesystem ACLs off-box; this heuristic does not read the path",
            ),
        )
    return ()


PROCESSORS = (
    _check_management,
    _check_duplicate_cn,
    _check_tls_secret,
    _check_crypto_material_paths,
)


def _global_hints(text: str) -> list[Finding]:
    tl = text.lower()
    out: list[Finding] = []
    if ("redirect-gateway" in tl or "route-gateway" in tl) and "block-outside-dns" not in tl:
        out.append(
            Finding(
                "INFO",
                None,
                "redirect-gateway / route-gateway without block-outside-dns — review client DNS leak posture against policy",
            )
        )
    return out


def audit_text(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, low in iter_directives(text):
        for severity, rx, msg in _RULES_INLINE:
            if rx.match(low):
                findings.append(Finding(severity, lineno, msg))
                break
        for proc in PROCESSORS:
            findings.extend(proc(low, lineno))
    findings.extend(_global_hints(text))
    findings.sort(
        key=lambda f: (-{"CRITICAL": 4, "WARNING": 3, "INFO": 1}.get(f.severity, 0), f.line or 0)
    )
    return findings


def main(argv: list[str]) -> int:
    paths = argv[1:]
    blobs: list[tuple[str, str]] = []
    if not paths:
        blobs.append(("stdin", sys.stdin.read()))
    else:
        for p in paths:
            path = Path(p)
            if not path.is_file():
                print(f"skip (not a regular file): {path}", file=sys.stderr)
                continue
            blobs.append((str(path), path.read_text(encoding="utf-8", errors="replace")))

    worst = 0
    had_output = False
    for label, txt in blobs:
        hits = audit_text(txt)
        if not hits:
            print(f"=== {label}: OK (heuristic sweep) ===", file=sys.stderr)
            continue
        had_output = True
        print(f"=== {label}: {len(hits)} finding(s) ===", file=sys.stderr)
        for h in hits:
            loc = f"line {h.line}"
            print(f"[{h.severity}] {loc}: {h.message}", file=sys.stderr)
            if h.severity == "CRITICAL":
                worst = max(worst, 2)
            elif h.severity == "WARNING" and worst < 2:
                worst = max(worst, 1)

    if not had_output and not paths:
        print("stdin was empty — nothing to audit", file=sys.stderr)
    return worst


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
