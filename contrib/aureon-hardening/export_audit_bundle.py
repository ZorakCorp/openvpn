#!/usr/bin/env python3
"""Zip artefacts with a MANIFEST.json of paths + SHA-256 (stdlib; no upload)."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--out",
        required=True,
        help="Output .zip path",
    )
    p.add_argument(
        "files",
        nargs="+",
        metavar="PATH",
        help="Files (or dirs — skipped unless --include-dirs) to include",
    )
    p.add_argument(
        "--include-dirs",
        action="store_true",
        help="Allow directories (stored as empty entries with note only — prefer flat files)",
    )
    p.add_argument("--note", default="", help="Free-text organisational note embedded in MANIFEST")

    args = p.parse_args()
    out_zip = Path(args.out).expanduser().resolve()

    manifest: dict = {
        "schema": "aureon.audit_bundle.v1",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "note": args.note,
        "members": [],
    }

    arc_names: dict[str, int] = {}

    try:
        with zipfile.ZipFile(
            out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6
        ) as zf:
            for raw in args.files:
                path = Path(raw).expanduser().resolve()
                if not path.exists():
                    sys.stderr.write(f"skip missing: {path}\n")
                    continue
                if path.is_dir():
                    if not args.include_dirs:
                        sys.stderr.write(f"skip directory (pass --include-dirs): {path}\n")
                        continue
                    data = (
                        b"DIR_PLACEHOLDER_NOT_RECURSED: "
                        + str(path).encode("utf-8", errors="replace")
                        + b"\n"
                    )
                    arc = "dir_" + hashlib.sha256(str(path).encode()).hexdigest()[:16] + ".txt"
                    digest = hashlib.sha256(data).hexdigest()
                else:
                    data = path.read_bytes()
                    arc = path.name
                    if arc in arc_names:
                        arc_names[arc] += 1
                        stem = path.stem
                        suf = path.suffix
                        arc = f"{stem}.{arc_names[arc]}{suf}"
                    else:
                        arc_names[arc] = 1
                    digest = hashlib.sha256(data).hexdigest()

                member = {
                    "source_path": str(path),
                    "zip_name": arc,
                    "sha256": digest,
                    "bytes": len(data),
                    "is_dir_marker": path.is_dir(),
                }
                manifest["members"].append(member)
                if path.is_dir():
                    zf.writestr(
                        arc,
                        b"",
                    )
                else:
                    zf.writestr(arc, data)
            zf.writestr(
                "MANIFEST.json",
                json.dumps(manifest, indent=2, sort_keys=True).encode(),
            )

    except OSError as e:
        sys.stderr.write(f"{e}\n")
        return 2

    mh = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    print(f"Wrote {out_zip} members={len(manifest['members'])} manifest_sha256={mh}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
