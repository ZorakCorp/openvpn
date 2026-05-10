#!/usr/bin/env python3
"""HTTP(S) client for SSO demo — reads session id from plugin temp file."""

import argparse
import os
import re
import ssl
import sys
from http.client import HTTPSConnection

try:
    from http.client import HTTPConnection
except ImportError:  # pragma: no cover
    HTTPConnection = None

_SESSION_KEY_RE = re.compile(r"^[0-9a-fA-F]{8,512}$")


def main():
    p = argparse.ArgumentParser(description="OpenVPN SSO demo HTTP(S) client.")
    p.add_argument(
        "--session-file",
        default=os.environ.get(
            "KV_HTTP_SESSION_FILE", "/tmp/openvpn_sso_user"
        ),
        help="Path to file containing SSO session identifier (newline stripped).",
    )
    default_host = os.environ.get("KV_HTTP_HOST", "10.8.0.1")
    default_port = int(os.environ.get("KV_HTTP_PORT", "8080"))
    p.add_argument("--host", default=default_host, help="HTTP server host/IP.")
    p.add_argument("--port", type=int, default=default_port, help="HTTP server TCP port.")
    p.add_argument(
        "--https",
        action="store_true",
        help="Use HTTPS (recommended with http-server.py --tls-cert)",
    )
    p.add_argument(
        "--cafile",
        metavar="PEMFILE",
        help="CA bundle to verify server certificate (HTTPS)",
    )
    p.add_argument(
        "--insecure-lab-only",
        action="store_true",
        help="Disable certificate verification — unsafe except controlled lab setups",
    )
    args = p.parse_args()
    if args.https and not args.cafile and not args.insecure_lab_only:
        sys.exit(
            "HTTPS requires --cafile or --insecure-lab-only (explicit opt-in)"
        )

    try:
        with open(args.session_file, encoding="utf-8") as myfile:
            session_key = myfile.read().strip()
    except OSError as e:
        sys.exit(f"cannot read session file {args.session_file}: {e}")

    if not session_key:
        sys.exit("session file empty")
    if not _SESSION_KEY_RE.fullmatch(session_key):
        sys.exit("session identifier has unexpected format")

    timeout = float(os.environ.get("KV_HTTP_TIMEOUT", "30"))
    path = "/" + session_key

    try:
        if args.https:
            if args.insecure_lab_only:
                sys.stderr.write(
                    "WARNING: TLS verification disabled — never use --insecure-lab-only in production\n"
                )
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            else:
                ctx = ssl.create_default_context(cafile=args.cafile)
            conn = HTTPSConnection(args.host, args.port, context=ctx, timeout=timeout)
        else:
            conn = HTTPConnection(args.host, args.port, timeout=timeout)

        conn.request("GET", path)
        r1 = conn.getresponse()
        body = r1.read()

        if r1.status == 200:
            print(body.decode(errors="replace").strip())
        elif r1.status == 404:
            print("Authentication failed")
        else:
            print(r1.status, r1.reason)
    except OSError as e:
        sys.exit(f"HTTP request failed: {e}")


if __name__ == "__main__":
    main()
