#!/usr/bin/env python3
# RFC 9261-style demo SSO HTTP responder; do not expose to hostile networks — no TLS here.
"""Minimal HTTP handler for OpenVPN keying-material-exporter SSO demo."""

import argparse
import html
import os
import re
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Keys under /tmp/openvpn_sso_<key>; plugin uses long hex-derived identifiers.
_SAFE_SESSION_KEY_RE = re.compile(r"^[0-9a-fA-F]{8,512}$")


class ExampleHTTPRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write(f"{self.address_string()} - {format % args}\n")

    def _session_path(self, raw_path):
        session_key = os.path.basename(raw_path.split("?", 1)[0].strip("/"))
        if not _SAFE_SESSION_KEY_RE.fullmatch(session_key):
            self.send_error(400, "invalid session identifier")
            return None
        return os.path.join("/tmp", f"openvpn_sso_{session_key}")

    def do_GET(self):
        path = self._session_path(self.path)
        if path is None:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                user = fh.read().rstrip("\r\n")
        except OSError:
            self.send_error(404, "authentication failed")
            return

        payload = html.escape(user, quote=True)
        body = (
            "<!DOCTYPE html><html><body><h1>Greetings {}. "
            "You are authorized</h1></body></html>".format(payload)
        )
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)


def run(bind, port, tls_cert=None, tls_key=None):
    server_address = (bind, port)
    httpd = ThreadingHTTPServer(server_address, ExampleHTTPRequestHandler)
    if tls_cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(tls_cert, tls_key or tls_cert)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        sys.stderr.write(
            "SSO demo HTTPS server on https://{}:{}\n".format(bind, port)
        )
        sys.stderr.write(
            "  Use certs you control — browser trust requires proper issuance / pinning.\n"
        )
    else:
        sys.stderr.write(
            "Demo HTTP SSO server on http://{}:{} "
            "(plaintext — use --tls-cert / --tls-key or a reverse-proxy for HTTPS)\n".format(
                bind, port
            )
        )
    httpd.serve_forever()


def main():
    p = argparse.ArgumentParser(description="OpenVPN SSO demo HTTP server.")
    p.add_argument(
        "--bind",
        default=os.environ.get("KV_HTTP_BIND", "0.0.0.0"),
        metavar="ADDRESS",
        help="Listen address (default: 0.0.0.0 or KV_HTTP_BIND). Use 127.0.0.1 for safer local demos.",
    )
    p.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("KV_HTTP_PORT", "8080")),
        metavar="PORT",
        help="Listen TCP port.",
    )
    p.add_argument(
        "--tls-cert",
        metavar="PEMFILE",
        help="If set with --tls-key, wrap listener in TLS v1.2+ (demo / lab)",
    )
    p.add_argument(
        "--tls-key",
        metavar="KEYFILE",
        help="Private key for --tls-cert (omit to reuse cert path for combined PEM)",
    )
    args = p.parse_args()
    if not (1 <= args.port <= 65535):
        sys.exit("invalid port")
    if args.tls_cert and not os.path.isfile(args.tls_cert):
        sys.exit("--tls-cert file missing")
    if args.tls_key and not os.path.isfile(args.tls_key):
        sys.exit("--tls-key file missing")

    try:
        run(args.bind, args.port, args.tls_cert, args.tls_key)
    except KeyboardInterrupt:
        sys.stderr.write("http server stopped\n")


if __name__ == "__main__":
    main()
