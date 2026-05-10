from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from audit_ovpn_config import audit_text


def test_tls_11_is_critical() -> None:
    hits = audit_text("tls-version-min 1.1\n")
    assert any(h.severity == "CRITICAL" for h in hits)


def test_redirect_gateway_dns_hint() -> None:
    cfg = "client\ndev tun\nredirect-gateway def1\n"
    hits = audit_text(cfg)
    assert any("block-outside-dns" in h.message for h in hits if h.line is None)


def test_data_ciphers_legacy_warning() -> None:
    hits = audit_text("data-ciphers BF-CBC\n")
    assert any("legacy" in h.message.lower() for h in hits if h.severity == "WARNING")


def test_ca_path_info() -> None:
    hits = audit_text("ca /etc/openvpn/ca.crt\n")
    assert any("ACL" in h.message or "filesystem" in h.message for h in hits)
