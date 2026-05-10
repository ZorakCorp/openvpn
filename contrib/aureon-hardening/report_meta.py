"""Shared Aureon structured-report envelope fields (stdlib)."""

from __future__ import annotations

from typing import Any

EMITTER_PAYLOAD_VERSION = 1


def build_report_meta(
    emitter_script: str,
    *,
    run_id: str | None = None,
    host_label: str | None = None,
    tenant: str | None = None,
) -> dict[str, Any]:
    """Fields merged into JSON reports and appended audit JSONL contexts."""
    m: dict[str, Any] = {
        "report_format_version": EMITTER_PAYLOAD_VERSION,
        "emitter": emitter_script,
        "emitter_payload_version": EMITTER_PAYLOAD_VERSION,
    }
    if run_id:
        m["run_id"] = run_id
    if host_label:
        m["host_label"] = host_label
    if tenant:
        m["tenant"] = tenant
    return m
