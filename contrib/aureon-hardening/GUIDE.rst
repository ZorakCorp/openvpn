===============================================================================
 High-assurance OpenVPN deployment (Aureon-oriented operational guide)
===============================================================================

.. note::

   This document does **not** certify software as "military grade" or
   "intelligence-grade." Those outcomes require a **defined assurance target**
   (e.g. national or sector profile), **independent assessment**, and **ongoing
   operations**. The goal here is a **repeatable engineering baseline**: threat
   awareness, layered controls, observability, and verification.

-------------------------------------------------------------------------------
1. Name the bar (assurance & compliance)
-------------------------------------------------------------------------------

Choose an explicit standard or profile you can audit against, for example:

* `NIST SP 800-53 <https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final>`_ (control families + baselines).

* NIAP / `Common Criteria <https://www.commoncriteriaportal.org/>`_ protection profiles where product claims matter.

* Sector-specific overlays (finance, healthcare, defence ICT) layered on TLS,
  VPN, PKI, and incident-response policies internal to your organisation.

Document **security objectives**, **assets**, **adversaries**, and **Residual
risk** acceptance in your security case.

-------------------------------------------------------------------------------
2. Threat modeling (architecture boundary)
-------------------------------------------------------------------------------

Apply STRIDE-style analysis on at least:

* **Wire path** — MITM before session establishment; rogue DHCP/DNS on client LAN.

* **PKI trust** — stolen CA key, sloppy CRL/OCSP, long-lived certs, shared keys.

* **Management plane** — ``--management`` over TCP exposed beyond localhost;
  scripted automation without authentication.

* **Script / plugin surface** — ``--up``/``--down``, ``dns-updown`` helpers,
  custom auth backends: treat environment and temp files as **untrusted-ish**
  boundaries; smallest helpers; no shell injection; timeouts on outbound calls.

* **Post-connect lateral movement** — flat ``tun`` networks; unrestricted
  client-to-client traffic.

-------------------------------------------------------------------------------
3. Cryptography configuration (control channel & data channel)
-------------------------------------------------------------------------------

Prefer **negotiated modern AEAD** on the data channel and **TLS ≥ 1.2** minimum
(control channel defaults improve over time — **pin floors explicitly**).

* See ``tls-version-min``, ``tls-ciphersuites``, ``tls-ciphers``, ``data-ciphers``,
  ``data-ciphers-fallback``, and ``tls-groups`` in ``doc/man-sections/tls-options.rst``.

* **Do not** reintroduce legacy ``comp-lzo`` or obsolete ``--cipher BF-CBC``-style
  defaults unless you operate a segregated compatibility enclave **and**
  compensate with monitoring and segmentation.

Sample **directive fragments** (adjust to library capabilities and cipher
survey output from ``openvpn --show-*``)::


  tls-version-min 1.2
  tls-ciphersuites TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256

  ; Data channel AEAD negotiation (colon-separated preference order)
  data-ciphers AES-256-GCM:CHACHA20-POLY1305:AES-128-GCM

Certificates:

* Prefer **hardware-backed keys** or **offline / HSM** sub-CA where policy requires.

* Short **notAfter** horizons, disciplined **renewal**, **mandatory revocation**
  path testing (push CRL refresh, OCSP stapling posture per your TLS stack).


-------------------------------------------------------------------------------
4. Network & tenancy segmentation
-------------------------------------------------------------------------------

* Isolate VPN clients into **VLANs / VRF / cloud security groups**, not one
  unrestricted broadcast domain.

* Use ``--topology subnet`` versus legacy ``net30`` consciously; document DHCP
  and routing interactions.

* Where policy demands, disable or tightly filter **client-to-client** relay on
  the server.

-------------------------------------------------------------------------------
5. Management interface & observability (Aureon defaults)
-------------------------------------------------------------------------------

Treat ``management`` like an **authenticated API**:

* Prefer **unix socket + password file** locally; bind TCP only to loopback **and**
  authenticate (see warnings in ``doc/man-sections/management-options.rst``).

Do **not** expose management to the wild internet without defence in depth (
mTLS + allowlists + rate limits + anomaly detection).


**Logs & correlation**

• Structured syslog / JSON where possible; ship to central SIEM.

• Correlate TLS handshakes with account / device identity from your IAM.

• Preserve integrity (append-only storage, tamper-evident archiving) where
  regulations require forensic-grade retention.


-------------------------------------------------------------------------------
6. Incident response playbooks (operational realism)
-------------------------------------------------------------------------------

Pre-write runbooks covering at least:

* **Sub-CA compromise** — mass re-issue vs burn-and-rebuild; CRL size / OCSP spike.

* **Single client credential theft** — per-device revocation blast radius.

* **Suspected plaintext SSO / cleartext side-channel leaks** — session reset,
  key rotation intervals.

Quarterly tabletop exercises beat shelf-ware templates.

-------------------------------------------------------------------------------
7. Supply chain & CI integrity (build & release)
-------------------------------------------------------------------------------

Upstream OpenVPN relies on reproducible-ish autotools/cmake flows; tighten **your**
consumption perimeter:

• Verifying **tarball signatures**, **commits/tags**, pinning dependencies.

• Generating/publishing **SBOM** artefacts for binaries you distribute.

• **Least-privilege CI tokens**: default read-only scopes; escalate only jobs
  that deploy.

• Periodic **dependency & static analysis** (Coverity-class, sanitizers).


-------------------------------------------------------------------------------
8. Automated configuration review (repository helper)
-------------------------------------------------------------------------------

Run::

  python3 contrib/aureon-hardening/audit_ovpn_config.py path/to/site.ovpn ...

The auditor is **heuristic**: it catches common foot-guns but **never** replaces
peer review or formal verification.

-------------------------------------------------------------------------------
9. SSO HTTP demo uplift (repository sample)
-------------------------------------------------------------------------------

Plaintext HTTP SSO is **demo only**. Prefer:

* Reverse proxy enforcing **HTTPS** terminating with modern TLS at the boundary; **or**

* ``http-server.py --tls-cert ... --tls-key ...`` (**Python 3 stdlib**) for lab
  testing with issuance procedures you control.

Never ship self-signed verifier-disable patterns to browsers in production IAM
paths.

-------------------------------------------------------------------------------
10. Endpoint inventory scanner (explicit consent, READ-ONLY)
-------------------------------------------------------------------------------

Commercial security stacks combine **drivers**, **signatures**, **behaviour rules**,
telemetry, cloud reputation, **quarantine/remediation workflows**, SOAR playbooks—and
often managed SOC review. ``device_health_scan.py`` is deliberately **narrow**:

* authorised **explicit consent flag** (--ack-readonly-inventory),

* bounded file walk with **deterministic summaries**,

* **no covert upload** of filenames or payloads—only stdout/stderr you choose to save,

* **optional** invocation of vendor tools you installed (``clamscan``) or documented
  Windows Defender hooks—with clear labelling inside the emitted JSON/report.

* optional **``--run-id``** / **``--host-label``** / **``--tenant``** fields embedded as **``report_meta``**
  in ``--json`` output for pipeline correlation.

::

  python3 contrib/aureon-hardening/device_health_scan.py --ack-readonly-inventory \\
        --roots "$HOME/Documents" \\
        --stale-days 730 --stale-by mtime \\
        --json > host-inventory-$(date -u +%Y%m%dT%H%MZ).json


Never treat this enumerator as antivirus. Feed findings into **authorised EDR/AV**
workstreams and organisational change-management—especially before deleting or moving
bulk data surfaced as "cold."

-------------------------------------------------------------------------------
11. Phase-2 guided remediation (destructive only with manifest + ack)
-------------------------------------------------------------------------------

``device_remediate_phase2.py`` extends the House of Asher / Aureon endpoint suite with
**inventory + optional remediation** that still refuses naïve single-click wipe behaviour.

**Read-oriented / low risk subcommands**

* ``wifi`` · ``metrics`` — radio / host quick views (see inline honesty strings).
* ``dns-probe`` — ``nslookup`` (Windows) / ``dig`` (Unix) latency snapshot.
* ``trace-lite TARGET`` — shortened ``tracert``/``traceroute``/``tracepath`` hop view.
* ``arp-snapshot`` — ARP / neighbour cache export (not spoofing detection).
* ``browser-cache-scan`` — estimates cache directory weight (capped walk).
* ``startup-inventory`` (Windows) · ``systemd-user-hints`` (Linux) — autorun context.
* ``battery-report --out`` — Windows ``powercfg`` HTML report.
* ``manifest-sha256 FILE`` — CI / policy digest hook for signed-off JSON.

**Consent-gated IO bench**

* ``disk-bench`` — sequential read/write MB/s inside **your** directory; needs
  ``--execute-ack EXECUTE_PHASE2_DISK_BENCH``.

**Manifest pipelines (defaults ``approved:false`` everywhere)**

* ``cleanup-plan`` / ``cleanup-apply`` — large file removal (``EXECUTE_PHASE2_DELETE``).
* ``dupes-plan`` / ``dupes-apply`` — hashed duplicate cohorts (``EXECUTE_PHASE2_DELETE_DUPES``).
* ``apps-plan`` / ``apps-apply`` — Windows Appx removal (``EXECUTE_PHASE2_UNINSTALL_APPX``).
* ``flatpak-plan`` / ``flatpak-apply`` — Linux flatpak removal (``EXECUTE_PHASE2_FLATPAK_RM``).

Optional **``--manifest-sha256``** on every destructive apply compares the on-disk JSON
before execution. Optional **``--audit-log PATH``** appends JSON-lines for accountability
(forward with your SIEM/agent if policy demands). Each JSONL line is lexicographically key-sorted
with a leading **``utc``** field; optional **``--run-id``**, **``--host-label``**, and **``--tenant``**
are merged into emitted JSON as **``report_meta``** / audit context for correlation.

**Apply dry-runs**

Destructive applies accept **``--dry-run``**: manifest + acknowledgement are still required; the
tool prints ``[dry-run]`` actions and appends JSONL ``would_*`` rows without deleting or uninstalling.

**Windows task scheduler (lightweight)**

* ``tasks-snapshot`` — ``schtasks /query /fo CSV`` (truncated)—complements ``startup-inventory``.

**Tkinter cockpit**

* ``gui`` — surfaces Wi-Fi, DNS, ARP, traceroute-lite, caches, Windows startup JSON,
  plus plan/apply stubs (typed token still enforced on apply).

Operational rule: there is **still** no faithful replacement for commercial EDR—you are
accountable for manifest contents, ``allowed_roots`` scoping, backups, and organisational
change control.

::

  python3 contrib/aureon-hardening/device_remediate_phase2.py metrics
  python3 contrib/aureon-hardening/device_remediate_phase2.py dns-probe --query openvpn.net
  python3 contrib/aureon-hardening/device_remediate_phase2.py trace-lite one.one.one.one
  python3 contrib/aureon-hardening/device_remediate_phase2.py gui

-------------------------------------------------------------------------------
12. Orchestration / handoff artefacts
-------------------------------------------------------------------------------

**Doctor bundle (read-heavy chain)**

Run ``aureon_doctor.py`` to execute Wi-Fi sweep, metrics, DNS probe, optional ``audit_ovpn_config.py``
against supplied ``.ovpn`` paths, plus ``device_health_scan.py`` when you pass explicit inventory
consent::

  python3 contrib/aureon-hardening/aureon_doctor.py --ack-readonly-inventory \\
        --configs path/to/site.ovpn --strict --json > doctor-bundle.json

``--strict`` exits non-zero if any probe subprocess returned an error — omit it for exploratory runs.

**JSONL retention (``--audit-log``)**

Treat audit logs as tier-1 artefacts: immutable storage or WORM-equivalent bucket, predictable
maximum line length, ingest-time SHA-256 of each file chunk in your downstream logging stack, and a
published retention/disposal schedule mapped to organisational policy (these scripts never auto-delete
logs).

**Handoff ZIP**

Package JSON reports plus redacted artefacts using ``export_audit_bundle.py``::

  python3 contrib/aureon-hardening/export_audit_bundle.py --out aureon-handoff.zip r1.json r2.jsonl

``device_health_scan`` JSON emits the same optional **``report_meta``** correlation envelope at the top
level (**``emitter``**, **``run_id``**, …).

-------------------------------------------------------------------------------
13. References inside this tree
-------------------------------------------------------------------------------

* ``sample/sample-config-files/hardened/server.fragment``

* ``sample/sample-config-files/hardened/client.fragment``

* ``doc/man-sections/tls-options.rst``

* ``doc/man-sections/management-options.rst``

* ``doc/man-sections/script-options.rst``

