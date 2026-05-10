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
10. References inside this tree
-------------------------------------------------------------------------------

* ``sample/sample-config-files/hardened/server.fragment``

* ``sample/sample-config-files/hardened/client.fragment``

* ``doc/man-sections/tls-options.rst``

* ``doc/man-sections/management-options.rst``

* ``doc/man-sections/script-options.rst``

