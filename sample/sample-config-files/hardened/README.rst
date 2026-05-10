===============================================================================
 Hardened configuration fragments (baseline)
===============================================================================

These files are **not** drop-in turnkey VPNs — they omit ``ca``, ``cert``,
``key``, ``dh``/``ecdhe``, topology, routing, firewall, PKI issuance, CRL/OCSP,
and revocation automation.

Merge selectively after:

* surveying local cipher/group support (``openvpn --show-*``),

* approving policy with your security / compliance stakeholders,

* reading ``contrib/aureon-hardening/GUIDE.rst``.
