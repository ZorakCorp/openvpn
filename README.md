<div align="center">

# House of Asher × OpenVPN

**Hardened OpenVPN lineage · security-first defaults · Aureon posture pack**

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](./COPYING)
[![Upstream](https://img.shields.io/badge/upstream-OpenVPN-2b3137?logo=openvpn)](https://github.com/OpenVPN/openvpn)

*Engineering brand: **House of Asher** · Repository: **[ZorakCorp/openvpn](https://github.com/ZorakCorp/openvpn)***

</div>

---

This repository is **not** the official OpenVPN Inc. release tree. It tracks upstream **OpenVPN** with **House of Asher** security hardening: sample/script fixes, operational guidance, configuration fragments, and CI least-privilege defaults—packaged for teams that want a **disciplined VPN baseline** without pretending a marketing label replaces formal assurance.

| Pillar | What you get |
|--------|----------------|
| **Integrity** | Audited script surfaces (Python/shell/Perl demos), safer temp handling, stricter auth logic in samples |
| **Posture** | [`contrib/aureon-hardening/GUIDE.rst`](./contrib/aureon-hardening/GUIDE.rst) — architecture, crypto floors, management plane, IR, supply chain |
| **Verification** | [`contrib/aureon-hardening/audit_ovpn_config.py`](./contrib/aureon-hardening/audit_ovpn_config.py) — stdlib heuristic config sweep |
| **Endpoint posture** | [`contrib/aureon-hardening/device_health_scan.py`](./contrib/aureon-hardening/device_health_scan.py) — READ-ONLY storage/staleness audit (not AV) |
| **Guided remediation** | [`contrib/aureon-hardening/device_remediate_phase2.py`](./contrib/aureon-hardening/device_remediate_phase2.py) — DNS/ARP/traceroute, disk bench, **dupes** + **cleanup** + **Appx** + **flatpak** manifests, optional **SHA‑256** gate + **audit JSONL**, Tkinter cockpit |
| **Doctor & handoff** | [`contrib/aureon-hardening/aureon_doctor.py`](./contrib/aureon-hardening/aureon_doctor.py) (chained probes) · [`export_audit_bundle.py`](./contrib/aureon-hardening/export_audit_bundle.py) (zip + manifest) |
| **Fragments** | [`sample/sample-config-files/hardened/`](./sample/sample-config-files/hardened/) — merge-after-policy TLS/client-server baselines |

---

## Quick build (Unix)

```sh
tar -xf openvpn-<version>.tar.gz
cd openvpn-<version>
./configure
make
sudo make install
```

Windows (CMake / MSVC / MinGW): see [**README.cmake.md**](./README.cmake.md).

Full install detail: [**INSTALL**](./INSTALL).

---

## Documentation map

| Doc | Topic |
|-----|--------|
| [openvpn.net/man](http://openvpn.net/man.html) | Upstream manual |
| [openvpn.net/howto](http://openvpn.net/howto.html) | HOWTO |
| [README.cmake.md](./README.cmake.md) | Windows / CMake builds |
| [contrib/aureon-hardening/GUIDE.rst](./contrib/aureon-hardening/GUIDE.rst) | High-assurance **operational** baseline (policy + layering) |

---

## Upstream & license

Copyright © 2002-2026 **OpenVPN Inc.** This program is free software under the [**GNU General Public License v2**](./COPYING).

- Upstream releases: [openvpn.net/community-downloads](https://openvpn.net/community-downloads/)
- Upstream sources: [github.com/OpenVPN/openvpn](https://github.com/OpenVPN/openvpn)
- Report vulnerabilities in **upstream**: follow OpenVPN’s published security process.
- Issues for **this fork**: [github.com/ZorakCorp/openvpn/issues](https://github.com/ZorakCorp/openvpn/issues)

Companion projects maintained upstream: [**easy-rsa**](https://github.com/OpenVPN/easy-rsa) · [**tap-windows6**](https://github.com/OpenVPN/tap-windows6) · [**openvpn-build**](https://github.com/OpenVPN/openvpn-build)

---

## House of Asher ethos

Defense is **layers + evidence**: named assurance targets (where applicable), threat-aware configuration, observable failure, least privilege—including automation tokens—not slogans instead of audits.

—

*Maintained for **House of Asher** · [ZorakCorp](https://github.com/ZorakCorp) · OpenVPN is a trademark of OpenVPN Inc.*
