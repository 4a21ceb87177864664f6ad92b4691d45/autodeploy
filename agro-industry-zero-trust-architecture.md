# Zero-Trust Network & Security Architecture
## Large-Scale Agro-Industry Enterprise (Linux-Predominant Environment)

**Document type:** Reference architecture
**Scope:** Corporate LAN, DMZ, IoT/SCADA (agro-machinery), Data Center, Local LLM hosting, forensic readiness
**Guiding principle:** Zero Trust — "never trust, always verify," least privilege, explicit verification, assume breach

---

## 1. Network Topology & IP Management

### 1.1 High-Level Segmentation Philosophy

Rather than a flat trusted-LAN model, the architecture is built on **micro-segmentation**: every zone is treated as hostile to every other zone by default, with explicit allow-listed flows enforced at Layer 3/4 (firewall/ACL) and Layer 7 (application-aware inspection) boundaries.

### 1.2 Site Structure

A typical deployment has three site classes:

- **HQ / Data Center site** — core compute, primary security stack
- **Regional agro-processing plants** — SCADA/OT, local corporate LAN, DR/edge compute
- **Remote field sites** (farms, silos, remote sensor clusters) — thin edge, satellite/4G-5G backhaul

### 1.3 RFC 1918 Addressing Plan (example allocation)

| Zone | CIDR (example) | VLAN | Notes |
|---|---|---|---|
| Core Data Center — Compute | 10.10.0.0/22 | 100 | Hypervisor/K8s nodes |
| Core Data Center — Storage/iSCSI | 10.10.4.0/24 | 101 | Isolated storage fabric, no default gateway to internet |
| Core Data Center — OOB/iLO/IPMI | 10.10.5.0/24 | 102 | Management-only, air-gapped from prod VLANs except jump host |
| DMZ — Public-facing services | 10.20.0.0/24 | 200 | Reverse proxies, WAF nodes, external DNS |
| DMZ — Partner/EDI exchange | 10.20.1.0/24 | 201 | B2B feeds (commodity exchanges, logistics partners) |
| Corporate LAN — HQ users | 10.30.0.0/22 | 300-303 | Split by department (Finance, Ops, Agronomy, Exec) |
| Corporate LAN — Print/shared svc | 10.30.8.0/24 | 304 | |
| IoT/SCADA — Field sensors (soil, irrigation, weather) | 10.40.0.0/22 | 400 | Purdue Model Level 0-1 |
| IoT/SCADA — PLC/RTU controllers | 10.40.4.0/23 | 401 | Purdue Level 1-2 |
| IoT/SCADA — HMI / local supervisory | 10.40.8.0/24 | 402 | Purdue Level 2 |
| IoT/SCADA — Historian / MES gateway | 10.40.9.0/24 | 403 | Purdue Level 3, sole bridge to IT |
| LLM/AI Enclave — Inference | 10.50.0.0/24 | 500 | Isolated compute, no direct route to prod DB |
| LLM/AI Enclave — Vector store/RAG cache | 10.50.1.0/24 | 501 | Contains only sanitized/derivative data |
| Guest/BYOD | 10.60.0.0/23 | 600 | Full internet-only, no internal routing |
| Remote sites (per-farm /27 or /28 pools) | 10.70.0.0/16 subnetted per site | 700+ | Aggregated via SD-WAN |

**Design notes:**
- OT (IoT/SCADA) subnetting follows the **Purdue Enterprise Reference Architecture (PERA)**, with the Historian/MES gateway (Level 3) acting as the *only* permitted broker between OT and IT — no direct IT-to-PLC routes ever exist.
- The LLM enclave is deliberately addressed outside both the DMZ and the core Data Center compute range so it can be firewalled as a distinct trust zone (see Section 5).
- No zone is granted a default route to another zone; inter-VLAN routing is only via the firewall's routed interfaces with explicit policy, never via a Layer 3 switch with implicit "permit any inter-vlan."

### 1.4 Segmentation Enforcement

- **East-West:** Next-gen firewalls (NGFW) or Linux-native segmentation (nftables + Calico/Cilium network policies in Kubernetes) enforce inter-VLAN rules. Cilium with eBPF is recommended for the Data Center/K8s layer for identity-aware (not just IP-based) policy.
- **North-South:** Perimeter NGFW pair (active/passive or active/active HA) terminates all external routes.
- **OT/IT boundary:** Unidirectional security gateway (data diode) is strongly recommended for Historian → IT reporting flows where real-time bidirectional control access from IT is not required. Where bidirectional access is unavoidable (e.g., remote diagnostics), it must pass through a jump host with session recording and time-boxed access (see Section 3).

---

## 2. External Security (Perimeter Defense)

### 2.1 Web Application Firewall (WAF)

- Deploy WAF in front of all public-facing services (grower portals, e-commerce/B2B ordering, API gateways) — either as a reverse-proxy appliance (e.g., ModSecurity/Coraza with OWASP Core Rule Set on nginx, or a cloud WAF/CDN) positioned in the DMZ.
- Enforce **positive security model** (allow-list of expected request patterns) for high-value APIs rather than relying solely on signature-based blocking.
- Virtual patching workflow: WAF rules updated within a defined SLA (e.g., 24-48h) whenever a CVE is disclosed affecting in-use software, ahead of the underlying patch being applied.

### 2.2 DDoS Mitigation

- Layered approach:
  - **Volumetric (L3/L4):** Upstream scrubbing via ISP/carrier or cloud DDoS protection service, anycast-based absorption.
  - **Application layer (L7):** Rate limiting, JA3/TLS fingerprinting, bot management at the WAF/CDN tier.
- BGP flowspec or RTBH (remote triggered blackhole) agreements with upstream providers for large-scale volumetric events, particularly relevant given agro-industry seasonal spikes (harvest-time portal traffic, commodity pricing windows) that attackers may target for maximum disruption.

### 2.3 Secure External Access — VPN / ZTNA

Move away from traditional "network-level" VPN (which grants broad LAN access) toward **ZTNA (Zero Trust Network Access)**:

- **Remote employees / HQ staff:** ZTNA broker (identity-aware proxy) grants per-application access after continuous verification of device posture (patch level, disk encryption, EDR presence) + user identity (SSO/MFA via SAML/OIDC) + contextual signals (geo, time, device trust score). No lateral network visibility is granted — user reaches only the specific app/service, not the subnet.
- **Remote/field facilities with legacy needs (e.g., SCADA vendor remote support):** Site-to-site IPsec VPN terminating in a dedicated OT-DMZ segment, never directly into the OT VLAN. All vendor remote-support sessions go through a Privileged Access Management (PAM) jump host with mandatory session recording, and are time-boxed (just-in-time access, auto-expiring credentials).
- MFA is mandatory for all external access paths, phishing-resistant methods (FIDO2/WebAuthn hardware keys) prioritized for privileged/admin accounts over OTP/push where feasible.

---

## 3. Internal Security & Control

### 3.1 Identity & Access

- Central IdP (e.g., Keycloak/self-hosted or enterprise SSO) issuing short-lived tokens; all internal service-to-service auth uses mTLS with a private CA (SPIFFE/SPIRE recommended for workload identity in the Data Center).
- **RBAC/ABAC everywhere**: role assignments tied to job function (Agronomist, Plant Operator, Finance, IT Admin), with attribute-based conditions (device compliance, location, time-of-day) layered on top for sensitive systems.
- Privileged accounts are separate from daily-use accounts (no standing admin rights on personal logins); PAM solution (e.g., open-source Teleport, or commercial equivalent) brokers all SSH/RDP/DB admin sessions with recording and approval workflows.

### 3.2 Lateral Movement Prevention

- **Micro-segmentation** as described in Section 1 is the primary control.
- Host-based controls: default-deny outbound on servers (egress filtering) so a compromised host cannot freely reach C2 infrastructure or exfiltrate to arbitrary destinations.
- **No flat "server admin" credential reuse** — enforce unique local admin/root credentials per host via a credential vault (e.g., HashiCorp Vault, CyberArk) with automatic rotation; eliminates pass-the-hash style lateral movement.
- Disable/restrict SMB, RDP, and other lateral-movement-favored protocols between workstation VLANs; corporate LAN workstations cannot talk to each other directly (peer isolation / "client isolation" at the switch/VLAN level) except through server-mediated services.
- Kubernetes/container layer: enforce NetworkPolicies default-deny, Pod Security Standards (restricted profile), and image provenance (signed images only, admission controller enforcement via e.g. Kyverno/OPA Gatekeeper).

### 3.3 Network Monitoring

- **NDR (Network Detection & Response):** Full east-west traffic visibility via mirrored ports/taps at core switches feeding a network sensor (e.g., Zeek/Suricata-based) for protocol-aware anomaly detection — essential for catching lateral movement that stays "under" endpoint EDR visibility.
- **NetFlow/IPFIX** collection from all core/distribution switches into the SIEM for baseline traffic modeling and anomaly alerting (unusual data volumes, off-hours transfers, beaconing patterns).
- OT-specific monitoring: passive OT network monitoring tool (e.g., Zeek with OT protocol parsers for Modbus/DNP3/OPC-UA) deployed as a **span-port only** sensor — never inline — to avoid availability risk to production agro-machinery control loops.

---

## 4. Linux Environment Hardening

Given the predominantly Linux footprint, hardening is applied consistently via configuration management (Ansible/Salt) rather than manual, host-by-host effort.

### 4.1 Baseline Hardening

- **CIS Benchmarks** (Level 1/2 as appropriate) applied via automated configuration management to every server image; golden images rebuilt regularly rather than patched-in-place drift.
- Kernel hardening: enable `SELinux` (enforcing mode) or `AppArmor` fleet-wide — not permissive/disabled as commonly found in the wild. Kernel lockdown mode enabled where kernel version supports it.
- Minimal package footprint: no compilers, no unnecessary network services on production hosts; package installation restricted via internal mirrored repos only (no direct internet package installs from prod).
- Immutable/read-only root filesystem for stateless services where feasible (containers, some appliance-style Linux hosts).

### 4.2 Access Hardening

- SSH: key-based auth only, root login disabled, `AllowUsers`/`AllowGroups` scoping, all SSH access brokered through the PAM/bastion layer (Section 3.1) rather than directly exposed — no server should have SSH reachable from the general corporate LAN, only from the jump-host subnet.
- `sudo` with granular command allow-listing per role, all `sudo` invocations logged to the central log pipeline.

### 4.3 Intrusion Detection / Prevention (Linux-specific)

- **Host-based:** `auditd` configured with a hardened ruleset (based on CIS/NIST recommendations) capturing privilege escalation, file integrity events on sensitive paths (`/etc/passwd`, `/etc/shadow`, application config, SCADA gateway configs), and process execution.
- **File Integrity Monitoring (FIM):** AIDE or a commercial EDR's FIM module, baselines compared on a schedule with alerting on unauthorized change — critical for detecting rootkits/implants and unauthorized changes to control-system-adjacent gateway hosts.
- **EDR:** Linux-compatible EDR agent (e.g., Wazuh as an open-source option, or commercial equivalent) fleet-wide for behavioral detection, feeding into the SIEM.
- **Network IDS/IPS:** Suricata in IPS mode at segment boundaries (Data Center ingress/egress, DMZ, OT-DMZ boundary) using a maintained ruleset (ET Open/Pro or equivalent) plus custom rules tuned for agro-sector-relevant threat intel (commodity-sector-targeted APT groups, known ICS malware signatures such as those historically seen in Industroyer/INCONTROLLER-class tooling).

### 4.4 Patch & Vulnerability Management

- Authenticated vulnerability scanning (e.g., OpenVAS/Nessus) on a recurring cycle across all zones, with OT/SCADA scanning done passively or during scheduled maintenance windows only (active scanning of legacy PLCs can crash them).
- SLA-driven patch cycles tiered by criticality (internet-facing/DMZ = fastest SLA, OT = slowest, requiring change-control and vendor validation).
- Kernel live-patching (kpatch/kGraft, or ksplice-equivalent) for Data Center Linux hosts to reduce the reboot-driven patch backlog on availability-sensitive systems.

### 4.5 Centralized Audit Logging (Linux)

- All hosts forward `auditd`, `journald`/syslog, and application logs via a hardened forwarder (e.g., Fluent Bit/rsyslog over TLS) to the central SIEM (Section 6).
- Log integrity: append-only/forward-only forwarding configuration; local log tampering is a secondary control only — the SIEM copy is authoritative and access-controlled separately from the source host's own admins (separation of duties between server admins and log-repository admins).

---

## 5. Local LLM Security Architecture

### 5.1 Isolation Model

The local LLM deployment is treated as its **own trust zone**, not as an extension of application or data infrastructure:

- Inference workloads run in a dedicated VLAN (10.50.0.0/24 in the plan above), on dedicated GPU compute (bare-metal or strictly isolated VMs — avoid shared-tenancy GPU passthrough with other workloads where possible).
- **No direct network path** from the LLM enclave to production databases (ERP, agronomy data warehouse, financial systems, SCADA historian). Any data the model needs is delivered through a mediated, read-only, purpose-built data pipeline (see 5.2) — never live query access.
- Outbound internet access from the LLM enclave is default-deny; if the deployment requires external model-weight updates or telemetry, this occurs through an explicit, logged, allow-listed egress path only — this also mitigates data-exfiltration-via-model-output-callback vectors.

### 5.2 Data Access Pattern (RAG / Grounding)

- If Retrieval-Augmented Generation is used, the vector store (10.50.1.0/24) contains only a **sanitized, purpose-built extract** of source data — never a live replica or raw production database connection.
- Sanitization pipeline strips PII/commercially sensitive fields not required for the use case (e.g., contract pricing terms, employee PII) before ingestion into the vector store, with a documented data classification review before any new data source is connected.
- The extraction/sync job runs with a **read-only, scoped service account**, one-way from production to the LLM data zone, never the reverse.

### 5.3 Defending Against Prompt Injection & Data Exfiltration

- Treat all model input — including RAG-retrieved content, uploaded documents, and tool/API outputs — as **untrusted input**, on par with user input from an unauthenticated web form.
- **Output filtering / DLP:** Outbound model responses pass through a data-loss-prevention filter checking for patterns matching sensitive data classes (financial figures beyond threshold, credential-like strings, PII patterns) before being returned to the user or downstream system.
- **Tool/function-calling isolation:** If the LLM is granted tool use (e.g., "query the inventory system"), each tool is a narrowly scoped, individually authorized API — not a generic database credential handed to the model's execution context. Apply the same least-privilege principle to LLM-invoked tools as to human users.
- **Segregation of instruction and data channels** where the LLM framework supports it (system-prompt isolation from retrieved/user content), plus periodic red-teaming specifically for prompt-injection resilience (indirect injection via poisoned documents, RAG content, or tool outputs) as part of the regular pentest cycle.
- Rate limiting and anomaly detection on the inference API itself (unusual query volume, patterns consistent with automated extraction attempts).

### 5.4 RBAC for API Access

- All access to the LLM API goes through the same central IdP/SSO as the rest of the enterprise — no standalone API-key-only access for interactive users.
- Scoped API keys/service identities for machine-to-machine integrations, each mapped to a specific allowed use case, with usage logged and reviewed.
- Role tiers, e.g.:
  - **General staff:** query-only access to approved, sanitized knowledge-base content.
  - **Agronomy/Ops analysts:** access to a broader but still scoped dataset relevant to their function.
  - **LLM platform admins:** access to model configuration, RAG pipeline management — separate from data-source admin roles (separation of duties).
- All access decisions and prompts/outputs (or at minimum metadata: who, when, which data sources were touched) are logged to the SIEM for the same audit/forensic purposes as any other sensitive system.

---

## 6. Forensic Readiness

### 6.1 Centralized Logging (SIEM)

- All zones (Corporate LAN, DMZ, Data Center, OT gateway layer, LLM enclave) forward logs to a central SIEM (e.g., Wazuh, Elastic Security, or commercial equivalent), with **log source diversity**: host audit logs, network flow data, firewall/NGFW logs, WAF logs, IdP/authentication logs, EDR telemetry, and LLM access/audit logs.
- **Time synchronization (NTP/chrony)** enforced fleet-wide with a trusted internal time source — accurate timestamps are foundational to any forensic timeline reconstruction.
- Log retention tiered by regulatory/business need (commonly 90 days hot/searchable, 1+ year cold/archival, adjust to applicable regional data-protection and industry compliance requirements) — verify against local regulatory obligations rather than assuming a fixed global standard.
- SIEM access itself is privileged and audited; the people who administer production servers should not have unilateral ability to alter or delete the SIEM's copy of their own logs (separation of duties, Section 4.5).

### 6.2 Immutable Backups

- **3-2-1-1 backup strategy**: 3 copies, 2 different media types, 1 offsite, **1 immutable/air-gapped** copy — the immutable copy specifically to survive a ransomware/APT scenario where an attacker attempts to destroy backups as part of the attack.
- Immutability enforced via WORM-capable storage (object-lock enabled object storage, or a backup platform with cryptographically enforced immutability) — not merely "delete permission removed via ACL," which a compromised admin account could still bypass.
- Backup infrastructure itself sits in its own segmented zone, reachable only via the backup software's push/pull mechanism — backup credentials are never valid for interactive login to production systems, limiting blast radius if backup infrastructure credentials leak.
- Regular **restore testing** (not just backup-success verification) on a defined cadence, including tabletop/full-scale DR exercises simulating an APT/ransomware scenario specifically.
- SCADA/OT configuration backups (PLC logic, HMI configs) included in the same immutable backup strategy — OT recovery is often the operationally critical path in an agro-industry APT scenario (a plant that can't run its irrigation/processing control systems is a direct production-loss event).

### 6.3 Incident Response Readiness

- Pre-staged forensic collection tooling (memory acquisition, disk imaging capability) available for both Data Center Linux hosts and, where feasible, OT gateway systems — ideally validated in advance rather than sourced ad hoc during an active incident.
- Network segmentation (Section 1/3) doubles as **incident containment capability**: pre-defined "isolation" firewall rule sets that can be activated quickly to quarantine a compromised VLAN without taking down unrelated zones.
- Defined chain-of-custody procedures for any evidence collected, particularly important if a breach may result in legal/regulatory action or insurance claims.
- Retainer relationship with an external incident-response/forensics firm established *before* an incident, not during one — evaluate this as a standing operational requirement rather than a reactive purchase.

---

## Summary: Zero-Trust Principles Applied Throughout

| Principle | Where Applied |
|---|---|
| Verify explicitly | IdP + MFA + device posture checks on every access request, human or service |
| Least privilege access | RBAC/ABAC, scoped service accounts, PAM-brokered admin access, LLM tool-scoping |
| Assume breach | Micro-segmentation, egress filtering, immutable backups, NDR/EDR everywhere |
| Segment by trust level, not by network convenience | Purdue-model OT segmentation, dedicated LLM enclave, DMZ/Corp/DC separation |
| Continuous monitoring over perimeter-only defense | SIEM, NDR, FIM, auditd fleet-wide, LLM access logging |

**A note on maintenance:** an architecture document is a starting design, not a static state. Threat intelligence relevant to the agro/food-supply sector, newly disclosed CVEs affecting the specific vendors in use (SCADA/PLC vendors, Linux distributions, LLM serving stack), and regulatory requirements should be reviewed on a defined cadence (recommend quarterly at minimum) and fed back into this design.
