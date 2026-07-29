# Zero-Trust AutoDeploy Prototype for RHEL & Debian Environments

An enterprise autodeployment, hardening, and compliance validation tool tailored for Linux-predominant enterprise infrastructure across both **RHEL family** (RHEL, Rocky, Alma, Fedora) and **Debian family** (Debian, Ubuntu) operating systems.

Built upon the security framework defined in `agro-industry-zero-trust-architecture.md` and following the layout specified in `Mapofdesing.md`.

---

## 🏗 Directory Structure

```text
rhel-autodeploy/
├── bin/
│   └── autodeploy.py           # Main orchestrator CLI
├── lib/
│   ├── config.py               # Configuration schema & YAML parser
│   └── logger.py               # Structured & Rich console logger
├── modules/
│   ├── cloud_init.py           # Cloud-init rendering engine
│   ├── harden.py               # Cross-distro system hardening engine
│   └── validate.py             # Zero-Trust post-deployment compliance auditor
├── templates/
│   ├── user-data.yaml.j2       # Cloud-init payload template
│   ├── meta-data.yaml.j2       # Cloud-init metadata template
│   └── network-config.yaml.j2  # Cloud-init network config template
├── config.example.yaml         # Example configuration
├── requirements.txt            # Python dependencies
└── README.md                   # Documentation
```

---

## 🛡 Key Features & Zero-Trust Alignment

1. **Dual-Distribution Engine**:
   - Auto-detects `/etc/os-release` (or accepts manual override).
   - **RHEL Family**: Manages `dnf`/`yum`, `SELinux` (Enforcing mode), `firewalld`, and `nmstate`.
   - **Debian Family**: Manages `apt`, `AppArmor`, `ufw`/`nftables`, and `netplan`.

2. **Micro-Segmentation Zone Profiles**:
   - `core_dc`: Core Data Center compute (Ports 22, 443, 6443, 8443).
   - `dmz`: Public-facing WAF & reverse proxies (Ports 80, 443, 22).
   - `corporate_lan`: Corporate workstations & administrative access (Port 22).
   - `iot_scada`: Purdue Model Level 0-3 OT/SCADA segments (Ports 502 Modbus, 4840 OPC-UA).
   - `llm_enclave`: Isolated local LLM inference & vector database (Ports 8000, 8080, 22; default deny outbound).

3. **Baseline Hardening Baseline**:
   - Mandatory Access Control (`SELinux` / `AppArmor`).
   - SSH server lockdown (Root login disabled, pubkey auth mandatory, strict ciphers).
   - Kernel IP stack defense (`sysctl` rules for IP spoofing, ICMP redirects, ASLR, dmesg restriction).
   - Forensic auditing (`auditd` CIS/NIST rule injection).

---

## 🚀 Getting Started

### Prerequisites

Python 3.8+ with standard virtual environment:

```bash
python3 -m venv venv
source venv/bin/venv/activate
pip install -r requirements.txt
```

### CLI Usage

#### 1. Render Cloud-Init Bootstrap Payloads

Generates `user-data.yaml`, `meta-data.yaml`, and `network-config.yaml` for initial provisioners:

```bash
python3 bin/autodeploy.py render --config config.example.yaml --output ./cloud-init-output
```

#### 2. Dry-Run System Hardening

Inspect commands that would be executed on the target system:

```bash
python3 bin/autodeploy.py harden --config config.example.yaml --dry-run
```

#### 3. Execute System Hardening (Local Node)

Run live zero-trust hardening on the host machine:

```bash
sudo python3 bin/autodeploy.py harden --config config.example.yaml
```

#### 4. Run Post-Deployment Compliance Audit

Performs automated audit checks (MAC, sysctl, SSH, auditd, firewall):

```bash
python3 bin/autodeploy.py validate --config config.example.yaml
```

#### 5. Execute Full AutoDeploy Pipeline

Run cloud-init rendering, hardening (dry-run mode option available), and compliance check in one command:

```bash
python3 bin/autodeploy.py deploy --config config.example.yaml --dry-run
```
