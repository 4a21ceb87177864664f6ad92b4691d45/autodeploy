"""
Configuration schema and parser for AutoDeploy Zero-Trust Tool.
"""

import os
import yaml
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

VALID_DISTRO_FAMILIES = ["rhel", "debian", "auto"]
VALID_ZONES = ["core_dc", "dmz", "corporate_lan", "iot_scada", "llm_enclave"]

# Zone specifications derived from agro-industry-zero-trust-architecture.md
ZONE_PROFILES = {
    "core_dc": {
        "description": "Core Data Center Compute & Storage (VLAN 100-102)",
        "allowed_inbound_ports": [22, 443, 6443, 8443],
        "default_egress": "restricted",
        "mac_required": True,
        "ot_permissive": False,
    },
    "dmz": {
        "description": "Public-facing DMZ & Reverse Proxies / WAF (VLAN 200-201)",
        "allowed_inbound_ports": [80, 443, 22],
        "default_egress": "restricted",
        "mac_required": True,
        "ot_permissive": False,
    },
    "corporate_lan": {
        "description": "Corporate HQ Users & Print Services (VLAN 300-304)",
        "allowed_inbound_ports": [22],
        "default_egress": "filtered",
        "mac_required": True,
        "ot_permissive": False,
    },
    "iot_scada": {
        "description": "OT / SCADA Purdue Level 0-3 Segments (VLAN 400-403)",
        "allowed_inbound_ports": [502, 4840, 22],  # Modbus TCP, OPC-UA
        "default_egress": "airgapped_historian_only",
        "mac_required": True,
        "ot_permissive": True,
    },
    "llm_enclave": {
        "description": "Isolated AI/LLM Inference & Vector Store Enclave (VLAN 500-501)",
        "allowed_inbound_ports": [8000, 8080, 22],
        "default_egress": "deny_all",
        "mac_required": True,
        "ot_permissive": False,
    }
}

@dataclass
class TargetNodeConfig:
    hostname: str = "node-01"
    distro_family: str = "auto"  # rhel | debian | auto
    zone: str = "core_dc"        # core_dc | dmz | corporate_lan | iot_scada | llm_enclave
    ip_address: str = "10.10.0.50/24"
    gateway: str = "10.10.0.1"
    vlan_id: int = 100
    dns_servers: List[str] = field(default_factory=lambda: ["10.10.0.2", "1.1.1.1"])

@dataclass
class SecurityConfig:
    enforce_mac: bool = True               # SELinux (RHEL) / AppArmor (Debian)
    enforce_firewall: bool = True          # firewalld (RHEL) / ufw or nftables (Debian)
    harden_ssh: bool = True                # Disable root, pubkey only, ciphers
    harden_sysctl: bool = True             # Kernel & IP stack hardening
    setup_auditd: bool = True              # CIS/NIST auditd rules
    disable_unused_services: bool = True   # Disable wireless, cups, bluetooth, etc.

@dataclass
class CloudInitConfig:
    admin_username: str = "sysadmin"
    ssh_authorized_keys: List[str] = field(default_factory=list)
    packages: List[str] = field(default_factory=lambda: ["curl", "git", "vim", "audit", "nftables"])

@dataclass
class DeploymentConfig:
    target_node: TargetNodeConfig = field(default_factory=TargetNodeConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    cloud_init: CloudInitConfig = field(default_factory=CloudInitConfig)
    raw: Dict[str, Any] = field(default_factory=dict)

def load_config(config_path: str) -> DeploymentConfig:
    """Loads and validates deployment configuration from YAML file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    target_data = data.get("target_node", {})
    security_data = data.get("security", {})
    cloud_init_data = data.get("cloud_init", {})

    distro_family = str(target_data.get("distro_family", "auto")).lower()
    if distro_family not in VALID_DISTRO_FAMILIES:
        raise ValueError(f"Invalid distro_family '{distro_family}'. Must be one of {VALID_DISTRO_FAMILIES}")

    zone = str(target_data.get("zone", "core_dc")).lower()
    if zone not in VALID_ZONES:
        raise ValueError(f"Invalid zone '{zone}'. Must be one of {VALID_ZONES}")

    target_node = TargetNodeConfig(
        hostname=target_data.get("hostname", "node-01"),
        distro_family=distro_family,
        zone=zone,
        ip_address=target_data.get("ip_address", "10.10.0.50/24"),
        gateway=target_data.get("gateway", "10.10.0.1"),
        vlan_id=int(target_data.get("vlan_id", 100)),
        dns_servers=target_data.get("dns_servers", ["10.10.0.2", "1.1.1.1"])
    )

    security = SecurityConfig(
        enforce_mac=security_data.get("enforce_mac", True),
        enforce_firewall=security_data.get("enforce_firewall", True),
        harden_ssh=security_data.get("harden_ssh", True),
        harden_sysctl=security_data.get("harden_sysctl", True),
        setup_auditd=security_data.get("setup_auditd", True),
        disable_unused_services=security_data.get("disable_unused_services", True)
    )

    cloud_init = CloudInitConfig(
        admin_username=cloud_init_data.get("admin_username", "sysadmin"),
        ssh_authorized_keys=cloud_init_data.get("ssh_authorized_keys", []),
        packages=cloud_init_data.get("packages", ["curl", "git", "vim", "audit", "nftables"])
    )

    return DeploymentConfig(
        target_node=target_node,
        security=security,
        cloud_init=cloud_init,
        raw=data
    )
