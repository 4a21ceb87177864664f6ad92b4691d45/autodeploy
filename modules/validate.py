"""
Validation and Zero-Trust Compliance Auditor Module for AutoDeploy.
Runs post-deployment security compliance checks on RHEL and Debian nodes.
"""

import os
import sys
import subprocess
from typing import Dict, Any, List
from rich.table import Table
from rich.panel import Panel
from lib.config import DeploymentConfig, ZONE_PROFILES
from lib.logger import logger, console
from modules.harden import detect_distro_family

class ComplianceAuditor:
    def __init__(self, config: DeploymentConfig):
        self.config = config
        target_family = config.target_node.distro_family
        if target_family == "auto":
            self.distro_family = detect_distro_family()
        else:
            self.distro_family = target_family

        self.zone_name = config.target_node.zone
        self.zone_info = ZONE_PROFILES.get(self.zone_name, ZONE_PROFILES["core_dc"])
        self.checks: List[Dict[str, Any]] = []

    def add_check_result(self, name: str, category: str, status: bool, details: str):
        self.checks.append({
            "name": name,
            "category": category,
            "status": "PASS" if status else "FAIL",
            "details": details
        })

    def check_mac_status(self):
        """Checks if SELinux (RHEL) or AppArmor (Debian) is active."""
        if self.distro_family == "rhel":
            try:
                res = subprocess.run(["getenforce"], capture_output=True, text=True)
                mode = res.stdout.strip().lower()
                is_pass = (mode == "enforcing")
                self.add_check_result(
                    "SELinux Enforcing Mode",
                    "MAC",
                    is_pass,
                    f"SELinux status: {mode.upper()} (Required: ENFORCING)"
                )
            except Exception as e:
                self.add_check_result("SELinux Status", "MAC", False, f"Could not determine SELinux: {e}")
        else:
            try:
                res = subprocess.run(["aa-status", "--enabled"], capture_output=True, text=True)
                is_pass = (res.returncode == 0)
                self.add_check_result(
                    "AppArmor Active",
                    "MAC",
                    is_pass,
                    "AppArmor enabled" if is_pass else "AppArmor disabled or missing"
                )
            except Exception as e:
                self.add_check_result("AppArmor Status", "MAC", False, f"Could not determine AppArmor: {e}")

    def check_sysctl_parameters(self):
        """Checks key Zero-Trust kernel parameters."""
        params_to_check = {
            "net.ipv4.ip_forward": "0",
            "kernel.randomize_va_space": "2",
            "fs.suid_dumpable": "0",
            "kernel.dmesg_restrict": "1",
            "net.ipv4.tcp_syncookies": "1"
        }

        for param, expected in params_to_check.items():
            try:
                res = subprocess.run(["sysctl", "-n", param], capture_output=True, text=True)
                actual = res.stdout.strip()
                is_pass = (actual == expected)
                self.add_check_result(
                    f"Sysctl {param}",
                    "Kernel Hardening",
                    is_pass,
                    f"Actual: '{actual}', Expected: '{expected}'"
                )
            except Exception as e:
                self.add_check_result(f"Sysctl {param}", "Kernel Hardening", False, f"Error checking: {e}")

    def check_ssh_hardening(self):
        """Validates SSH server configuration files for Zero-Trust settings."""
        sshd_files = ["/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d/99-zerotrust.conf"]
        combined_content = ""
        for path in sshd_files:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    combined_content += f.read().lower() + "\n"

        root_disabled = ("permitrootlogin no" in combined_content)
        password_disabled = ("passwordauthentication no" in combined_content)

        self.add_check_result(
            "SSH Root Login Disabled",
            "Access Control",
            root_disabled,
            "PermitRootLogin is set to no" if root_disabled else "PermitRootLogin allowed or unverified"
        )
        self.add_check_result(
            "SSH Password Auth Disabled",
            "Access Control",
            password_disabled,
            "PasswordAuthentication set to no" if password_disabled else "PasswordAuthentication allowed or unverified"
        )

    def check_auditd(self):
        """Checks if auditd daemon is active and rules are loaded."""
        try:
            res = subprocess.run(["systemctl", "is-active", "auditd"], capture_output=True, text=True)
            active = (res.stdout.strip() == "active")
            self.add_check_result(
                "Auditd Service Active",
                "Auditing",
                active,
                f"auditd service state: {res.stdout.strip()}"
            )
        except Exception as e:
            self.add_check_result("Auditd Service Active", "Auditing", False, f"Failed check: {e}")

    def check_firewall(self):
        """Checks firewall status."""
        fw_cmd = ["firewall-cmd", "--state"] if self.distro_family == "rhel" else ["ufw", "status"]
        try:
            res = subprocess.run(fw_cmd, capture_output=True, text=True)
            active = (res.returncode == 0)
            self.add_check_result(
                f"Firewall Active ({'firewalld' if self.distro_family == 'rhel' else 'ufw'})",
                "Network Defense",
                active,
                f"Firewall service status code: {res.returncode}"
            )
        except Exception as e:
            self.add_check_result("Firewall Active", "Network Defense", False, f"Failed firewall check: {e}")

    def run_audit(self) -> Dict[str, Any]:
        """Runs complete verification check and prints rich compliance summary."""
        logger.info(f"[bold cyan]Running Zero-Trust Compliance Audit for {self.distro_family.upper()} Node in Zone '{self.zone_name}'[/bold cyan]")
        self.checks.clear()

        self.check_mac_status()
        self.check_sysctl_parameters()
        self.check_ssh_hardening()
        self.check_auditd()
        self.check_firewall()

        passed_count = sum(1 for c in self.checks if c["status"] == "PASS")
        total_count = len(self.checks)
        score = (passed_count / total_count * 100) if total_count > 0 else 0

        table = Table(title=f"Zero-Trust Compliance Report — Score: {score:.1f}% ({passed_count}/{total_count} Passed)")
        table.add_column("Category", style="cyan", no_wrap=True)
        table.add_column("Compliance Check", style="bold")
        table.add_column("Status", justify="center")
        table.add_column("Details", style="dim")

        for check in self.checks:
            status_style = "[bold green]PASS[/bold green]" if check["status"] == "PASS" else "[bold red]FAIL[/bold red]"
            table.add_row(check["category"], check["name"], status_style, check["details"])

        console.print("\n")
        console.print(table)
        console.print("\n")

        return {
            "score": score,
            "passed": passed_count,
            "total": total_count,
            "checks": self.checks
        }
