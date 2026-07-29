"""
Hardening module for RHEL and Debian Zero-Trust Autodeployment Tool.
Handles baseline security hardening, MAC (SELinux/AppArmor), Sysctl kernel tuning,
Firewall micro-segmentation, SSH locking, and CIS auditd rules.
"""

import os
import sys
import subprocess
from typing import Dict, Any, List
from lib.config import DeploymentConfig, ZONE_PROFILES
from lib.logger import logger

def detect_distro_family() -> str:
    """Detects if running system is RHEL family or Debian family via /etc/os-release."""
    os_release_path = "/etc/os-release"
    if not os.path.exists(os_release_path):
        return "rhel"  # fallback default

    with open(os_release_path, "r", encoding="utf-8") as f:
        content = f.read().lower()

    if any(k in content for k in ["rhel", "redhat", "rocky", "alma", "fedora", "centos"]):
        return "rhel"
    elif any(k in content for k in ["debian", "ubuntu", "pop"]):
        return "debian"
    
    return "rhel"

class HardeningEngine:
    def __init__(self, config: DeploymentConfig, dry_run: bool = False):
        self.config = config
        self.dry_run = dry_run
        
        target_family = config.target_node.distro_family
        if target_family == "auto":
            self.distro_family = detect_distro_family()
        else:
            self.distro_family = target_family

        self.zone_name = config.target_node.zone
        self.zone_info = ZONE_PROFILES.get(self.zone_name, ZONE_PROFILES["core_dc"])

    def run_command(self, cmd: List[str], desc: str) -> bool:
        """Executes a system command or logs it in dry-run mode."""
        cmd_str = " ".join(cmd)
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would execute: [cyan]{cmd_str}[/cyan] ({desc})")
            return True
        
        logger.info(f"Executing: [cyan]{cmd_str}[/cyan] ({desc})")
        try:
            res = subprocess.run(cmd, check=True, capture_output=True, text=True)
            if res.stdout:
                logger.debug(f"Stdout: {res.stdout.strip()}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed ({desc}): {e.stderr.strip() or e}")
            return False
        except Exception as e:
            logger.error(f"Error running command ({desc}): {e}")
            return False

    def write_file(self, file_path: str, content: str, permissions: str = "0644") -> bool:
        """Writes content to a system configuration file or logs dry-run."""
        if self.dry_run:
            logger.info(f"[DRY-RUN] Would write config file [green]{file_path}[/green] (mode {permissions})")
            logger.debug(f"Content preview:\n{content[:200]}...")
            return True
        
        logger.info(f"Writing file: [green]{file_path}[/green]")
        try:
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            os.chmod(file_path, int(permissions, 8))
            return True
        except Exception as e:
            logger.error(f"Failed writing file {file_path}: {e}")
            return False

    def apply_mac_hardening(self) -> bool:
        """Applies SELinux (RHEL) or AppArmor (Debian) MAC controls."""
        logger.info(f"Applying Mandatory Access Control (MAC) for [bold]{self.distro_family.upper()}[/bold]")
        if self.distro_family == "rhel":
            # SELinux Enforcing
            selinux_cfg = "/etc/selinux/config"
            if os.path.exists(selinux_cfg) or self.dry_run:
                self.run_command(["setenforce", "1"], "Enable SELinux enforcing mode")
                # Ensure persistent SELINUX=enforcing
                if not self.dry_run and os.path.exists(selinux_cfg):
                    with open(selinux_cfg, "r") as f:
                        lines = f.readlines()
                    new_lines = []
                    for line in lines:
                        if line.startswith("SELINUX="):
                            new_lines.append("SELINUX=enforcing\n")
                        else:
                            new_lines.append(line)
                    with open(selinux_cfg, "w") as f:
                        f.writelines(new_lines)
            return True
        else:
            # Debian AppArmor
            self.run_command(["systemctl", "enable", "--now", "apparmor"], "Enable AppArmor service")
            return True

    def apply_sysctl_hardening(self) -> bool:
        """Applies Zero-Trust kernel & network stack hardening via sysctl."""
        logger.info("Applying Sysctl Kernel & IP Stack Security Hardening")
        sysctl_content = """# Zero-Trust Agro-Industry Hardening Baseline
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
fs.suid_dumpable = 0
kernel.randomize_va_space = 2
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
"""
        success = self.write_file("/etc/sysctl.d/99-zerotrust.conf", sysctl_content)
        if success:
            self.run_command(["sysctl", "--system"], "Load sysctl rules")
        return success

    def apply_ssh_hardening(self) -> bool:
        """Applies SSH Server Security Rules."""
        logger.info("Applying SSH Hardening Configuration")
        sshd_cfg = """# Zero-Trust SSH Server Hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
AllowTcpForwarding no
Protocol 2
"""
        success = self.write_file("/etc/ssh/sshd_config.d/99-zerotrust.conf", sshd_cfg, permissions="0600")
        if success:
            ssh_svc = "sshd" if self.distro_family == "rhel" else "ssh"
            self.run_command(["systemctl", "restart", ssh_svc], f"Restart {ssh_svc} service")
        return success

    def apply_firewall_rules(self) -> bool:
        """Applies firewall micro-segmentation based on target zone profile."""
        allowed_ports = self.zone_info["allowed_inbound_ports"]
        logger.info(f"Configuring Firewall Micro-segmentation for Zone: [yellow]{self.zone_name}[/yellow] (Ports: {allowed_ports})")

        if self.distro_family == "rhel":
            # Firewalld configuration
            self.run_command(["systemctl", "enable", "--now", "firewalld"], "Enable firewalld")
            self.run_command(["firewall-cmd", "--set-default-zone=drop"], "Set default firewall zone to drop")
            for port in allowed_ports:
                self.run_command(
                    ["firewall-cmd", "--permanent", "--add-port", f"{port}/tcp"],
                    f"Allow TCP port {port} in firewalld"
                )
            self.run_command(["firewall-cmd", "--reload"], "Reload firewalld rules")
        else:
            # Debian UFW / Nftables configuration
            self.run_command(["ufw", "--force", "reset"], "Reset UFW rules")
            self.run_command(["ufw", "default", "deny", "incoming"], "Set UFW default incoming deny")
            self.run_command(["ufw", "default", "deny", "outgoing"], "Set UFW default outgoing deny")
            
            # Basic outgoing infrastructure rules (DNS, NTP, HTTP/HTTPS for updates)
            self.run_command(["ufw", "allow", "out", "53/udp"], "Allow outgoing DNS")
            self.run_command(["ufw", "allow", "out", "123/udp"], "Allow outgoing NTP")
            self.run_command(["ufw", "allow", "out", "80/tcp"], "Allow outgoing HTTP updates")
            self.run_command(["ufw", "allow", "out", "443/tcp"], "Allow outgoing HTTPS updates")

            for port in allowed_ports:
                self.run_command(["ufw", "allow", f"{port}/tcp"], f"Allow TCP port {port} in UFW")
            self.run_command(["ufw", "--force", "enable"], "Enable UFW firewall")

        return True

    def apply_auditd_rules(self) -> bool:
        """Applies CIS / NIST auditd rules for command, user, and config tracking."""
        logger.info("Applying CIS auditd Audit Logging Rules")
        audit_rules = """# Zero-Trust Forensic Readiness Audit Rules
-D
-b 8192
-f 1

# Audit file changes to passwd/shadow
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k privilege_escalation
-w /etc/sudoers.d/ -p wa -k privilege_escalation

# Audit execution of privileged binaries
-a always,exit -F arch=b64 -S execve -F euid=0 -k root_exec
-a always,exit -F arch=b32 -S execve -F euid=0 -k root_exec

# Audit changes to system network configuration
-w /etc/sysctl.d/ -p wa -k sysctl_changes
-w /etc/network/ -p wa -k network_changes
-w /etc/sysconfig/network-scripts/ -p wa -k network_changes

# Lock auditd rules
-e 2
"""
        success = self.write_file("/etc/audit/rules.d/zerotrust.rules", audit_rules, permissions="0600")
        if success:
            self.run_command(["auditctl", "-R", "/etc/audit/rules.d/zerotrust.rules"], "Reload auditd rules")
        return success

    def run_all(self) -> bool:
        """Runs the entire zero-trust hardening suite."""
        logger.info(f"[bold green]Starting Zero-Trust Hardening for {self.distro_family.upper()} ({self.zone_name})[/bold green]")
        results = []
        
        if self.config.security.enforce_mac:
            results.append(self.apply_mac_hardening())
        if self.config.security.harden_sysctl:
            results.append(self.apply_sysctl_hardening())
        if self.config.security.harden_ssh:
            results.append(self.apply_ssh_hardening())
        if self.config.security.enforce_firewall:
            results.append(self.apply_firewall_rules())
        if self.config.security.setup_auditd:
            results.append(self.apply_auditd_rules())

        overall_success = all(results)
        if overall_success:
            logger.info("[bold green]Zero-Trust Baseline Hardening Complete Successfully![/bold green]")
        else:
            logger.warning("[bold yellow]Zero-Trust Hardening completed with warnings or partial failures.[/bold yellow]")
        
        return overall_success
