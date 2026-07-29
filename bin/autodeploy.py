#!/usr/bin/env python3
"""
AutoDeploy CLI Orchestrator: Zero-Trust Linux Environment Provisioner & Hardener.
Supports RHEL and Debian Family targets across Agro-Industry micro-segmentation zones.
"""

import sys
import os
import argparse

# Add parent directory to sys.path to allow imports from lib and modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from lib.config import load_config, DeploymentConfig, ZONE_PROFILES
from lib.logger import setup_logger, logger, console
from modules.cloud_init import CloudInitRenderer
from modules.harden import HardeningEngine
from modules.validate import ComplianceAuditor

def cmd_render(args):
    """Renders Cloud-Init Jinja2 payload templates."""
    logger.info(f"Loading configuration from: [bold]{args.config}[/bold]")
    config = load_config(args.config)
    
    template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "templates"))
    renderer = CloudInitRenderer(template_dir)
    rendered = renderer.render_all(config, args.output)
    
    logger.info(f"[bold green]Successfully rendered {len(rendered)} cloud-init artifacts into '{args.output}'[/bold green]")

def cmd_harden(args):
    """Applies Zero-Trust System Hardening."""
    logger.info(f"Loading configuration from: [bold]{args.config}[/bold]")
    config = load_config(args.config)
    
    engine = HardeningEngine(config, dry_run=args.dry_run)
    success = engine.run_all()
    if not success:
        sys.exit(1)

def cmd_validate(args):
    """Runs Post-Deployment Zero-Trust Compliance Check."""
    logger.info(f"Loading configuration from: [bold]{args.config}[/bold]")
    config = load_config(args.config)
    
    auditor = ComplianceAuditor(config)
    report = auditor.run_audit()
    if report["score"] < 80.0:
        logger.warning(f"[bold red]Compliance score ({report['score']:.1f}%) is below 80% threshold![/bold red]")
        sys.exit(1)

def cmd_deploy(args):
    """Runs full pipeline: Cloud-init render, baseline hardening, and compliance validation."""
    logger.info("[bold cyan]====================================================[/bold cyan]")
    logger.info("[bold cyan]   Zero-Trust AutoDeploy Pipeline Initializing      [/bold cyan]")
    logger.info("[bold cyan]====================================================[/bold cyan]")
    
    # 1. Render cloud-init templates
    cmd_render(args)
    
    # 2. Execute Zero-Trust baseline hardening
    cmd_harden(args)
    
    # 3. Validate security compliance
    cmd_validate(args)
    
    logger.info("[bold green]Pipeline execution completed successfully![/bold green]")

def main():
    parser = argparse.ArgumentParser(
        description="AutoDeploy: RHEL & Debian Zero-Trust Autodeployment Orchestrator",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"], help="Log verbosity level")
    parser.add_argument("--log-file", default=None, help="Optional log file path for JSON structured logs")

    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommands")

    # Render subcommand
    render_parser = subparsers.add_parser("render", help="Render Cloud-Init payload templates")
    render_parser.add_argument("--config", "-c", default="config.example.yaml", help="Path to config file")
    render_parser.add_argument("--output", "-o", default="./cloud-init-output", help="Output directory for rendered cloud-init files")
    render_parser.set_defaults(func=cmd_render)

    # Harden subcommand
    harden_parser = subparsers.add_parser("harden", help="Apply Zero-Trust System Hardening")
    harden_parser.add_argument("--config", "-c", default="config.example.yaml", help="Path to config file")
    harden_parser.add_argument("--dry-run", action="store_true", help="Log commands without making system modifications")
    harden_parser.set_defaults(func=cmd_harden)

    # Validate subcommand
    validate_parser = subparsers.add_parser("validate", help="Run Post-Deployment Zero-Trust Compliance Audit")
    validate_parser.add_argument("--config", "-c", default="config.example.yaml", help="Path to config file")
    validate_parser.set_defaults(func=cmd_validate)

    # Deploy subcommand
    deploy_parser = subparsers.add_parser("deploy", help="Run full pipeline (render, harden, validate)")
    deploy_parser.add_argument("--config", "-c", default="config.example.yaml", help="Path to config file")
    deploy_parser.add_argument("--output", "-o", default="./cloud-init-output", help="Output directory for rendered cloud-init files")
    deploy_parser.add_argument("--dry-run", action="store_true", help="Execute hardening in dry-run mode")
    deploy_parser.set_defaults(func=cmd_deploy)

    args = parser.parse_args()
    setup_logger(level=args.log_level, log_file=args.log_file)
    
    args.func(args)

if __name__ == "__main__":
    main()
