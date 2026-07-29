"""
Cloud-init rendering engine for AutoDeploy.
"""

import os
from jinja2 import Environment, FileSystemLoader
from lib.config import DeploymentConfig
from lib.logger import logger

class CloudInitRenderer:
    def __init__(self, template_dir: str):
        self.template_dir = template_dir
        self.env = Environment(loader=FileSystemLoader(template_dir))

    def render_all(self, config: DeploymentConfig, output_dir: str) -> dict:
        """Renders user-data, meta-data, and network-config files to output_dir."""
        os.makedirs(output_dir, exist_ok=True)
        rendered_files = {}

        templates = [
            ("user-data.yaml.j2", "user-data.yaml"),
            ("meta-data.yaml.j2", "meta-data.yaml"),
            ("network-config.yaml.j2", "network-config.yaml"),
        ]

        context = {
            "target_node": config.target_node,
            "security": config.security,
            "cloud_init": config.cloud_init,
        }

        for template_name, output_filename in templates:
            template = self.env.get_template(template_name)
            content = template.render(**context)
            out_path = os.path.join(output_dir, output_filename)
            with open(out_path, "w", encoding="utf-8") as f:
                f.write(content)
            rendered_files[output_filename] = out_path
            logger.info(f"Rendered cloud-init artifact: [green]{out_path}[/green]")

        return rendered_files
