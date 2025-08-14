# config.py
"""
Configuration management for Ubuntu MCP Server
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict


@dataclass
class ServerConfig:
    """Server configuration"""
    name: str = "ubuntu-controller"
    version: str = "1.0.0"
    description: str = "MCP Server for Ubuntu System Control"
    max_connections: int = 10
    log_level: str = "INFO"
    log_file: Optional[str] = None


@dataclass
class SecurityConfig:
    """Security configuration"""
    policy_name: str = "safe"
    allowed_paths: list = None
    forbidden_paths: list = None
    allowed_commands: list = None
    forbidden_commands: list = None
    max_command_timeout: int = 30
    allow_sudo: bool = False
    max_file_size: int = 1024 * 1024  # 1MB

    def __post_init__(self):
        if self.allowed_paths is None:
            self.allowed_paths = []
        if self.forbidden_paths is None:
            self.forbidden_paths = []
        if self.allowed_commands is None:
            self.allowed_commands = []
        if self.forbidden_commands is None:
            self.forbidden_commands = []


class ConfigManager:
    """Manage configuration loading and validation"""

    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._get_default_config_path()
        self.server_config = ServerConfig()
        self.security_config = SecurityConfig()

    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        home_dir = Path.home()
        config_dir = home_dir / ".config" / "ubuntu-mcp"
        config_dir.mkdir(parents=True, exist_ok=True)
        return str(config_dir / "config.json")

    def load_config(self) -> None:
        """Load configuration from file"""
        if not os.path.exists(self.config_path):
            self.create_default_config()
            return

        try:
            with open(self.config_path, 'r') as f:
                config_data = json.load(f)

            # Load server config
            if 'server' in config_data:
                server_data = config_data['server']
                self.server_config = ServerConfig(**server_data)

            # Load security config
            if 'security' in config_data:
                security_data = config_data['security']
                self.security_config = SecurityConfig(**security_data)

        except Exception as e:
            raise ValueError(f"Failed to load config: {e}")

    def save_config(self) -> None:
        """Save current configuration to file"""
        config_data = {
            'server': asdict(self.server_config),
            'security': asdict(self.security_config)
        }

        os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
        with open(self.config_path, 'w') as f:
            json.dump(config_data, f, indent=2)

    def create_default_config(self) -> None:
        """Create default configuration"""
        home_dir = os.path.expanduser("~")

        # Safe default security policy
        self.security_config = SecurityConfig(
            policy_name="safe",
            allowed_paths=[
                home_dir,
                "/tmp",
                "/var/tmp"
            ],
            forbidden_paths=[
                "/etc/passwd",
                "/etc/shadow",
                "/root",
                "/boot",
                "/sys",
                "/proc"
            ],
            allowed_commands=[
                "ls", "cat", "echo", "pwd", "whoami", "date",
                "grep", "find", "which", "file", "head", "tail",
                "apt", "git", "python3", "pip3"
            ],
            forbidden_commands=[
                "rm", "rmdir", "dd", "mkfs", "shutdown", "reboot",
                "mount", "umount", "chmod", "chown"
            ],
            allow_sudo=False,
            max_command_timeout=30
        )

        self.save_config()
