# install.py
"""
Installation script for Ubuntu MCP Server
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


class UbuntuMCPInstaller:
    """Installer for Ubuntu MCP Server"""

    def __init__(self):
        self.install_dir = Path("/opt/ubuntu-mcp")
        self.config_dir = Path.home() / ".config" / "ubuntu-mcp"
        self.service_file = "/etc/systemd/system/ubuntu-mcp.service"

    def check_prerequisites(self) -> bool:
        """Check if system meets prerequisites"""
        print("Checking prerequisites...")

        # Check Python version
        if sys.version_info < (3, 8):
            print("Error: Python 3.8 or higher required")
            return False

        # Check if running on Ubuntu
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'ubuntu' not in content.lower():
                    print("Warning: This appears to not be Ubuntu")
        except FileNotFoundError:
            print("Warning: Cannot detect OS version")

        return True

    def install_dependencies(self) -> bool:
        """Install required Python packages"""
        print("Installing dependencies...")

        try:
            subprocess.run([
                sys.executable, "-m", "pip", "install",
                "mcp>=0.3.0", "psutil>=5.9.0"
            ], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            return False

    def create_directories(self) -> bool:
        """Create necessary directories"""
        print("Creating directories...")

        try:
            self.install_dir.mkdir(parents=True, exist_ok=True)
            self.config_dir.mkdir(parents=True, exist_ok=True)

            # Set appropriate permissions
            os.chmod(self.install_dir, 0o755)
            os.chmod(self.config_dir, 0o700)

            return True
        except Exception as e:
            print(f"Failed to create directories: {e}")
            return False

    def install_files(self) -> bool:
        """Install server files"""
        print("Installing server files...")

        try:
            # Copy main server file
            current_dir = Path(__file__).parent
            server_file = current_dir / "ubuntu_mcp_server.py"
            config_file = current_dir / "config.py"

            if server_file.exists():
                shutil.copy2(server_file, self.install_dir / "server.py")
            if config_file.exists():
                shutil.copy2(config_file, self.install_dir / "config.py")

            # Make server executable
            os.chmod(self.install_dir / "server.py", 0o755)

            return True
        except Exception as e:
            print(f"Failed to install files: {e}")
            return False

    def create_service_file(self) -> bool:
        """Create systemd service file"""
        print("Creating systemd service...")

        service_content = f"""[Unit]
Description=Ubuntu MCP Server
After=network.target

[Service]
Type=simple
User={os.getenv('USER', 'ubuntu')}
Group={os.getenv('USER', 'ubuntu')}
WorkingDirectory={self.install_dir}
ExecStart={sys.executable} {self.install_dir}/server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

        try:
            with open(self.service_file, 'w') as f:
                f.write(service_content)

            os.chmod(self.service_file, 0o644)
            return True
        except Exception as e:
            print(f"Failed to create service file: {e}")
            return False

    def install(self) -> bool:
        """Run complete installation"""
        print("Starting Ubuntu MCP Server installation...")

        if not self.check_prerequisites():
            return False

        steps = [
            self.install_dependencies,
            self.create_directories,
            self.install_files,
            self.create_service_file
        ]

        for step in steps:
            if not step():
                print(f"Installation failed at step: {step.__name__}")
                return False

        print("Installation completed successfully!")
        print(f"Config directory: {self.config_dir}")
        print(f"Install directory: {self.install_dir}")
        print("\nTo start the service:")
        print("sudo systemctl enable ubuntu-mcp")
        print("sudo systemctl start ubuntu-mcp")

        return True


def main():
    """Main installation function"""
    if os.geteuid() != 0:
        print("This installer should be run with sudo privileges")
        print("Usage: sudo python3 install.py")
        return 1

    installer = UbuntuMCPInstaller()
    success = installer.install()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

