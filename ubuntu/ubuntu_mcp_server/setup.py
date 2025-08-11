#!/usr/bin/env python3
"""
Setup script for Secure Ubuntu MCP Server
Provides automated installation and configuration
"""

import os
import sys
import subprocess
import json
import argparse
from pathlib import Path
from typing import Dict, Any


def check_python_version():
    """Ensure Python 3.9+ is being used"""
    if sys.version_info < (3, 9):
        print("❌ Python 3.9 or higher is required!")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version}")


def check_ubuntu_version():
    """Check if running on supported Ubuntu version"""
    try:
        with open('/etc/os-release', 'r') as f:
            os_info = dict(line.strip().split('=', 1) for line in f if '=' in line)
            name = os_info.get('NAME', '').strip('"')
            version = os_info.get('VERSION_ID', '').strip('"')
            
            if 'ubuntu' not in name.lower():
                print(f"⚠️  Warning: This server is designed for Ubuntu. Detected: {name}")
                return False
            
            version_num = float(version)
            if version_num < 18.04:
                print(f"⚠️  Warning: Ubuntu 18.04+ recommended. Detected: {version}")
                return False
                
            print(f"✅ Ubuntu version: {name} {version}")
            return True
    except Exception as e:
        print(f"⚠️  Could not detect OS version: {e}")
        return False


def create_virtual_environment():
    """Create and setup virtual environment"""
    venv_path = Path('.venv')
    
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return
    
    print("📦 Creating virtual environment...")
    try:
        subprocess.run([sys.executable, '-m', 'venv', '.venv'], check=True)
        print("✅ Virtual environment created")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        sys.exit(1)


def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")
    
    pip_executable = Path('.venv/bin/pip')
    if not pip_executable.exists():
        pip_executable = Path('.venv/Scripts/pip.exe')  # Windows
    
    if not pip_executable.exists():
        print("❌ Could not find pip in virtual environment")
        sys.exit(1)
    
    try:
        # Upgrade pip first
        subprocess.run([str(pip_executable), 'install', '--upgrade', 'pip'], check=True)
        
        # Install requirements
        subprocess.run([str(pip_executable), 'install', '-r', 'requirements.txt'], check=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)


def run_tests():
    """Run functionality and security tests"""
    print("🧪 Running tests...")
    
    python_executable = Path('.venv/bin/python3')
    if not python_executable.exists():
        python_executable = Path('.venv/Scripts/python.exe')  # Windows
    
    try:
        # Run functionality tests
        print("  - Running functionality tests...")
        result = subprocess.run([str(python_executable), 'main.py', '--test'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Functionality tests failed: {result.stderr}")
            return False
        
        # Run security tests
        print("  - Running security tests...")
        result = subprocess.run([str(python_executable), 'main.py', '--security-test'], 
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Security tests failed: {result.stderr}")
            return False
        
        print("✅ All tests passed!")
        return True
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


def generate_claude_config(install_path: str) -> Dict[str, Any]:
    """Generate Claude Desktop configuration"""
    venv_python = f"{install_path}/.venv/bin/python3"
    main_script = f"{install_path}/main.py"
    
    config = {
        "mcpServers": {
            "secure-ubuntu": {
                "command": venv_python,
                "args": [main_script, "--policy", "secure"],
                "env": {
                    "MCP_LOG_LEVEL": "INFO"
                }
            }
        }
    }
    return config


def setup_claude_integration(install_path: str):
    """Setup Claude Desktop integration"""
    print("🔧 Setting up Claude Desktop integration...")
    
    # Generate configuration
    config = generate_claude_config(install_path)
    
    # Default Claude Desktop config path
    claude_config_dir = Path.home() / '.config' / 'claude-desktop'
    claude_config_file = claude_config_dir / 'claude_desktop_config.json'
    
    print(f"\n📋 Claude Desktop Configuration:")
    print(f"Add this to your Claude Desktop config file:")
    print(f"Config file location: {claude_config_file}")
    print(f"\n{json.dumps(config, indent=2)}")
    
    # Offer to create the config
    if input("\n❓ Would you like to create/update the Claude Desktop config? (y/N): ").lower() == 'y':
        try:
            claude_config_dir.mkdir(parents=True, exist_ok=True)
            
            # Merge with existing config if it exists
            existing_config = {}
            if claude_config_file.exists():
                with open(claude_config_file, 'r') as f:
                    existing_config = json.load(f)
            
            # Merge configurations
            if 'mcpServers' not in existing_config:
                existing_config['mcpServers'] = {}
            existing_config['mcpServers'].update(config['mcpServers'])
            
            # Write updated config
            with open(claude_config_file, 'w') as f:
                json.dump(existing_config, f, indent=2)
            
            print(f"✅ Claude Desktop config updated at {claude_config_file}")
            print("⚠️  Please restart Claude Desktop to apply changes")
        except Exception as e:
            print(f"❌ Failed to update Claude Desktop config: {e}")
            print("Please manually add the configuration shown above")


def create_example_config():
    """Create example configuration file"""
    example_config = {
        "server": {
            "name": "secure-ubuntu-controller",
            "version": "1.0.0",
            "description": "Secure Ubuntu MCP Server",
            "log_level": "INFO"
        },
        "security": {
            "policy_name": "secure",
            "allowed_paths": ["~/", "/tmp", "/var/tmp"],
            "forbidden_paths": ["/etc", "/root", "/boot", "/sys", "/proc"],
            "max_command_timeout": 30,
            "allow_sudo": False,
            "audit_actions": True
        }
    }
    
    config_file = Path('config.example.json')
    with open(config_file, 'w') as f:
        json.dump(example_config, f, indent=2)
    
    print(f"✅ Example configuration created at {config_file}")


def print_next_steps(install_path: str):
    """Print next steps for the user"""
    venv_python = f"{install_path}/.venv/bin/python3"
    
    print(f"""
🎉 Installation Complete!

📁 Installation directory: {install_path}

🚀 Next Steps:

1. **Test the server**:
   {venv_python} main.py --test

2. **Run security tests**:
   {venv_python} main.py --security-test

3. **Start the server**:
   {venv_python} main.py --policy secure

4. **Claude Desktop Integration**:
   - Add the configuration shown above to your Claude Desktop config
   - Restart Claude Desktop
   - Test with: "Check my system status"

5. **Customize Security**:
   - Review config.example.json for custom settings
   - Copy to config.json and modify as needed
   - Use --policy dev for development environments

📚 Documentation:
   - README.md - Full documentation
   - CONTRIBUTING.md - Development guide
   - CHANGELOG.md - Version history

🔒 Security:
   - Review allowed_paths and forbidden_paths in your policy
   - Monitor audit logs at /tmp/ubuntu_mcp_audit.log
   - Start with secure policy and adjust as needed

❓ Having issues? Check the troubleshooting section in README.md
""")


def main():
    parser = argparse.ArgumentParser(description="Setup Secure Ubuntu MCP Server")
    parser.add_argument('--skip-tests', action='store_true', help='Skip running tests')
    parser.add_argument('--skip-claude', action='store_true', help='Skip Claude Desktop setup')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')
    
    args = parser.parse_args()
    
    if not args.quiet:
        print("🔒 Secure Ubuntu MCP Server Setup")
        print("==================================")
    
    install_path = str(Path.cwd().absolute())
    
    # Check prerequisites
    check_python_version()
    check_ubuntu_version()
    
    # Setup environment
    create_virtual_environment()
    install_dependencies()
    
    # Create example configuration
    create_example_config()
    
    # Run tests unless skipped
    if not args.skip_tests:
        if not run_tests():
            print("⚠️  Tests failed - installation may have issues")
            if input("Continue anyway? (y/N): ").lower() != 'y':
                sys.exit(1)
    
    # Setup Claude integration unless skipped
    if not args.skip_claude:
        setup_claude_integration(install_path)
    
    # Show next steps
    if not args.quiet:
        print_next_steps(install_path)
    
    print("✅ Setup complete!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)
