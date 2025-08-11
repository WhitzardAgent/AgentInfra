# Secure Ubuntu MCP Server

> 🔒 **Security-First** Model Context Protocol server for safe Ubuntu system operations

A hardened, production-ready [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides AI assistants with **secure, controlled access** to Ubuntu system operations. Built with comprehensive security controls, audit logging, and defense-in-depth principles.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Security Focused](https://img.shields.io/badge/security-focused-green.svg)](#security-features)
[![MCP Compatible](https://img.shields.io/badge/MCP-compatible-blue.svg)](https://modelcontextprotocol.io/)

## ✨ Key Features

### 🛡️ Security-First Architecture
- **Path traversal protection** - Symlink resolution with allowlist/denylist controls
- **Command sanitization** - Shell injection prevention with safe argument parsing
- **Resource limits** - File size, execution timeouts, and output size controls
- **Comprehensive audit logging** - All operations logged with user attribution
- **Defense in depth** - Multiple security layers with fail-safe defaults

### 🎯 Core Capabilities
- **File Operations** - Read, write, and list directories with permission validation
- **Command Execution** - Safe shell command execution with whitelist/blacklist filtering
- **System Information** - OS details, memory, and disk usage monitoring
- **Package Management** - APT package search and listing (installation requires explicit config)

### 🏗️ Production Ready
- **Modular design** with clear separation of concerns
- **Comprehensive error handling** with meaningful error messages
- **Extensive test suite** including security validation tests
- **Configurable policies** for different use cases and environments
- **Zero-dependency security** - Core security doesn't rely on external packages

## 🚀 Quick Start

### Prerequisites
- Ubuntu 18.04+ (tested on 20.04, 22.04, 24.04)
- Python 3.9 or higher
- Standard Unix utilities (ls, cat, echo, etc.)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/secure-ubuntu-mcp.git
cd secure-ubuntu-mcp

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify installation with built-in tests
python main.py --test
```

### Basic Usage

```bash
# Start with secure policy (recommended)
python main.py --policy secure

# Start with development policy (more permissive)
python main.py --policy dev

# Test security measures
python main.py --security-test
```

## 🔧 Integration

### Claude Desktop

#### Getting Claude Desktop on Linux

**Official Support**: Claude Desktop doesn't officially support Linux, but the community has created solutions!

**Recommended Method**: Use the community Debian package by @aaddrick:

```bash
# Download and install Claude Desktop for Linux
wget https://github.com/aaddrick/claude-desktop-debian/releases/latest/download/claude-desktop_latest_amd64.deb
sudo dpkg -i claude-desktop_latest_amd64.deb
sudo apt-get install -f  # Fix any dependency issues
```

For other methods and troubleshooting, see: https://github.com/aaddrick/claude-desktop-debian

#### Configuration

Once Claude Desktop is installed, add to your configuration (`~/.config/claude-desktop/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "secure-ubuntu": {
      "command": "/path/to/secure-ubuntu-mcp/.venv/bin/python3",
      "args": ["/path/to/secure-ubuntu-mcp/main.py", "--policy", "secure"],
      "env": {
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

> ⚠️ **Important**: Use absolute paths and the virtual environment Python interpreter

**Verification**: After restarting Claude Desktop, you should see "secure-ubuntu" listed as a connected server, and Claude will have access to system control tools.

### Other MCP Clients

The server implements the standard MCP protocol and works with any MCP-compatible client:

```python
# Example with mcp Python client
import asyncio
from mcp.client import ClientSession

async def example():
    # Connect to the server
    # Implementation depends on your MCP client
    pass
```

## 🛡️ Security Policies

### Secure Policy (Default)
Recommended for production and untrusted environments:

- **Allowed Paths**: `~/`, `/tmp`, `/var/tmp`
- **Forbidden Paths**: `/etc`, `/root`, `/boot`, `/sys`, `/proc`, `/dev`, `/usr`, `/bin`, `/sbin`
- **Command Whitelist**: `ls`, `cat`, `echo`, `pwd`, `whoami`, `date`, `find`, `grep`, `apt` (search only)
- **Resource Limits**: 1MB files, 15s timeouts, 256KB output
- **Sudo**: Disabled
- **Shell Execution**: Disabled (uses safe direct execution)

### Development Policy
More permissive for development environments:

- **Additional Allowed Paths**: `/opt`, `/usr/local`
- **Fewer Restrictions**: Access to more system areas
- **Larger Limits**: 10MB files, 60s timeouts, 1MB output
- **More Commands**: Most development tools allowed
- **Sudo**: Still disabled by default (can be enabled)

### Custom Policies

Create your own security policy:

```python
from main import SecurityPolicy

custom_policy = SecurityPolicy(
    allowed_paths=["/your/custom/paths"],
    forbidden_paths=["/sensitive/areas"],
    allowed_commands=["safe", "commands"],
    forbidden_commands=["dangerous", "commands"],
    max_command_timeout=30,
    allow_sudo=False,  # Use with extreme caution
    audit_actions=True
)
```

## 🔍 Available Tools

### File Operations
- `list_directory(path)` - List directory contents with metadata
- `read_file(file_path)` - Read file contents with size validation
- `write_file(file_path, content, create_dirs=False)` - Write with atomic operations

### System Operations
- `execute_command(command, working_dir=None)` - Execute shell commands safely
- `get_system_info()` - Get OS, memory, and disk information

### Package Management
- `search_packages(query)` - Search APT repositories
- `install_package(package_name)` - Check package availability (listing only)

## 🔒 Security Features

### Protection Against Common Attacks

**Path Traversal Prevention**:
```bash
# These are all blocked:
../../../etc/passwd
/etc/passwd
/tmp/../etc/passwd
symlinks_to_sensitive_files
```

**Command Injection Prevention**:
```bash
# These are all blocked:
echo hello; rm -rf /
echo `cat /etc/passwd`
echo $(whoami)
ls | rm -rf /
```

**Resource Exhaustion Protection**:
- File size limits prevent memory exhaustion
- Execution timeouts prevent hanging processes
- Output size limits prevent log flooding
- Directory listing limits prevent enumeration attacks

### Audit Trail

All operations are logged with:
- User attribution
- Timestamp and operation type
- Full path resolution
- Success/failure status
- Security violation details

## 🧪 Testing

### Functionality Tests
```bash
# Test core functionality
python main.py --test
```

### Security Validation
```bash
# Run comprehensive security tests
python main.py --security-test
```

### Manual Testing
```bash
# Test MCP protocol directly
python test_client.py --simple
```

## 📊 Example Usage

Once integrated with an AI assistant:

**System Monitoring**:
> "Check my system status and disk space"

**File Management**:
> "List the files in my home directory and show me the largest ones"

**Development Tasks**:
> "Check if Python is installed and show me the version"

**Log Analysis**:
> "Look for any error files in my project directory"

## ⚙️ Configuration

### Environment Variables
- `MCP_LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)
- `MCP_POLICY` - Security policy (secure, dev)
- `MCP_CONFIG_PATH` - Path to custom configuration file

### Configuration File
Create `config.json` for custom settings:

```json
{
  "server": {
    "name": "secure-ubuntu-controller",
    "version": "1.0.0",
    "log_level": "INFO"
  },
  "security": {
    "policy_name": "secure",
    "allowed_paths": ["~/", "/tmp"],
    "max_command_timeout": 30,
    "allow_sudo": false,
    "audit_actions": true
  }
}
```

## 🛠️ Development

### Adding New Tools

```python
@mcp.tool("your_tool_name")
async def your_tool(param: str) -> str:
    """Tool description for AI assistant"""
    try:
        # Use controller methods for safe operations
        result = controller.safe_operation(param)
        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)}, indent=2)
```

### Extending Security

```python
def create_custom_policy() -> SecurityPolicy:
    """Create a custom security policy"""
    return SecurityPolicy(
        allowed_paths=["/your/paths"],
        forbidden_commands=["dangerous", "commands"],
        # ... other settings
    )
```

## 🔧 Troubleshooting

### Common Issues

**"Server appears to hang"**
- This is normal! MCP servers run continuously and communicate via stdio
- The server is waiting for MCP protocol messages

**"ModuleNotFoundError: No module named 'mcp'"**
- Ensure you're using the virtual environment Python interpreter
- Check your Claude Desktop config uses the full path to `.venv/bin/python3`

**"SecurityViolation" errors**
- Check if the path/command is allowed by your security policy
- Review audit logs at `/tmp/ubuntu_mcp_audit.log`
- Consider using development policy for testing

**"Permission denied" errors**
- Verify your user has access to the requested paths
- Check file/directory permissions with `ls -la`

### Debug Mode

```bash
# Enable verbose logging
python main.py --log-level DEBUG --policy secure

# Check audit logs
tail -f /tmp/ubuntu_mcp_audit.log
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Setup
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes with tests
4. Ensure all tests pass: `python main.py --test && python main.py --security-test`
5. Submit a pull request

### Code Standards
- Follow PEP 8 style guidelines
- Add type hints for all public functions
- Include comprehensive docstrings
- Write tests for new functionality
- Maintain security-first principles

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔐 Security Disclosure

If you discover a security vulnerability, please email [radjackbartok@proton.me] instead of creating a public issue. We take security seriously and will respond promptly.

## 🙏 Acknowledgments

- [Model Context Protocol](https://modelcontextprotocol.io/) team for the excellent protocol
- Security researchers and the infosec community for best practices
- Python security community for ongoing guidance

## 📈 Roadmap

- [ ] **Enhanced Logging** - Structured JSON logging with more context
- [ ] **Container Support** - Docker integration and container-aware policies  
- [ ] **Network Tools** - Safe networking utilities (ping, traceroute, etc.)
- [ ] **Process Management** - Safe process monitoring and control
- [ ] **Configuration UI** - Web interface for policy management
- [ ] **Integration Tests** - Comprehensive end-to-end testing
- [ ] **Performance Optimization** - Caching and performance improvements
- [ ] **Multi-User Support** - Role-based access controls

---

**Made for the security-conscious AI community**

> 💡 **Pro Tip**: Start with the secure policy and gradually increase permissions as needed. It's easier to add permissions than to recover from a security incident!
