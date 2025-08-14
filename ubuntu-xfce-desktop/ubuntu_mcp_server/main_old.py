"""
Secure Ubuntu MCP Server

A hardened Model Context Protocol server for controlling Ubuntu systems.
Provides safe, controlled access with comprehensive security protections.
"""

import asyncio
import json
import logging
import os
import pwd
import grp
import shutil
import stat
import subprocess
import tempfile
import hashlib
import time
import shlex
from pathlib import Path, PurePath
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import re

# MCP Protocol implementation - assuming this module exists
# You can use a mock for local testing if mcp is not installed:
# class FastMCP:
#     def __init__(self, name): self.name = name
#     def tool(self, name): return lambda f: f
#     async def run_stdio_async(self): print("MCP server mock running...")
from fastmcp import FastMCP


class SecurityViolation(Exception):
    """Raised when a security policy violation is detected"""
    pass


class PermissionLevel(Enum):
    """Define permission levels for operations"""
    READ_ONLY = "read_only"
    SAFE_WRITE = "safe_write"
    SYSTEM_ADMIN = "system_admin"
    RESTRICTED = "restricted"


@dataclass
class SecurityPolicy:
    """Enhanced security policy configuration"""
    # Path controls
    allowed_paths: List[str] = field(default_factory=list)
    forbidden_paths: List[str] = field(default_factory=list)

    # Command controls
    allowed_commands: List[str] = field(default_factory=list)
    forbidden_commands: List[str] = field(default_factory=list)
    command_whitelist_mode: bool = True  # If True, only allowed_commands can run

    # Resource limits
    max_command_timeout: int = 30
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    max_output_size: int = 1024 * 1024  # 1MB
    max_directory_items: int = 1000

    # Security features
    allow_sudo: bool = False
    resolve_symlinks: bool = True  # Always resolve symlinks for security
    check_file_permissions: bool = True
    audit_actions: bool = True
    use_path_cache: bool = False  # Disabled by default for security
    use_shell_exec: bool = False  # Disabled by default for security

    # Protected locations
    server_executable_paths: Set[str] = field(default_factory=set)
    system_critical_paths: Set[str] = field(default_factory=set)


class SecurityChecker:
    """Centralized security validation and enforcement"""

    def __init__(self, policy: SecurityPolicy):
        self.policy = policy
        self.logger = logging.getLogger(f"{__name__}.security")

        # Cache for resolved paths to avoid repeated filesystem calls
        self._path_resolution_cache = {}
        self._cache_max_age = 300  # 5 minutes
        self._cache_timestamps = {}

    def _get_cache_key(self, path: str) -> str:
        """Generate cache key for path resolution"""
        return hashlib.sha256(path.encode()).hexdigest()

    def _is_cache_valid(self, cache_key: str) -> bool:
        """Check if cached path resolution is still valid"""
        if cache_key not in self._cache_timestamps:
            return False
        return time.time() - self._cache_timestamps[cache_key] < self._cache_max_age

    def resolve_path_safely(self, path: str) -> str:
        """
        Resolve path while protecting against symlink attacks
        Returns the canonical absolute path

        Note: Caching disabled by default to prevent TOCTOU vulnerabilities
        """
        # Only use cache if explicitly enabled in policy
        if self.policy.use_path_cache:
            cache_key = self._get_cache_key(path)
            if self._is_cache_valid(cache_key):
                return self._path_resolution_cache[cache_key]

        try:
            # Convert to Path object for safe manipulation
            # Use os.path.abspath to handle cases like `../` correctly from the start
            path_obj = Path(os.path.abspath(path))

            if self.policy.resolve_symlinks:
                # Resolve all symlinks - this is critical for security
                # strict=False allows resolving paths where the final component may not exist (e.g., for writing a new file)
                resolved_path = path_obj.resolve(strict=False)
            else:
                # Just get absolute path without resolving symlinks (less secure)
                resolved_path = path_obj.absolute()

            canonical_path = str(resolved_path)

            # Cache the result only if caching is enabled
            if self.policy.use_path_cache:
                cache_key = self._get_cache_key(path)
                self._path_resolution_cache[cache_key] = canonical_path
                self._cache_timestamps[cache_key] = time.time()

            return canonical_path

        except (OSError, RuntimeError) as e:
            # Path resolution failed - likely a broken symlink or permission issue
            self.logger.warning(f"Path resolution failed for {path}: {e}")
            raise SecurityViolation(f"Cannot resolve path: {path}")

    def validate_path_access(self, path: str, operation: str = "access") -> str:
        """
        Validate that a path is safe to access
        Returns the resolved canonical path if safe
        """
        # Resolve the path safely
        canonical_path = self.resolve_path_safely(path)

        # Check against server's own files
        for server_path in self.policy.server_executable_paths:
            if canonical_path.startswith(server_path):
                raise SecurityViolation(
                    f"Access denied to server files: {canonical_path}"
                )

        # Check against system critical paths
        for critical_path in self.policy.system_critical_paths:
            if canonical_path.startswith(critical_path):
                raise SecurityViolation(
                    f"Access denied to critical system path: {canonical_path}"
                )

        # Check forbidden paths first (higher priority)
        for forbidden in self.policy.forbidden_paths:
            # Resolve forbidden paths too for a correct comparison
            forbidden_canonical = self.resolve_path_safely(forbidden)
            if canonical_path.startswith(forbidden_canonical):
                raise SecurityViolation(
                    f"Path explicitly forbidden: {canonical_path}"
                )

        # Check allowed paths
        path_allowed = False
        if not self.policy.allowed_paths:
            # No restrictions if allowed_paths is empty
            path_allowed = True
        else:
            for allowed in self.policy.allowed_paths:
                allowed_canonical = self.resolve_path_safely(allowed)
                if canonical_path.startswith(allowed_canonical):
                    path_allowed = True
                    break

        if not path_allowed:
            raise SecurityViolation(
                f"Path not in allowed locations: {canonical_path}"
            )

        # Additional permission checks
        if self.policy.check_file_permissions and Path(canonical_path).exists():
            self._check_file_permissions(canonical_path, operation)

        return canonical_path

    def _check_file_permissions(self, path: str, operation: str):
        """Check if current user has appropriate permissions"""
        try:
            path_obj = Path(path)
            stat_info = path_obj.stat()

            # Get current user info
            current_uid = os.getuid()
            current_gids = [os.getgid()] + os.getgroups()

            # Check ownership and permissions
            file_mode = stat_info.st_mode
            has_perm = False

            if operation in ["read", "access"]:
                if stat_info.st_uid == current_uid and (file_mode & stat.S_IRUSR):
                    has_perm = True
                elif stat_info.st_gid in current_gids and (file_mode & stat.S_IRGRP):
                    has_perm = True
                elif file_mode & stat.S_IROTH:
                    has_perm = True
            elif operation in ["write", "modify"]:
                if stat_info.st_uid == current_uid and (file_mode & stat.S_IWUSR):
                    has_perm = True
                elif stat_info.st_gid in current_gids and (file_mode & stat.S_IWGRP):
                    has_perm = True
                elif file_mode & stat.S_IWOTH:
                    has_perm = True
            else:  # default to no permission for unknown operations
                has_perm = False

            if not has_perm:
                raise SecurityViolation(
                    f"Insufficient permissions for {operation} on {path}"
                )

        except OSError as e:
            raise SecurityViolation(f"Cannot check permissions for {path}: {e}")

    def validate_command(self, command: str) -> List[str]:
        """
        Validate that a command is safe to execute
        Returns the parsed command arguments for safe execution
        """
        if not command.strip():
            raise SecurityViolation("Empty command not allowed")

        # Parse command safely using shlex to handle quotes and escaping
        try:
            cmd_parts = shlex.split(command.strip())
        except ValueError as e:
            raise SecurityViolation(f"Invalid command syntax: {e}")

        if not cmd_parts:
            raise SecurityViolation("Empty command after parsing")

        base_command = cmd_parts[0]

        # Handle sudo commands
        if base_command == 'sudo':
            if not self.policy.allow_sudo:
                raise SecurityViolation("Sudo commands are not allowed by the current security policy.")
            if len(cmd_parts) < 2:
                raise SecurityViolation("Invalid sudo command: missing command to execute.")
            base_command = cmd_parts[1]

        # Resolve the full path of the command to prevent PATH manipulation
        full_command_path = shutil.which(base_command)
        if not full_command_path:
            # Command not found in PATH - check if it's an absolute path
            if os.path.isabs(base_command) and os.path.exists(base_command) and os.access(base_command, os.X_OK):
                full_command_path = base_command
            else:
                raise SecurityViolation(f"Command not found or not executable: {base_command}")

        # Get the basename for policy checking
        command_basename = os.path.basename(full_command_path)

        # Check forbidden commands first
        if command_basename in self.policy.forbidden_commands:
            raise SecurityViolation(f"Command explicitly forbidden: {command_basename}")

        # Check allowed commands if in whitelist mode
        if self.policy.command_whitelist_mode:
            if not self.policy.allowed_commands:
                raise SecurityViolation("No commands are allowed (command whitelist is empty).")
            if command_basename not in self.policy.allowed_commands:
                raise SecurityViolation(f"Command not in whitelist: {command_basename}")

        # Additional dangerous pattern checks in full command string
        # These checks are particularly important if `use_shell_exec` is True.
        dangerous_patterns = {
            '`': "Backticks (command substitution)",
            '$(': "Dollar-parenthesis (command substitution)",
            ';': "Semicolon (command chaining)",
            '&&': "AND logical operator (command chaining)",
            '||': "OR logical operator (command chaining)",
            '|': "Pipe (command chaining, except for allowed commands)",
        }

        full_command_str = ' '.join(cmd_parts)
        for pattern, desc in dangerous_patterns.items():
            if pattern in full_command_str:
                # Allow pipes for whitelisted commands known to use them (like grep, wc, etc.)
                if pattern == '|' and command_basename in self.policy.allowed_commands:
                    continue
                self.logger.warning(
                    f"Potentially dangerous pattern '{pattern}' detected in command: {full_command_str}")
                if self.policy.use_shell_exec:
                    raise SecurityViolation(f"Dangerous pattern detected in shell command: {desc}")

        return cmd_parts

    def validate_file_operation(self, path: str, operation: str, size: Optional[int] = None) -> str:
        """Validate file operations with size and permission checks"""
        canonical_path = self.validate_path_access(path, operation)

        if size is not None and size > self.policy.max_file_size:
            raise SecurityViolation(
                f"File content size {size} exceeds limit {self.policy.max_file_size}"
            )

        # Check if file exists and get its current size if reading
        if operation == "read" and Path(canonical_path).exists():
            current_size = Path(canonical_path).stat().st_size
            if current_size > self.policy.max_file_size:
                raise SecurityViolation(
                    f"Existing file is too large to read: {current_size} bytes"
                )

        return canonical_path


class AuditLogger:
    """Security audit logging"""

    def __init__(self, enabled: bool = True, log_file: str = '/tmp/ubuntu_mcp_audit.log'):
        self.enabled = enabled
        self.logger = logging.getLogger(f"{__name__}.audit")

        # Setup audit log handler if enabled
        if enabled:
            # Prevent adding handlers multiple times if instantiated repeatedly
            if not self.logger.handlers:
                try:
                    audit_handler = logging.FileHandler(log_file)
                    audit_formatter = logging.Formatter(
                        '%(asctime)s - AUDIT - %(levelname)s - %(message)s'
                    )
                    audit_handler.setFormatter(audit_formatter)
                    self.logger.addHandler(audit_handler)
                    self.logger.setLevel(logging.INFO)
                    self.logger.propagate = False
                except (OSError, PermissionError) as e:
                    logging.getLogger(__name__).error(f"Failed to configure audit logger at {log_file}: {e}")
                    self.enabled = False

    def log_command(self, command: str, user: str, working_dir: Optional[str] = None):
        """Log command execution"""
        if self.enabled:
            self.logger.info(f"COMMAND_ATTEMPT: user={user} cmd='{command}' cwd={working_dir or 'default'}")

    def log_file_access(self, operation: str, path: str, user: str, success: bool):
        """Log file access operations"""
        if self.enabled:
            status = "SUCCESS" if success else "FAILED"
            self.logger.info(f"FILE_{operation.upper()}: user={user} path='{path}' status={status}")

    def log_security_violation(self, violation: str, user: str, details: str):
        """Log security violations"""
        if self.enabled:
            self.logger.warning(f"SECURITY_VIOLATION: user={user} violation='{violation}' details='{details}'")


class SecureUbuntuController:
    """Hardened Ubuntu system controller with comprehensive security"""

    def __init__(self, security_policy: SecurityPolicy):
        self.security_policy = security_policy
        self.security_checker = SecurityChecker(security_policy)
        self.audit_logger = AuditLogger(security_policy.audit_actions)
        self.logger = logging.getLogger(__name__)

        # Get current user for audit logging
        try:
            self.current_user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            self.current_user = str(os.getuid())

    async def execute_command(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        """Execute a shell command with comprehensive security controls"""
        self.audit_logger.log_command(command, self.current_user, working_dir)
        try:
            # Validate and parse command
            cmd_parts = self.security_checker.validate_command(command)

            # Validate working directory if provided
            resolved_working_dir = None
            if working_dir:
                resolved_working_dir = self.security_checker.validate_path_access(
                    working_dir, "access"
                )
                if not Path(resolved_working_dir).is_dir():
                    raise ValueError(f"Working directory does not exist or is not a directory: {resolved_working_dir}")

            # Create a controlled environment
            env = os.environ.copy()
            # Remove potentially dangerous environment variables
            dangerous_env_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'IFS']
            for var in dangerous_env_vars:
                if var in env:
                    del env[var]

            # Sanitize PATH to only include trusted directories
            trusted_paths = ['/usr/bin', '/bin', '/usr/local/bin', '/usr/sbin', '/sbin']
            env['PATH'] = ':'.join(trusted_paths)

            # Choose execution method based on policy
            if self.security_policy.use_shell_exec:
                # Legacy shell execution (less secure but more compatible)
                # The command validation must be extra strict for this mode.
                process = await asyncio.create_subprocess_shell(
                    command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=resolved_working_dir,
                    env=env,
                    preexec_fn=os.setpgrp
                )
            else:
                # Secure direct execution (recommended)
                process = await asyncio.create_subprocess_exec(
                    *cmd_parts,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=resolved_working_dir,
                    env=env,
                    preexec_fn=os.setpgrp
                )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=self.security_policy.max_command_timeout
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"Command timed out: {command}")
                # Kill the entire process group to prevent orphaned processes
                try:
                    os.killpg(os.getpgid(process.pid), 9)
                except ProcessLookupError:
                    pass  # Process might have already finished
                raise TimeoutError(f"Command timed out after {self.security_policy.max_command_timeout}s")

            # Limit output size
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')

            if len(stdout_str) > self.security_policy.max_output_size:
                stdout_str = stdout_str[:self.security_policy.max_output_size] + "\n\n[...STDOUT TRUNCATED...]"

            if len(stderr_str) > self.security_policy.max_output_size:
                stderr_str = stderr_str[:self.security_policy.max_output_size] + "\n\n[...STDERR TRUNCATED...]"

            return {
                "return_code": process.returncode,
                "stdout": stdout_str,
                "stderr": stderr_str,
                "command": command,
                "executed_as": cmd_parts,
                "working_dir": resolved_working_dir,
                "execution_method": "shell" if self.security_policy.use_shell_exec else "direct"
            }

        except SecurityViolation as e:
            self.audit_logger.log_security_violation("COMMAND_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed for '{command}': {e}", exc_info=True)
            raise

    def list_directory(self, path: str) -> List[Dict[str, Any]]:
        """List directory contents with security validation"""
        canonical_path = None
        try:
            canonical_path = self.security_checker.validate_path_access(path, "read")

            path_obj = Path(canonical_path)
            if not path_obj.is_dir():
                raise ValueError(f"Path is not a directory: {canonical_path}")

            items = []
            item_count = 0
            for item in path_obj.iterdir():
                if item_count >= self.security_policy.max_directory_items:
                    items.append({
                        "name": f"[TRUNCATED - {self.security_policy.max_directory_items} item limit reached]",
                        "type": "notice",
                        "error": ""
                    })
                    break
                item_count += 1

                try:
                    stat_info = item.stat()
                    owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                    group_name = grp.getgrgid(stat_info.st_gid).gr_name
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat_info.st_size,
                        "permissions": stat.filemode(stat_info.st_mode),
                        "owner": owner_name,
                        "group": group_name,
                        "modified": stat_info.st_mtime,
                        "is_symlink": item.is_symlink()
                    })
                except (OSError, KeyError) as e:
                    items.append({
                        "name": item.name,
                        "type": "unreadable",
                        "error": str(e)
                    })

            self.audit_logger.log_file_access("LIST", canonical_path, self.current_user, True)
            return sorted(items, key=lambda x: (x.get("type", ""), x.get("name", "")))

        except SecurityViolation as e:
            self.audit_logger.log_security_violation("DIRECTORY_LIST_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("LIST", path, self.current_user, False)
            self.logger.error(f"Directory listing failed for '{path}': {e}")
            raise

    def read_file(self, file_path: str) -> str:
        """Read file contents with security validation"""
        canonical_path = None
        try:
            canonical_path = self.security_checker.validate_file_operation(file_path, "read")

            path_obj = Path(canonical_path)
            if not path_obj.is_file():
                raise ValueError(f"Path is not a regular file: {canonical_path}")

            with open(canonical_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(self.security_policy.max_file_size + 1)

            if len(content) > self.security_policy.max_file_size:
                raise ValueError(f"File is too large to read (>{self.security_policy.max_file_size} bytes)")

            self.audit_logger.log_file_access("READ", canonical_path, self.current_user, True)
            return content

        except SecurityViolation as e:
            self.audit_logger.log_security_violation("FILE_READ_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("READ", file_path, self.current_user, False)
            self.logger.error(f"File read failed for '{file_path}': {e}")
            raise

    def write_file(self, file_path: str, content: str, create_dirs: bool = False) -> bool:
        """Write content to file with security validation"""
        canonical_path = None
        try:
            content_size = len(content.encode('utf-8'))
            canonical_path = self.security_checker.validate_file_operation(
                file_path, "write", content_size
            )

            path_obj = Path(canonical_path)

            # Create directories if requested and allowed
            if create_dirs:
                parent_dir = path_obj.parent
                if not parent_dir.exists():
                    # Validate parent directory creation is also allowed
                    self.security_checker.validate_path_access(str(parent_dir), "write")
                    parent_dir.mkdir(parents=True, exist_ok=True)

            # Create backup if file exists
            if path_obj.exists() and path_obj.is_file():
                backup_path = Path(f"{canonical_path}.backup.{int(time.time())}")
                try:
                    shutil.copy2(canonical_path, backup_path)
                    self.logger.info(f"Created backup: {backup_path}")
                except Exception as e:
                    self.logger.warning(f"Could not create backup for {canonical_path}: {e}")

            # Write to temporary file first, then atomic move for safety
            temp_fd, temp_path_str = tempfile.mkstemp(
                dir=str(path_obj.parent),
                prefix=f".{path_obj.name}.tmp-"
            )
            temp_path = Path(temp_path_str)

            try:
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    f.write(content)
                # Atomic move
                shutil.move(str(temp_path), canonical_path)
                self.audit_logger.log_file_access("WRITE", canonical_path, self.current_user, True)
                return True
            finally:
                # Ensure temp file is cleaned up on error
                if temp_path.exists():
                    temp_path.unlink()

        except SecurityViolation as e:
            self.audit_logger.log_security_violation("FILE_WRITE_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("WRITE", file_path, self.current_user, False)
            self.logger.error(f"File write failed for '{file_path}': {e}")
            raise

    def get_system_info(self) -> Dict[str, Any]:
        """Get basic system information using safe methods"""
        try:
            info = {}
            # OS Info
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = {k: v.strip('"') for k, v in (line.strip().split('=', 1) for line in f if '=' in line)}
                info["os_info"] = os_info
            except Exception:
                info["os_info"] = {"error": "Could not read OS info"}
            # Memory Info
            try:
                with open('/proc/meminfo', 'r') as f:
                    mem_lines = [line for line in f if line.startswith(('MemTotal:', 'MemAvailable:'))]
                    info["memory"] = {k.strip(): v.strip() for k, v in (line.split(':', 1) for line in mem_lines)}
            except Exception:
                info["memory"] = {"error": "Could not read memory info"}
            # Disk Usage
            try:
                disk = shutil.disk_usage('/')
                info["disk_usage_root"] = {"total": disk.total, "used": disk.used, "free": disk.free}
            except Exception:
                info["disk_usage_root"] = {"error": "Could not get disk usage"}

            info.update({
                "current_user": self.current_user,
                "hostname": os.uname().nodename, "platform": os.uname().sysname,
                "architecture": os.uname().machine
            })
            return info
        except Exception as e:
            self.logger.error(f"System info gathering failed: {e}")
            raise


def create_secure_policy() -> SecurityPolicy:
    """Create a highly secure policy for production use"""
    home_dir = os.path.expanduser("~")
    current_script = os.path.abspath(__file__)
    script_dir = os.path.dirname(current_script)

    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp"],
        forbidden_paths=["/etc", "/root", "/boot", "/sys", "/proc", "/dev", "/var/log", "/var/lib", "/usr", "/sbin",
                         "/bin"],
        max_command_timeout=15,
        max_file_size=1 * 1024 * 1024,  # 1MB
        max_output_size=256 * 1024,  # 256KB
        max_directory_items=100,
        allow_sudo=False,
        resolve_symlinks=True,
        check_file_permissions=True,
        audit_actions=True,
        use_path_cache=False,
        use_shell_exec=False,
        command_whitelist_mode=True,
        allowed_commands=[
            "ls", "cat", "echo", "pwd", "whoami", "date", "uname",
            "grep", "head", "tail", "wc", "sort", "uniq", "cut",
            "find", "which", "file", "stat", "du", "df",
            "apt"  # For package search/list
        ],
        forbidden_commands=[
            "rm", "rmdir", "dd", "mkfs", "fdisk", "cfdisk", "shutdown",
            "reboot", "halt", "init", "systemctl", "service", "mount", "umount",
            "chmod", "chown", "chgrp", "su", "sudo", "passwd", "useradd",
            "userdel", "usermod", "crontab", "at", "batch", "nohup", "pkill", "kill"
        ],
        server_executable_paths={script_dir, os.path.dirname(script_dir)},
        system_critical_paths={"/etc", "/boot", "/sys", "/proc", "/dev"}
    )


def create_development_policy() -> SecurityPolicy:
    """Create a more permissive but still secure policy for development"""
    home_dir = os.path.expanduser("~")
    current_script = os.path.abspath(__file__)
    script_dir = os.path.dirname(current_script)

    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp", "/opt", "/usr/local"],
        forbidden_paths=["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root", "/boot", "/sys", "/proc"],
        max_command_timeout=60,
        max_file_size=10 * 1024 * 1024,  # 10MB
        max_output_size=1 * 1024 * 1024,  # 1MB
        max_directory_items=500,
        allow_sudo=False,  # Still recommended to be False
        resolve_symlinks=True,
        check_file_permissions=True,
        audit_actions=True,
        use_path_cache=False,
        use_shell_exec=False,
        command_whitelist_mode=False,
        allowed_commands=[],  # Not used in non-whitelist mode
        forbidden_commands=[
            "dd", "mkfs", "fdisk", "cfdisk", "shutdown", "reboot", "halt",
            "init", "passwd", "useradd", "userdel", "usermod", "su", "sudo"
        ],
        server_executable_paths={script_dir, os.path.dirname(script_dir)},
        system_critical_paths={"/boot", "/sys", "/proc", "/dev"}
    )


def create_ubuntu_mcp_server(security_policy: SecurityPolicy) -> FastMCP:
    """Create and configure the secure Ubuntu MCP server"""
    controller = SecureUbuntuController(security_policy)
    mcp = FastMCP("Secure Ubuntu Controller")

    def format_error(e: Exception) -> str:
        return json.dumps({"error": str(e), "type": type(e).__name__}, indent=2)

    @mcp.tool("execute_command")
    async def execute_command(command: str, working_dir: str = None) -> str:
        """Executes a shell command on the Ubuntu system.
        Args:
            command: The shell command to execute.
            working_dir: Optional working directory for the command.
        Returns:
            A JSON string with the command results, including stdout, stderr, and return code.
        """
        try:
            result = await controller.execute_command(command, working_dir)
            return json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("list_directory")
    async def list_directory(path: str) -> str:
        """Lists the contents of a directory.
        Args:
            path: The directory path to list.
        Returns:
            A JSON string with the directory contents.
        """
        try:
            items = controller.list_directory(path)
            return json.dumps(items, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("read_file")
    async def read_file(file_path: str) -> str:
        """Reads the contents of a file.
        Args:
            file_path: The path to the file to read.
        Returns:
            The raw file contents as a string, or a JSON error object on failure.
        """
        try:
            return controller.read_file(file_path)
        except Exception as e:
            # Distinguish content from error by returning JSON for errors
            return format_error(e)

    @mcp.tool("write_file")
    async def write_file(file_path: str, content: str, create_dirs: bool = False) -> str:
        """Writes content to a file, creating backups of existing files.
        Args:
            file_path: The path where to write the file.
            content: The content to write.
            create_dirs: If True, create parent directories if they don't exist.
        Returns:
            A success message or a JSON error object on failure.
        """
        try:
            success = controller.write_file(file_path, content, create_dirs)
            return json.dumps({"success": success, "path": file_path})
        except Exception as e:
            return format_error(e)

    @mcp.tool("get_system_info")
    async def get_system_info() -> str:
        """Gets basic system information.
        Returns:
            A JSON string with system information.
        """
        try:
            info = controller.get_system_info()
            return json.dumps(info, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("install_package")
    async def install_package(package_name: str) -> str:
        """
        Checks if a package is available for installation using 'apt'.
        Note: For security, this tool does not actually install packages. It only lists them.
        To enable installation, the policy must allow sudo and the command must be changed.

        Args:
            package_name: The name of the package to check.

        Returns:
            JSON string with the results from 'apt list'.
        """
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.+-]+$', package_name):
                raise SecurityViolation(f"Invalid package name format: {package_name}")

            # Using 'apt list' is safer than 'apt install'
            command = f"apt list --installed {shlex.quote(package_name)}"
            result = await controller.execute_command(command)
            return json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)

    @mcp.tool("search_packages")
    async def search_packages(query: str) -> str:
        """
        Searches for packages using 'apt search'.

        Args:
            query: The search term for packages.

        Returns:
            JSON string with the search results.
        """
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.+-]+$', query):
                raise SecurityViolation(f"Invalid search query format: {query}")

            command = f"apt search {shlex.quote(query)}"
            result = await controller.execute_command(command)
            return json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)

    return mcp


async def run_security_tests():
    """Comprehensive security testing suite"""
    print("=== Running Security Tests ===")
    policy = create_secure_policy()
    # Disable shell exec for tests to ensure we are testing the secure path
    policy.use_shell_exec = False
    controller = SecureUbuntuController(policy)
    results = {}

    async def run_test(name, test_func, *args):
        try:
            await test_func(*args)
            results[name] = "❌ FAIL: Security measure was bypassed."
        except SecurityViolation:
            results[name] = "✅ PASS: Security measure worked as expected."
        except Exception as e:
            results[name] = f"❓ ERROR: Test raised an unexpected exception: {type(e).__name__}: {e}"

    # 1. Symlink attack
    test_symlink = Path("/tmp/symlink_to_etc_passwd")
    if test_symlink.exists(): test_symlink.unlink()
    if not Path("/etc/passwd").exists():
        results["Symlink Attack"] = "❓ SKIP: /etc/passwd not found."
    else:
        os.symlink("/etc/passwd", test_symlink)
        await run_test("Symlink Attack", controller.read_file, str(test_symlink))
        test_symlink.unlink()

    # 2. Path traversal
    await run_test("Path Traversal", controller.read_file, "/tmp/../../etc/passwd")

    # 3. Server file protection
    await run_test("Server File Protection", controller.read_file, __file__)

    # 4. Command injection (should be blocked by shlex parsing)
    await run_test("Command Injection (Semicolon)", controller.execute_command, "echo hello; ls /")

    # 5. Forbidden command
    await run_test("Forbidden Command (rm)", controller.execute_command, "rm -rf /")

    # 6. Command not in whitelist
    await run_test("Non-Whitelisted Command (nmap)", controller.execute_command, "nmap localhost")

    # 7. File size limit
    try:
        large_content = "x" * (policy.max_file_size + 1)
        controller.write_file("/tmp/large_file_test.txt", large_content)
        results["File Size Limit"] = "❌ FAIL: Large file write was not blocked."
    except SecurityViolation:
        results["File Size Limit"] = "✅ PASS: Large file write was blocked."
    finally:
        if os.path.exists("/tmp/large_file_test.txt"): os.remove("/tmp/large_file_test.txt")

    print("\n--- Security Test Results ---")
    for name, result in results.items():
        print(f"{name:<25} {result}")

    if any("❌ FAIL" in r for r in results.values()):
        print("\n⚠️  Security vulnerabilities detected!")
        return False
    else:
        print("\n🔒 All security tests passed!")
        return True


async def test_controller():
    """Test the Ubuntu controller functionality"""
    print("\n=== Testing Secure Ubuntu Controller Functionality ===")
    policy = create_secure_policy()
    controller = SecureUbuntuController(policy)

    try:
        print("\n1. Testing system info...")
        info = controller.get_system_info()
        print(f"  OS: {info.get('os_info', {}).get('PRETTY_NAME', 'N/A')}, User: {info['current_user']}")

        print("\n2. Testing directory listing...")
        home = os.path.expanduser("~")
        items = controller.list_directory(home)
        print(f"  Found {len(items)} items in {home}. (Truncated at {policy.max_directory_items})")

        print("\n3. Testing safe command execution...")
        res = await controller.execute_command("echo 'Hello from secure controller'")
        print(f"  Command executed. STDOUT: {res['stdout'].strip()}")
        assert res['return_code'] == 0

        print("\n4. Testing file operations...")
        test_file = "/tmp/secure_mcp_test.txt"
        test_content = "This is a test file."
        controller.write_file(test_file, test_content, create_dirs=True)
        print(f"  Wrote to {test_file}")
        read_content = controller.read_file(test_file)
        print(f"  Read back content. Match: {read_content == test_content}")
        assert read_content == test_content
        os.remove(test_file)
        if os.path.exists(f"{test_file}.backup"): os.remove(f"{test_file}.backup")
        print("  Cleaned up test file.")

        print("\n5. Testing expected security violation...")
        try:
            await controller.execute_command("sudo whoami")
        except SecurityViolation as e:
            print(f"  Correctly blocked forbidden command: {e}")

        print("\n✅ All functional tests passed!")

    except Exception as e:
        print(f"❌ A functional test failed: {e}")
        import traceback
        traceback.print_exc()


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(description="Secure Ubuntu MCP Server")
    parser.add_argument("--policy", choices=["secure", "dev"], default="dev", help="Security policy to use")
    parser.add_argument("--test", action="store_true", help="Run functionality tests")
    parser.add_argument("--security-test", action="store_true", help="Run security validation tests")
    parser.add_argument("--log-level", default="INFO", help="Logging level (e.g., DEBUG, INFO, WARNING)")

    args = parser.parse_args()

    logging.basicConfig(level=args.log_level.upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    # if args.security_test:
    #     success = await run_security_tests()
    #     sys.exit(0 if success else 1)

    # if args.test:
    #     await test_controller()
    #     return

    if args.policy == "dev":
        policy = create_development_policy()
    else:
        policy = create_secure_policy()

    print(f"Starting Secure Ubuntu MCP Server with '{args.policy}' policy...", file=sys.stderr)
    mcp_server = create_ubuntu_mcp_server(policy)
    mcp_server.run(transport="http", host="0.0.0.0", port=9000, path="/mcp")


if __name__ == "__main__":
    import argparse
    import sys

    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Secure Ubuntu MCP Server stopped by user.", file=sys.stderr)
    except Exception as e:
        logging.getLogger(__name__).critical(f"Server exited with a critical error: {e}", exc_info=True)
        sys.exit(1)