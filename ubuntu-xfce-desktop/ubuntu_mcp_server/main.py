"""
Secure Desktop MCP Server (Integrated Version)

A hardened Model Context Protocol server for controlling Ubuntu systems,
including both terminal and GUI operations.
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
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import re
import argparse
import sys
import tempfile
import os
from PIL import Image
import base64
# --- 新增：GUI 和辅助库的导入 ---
import ctypes
import ctypes.util
import numpy as np
from PIL import Image
import pyautogui

# FastMCP 库
from fastmcp import FastMCP

# --- 新增：从 actions.py 整合的常量 ---
KEYBOARD_KEYS = ['\t', '\n', '\r', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', 'accept', 'add', 'alt', 'altleft', 'altright', 'apps', 'backspace', 'browserback', 'browserfavorites', 'browserforward', 'browserhome', 'browserrefresh', 'browsersearch', 'browserstop', 'capslock', 'clear', 'convert', 'ctrl', 'ctrlleft', 'ctrlright', 'decimal', 'del', 'delete', 'divide', 'down', 'end', 'enter', 'esc', 'escape', 'execute', 'f1', 'f10', 'f11', 'f12', 'f13', 'f14', 'f15', 'f16', 'f17', 'f18', 'f19', 'f2', 'f20', 'f21', 'f22', 'f23', 'f24', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'final', 'fn', 'hanguel', 'hangul', 'hanja', 'help', 'home', 'insert', 'junja', 'kana', 'kanji', 'launchapp1', 'launchapp2', 'launchmail', 'launchmediaselect', 'left', 'modechange', 'multiply', 'nexttrack', 'nonconvert', 'num0', 'num1', 'num2', 'num3', 'num4', 'num5', 'num6', 'num7', 'num8', 'num9', 'numlock', 'pagedown', 'pageup', 'pause', 'pgdn', 'pgup', 'playpause', 'prevtrack', 'print', 'printscreen', 'prntscrn', 'prtsc', 'prtscr', 'return', 'right', 'scrolllock', 'select', 'separator', 'shift', 'shiftleft', 'shiftright', 'sleep', 'stop', 'subtract', 'tab', 'up', 'volumedown', 'volumemute', 'volumeup', 'win', 'winleft', 'winright', 'yen', 'command', 'option', 'optionleft', 'optionright']

PIXEL_DATA_PTR = ctypes.POINTER(ctypes.c_ulong)
Atom = ctypes.c_ulong

# --- 新增：从 pyxcursor.py 整合的类 ---
class Xcursor:
    import struct, array
    class XFixesCursorImage(ctypes.Structure):
        _fields_ = [('x', ctypes.c_short), ('y', ctypes.c_short), ('width', ctypes.c_ushort), ('height', ctypes.c_ushort), ('xhot', ctypes.c_ushort), ('yhot', ctypes.c_ushort), ('cursor_serial', ctypes.c_ulong), ('pixels', PIXEL_DATA_PTR), ('atom', Atom), ('name', ctypes.c_char_p)]
    class Display(ctypes.Structure): pass

    display = None
    def __init__(self, display_str=None):
        if not display_str:
            try: display_str = os.environ["DISPLAY"].encode("utf-8")
            except KeyError: raise Exception("$DISPLAY not set.")
        XFixes = ctypes.util.find_library("Xfixes")
        if not XFixes: raise Exception("No XFixes library found.")
        self.XFixeslib = ctypes.cdll.LoadLibrary(XFixes)
        x11 = ctypes.util.find_library("X11")
        if not x11: raise Exception("No X11 library found.")
        self.xlib = ctypes.cdll.LoadLibrary(x11)
        XFixesGetCursorImage = self.XFixeslib.XFixesGetCursorImage
        XFixesGetCursorImage.restype = ctypes.POINTER(self.XFixesCursorImage)
        XFixesGetCursorImage.argtypes = [ctypes.POINTER(self.Display)]
        self.XFixesGetCursorImage = XFixesGetCursorImage
        XOpenDisplay = self.xlib.XOpenDisplay
        XOpenDisplay.restype = ctypes.POINTER(self.Display)
        XOpenDisplay.argtypes = [ctypes.c_char_p]
        if not self.display: self.display = self.xlib.XOpenDisplay(display_str)
    def getCursorImageData(self):
        cursor_data = self.XFixesGetCursorImage(self.display)
        if not (cursor_data and cursor_data[0]): raise Exception("Cannot read XFixesGetCursorImage()")
        return cursor_data[0]
    def getCursorImageArrayFast(self):
        data = self.getCursorImageData()
        height, width = data.height, data.width
        bytearr = ctypes.cast(data.pixels, ctypes.POINTER(ctypes.c_ulong * height * width))[0]
        imgarray = np.array(bytearray(bytearr))
        imgarray = imgarray.reshape(height, width, 8)[:, :, (0, 1, 2, 3)]
        return imgarray


# 异步助手
async def run_sync_in_executor(sync_fn, *args, **kwargs):
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: sync_fn(*args, **kwargs))

# --- 安全框架 (来自您的代码) ---
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
    # --- 新增：GUI 策略 ---
    allow_gui_operations: bool = True
    
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
        self._path_resolution_cache = {}
        self._cache_max_age = 300  # 5 minutes
        self._cache_timestamps = {}

    def _get_cache_key(self, path: str) -> str:
        return hashlib.sha256(path.encode()).hexdigest()

    def _is_cache_valid(self, cache_key: str) -> bool:
        if cache_key not in self._cache_timestamps:
            return False
        return time.time() - self._cache_timestamps[cache_key] < self._cache_max_age

    def resolve_path_safely(self, path: str) -> str:
        if self.policy.use_path_cache:
            cache_key = self._get_cache_key(path)
            if self._is_cache_valid(cache_key):
                return self._path_resolution_cache[cache_key]
        try:
            path_obj = Path(os.path.abspath(path))
            if self.policy.resolve_symlinks:
                resolved_path = path_obj.resolve(strict=False)
            else:
                resolved_path = path_obj.absolute()
            canonical_path = str(resolved_path)
            if self.policy.use_path_cache:
                cache_key = self._get_cache_key(path)
                self._path_resolution_cache[cache_key] = canonical_path
                self._cache_timestamps[cache_key] = time.time()
            return canonical_path
        except (OSError, RuntimeError) as e:
            self.logger.warning(f"Path resolution failed for {path}: {e}")
            raise SecurityViolation(f"Cannot resolve path: {path}")

    def validate_path_access(self, path: str, operation: str = "access") -> str:
        canonical_path = self.resolve_path_safely(path)
        for server_path in self.policy.server_executable_paths:
            if canonical_path.startswith(server_path):
                raise SecurityViolation(f"Access denied to server files: {canonical_path}")
        for critical_path in self.policy.system_critical_paths:
            if canonical_path.startswith(critical_path):
                raise SecurityViolation(f"Access denied to critical system path: {canonical_path}")
        for forbidden in self.policy.forbidden_paths:
            forbidden_canonical = self.resolve_path_safely(forbidden)
            if canonical_path.startswith(forbidden_canonical):
                raise SecurityViolation(f"Path explicitly forbidden: {canonical_path}")
        path_allowed = False
        if not self.policy.allowed_paths:
            path_allowed = True
        else:
            for allowed in self.policy.allowed_paths:
                allowed_canonical = self.resolve_path_safely(allowed)
                if canonical_path.startswith(allowed_canonical):
                    path_allowed = True
                    break
        if not path_allowed:
            raise SecurityViolation(f"Path not in allowed locations: {canonical_path}")
        if self.policy.check_file_permissions and Path(canonical_path).exists():
            self._check_file_permissions(canonical_path, operation)
        return canonical_path

    def _check_file_permissions(self, path: str, operation: str):
        try:
            path_obj = Path(path)
            stat_info = path_obj.stat()
            current_uid = os.getuid()
            current_gids = [os.getgid()] + os.getgroups()
            file_mode = stat_info.st_mode
            has_perm = False
            if operation in ["read", "access"]:
                if stat_info.st_uid == current_uid and (file_mode & stat.S_IRUSR): has_perm = True
                elif stat_info.st_gid in current_gids and (file_mode & stat.S_IRGRP): has_perm = True
                elif file_mode & stat.S_IROTH: has_perm = True
            elif operation in ["write", "modify"]:
                if stat_info.st_uid == current_uid and (file_mode & stat.S_IWUSR): has_perm = True
                elif stat_info.st_gid in current_gids and (file_mode & stat.S_IWGRP): has_perm = True
                elif file_mode & stat.S_IWOTH: has_perm = True
            if not has_perm:
                raise SecurityViolation(f"Insufficient permissions for {operation} on {path}")
        except OSError as e:
            raise SecurityViolation(f"Cannot check permissions for {path}: {e}")

    def validate_command(self, command: str) -> List[str]:
        if not command.strip():
            raise SecurityViolation("Empty command not allowed")
        try:
            cmd_parts = shlex.split(command.strip())
        except ValueError as e:
            raise SecurityViolation(f"Invalid command syntax: {e}")
        if not cmd_parts:
            raise SecurityViolation("Empty command after parsing")
        base_command = cmd_parts[0]
        if base_command == 'sudo':
            if not self.policy.allow_sudo:
                raise SecurityViolation("Sudo commands are not allowed by the current security policy.")
            if len(cmd_parts) < 2:
                raise SecurityViolation("Invalid sudo command: missing command to execute.")
            base_command = cmd_parts[1]
        full_command_path = shutil.which(base_command)
        if not full_command_path:
            if os.path.isabs(base_command) and os.path.exists(base_command) and os.access(base_command, os.X_OK):
                full_command_path = base_command
            else:
                raise SecurityViolation(f"Command not found or not executable: {base_command}")
        command_basename = os.path.basename(full_command_path)
        if command_basename in self.policy.forbidden_commands:
            raise SecurityViolation(f"Command explicitly forbidden: {command_basename}")
        if self.policy.command_whitelist_mode:
            if not self.policy.allowed_commands:
                raise SecurityViolation("No commands are allowed (command whitelist is empty).")
            if command_basename not in self.policy.allowed_commands:
                raise SecurityViolation(f"Command not in whitelist: {command_basename}")
        dangerous_patterns = {'`': "Backticks", '$(': "Dollar-parenthesis", ';': "Semicolon", '&&': "AND", '||': "OR", '|': "Pipe"}
        full_command_str = ' '.join(cmd_parts)
        for pattern, desc in dangerous_patterns.items():
            if pattern in full_command_str:
                if pattern == '|' and command_basename in self.policy.allowed_commands:
                    continue
                self.logger.warning(f"Potentially dangerous pattern '{pattern}' detected in command: {full_command_str}")
                if self.policy.use_shell_exec:
                    raise SecurityViolation(f"Dangerous pattern detected in shell command: {desc}")
        return cmd_parts

    def validate_file_operation(self, path: str, operation: str, size: Optional[int] = None) -> str:
        canonical_path = self.validate_path_access(path, operation)
        if size is not None and size > self.policy.max_file_size:
            raise SecurityViolation(f"File content size {size} exceeds limit {self.policy.max_file_size}")
        if operation == "read" and Path(canonical_path).exists():
            current_size = Path(canonical_path).stat().st_size
            if current_size > self.policy.max_file_size:
                raise SecurityViolation(f"Existing file is too large to read: {current_size} bytes")
        return canonical_path

class AuditLogger:
    """Security audit logging"""
    def __init__(self, enabled: bool = True, log_file: str = '/tmp/desktop_mcp_audit.log'):
        self.enabled = enabled
        self.logger = logging.getLogger(f"{__name__}.audit")
        if enabled:
            if not self.logger.handlers:
                try:
                    audit_handler = logging.FileHandler(log_file)
                    audit_formatter = logging.Formatter('%(asctime)s - AUDIT - %(levelname)s - %(message)s')
                    audit_handler.setFormatter(audit_formatter)
                    self.logger.addHandler(audit_handler)
                    self.logger.setLevel(logging.INFO)
                    self.logger.propagate = False
                except (OSError, PermissionError) as e:
                    logging.getLogger(__name__).error(f"Failed to configure audit logger at {log_file}: {e}")
                    self.enabled = False
    def log_command(self, command: str, user: str, working_dir: Optional[str] = None):
        if self.enabled: self.logger.info(f"COMMAND_ATTEMPT: user={user} cmd='{command}' cwd={working_dir or 'default'}")
    def log_file_access(self, operation: str, path: str, user: str, success: bool):
        if self.enabled:
            status = "SUCCESS" if success else "FAILED"
            self.logger.info(f"FILE_{operation.upper()}: user={user} path='{path}' status={status}")
    def log_security_violation(self, violation: str, user: str, details: str):
        if self.enabled: self.logger.warning(f"SECURITY_VIOLATION: user={user} violation='{violation}' details='{details}'")

# --- 修改：将 SecureUbuntuController 重命名并扩展 ---
class SecureDesktopController:
    """
    统一的控制器，包含安全的终端和桌面GUI操作。
    """
    def __init__(self, security_policy: SecurityPolicy):
        self.security_policy = security_policy
        self.security_checker = SecurityChecker(security_policy)
        self.audit_logger = AuditLogger(security_policy.audit_actions)
        self.logger = logging.getLogger(__name__)
        try:
            self.current_user = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            self.current_user = str(os.getuid())

        # --- 新增：GUI 组件初始化 ---
        if self.security_policy.allow_gui_operations:
            self.logger.info("GUI operations are enabled. Initializing GUI components.")
            self.xcursor = Xcursor()
            pyautogui.FAILSAFE = False
            pyautogui.PAUSE = 0.1 # 添加一个小的延迟，使操作更稳定
            self.pyautogui = pyautogui
        else:
            self.logger.warning("GUI operations are disabled by security policy.")
            self.xcursor = None
            self.pyautogui = None

    def _check_gui_allowed(self):
        """检查 GUI 操作是否被策略允许"""
        if not self.security_policy.allow_gui_operations or not self.pyautogui:
            raise SecurityViolation("GUI operations are disabled by the current security policy.")

    # --- 终端操作方法 ---
    async def execute_command(self, command: str, working_dir: Optional[str] = None) -> Dict[str, Any]:
        self.audit_logger.log_command(command, self.current_user, working_dir)
        try:
            cmd_parts = self.security_checker.validate_command(command)
            resolved_working_dir = None
            if working_dir:
                resolved_working_dir = self.security_checker.validate_path_access(working_dir, "access")
                if not Path(resolved_working_dir).is_dir():
                    raise ValueError(f"Working directory does not exist or is not a directory: {resolved_working_dir}")
            env = os.environ.copy()
            dangerous_env_vars = ['LD_PRELOAD', 'LD_LIBRARY_PATH', 'IFS']
            for var in dangerous_env_vars:
                if var in env: del env[var]
            trusted_paths = ['/usr/bin', '/bin', '/usr/local/bin', '/usr/sbin', '/sbin']
            env['PATH'] = ':'.join(trusted_paths)
            if self.security_policy.use_shell_exec:
                process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=resolved_working_dir, env=env, preexec_fn=os.setpgrp)
            else:
                process = await asyncio.create_subprocess_exec(*cmd_parts, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, cwd=resolved_working_dir, env=env, preexec_fn=os.setpgrp)
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.security_policy.max_command_timeout)
            except asyncio.TimeoutError:
                self.logger.warning(f"Command timed out: {command}")
                try: os.killpg(os.getpgid(process.pid), 9)
                except ProcessLookupError: pass
                raise TimeoutError(f"Command timed out after {self.security_policy.max_command_timeout}s")
            stdout_str = stdout.decode('utf-8', errors='replace')
            stderr_str = stderr.decode('utf-8', errors='replace')
            if len(stdout_str) > self.security_policy.max_output_size:
                stdout_str = stdout_str[:self.security_policy.max_output_size] + "\n\n[...STDOUT TRUNCATED...]"
            if len(stderr_str) > self.security_policy.max_output_size:
                stderr_str = stderr_str[:self.security_policy.max_output_size] + "\n\n[...STDERR TRUNCATED...]"
            return {"return_code": process.returncode, "stdout": stdout_str, "stderr": stderr_str, "command": command, "executed_as": cmd_parts, "working_dir": resolved_working_dir, "execution_method": "shell" if self.security_policy.use_shell_exec else "direct"}
        except SecurityViolation as e:
            self.audit_logger.log_security_violation("COMMAND_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.logger.error(f"Command execution failed for '{command}': {e}", exc_info=True)
            raise

    def list_directory(self, path: str) -> List[Dict[str, Any]]:
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
                    items.append({"name": f"[TRUNCATED - {self.security_policy.max_directory_items} item limit reached]", "type": "notice", "error": ""})
                    break
                item_count += 1
                try:
                    stat_info = item.stat()
                    owner_name = pwd.getpwuid(stat_info.st_uid).pw_name
                    group_name = grp.getgrgid(stat_info.st_gid).gr_name
                    items.append({"name": item.name, "path": str(item), "type": "directory" if item.is_dir() else "file", "size": stat_info.st_size, "permissions": stat.filemode(stat_info.st_mode), "owner": owner_name, "group": group_name, "modified": stat_info.st_mtime, "is_symlink": item.is_symlink()})
                except (OSError, KeyError) as e:
                    items.append({"name": item.name, "type": "unreadable", "error": str(e)})
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
        canonical_path = None
        try:
            content_size = len(content.encode('utf-8'))
            canonical_path = self.security_checker.validate_file_operation(file_path, "write", content_size)
            path_obj = Path(canonical_path)
            if create_dirs:
                parent_dir = path_obj.parent
                if not parent_dir.exists():
                    self.security_checker.validate_path_access(str(parent_dir), "write")
                    parent_dir.mkdir(parents=True, exist_ok=True)
            if path_obj.exists() and path_obj.is_file():
                backup_path = Path(f"{canonical_path}.backup.{int(time.time())}")
                try:
                    shutil.copy2(canonical_path, backup_path)
                    self.logger.info(f"Created backup: {backup_path}")
                except Exception as e:
                    self.logger.warning(f"Could not create backup for {canonical_path}: {e}")
            temp_fd, temp_path_str = tempfile.mkstemp(dir=str(path_obj.parent), prefix=f".{path_obj.name}.tmp-")
            temp_path = Path(temp_path_str)
            try:
                with os.fdopen(temp_fd, 'w', encoding='utf-8') as f:
                    f.write(content)
                shutil.move(str(temp_path), canonical_path)
                self.audit_logger.log_file_access("WRITE", canonical_path, self.current_user, True)
                return True
            finally:
                if temp_path.exists(): temp_path.unlink()
        except SecurityViolation as e:
            self.audit_logger.log_security_violation("FILE_WRITE_BLOCKED", self.current_user, str(e))
            raise
        except Exception as e:
            self.audit_logger.log_file_access("WRITE", file_path, self.current_user, False)
            self.logger.error(f"File write failed for '{file_path}': {e}")
            raise

    def get_system_info(self) -> Dict[str, Any]:
        try:
            info = {}
            try:
                with open('/etc/os-release', 'r') as f:
                    os_info = {k: v.strip('"') for k, v in (line.strip().split('=', 1) for line in f if '=' in line)}
                info["os_info"] = os_info
            except Exception: info["os_info"] = {"error": "Could not read OS info"}
            try:
                with open('/proc/meminfo', 'r') as f:
                    mem_lines = [line for line in f if line.startswith(('MemTotal:', 'MemAvailable:'))]
                    info["memory"] = {k.strip(): v.strip() for k, v in (line.split(':', 1) for line in mem_lines)}
            except Exception: info["memory"] = {"error": "Could not read memory info"}
            try:
                disk = shutil.disk_usage('/')
                info["disk_usage_root"] = {"total": disk.total, "used": disk.used, "free": disk.free}
            except Exception: info["disk_usage_root"] = {"error": "Could not get disk usage"}
            info.update({"current_user": self.current_user, "hostname": os.uname().nodename, "platform": os.uname().sysname, "architecture": os.uname().machine})
            return info
        except Exception as e:
            self.logger.error(f"System info gathering failed: {e}")
            raise

    # --- 新增的 GUI 操作方法 ---
    async def get_screenshot(self) -> bytes:
        """
        获取屏幕截图，包含鼠标指针。
        此版本会先将截图保存为临时文件，然后读取文件内容返回。
        """
        self._check_gui_allowed()
        def take_screenshot_and_encode():
            # 使用临时文件保存截图
            fd, temp_path = tempfile.mkstemp(suffix=".png")
            os.close(fd)

            try:
                # 截取屏幕并包含鼠标
                img_array = self.xcursor.getCursorImageArrayFast()
                cursor_img = Image.fromarray(img_array)
                screenshot = self.pyautogui.screenshot()
                cursor_x, cursor_y = self.pyautogui.position()
                screenshot.paste(cursor_img, (cursor_x, cursor_y), cursor_img)
                screenshot.save(temp_path, 'PNG')

                # 读取文件的二进制内容
                with open(temp_path, 'rb') as f:
                    image_bytes = f.read()
                
                # 3. 将二进制数据编码为Base64字符串
                base64_encoded_string = base64.b64encode(image_bytes).decode('utf-8')
                
                return base64_encoded_string
            
            finally:
                # 清理临时文件
                if os.path.exists(temp_path):
                    os.remove(temp_path)

        return await run_sync_in_executor(take_screenshot_and_encode)
    # async def get_screenshot(self) -> bytes:
    #     self._check_gui_allowed()
    #     def take_screenshot():
    #         from io import BytesIO
    #         img_io = BytesIO()
    #         imgarray = self.xcursor.getCursorImageArrayFast()
    #         cursor_img = Image.fromarray(imgarray)
    #         screenshot = self.pyautogui.screenshot()
    #         cursor_x, cursor_y = self.pyautogui.position()
    #         screenshot.paste(cursor_img, (cursor_x, cursor_y), cursor_img)
    #         screenshot.save(img_io, 'PNG')
    #         img_io.seek(0)
    #         return img_io.read()
    #     return await run_sync_in_executor(take_screenshot)

    async def move_to(self, x: float, y: float, duration: float = 0.5):
        self._check_gui_allowed()
        await run_sync_in_executor(self.pyautogui.moveTo, x, y, duration=duration)

    async def click(self, button: str = 'left', x: Optional[float] = None, y: Optional[float] = None, clicks: int = 1):
        self._check_gui_allowed()
        await run_sync_in_executor(self.pyautogui.click, x=x, y=y, clicks=clicks, button=button)

    async def right_click(self, x: Optional[float] = None, y: Optional[float] = None):
        self._check_gui_allowed()
        await run_sync_in_executor(self.pyautogui.rightClick, x=x, y=y)

    async def double_click(self, x: Optional[float] = None, y: Optional[float] = None):
        self._check_gui_allowed()
        await run_sync_in_executor(self.pyautogui.doubleClick, x=x, y=y)

    async def drag(self, x: float, y: float, duration: float = 1.0):
        self._check_gui_allowed()
        await run_sync_in_executor(self.pyautogui.dragTo, x, y, duration=duration)

    async def scroll(self, dx: int = 0, dy: int = 0):
        self._check_gui_allowed()
        if dx != 0: await run_sync_in_executor(self.pyautogui.hscroll, dx)
        if dy != 0: await run_sync_in_executor(self.pyautogui.vscroll, dy)

    async def type(self, text: str):
        self._check_gui_allowed()
        await run_sync_in_executor(self.pyautogui.typewrite, text)

    async def press(self, key: str):
        self._check_gui_allowed()
        if key.lower() not in KEYBOARD_KEYS: raise SecurityViolation(f"Invalid key '{key}'")
        await run_sync_in_executor(self.pyautogui.press, key)

    async def hotkey(self, keys: List[str]):
        self._check_gui_allowed()
        for key in keys:
            if key.lower() not in KEYBOARD_KEYS: raise SecurityViolation(f"Invalid key '{key}'")
        await run_sync_in_executor(self.pyautogui.hotkey, *keys)

def create_development_policy() -> SecurityPolicy:
    home_dir = os.path.expanduser("~")
    current_script = os.path.abspath(__file__)
    script_dir = os.path.dirname(current_script)
    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp", "/opt", "/usr/local"],
        forbidden_paths=["/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root", "/boot", "/sys", "/proc"],
        max_command_timeout=60, max_file_size=10 * 1024 * 1024, max_output_size=1 * 1024 * 1024, max_directory_items=500,
        allow_sudo=False, resolve_symlinks=True, check_file_permissions=True, audit_actions=True,
        use_path_cache=False, use_shell_exec=False, command_whitelist_mode=False, allowed_commands=[],
        forbidden_commands=["dd", "mkfs", "fdisk", "cfdisk", "shutdown", "reboot", "halt", "init", "passwd", "useradd", "userdel", "usermod", "su", "sudo"],
        server_executable_paths={script_dir, os.path.dirname(script_dir)},
        system_critical_paths={"/boot", "/sys", "/proc", "/dev"},
        allow_gui_operations=True
    )

def create_secure_policy() -> SecurityPolicy:
    home_dir = os.path.expanduser("~")
    current_script = os.path.abspath(__file__)
    script_dir = os.path.dirname(current_script)
    return SecurityPolicy(
        allowed_paths=[home_dir, "/tmp", "/var/tmp"],
        forbidden_paths=["/etc", "/root", "/boot", "/sys", "/proc", "/dev", "/var/log", "/var/lib", "/usr", "/sbin", "/bin"],
        max_command_timeout=15, max_file_size=1 * 1024 * 1024, max_output_size=256 * 1024, max_directory_items=100,
        allow_sudo=False, resolve_symlinks=True, check_file_permissions=True, audit_actions=True,
        use_path_cache=False, use_shell_exec=False, command_whitelist_mode=True,
        allowed_commands=["ls", "cat", "echo", "pwd", "whoami", "date", "uname", "grep", "head", "tail", "wc", "sort", "uniq", "cut", "find", "which", "file", "stat", "du", "df", "apt"],
        forbidden_commands=["rm", "rmdir", "dd", "mkfs", "fdisk", "cfdisk", "shutdown", "reboot", "halt", "init", "systemctl", "service", "mount", "umount", "chmod", "chown", "chgrp", "su", "sudo", "passwd", "useradd", "userdel", "usermod", "crontab", "at", "batch", "nohup", "pkill", "kill"],
        server_executable_paths={script_dir, os.path.dirname(script_dir)},
        system_critical_paths={"/etc", "/boot", "/sys", "/proc", "/dev"},
        allow_gui_operations=True
    )

# --- 修改：create_ubuntu_mcp_server -> create_desktop_mcp_server ---
def create_desktop_mcp_server(security_policy: SecurityPolicy) -> FastMCP:
    """创建并配置安全的桌面 MCP 服务器"""
    controller = SecureDesktopController(security_policy)
    mcp = FastMCP("Secure Desktop Controller")

    def format_error(e: Exception) -> str:
        return json.dumps({"error": str(e), "type": type(e).__name__}, indent=2)

    # --- 注册终端工具 ---
    @mcp.tool("execute_command")
    async def execute_command(command: str, working_dir: str = None) -> str:
        try: return json.dumps(await controller.execute_command(command, working_dir), indent=2)
        except Exception as e: return format_error(e)

    @mcp.tool("list_directory")
    async def list_directory(path: str) -> str:
        try: return json.dumps(controller.list_directory(path), indent=2)
        except Exception as e: return format_error(e)

    @mcp.tool("read_file")
    async def read_file(file_path: str) -> str:
        try: return controller.read_file(file_path)
        except Exception as e: return format_error(e)

    @mcp.tool("write_file")
    async def write_file(file_path: str, content: str, create_dirs: bool = False) -> str:
        try:
            success = controller.write_file(file_path, content, create_dirs)
            return json.dumps({"success": success, "path": file_path})
        except Exception as e: return format_error(e)

    @mcp.tool("get_system_info")
    async def get_system_info() -> str:
        try: return json.dumps(controller.get_system_info(), indent=2)
        except Exception as e: return format_error(e)
        
    @mcp.tool("install_package")
    async def install_package(package_name: str) -> str:
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.+-]+$', package_name):
                raise SecurityViolation(f"Invalid package name format: {package_name}")
            command = f"apt list --installed {shlex.quote(package_name)}"
            result = await controller.execute_command(command)
            return json.dumps(result, indent=2)
        except Exception as e: return format_error(e)
        
    @mcp.tool("search_packages")
    async def search_packages(query: str) -> str:
        try:
            if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.+-]+$', query):
                raise SecurityViolation(f"Invalid search query format: {query}")
            command = f"apt search {shlex.quote(query)}"
            result = await controller.execute_command(command)
            return json.dumps(result, indent=2)
        except Exception as e: return format_error(e)

    # --- 新增：注册 GUI 工具 ---
    @mcp.tool("get_screenshot")
    async def get_screenshot() -> bytes:
        try: return await controller.get_screenshot()
        except Exception as e: return str(e).encode('utf-8')

    @mcp.tool("move_to")
    async def move_to(x: float, y: float, duration: float = 0.5) -> str:
        try: await controller.move_to(x, y, duration); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    @mcp.tool("click")
    async def click(button: str = 'left', x: Optional[float] = None, y: Optional[float] = None, clicks: int = 1) -> str:
        try: await controller.click(button, x, y, clicks); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)
    
    @mcp.tool("right_click")
    async def right_click(x: Optional[float] = None, y: Optional[float] = None) -> str:
        try: await controller.right_click(x, y); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)
        
    @mcp.tool("double_click")
    async def double_click(x: Optional[float] = None, y: Optional[float] = None) -> str:
        try: await controller.double_click(x, y); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    @mcp.tool("drag")
    async def drag(x: float, y: float, duration: float = 1.0) -> str:
        try: await controller.drag(x, y, duration); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    @mcp.tool("scroll")
    async def scroll(dx: int = 0, dy: int = 0) -> str:
        try: await controller.scroll(dx, dy); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    @mcp.tool("type")
    async def type(text: str) -> str:
        try: await controller.type(text); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    @mcp.tool("press")
    async def press(key: str) -> str:
        try: await controller.press(key); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    @mcp.tool("hotkey")
    async def hotkey(keys: List[str]) -> str:
        try: await controller.hotkey(keys); return json.dumps({"status": "success"})
        except Exception as e: return format_error(e)

    return mcp

def main():
    """主命令行入口"""
    parser = argparse.ArgumentParser(description="Secure Desktop MCP Server")
    parser.add_argument("--policy", choices=["secure", "dev"], default="dev", help="Security policy to use")
    parser.add_argument("--log-level", default="INFO", help="Logging level (e.g., DEBUG, INFO, WARNING)")
    args = parser.parse_args()
    logging.basicConfig(level=args.log_level.upper(), format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # 根据命令行参数选择策略
    if args.policy == "dev":
        policy = create_development_policy()
    else:
        policy = create_secure_policy()

    print(f"Starting Secure Desktop MCP Server with '{args.policy}' policy...", file=sys.stderr)
    mcp_server = create_desktop_mcp_server(policy)
    mcp_server.run(transport="http", host="0.0.0.0", port=9000, path="/mcp")

    # async def session_handler(session):
    #     # fastmcp 的工具是在 mcp 实例上全局注册的，
    #     # 所以会话处理器只需要保持会话活动即可
    #     print(f"New HTTP session started: {session.session_id}")
    #     await session.initialize()
    #     await session.wait_closed()
    #     print(f"HTTP session closed: {session.session_id}")

    # print(f"Starting MCP server with HTTP transport on http://0.0.0.0:9000/mcp", file=sys.stderr)
    # asyncio.run(run_http_server(
    #     mcp_server,
    #     session_handler,
    #     host="0.0.0.0",
    #     port=9000,
    #     path="/mcp"
    # ))
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Secure Desktop MCP Server stopped by user.", file=sys.stderr)
    except Exception as e:
        logging.getLogger(__name__).critical(f"Server exited with a critical error: {e}", exc_info=True)
        sys.exit(1)