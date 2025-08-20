import os
import sys
import subprocess
import threading
import time
import select
import pty
import shlex
import json
import re
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import deque
import tempfile
import signal
import fcntl
import termios
from fastmcp import FastMCP

def format_terminal_result(result: dict) -> str:
    """
    Format terminal execution result dict into a readable string with emojis.
    
    Args:
        result: Dictionary containing terminal result info.
        
    Returns:
        Formatted multi-line string summarizing key information with emojis.
    """
    success = result.get("success", False)
    output_lines = result.get("output", [])
    session = result.get("session", "unknown")
    command = result.get("command", "(no command)")
    interactive = result.get("interactive", False)
    wait_duration = result.get("wait_duration", 0)
    working_directory = result.get("working_directory", "Unknown")
    error = result.get("error")

    lines = []
    lines.append(f"👉 Command: {command}")
    lines.append(f"🖥️ Session: {session}")
    lines.append(f"✅ Success: {'Yes' if success else 'No'}")
    lines.append(f"📂 Working Directory: {working_directory}")
    lines.append(f"🎛️ Interactive Session: {'Yes' if interactive else 'No'}")
    lines.append(f"⏱️ Wait Duration: {wait_duration:.2f}s")

    if success:
        lines.append("📰 Output:")
        if output_lines:
            lines.extend(f"  {line}" for line in output_lines)
        else:
            lines.append("  (No output)")

        if "info" in result:
            lines.append(f"ℹ️ Info: {result['info']}")
        if "warning" in result:
            lines.append(f"⚠️ Warning: {result['warning']}")


    else:
        lines.append(f"❌ Error: {error if error else 'Unknown error'}")
        lines.append("📰 Output: (No output)")

    return "\n".join(lines)

@dataclass
class TerminalSession:
    """Represents a terminal session"""
    session_id: str
    process: subprocess.Popen
    master_fd: int
    output_buffer: deque
    current_dir: str
    env: Dict[str, str]
    is_active: bool = True
    is_interactive: bool = False
    last_activity: float = field(default_factory=time.time)
    waiting_for_silence: bool = False
    silence_threshold: float = 1.0  # Wait 1 second of silence

class SilenceAwareTerminalSimulator:
    """
    Terminal simulator that waits for output silence in interactive processes
    """
    
    def __init__(self, max_output_lines: int = 1000, max_wait_time: float = 120.0, cwd: str = "/home/sandbox"):
        self.sessions: Dict[str, TerminalSession] = {}
        self.active_session_id: Optional[str] = None
        self.max_output_lines = max_output_lines
        self.max_wait_time = max_wait_time
        self.command_history: List[str] = []
        self.output_threads: Dict[str, threading.Thread] = {}
        self.silence_events: Dict[str, threading.Event] = {}
        self.cwd = cwd
        
        # Interactive command detection
        self.interactive_commands = {
            'nc', 'netcat', 'telnet', 'ssh', 'ftp', 'sftp', 'mysql', 'psql', 
            'mongo', 'redis-cli', 'python', 'python3', 'node', 'irb', 'php',
            'gdb', 'lldb', 'sqlite3', 'psql', 'nmap', 'curl', 'wget'
        }
        
        # Different silence thresholds for different command types
        self.silence_thresholds = {
            'fast': 0.5,    # For shell commands, quick responses
            'normal': 1.0,  # For most interactive commands
            'slow': 2.0,    # For network operations, slow services
            'very_slow': 5.0  # For very slow operations
        }
        
        # Create default session
        self.create_session("default")
        self.switch_session("default")
    
    def create_session(self, session_id: str, shell: str = "/bin/bash") -> bool:
        """Create a new terminal session"""
        if session_id in self.sessions:
            return False
        
        try:
            master_fd, slave_fd = pty.openpty()
            
            # Configure terminal for raw mode
            attrs = termios.tcgetattr(slave_fd)
            # Don't modify echo settings for better interactive compatibility
            termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)
            
            # Make master_fd non-blocking
            flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
            fcntl.fcntl(master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            env = os.environ.copy()
            env['TERM'] = 'xterm-256color'
            env['PS1'] = f'[{session_id}] \\w $ '
            env['COLUMNS'] = '120'
            env['LINES'] = '30'
            env['PYTHONUNBUFFERED'] = '1'
            
            process = subprocess.Popen(
                [shell, '-i'],
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                env=env,
                preexec_fn=os.setsid,
                cwd=self.cwd
            )
            
            os.close(slave_fd)
            
            session = TerminalSession(
                session_id=session_id,
                process=process,
                master_fd=master_fd,
                output_buffer=deque(maxlen=self.max_output_lines),
                current_dir=self.cwd,
                env=env
            )
            
            self.sessions[session_id] = session
            self.silence_events[session_id] = threading.Event()
            
            self._start_silence_aware_thread(session_id)
            
            # Wait for initial shell setup
            time.sleep(0.3)
            
            return True
            
        except Exception as e:

            print(f"Error creating session {session_id}: {e}")
            return False
    
    def _start_silence_aware_thread(self, session_id: str):
        """Output thread that detects when output stops (silence)"""
        def monitor_output_silence():
            session = self.sessions[session_id]
            silence_event = self.silence_events[session_id]
            buffer = b""
            
            while session.is_active and session.process.poll() is None:
                try:
                    # Check for available data
                    ready, _, _ = select.select([session.master_fd], [], [], 0.1)
                    
                    if ready:
                        try:
                            data = os.read(session.master_fd, 4096)
                            if data:
                                # Update activity timestamp
                                session.last_activity = time.time()
                                buffer += data
                                
                                # Process all complete lines immediately
                                while b'\n' in buffer or b'\r' in buffer:
                                    if b'\n' in buffer:
                                        line, buffer = buffer.split(b'\n', 1)
                                    else:
                                        line, buffer = buffer.split(b'\r', 1)
                                    
                                    try:
                                        text = line.decode('utf-8', errors='replace').rstrip('\r')
                                        session.output_buffer.append(text)
                                    except:
                                        continue
                                
                                # Handle partial buffer (might be prompt or partial output)
                                if buffer:
                                    # Wait a tiny bit to see if it's just a partial read
                                    time.sleep(0.05)
                                    
                                    # Check if more data is immediately available
                                    ready_check, _, _ = select.select([session.master_fd], [], [], 0)
                                    if not ready_check:
                                        # No immediate data, check if this looks like a prompt
                                        try:
                                            text = buffer.decode('utf-8', errors='replace').rstrip('\r\n')
                                            if text and len(text) < 1000:  # Reasonable prompt size
                                                session.output_buffer.append(text)
                                                buffer = b""
                                        except:
                                            buffer = b""
                        
                        except (OSError, BlockingIOError):
                            continue
                    
                    # Check for silence if we're waiting for it
                    if session.waiting_for_silence:
                        silence_duration = time.time() - session.last_activity
                        if silence_duration >= session.silence_threshold:
                            session.waiting_for_silence = False
                            silence_event.set()
                    
                    time.sleep(0.01)  # Small sleep to prevent excessive CPU usage
                    
                except Exception as e:
                    print(f"Silence monitor error for {session_id}: {e}")
                    break
        
        thread = threading.Thread(target=monitor_output_silence, daemon=True)
        thread.start()
        self.output_threads[session_id] = thread
    
    def _determine_silence_threshold(self, command: str) -> float:
        """Determine appropriate silence threshold based on command type"""
        command_lower = command.lower()
        
        # Network operations - need longer silence threshold
        if any(cmd in command_lower for cmd in ['nc ', 'netcat', 'telnet', 'ssh', 'curl', 'wget', 'ping']):
            return self.silence_thresholds['slow']
        
        # Database operations
        elif any(cmd in command_lower for cmd in ['mysql', 'psql', 'mongo', 'sqlite']):
            return self.silence_thresholds['normal']
        
        # Interactive interpreters
        elif any(cmd in command_lower for cmd in ['python', 'node', 'irb', 'php']):
            return self.silence_thresholds['normal']
        
        # Slow operations
        elif any(cmd in command_lower for cmd in ['nmap', 'find /', 'grep -r']):
            return self.silence_thresholds['very_slow']
        
        # Fast shell commands
        else:
            return self.silence_thresholds['fast']
    
    def _detect_interactive_command(self, command: str) -> bool:
        """Detect if a command is likely to be interactive"""
        parts = shlex.split(command.strip()) if command.strip() else []
        if not parts:
            return False
        
        cmd_name = os.path.basename(parts[0])
        return cmd_name in self.interactive_commands
    
    def send_line(self, command: str) -> Dict[str, Any]:
        """
        Send command and wait for output silence
        """
        if command.startswith("__term_"):
            return self._handle_special_command(command)
        
        if not self.active_session_id or self.active_session_id not in self.sessions:
            return {
                "success": False,
                "error": "No active session",
                "output": [],
                "session": None
            }
        
        session = self.sessions[self.active_session_id]
        silence_event = self.silence_events[self.active_session_id]
        
        # Clear previous event
        silence_event.clear()
        
        # Record initial state
        initial_buffer_len = len(session.output_buffer)
        is_interactive = self._detect_interactive_command(command)
        
        # Set appropriate silence threshold
        session.silence_threshold = self._determine_silence_threshold(command)
        
        try:
            # Send command
            if command.strip():
                command_bytes = (command + '\n').encode('utf-8')
                os.write(session.master_fd, command_bytes)
                self.command_history.append(command)
            else:
                # Empty command (just enter) - useful in interactive sessions
                os.write(session.master_fd, b'\n')
            
            # Update activity time and start waiting for silence
            session.last_activity = time.time()
            session.waiting_for_silence = True
            
            # Wait for silence (no more output)
            start_wait = time.time()
            silence_achieved = silence_event.wait(timeout=self.max_wait_time)
            wait_duration = time.time() - start_wait
            
            # Collect all output since command was sent
            current_buffer_len = len(session.output_buffer)
            if current_buffer_len > initial_buffer_len:
                new_output = list(session.output_buffer)[initial_buffer_len:]
            else:
                new_output = []
            
            # Update interactive status based on output
            session.is_interactive = self._appears_interactive(new_output)
            
            # Prepare response
            result = {
                "success": True,
                "output": new_output,
                "session": self.active_session_id,
                "command": command,
                "interactive": session.is_interactive,
                "silence_achieved": silence_achieved,
                "wait_duration": round(wait_duration, 2),
                "silence_threshold": session.silence_threshold,
                "working_directory": self._get_current_directory()
            }
            
            # Add context-specific information
            if session.is_interactive:
                result["info"] = "Interactive session detected. Continue sending input."
            
            if not silence_achieved:
                result["warning"] = f"Silence not achieved within {self.max_wait_time}s. Output may still be coming."
            
            if wait_duration > 10:
                result["info"] = f"Long operation detected (waited {wait_duration:.1f}s for silence)."
            
            return result
            
        except Exception as e:
            session.waiting_for_silence = False
            return {
                "success": False,
                "error": str(e),
                "output": [],
                "session": self.active_session_id
            }
        finally:
            session.waiting_for_silence = False
    
    def _appears_interactive(self, output_lines: List[str]) -> bool:
        """Determine if current state appears interactive based on output"""
        if not output_lines:
            return False
        
        # Join recent output
        recent_text = '\n'.join(output_lines[-10:]).lower()
        
        # Interactive session indicators
        interactive_patterns = [
            r'connected to',
            r'connection established', 
            r'escape character',
            r'login\s*:',
            r'password\s*:',
            r'username\s*:',
            r'>>>\s*$',     # Python prompt
            r'>\s*$',       # Generic prompt  
            r'mysql>\s*$',
            r'psql>\s*$',
            r'sqlite>\s*$',
            r'redis>\s*$',
            r'ftp>\s*$',
            r'\(gdb\)\s*$',
            r'welcome\s+to',
            r'type\s+help',
            r'enter\s+command',
        ]
        
        # Check patterns
        for pattern in interactive_patterns:
            if re.search(pattern, recent_text, re.MULTILINE | re.IGNORECASE):
                return True
        
        # Check last line for prompt-like patterns
        if output_lines:
            last_line = output_lines[-1].strip()
            prompt_indicators = ['$ ', '# ', '> ', '>>> ', ': ', '? ', 'login:', 'password:']
            if any(last_line.endswith(indicator) for indicator in prompt_indicators):
                return True
        
        return False
    
    def set_silence_threshold(self, threshold: float) -> Dict[str, Any]:
        """Manually set silence threshold for current session"""
        if not self.active_session_id:
            return {"success": False, "error": "No active session"}
        
        session = self.sessions[self.active_session_id]
        old_threshold = session.silence_threshold
        session.silence_threshold = threshold
        
        return {
            "success": True,
            "old_threshold": old_threshold,
            "new_threshold": threshold,
            "output": [f"Silence threshold changed from {old_threshold}s to {threshold}s"]
        }
    
    def send_control_char(self, char: str) -> Dict[str, Any]:
        """Send control characters and wait for silence"""
        if not self.active_session_id or self.active_session_id not in self.sessions:
            return {"success": False, "error": "No active session"}
        
        session = self.sessions[self.active_session_id]
        silence_event = self.silence_events[self.active_session_id]
        
        control_chars = {
            'C': b'\x03',  # Ctrl+C (SIGINT)
            'D': b'\x04',  # Ctrl+D (EOF)
            'Z': b'\x1a',  # Ctrl+Z (SIGTSTP)
            '\\': b'\x1c', # Ctrl+\ (SIGQUIT)
        }
        
        if char.upper() not in control_chars:
            return {"success": False, "error": f"Unknown control character: {char}"}
        
        try:
            initial_buffer_len = len(session.output_buffer)
            silence_event.clear()
            
            # Set shorter threshold for control characters
            original_threshold = session.silence_threshold
            session.silence_threshold = 1.0
            
            session.last_activity = time.time()
            session.waiting_for_silence = True
            
            os.write(session.master_fd, control_chars[char.upper()])
            
            # Wait for silence after control character
            silence_achieved = silence_event.wait(timeout=10.0)
            
            # Collect output
            current_buffer_len = len(session.output_buffer)
            if current_buffer_len > initial_buffer_len:
                new_output = list(session.output_buffer)[initial_buffer_len:]
            else:
                new_output = []
            
            # Control-C usually exits interactive mode
            if char.upper() == 'C':
                session.is_interactive = False
            
            # Restore original threshold
            session.silence_threshold = original_threshold
            
            return {
                "success": True,
                "output": new_output,
                "control_char": f"Ctrl+{char.upper()}",
                "session": self.active_session_id,
                "silence_achieved": silence_achieved,
                "interactive": session.is_interactive
            }
            
        except Exception as e:
            session.silence_threshold = original_threshold
            return {"success": False, "error": str(e)}
        finally:
            session.waiting_for_silence = False
    
    def _handle_special_command(self, command: str) -> Dict[str, Any]:
        """Handle special terminal simulator commands"""
        parts = command.split()
        cmd = parts[0]
        
        if cmd == "__term_threshold" and len(parts) > 1:
            try:
                threshold = float(parts[1])
                return self.set_silence_threshold(threshold)
            except ValueError:
                return {"success": False, "error": "Invalid threshold value"}
        
        elif cmd == "__term_status":
            if self.active_session_id:
                session = self.sessions[self.active_session_id]
                return {
                    "success": True,
                    "session_id": self.active_session_id,
                    "interactive": session.is_interactive,
                    "waiting_for_silence": session.waiting_for_silence,
                    "silence_threshold": session.silence_threshold,
                    "last_activity": time.time() - session.last_activity,
                    "buffer_size": len(session.output_buffer),
                    "process_alive": session.process.poll() is None,
                    "output": [
                        f"Session: {self.active_session_id}",
                        f"Interactive: {session.is_interactive}",
                        f"Waiting for silence: {session.waiting_for_silence}",
                        f"Silence threshold: {session.silence_threshold}s",
                        f"Time since last activity: {time.time() - session.last_activity:.1f}s"
                    ]
                }
            return {"success": False, "error": "No active session"}
        
        elif cmd == "__term_ctrl" and len(parts) > 1:
            return self.send_control_char(parts[1])
        
        elif cmd == "__term_help":
            help_text = [
                "Silence-Aware Terminal Simulator Commands:",
                "__term_status - Show detailed session status",
                "__term_threshold <seconds> - Set silence threshold",  
                "__term_ctrl <char> - Send control character (C, D, Z, \\)",
                "__term_new <name> - Create new session", 
                "__term_switch <name> - Switch to session",
                "__term_kill <name> - Kill session",
                "",
                "Silence Detection:",
                "- Waits until interactive processes stop outputting",
                "- Different thresholds for different command types",
                "- Network commands: 2.0s silence threshold",
                "- Shell commands: 0.5s silence threshold", 
                "- Interactive programs: 1.0s silence threshold"
            ]
            return {"success": True, "output": help_text}
        
        # Include other commands from previous implementation
        elif cmd == "__term_sessions":
            session_info = []
            for sid, session in self.sessions.items():
                info = {
                    "id": sid,
                    "active": sid == self.active_session_id,
                    "interactive": session.is_interactive,
                    "waiting_for_silence": session.waiting_for_silence,
                    "silence_threshold": session.silence_threshold,
                    "pid": session.process.pid,
                    "alive": session.process.poll() is None
                }
                session_info.append(info)
            
            return {
                "success": True,
                "sessions": session_info,
                "active": self.active_session_id,
            }
        
        elif cmd == "__term_new" and len(parts) > 1:
            session_id = parts[1]
            success = self.create_session(session_id)
            return {
                "success": success,
                "output": [f"Created session: {session_id}" if success 
                          else f"Failed to create session: {session_id}"]
            }
        
        elif cmd == "__term_switch" and len(parts) > 1:
            session_id = parts[1]
            success = self.switch_session(session_id)
            return {
                "success": success,
                "output": [f"Switched to session: {session_id}" if success 
                          else f"Session not found: {session_id}"],
                "session": self.active_session_id
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown special command: {command}",
                "output": []
            }
    
    # Remaining methods (switch_session, kill_session, etc.)
    def switch_session(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            return False
        self.active_session_id = session_id
        return True
    
    def list_sessions(self) -> List[str]:
        return list(self.sessions.keys())
    
    def kill_session(self, session_id: str) -> bool:
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        session.is_active = False
        session.waiting_for_silence = False
        
        try:
            os.killpg(os.getpgid(session.process.pid), signal.SIGTERM)
            session.process.wait(timeout=5)
        except:
            try:
                os.killpg(os.getpgid(session.process.pid), signal.SIGKILL)
            except:
                pass
        
        try:
            os.close(session.master_fd)
        except:
            pass
        
        del self.sessions[session_id]
        if session_id in self.silence_events:
            del self.silence_events[session_id]
        
        if self.active_session_id == session_id:
            if self.sessions:
                self.active_session_id = next(iter(self.sessions.keys()))
            else:
                self.active_session_id = None
        
        return True
    
    def _get_current_directory(self) -> str:
        if not self.active_session_id:
            return self.cwd
        try:
            session = self.sessions[self.active_session_id]
            return session.current_dir
        except:
            return self.cwd
    
    def cleanup(self):
        for session_id in list(self.sessions.keys()):
            self.kill_session(session_id)


# Final MCP interface
class SilenceAwareMCPInterface:
    def __init__(self, cwd: str):
        self.terminal = SilenceAwareTerminalSimulator(cwd=cwd)
    
    def send_line(self, line: str) -> str:
        """Send line and wait for output silence"""
        result = self.terminal.send_line(line)
        return format_terminal_result(result) 
    
    def __del__(self):
        if hasattr(self, 'terminal'):
            self.terminal.cleanup()
# Final MCP interface
def create_ubuntu_mcp_server():
    terminal_interface = SilenceAwareMCPInterface(cwd='/home/sandbox/')
    print(terminal_interface.terminal.sessions)
    mcp = FastMCP("Secure Ubuntu Controller")

    
    @mcp.tool("send_line")
    def send_line(
        command: str,
        timeout: int = 120,
        session_id: str = "default",
    ) -> str:
        """
        Sends a line of input (command) to a terminal session and waits for output.

        Automatically switches to or creates the specified terminal session if necessary.
        Waits for the command output to complete within the specified timeout.

        Args:
            command: The command or input line to send to the terminal session.
            timeout: Maximum time to wait for command output in seconds (default: 120).
            session_id: Terminal session to use (defaults to "default").

        Returns:
            JSON string containing execution results, output, and session status.
        """
        try:
            # Switch to specified session if needed
            if session_id != "default":
                # Try to switch to session, create if it doesn't exist
                switch_result = terminal_interface.send_line(f"__term_switch {session_id}")
                if "Success: Yes" in switch_result:
                    # Session doesn't exist, create it
                    create_result = terminal_interface.send_line(f"__term_new {session_id}")
                    if "Success: Yes" in create_result:
                        terminal_interface.send_line(f"__term_switch {session_id}")

            # Update terminal's max wait time
            terminal_interface.terminal.max_wait_time = timeout

            # Send the command/input line
            result = terminal_interface.send_line(command)
            return result

        except Exception as e:
            error_result = {
                "success": False,
                "error": f"Terminal execution error: {str(e)}.",
                "output": [],
                "session": session_id
            }
            return json.dumps(error_result, indent=2)
    
    @mcp.tool("send_control_signal")
    def send_control_signal(
        signal: str,
        session_id: str = "default"
    ) -> str:
        """
        Sends a control signal to interrupt or control interactive processes.
        
        Args:
            signal: Control signal to send (C, D, Z, or \\)
                   C = Ctrl+C (interrupt), D = Ctrl+D (EOF), Z = Ctrl+Z (suspend), \\ = Ctrl+\\ (quit)
            session_id: Terminal session to send signal to
            
        Returns:
            JSON string with signal result and any output
        """
        try:
            # Switch to session if needed
            if session_id != "default":
                terminal_interface.send_line(f"__term_switch {session_id}")
            
            result = terminal_interface.send_line(f"__term_ctrl {signal}")
            return result
            
        except Exception as e:
            error_result = {
                "success": False,
                "error": f"Control signal error: {str(e)}",
                "signal": signal,
                "session": session_id
            }
            return json.dumps(error_result, indent=2)
    
    @mcp.tool("manage_terminal_session")
    def manage_terminal_session(
        action: str,
        session_id: str = None
    ) -> str:
        """
        Manages terminal sessions (list, create, switch, kill, status).
        
        Args:
            action: Action to perform - "list", "create", "switch", "kill", "status"
            session_id: Session ID for create/switch/kill actions (not needed for list/status)
            
        Returns:
            JSON string with action result and session information
        """
        try:
            if action == "list":
                result = terminal_interface.send_line("__term_sessions")
            elif action == "status":
                result = terminal_interface.send_line("__term_status")
            elif action == "create" and session_id:
                result = terminal_interface.send_line(f"__term_new {session_id}")
            elif action == "switch" and session_id:
                result = terminal_interface.send_line(f"__term_switch {session_id}")
            elif action == "kill" and session_id:
                result = terminal_interface.send_line(f"__term_kill {session_id}")
            else:
                error_result = {
                    "success": False,
                    "error": f"Invalid action '{action}' or missing session_id",
                    "valid_actions": ["list", "create", "switch", "kill", "status"]
                }
                return json.dumps(error_result, indent=2)
            
            return result
            
        except Exception as e:
            error_result = {
                "success": False,
                "error": f"Session management error: {str(e)}",
                "action": action,
                "session_id": session_id
            }
            return json.dumps(error_result, indent=2)
    
    @mcp.tool("get_terminal_help")
    def get_terminal_help() -> str:
        """
        Get help information about terminal simulator capabilities.
        
        Returns:
            JSON string with help information and usage examples
        """
        try:
            result = terminal_interface.send_line("__term_help")
            return result
        except Exception as e:
            error_result = {
                "success": False,
                "error": f"Help error: {str(e)}"
            }
            return json.dumps(error_result, indent=2)
    return mcp

# Demo showing silence detection
def silence_demo():
    print("Silence-Aware Terminal Simulator Demo")
    print("=" * 50)
    
    term = SilenceAwareMCPInterface()
    
    commands = [
        "echo 'Testing silence detection'",
        "__term_status",
        "nc node5.buuoj.cn 25915",  # Will wait until no more connection output
        "11",         # Will wait until server stops responding
        "4",             # Check current status  
        "6",
    ]
    
    for i, cmd in enumerate(commands):
        print(f"\n[{i+1}] > {cmd}")
        print("Waiting for output silence...")
        
        start_time = time.time()
        response = term.send_line(cmd)
        elapsed = time.time() - start_time
        
        result = json.loads(response)
        
        print(f"Silence achieved in {elapsed:.2f}s")
        
        if result.get("success"):
            output = result.get("output", [])
            print(f"Output lines: {len(output)}")
            
            for line in output[-5:]:  # Show last 5 lines
                print(f"  {line}")
            
            if result.get("interactive"):
                print("  [Interactive mode]")
            if result.get("silence_achieved"):
                print(f"  [Silence achieved after {result.get('wait_duration', 0)}s]")
            if result.get("warning"):
                print(f"  [Warning: {result.get('warning')}]")
        else:
            print(f"Error: {result.get('error')}")
        
        print("-" * 30)





def main():
    """Main entry point"""

    print(f"Starting Secure Ubuntu MCP Server ...", file=sys.stderr)
    mcp_server = create_ubuntu_mcp_server()
    mcp_server.run(transport="http", host="0.0.0.0", port=9000, path="/mcp")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Ubuntu MCP Server stopped by user.", file=sys.stderr)
    except Exception as e:
        # logging.getLogger(__name__).critical(f"Server exited with a critical error: {e}", exc_info=True)
        sys.exit(1)