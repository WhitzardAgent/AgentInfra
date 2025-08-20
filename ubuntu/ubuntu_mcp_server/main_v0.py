import subprocess
import threading
import time
import select
import os
import signal
import pty
import termios
import fcntl
from typing import Optional, Callable, Dict, Any
from dataclasses import dataclass
from enum import Enum
import logging
from fastmcp import FastMCP

class CommandStatus(Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TERMINATED = "terminated"

@dataclass
class CommandResult:
    command: str
    status: CommandStatus
    stdout: str
    stderr: str
    return_code: Optional[int]
    execution_time: float
    pid: Optional[int] = None

class BashExecutor:
    def __init__(self, timeout: int = 30, max_output_size: int = 1024*1024):
        """
        Initialize BashExecutor
        
        Args:
            timeout: Default timeout for commands in seconds
            max_output_size: Maximum output size to prevent memory issues
        """
        self.timeout = timeout
        self.max_output_size = max_output_size
        self.master_fd = None
        self.slave_fd = None
        self.process = None
        self.background_processes: Dict[int, subprocess.Popen] = {}
        self.interactive_mode = False
        self.output_callback: Optional[Callable[[str], None]] = None
        self.current_working_dir = os.getcwd()
        
        # Initialize the bash session
        self._start_session()
    
    def _start_session(self):
        """Start a new bash session using pty for full terminal emulation"""
        try:
            # Create a pseudo-terminal
            self.master_fd, self.slave_fd = pty.openpty()
            
            # Start bash process
            self.process = subprocess.Popen(
                ['/bin/bash', '-i'],  # Interactive bash
                stdin=self.slave_fd,
                stdout=self.slave_fd,
                stderr=self.slave_fd,
                preexec_fn=os.setsid,
                env=os.environ.copy(),
                cwd=self.current_working_dir
            )
            
            # Set non-blocking mode for master fd
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, os.O_NONBLOCK)
            
            # Wait a bit for bash to initialize
            time.sleep(0.1)
            self._clear_initial_output()
            
        except Exception as e:
            raise RuntimeError(f"Failed to start bash session: {e}")
    
    def _clear_initial_output(self):
        """Clear any initial bash output (like welcome messages)"""
        try:
            while True:
                ready, _, _ = select.select([self.master_fd], [], [], 0.1)
                if not ready:
                    break
                os.read(self.master_fd, 1024)
        except OSError:
            pass
    
    def execute(self, command: str, timeout: Optional[int] = None, 
                background: bool = False, working_dir: Optional[str] = None) -> CommandResult:
        """
        Execute a command in the bash session
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds (None for no timeout)
            background: Whether to run command in background
            working_dir: Working directory for the command (None to use current)
            
        Returns:
            CommandResult with execution details
        """
        if timeout is None:
            timeout = self.timeout
        
        start_time = time.time()
        
        # Handle working directory change
        original_dir = None
        if working_dir and working_dir != self.get_working_directory():
            original_dir = self.get_working_directory()
            if not self._change_directory_internal(working_dir):
                return CommandResult(
                    command=command,
                    status=CommandStatus.FAILED,
                    stdout="",
                    stderr=f"Failed to change to directory: {working_dir}",
                    return_code=1,
                    execution_time=0
                )
        
        try:
            if background:
                result = self._execute_background(command, timeout)
            else:
                result = self._execute_foreground(command, timeout, start_time)
        finally:
            # Restore original directory if it was changed
            if original_dir:
                self._change_directory_internal(original_dir)
        
        return result
    
    def _change_directory_internal(self, path: str) -> bool:
        """Internal method to change directory"""
        try:
            # Expand path
            expanded_path = os.path.expanduser(path)
            if not os.path.isabs(expanded_path):
                expanded_path = os.path.abspath(expanded_path)
            
            # Check if directory exists
            if not os.path.exists(expanded_path):
                return False
            
            if not os.path.isdir(expanded_path):
                return False
            
            # Send cd command
            cd_command = f"cd '{expanded_path}'\n"
            os.write(self.master_fd, cd_command.encode())
            
            # Wait a bit for command to execute
            time.sleep(0.1)
            
            # Clear any output
            self._clear_output_buffer()
            
            self.current_working_dir = expanded_path
            return True
            
        except Exception:
            return False
    
    def _clear_output_buffer(self):
        """Clear output buffer"""
        try:
            while True:
                ready, _, _ = select.select([self.master_fd], [], [], 0.05)
                if not ready:
                    break
                os.read(self.master_fd, 1024)
        except OSError:
            pass
    
    def _execute_foreground(self, command: str, timeout: int, start_time: float) -> CommandResult:
        """Execute command in foreground"""
        try:
            # Send command
            full_command = f"{command}\n"
            os.write(self.master_fd, full_command.encode())
            
            # Read output
            stdout_data = ""
            stderr_data = ""
            
            while True:
                elapsed = time.time() - start_time
                if timeout > 0 and elapsed > timeout:
                    return CommandResult(
                        command=command,
                        status=CommandStatus.FAILED,
                        stdout=stdout_data,
                        stderr="Command timed out",
                        return_code=None,
                        execution_time=elapsed
                    )
                
                # Check for output
                ready, _, _ = select.select([self.master_fd], [], [], 0.1)
                if ready:
                    try:
                        data = os.read(self.master_fd, 4096).decode('utf-8', errors='ignore')
                        stdout_data += data
                        
                        # Call output callback if set
                        if self.output_callback:
                            self.output_callback(data)
                        
                        # Check if command completed (simple heuristic)
                        if self._is_command_complete(stdout_data, command):
                            break
                            
                        # Prevent memory issues
                        if len(stdout_data) > self.max_output_size:
                            stdout_data = stdout_data[-self.max_output_size//2:] + "\n[... output truncated ...]\n"
                            
                    except OSError:
                        break
            
            execution_time = time.time() - start_time
            
            # Clean up output (remove command echo and prompt)
            cleaned_output = self._clean_output(stdout_data, command)
            
            return CommandResult(
                command=command,
                status=CommandStatus.COMPLETED,
                stdout=cleaned_output,
                stderr=stderr_data,
                return_code=0,  # We can't easily get return code with pty
                execution_time=execution_time
            )
            
        except Exception as e:
            return CommandResult(
                command=command,
                status=CommandStatus.FAILED,
                stdout="",
                stderr=str(e),
                return_code=1,
                execution_time=time.time() - start_time
            )
    
    def _execute_background(self, command: str, timeout: int) -> CommandResult:
        """Execute command in background"""
        try:
            # Add & to make it background if not already present
            if not command.strip().endswith('&'):
                command = command + ' &'
            
            result = self._execute_foreground(command, timeout, time.time())
            
            # Try to extract PID from output
            pid = self._extract_pid_from_output(result.stdout)
            result.pid = pid
            
            return result
            
        except Exception as e:
            return CommandResult(
                command=command,
                status=CommandStatus.FAILED,
                stdout="",
                stderr=str(e),
                return_code=1,
                execution_time=0
            )
    
    def start_interactive(self, command: str, working_dir: Optional[str] = None, 
                         output_callback: Optional[Callable[[str], None]] = None):
        """
        Start an interactive command (like nc, python, etc.)
        
        Args:
            command: Interactive command to start
            working_dir: Working directory for the command
            output_callback: Function to call with output data
        """
        # Handle working directory change
        if working_dir and working_dir != self.get_working_directory():
            if not self._change_directory_internal(working_dir):
                raise RuntimeError(f"Failed to change to directory: {working_dir}")
        
        self.interactive_mode = True
        self.output_callback = output_callback
        
        # Start the interactive command
        full_command = f"{command}\n"
        os.write(self.master_fd, full_command.encode())
        
        # Start output reading thread
        self.output_thread = threading.Thread(target=self._read_interactive_output)
        self.output_thread.daemon = True
        self.output_thread.start()
    
    def send_interactive_input(self, input_data: str):
        """Send input to interactive command"""
        if not self.interactive_mode:
            raise RuntimeError("Not in interactive mode")
        
        if not input_data.endswith('\n'):
            input_data += '\n'
        
        os.write(self.master_fd, input_data.encode())
    
    def stop_interactive(self):
        """Stop interactive mode"""
        if self.interactive_mode:
            # Send Ctrl+C
            os.write(self.master_fd, b'\x03')
            time.sleep(0.1)
            self.interactive_mode = False
            self.output_callback = None
    
    def _read_interactive_output(self):
        """Read output in interactive mode"""
        while self.interactive_mode:
            try:
                ready, _, _ = select.select([self.master_fd], [], [], 0.1)
                if ready:
                    data = os.read(self.master_fd, 4096).decode('utf-8', errors='ignore')
                    if self.output_callback:
                        self.output_callback(data)
            except OSError:
                break
    
    def _is_command_complete(self, output: str, command: str) -> bool:
        """
        Heuristic to determine if command has completed
        This is a simple implementation - could be improved
        """
        lines = output.strip().split('\n')
        if len(lines) < 2:
            return False
        
        # Look for bash prompt patterns
        last_line = lines[-1].strip()
        prompt_patterns = ['$', '#', '>', '>>>']
        
        # Check if last line looks like a prompt
        for pattern in prompt_patterns:
            if last_line.endswith(pattern):
                return True
        
        return False
    
    def _clean_output(self, output: str, command: str) -> str:
        """Clean command output by removing command echo and prompts"""
        lines = output.split('\n')
        cleaned_lines = []
        
        skip_first_command = True
        for line in lines:
            # Skip the first occurrence of the command itself
            if skip_first_command and command.strip() in line:
                skip_first_command = False
                continue
            
            # Skip obvious prompt lines
            stripped = line.strip()
            if stripped and not any(stripped.endswith(p) for p in ['$', '#'] if len(stripped) < 50):
                cleaned_lines.append(line)
            elif not stripped.endswith('$') and not stripped.endswith('#'):
                cleaned_lines.append(line)
        
        # Remove last line if it looks like a prompt
        if cleaned_lines and len(cleaned_lines[-1].strip()) < 10:
            cleaned_lines = cleaned_lines[:-1]
        
        return '\n'.join(cleaned_lines).strip()
    
    def _extract_pid_from_output(self, output: str) -> Optional[int]:
        """Extract PID from background command output"""
        import re
        # Look for patterns like [1] 12345
        pid_match = re.search(r'\[\d+\]\s+(\d+)', output)
        if pid_match:
            return int(pid_match.group(1))
        return None
    
    def get_working_directory(self) -> str:
        """Get current working directory"""
        result = self.execute("pwd", timeout=5)
        if result.status == CommandStatus.COMPLETED:
            return result.stdout.strip()
        return self.current_working_dir
    
    def change_directory(self, path: str) -> bool:
        """Change working directory"""
        return self._change_directory_internal(path)
    
    def is_alive(self) -> bool:
        """Check if bash session is still alive"""
        return self.process and self.process.poll() is None
    
    def restart_session(self):
        """Restart the bash session"""
        self.close()
        self._start_session()
    
    def close(self):
        """Close the bash session and cleanup"""
        self.interactive_mode = False
        
        if self.process:
            try:
                # Send exit command
                os.write(self.master_fd, b"exit\n")
                time.sleep(0.1)
                
                # Terminate process if still running
                if self.process.poll() is None:
                    os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                    time.sleep(0.5)
                    
                    if self.process.poll() is None:
                        os.killpg(os.getpgid(self.process.pid), signal.SIGKILL)
                        
            except:
                pass
            finally:
                self.process = None
        
        # Close file descriptors
        if self.master_fd:
            os.close(self.master_fd)
            self.master_fd = None
        if self.slave_fd:
            os.close(self.slave_fd)
            self.slave_fd = None
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


# Global executor instance for MCP tools
_global_executor: Optional[BashExecutor] = None
_interactive_output_buffer: str = ""

def _get_executor() -> BashExecutor:
    """Get or create global executor instance"""
    global _global_executor
    if _global_executor is None or not _global_executor.is_alive():
        if _global_executor:
            _global_executor.close()
        _global_executor = BashExecutor()
    return _global_executor

def _interactive_output_handler(data: str):
    """Handle interactive output by storing in buffer"""
    global _interactive_output_buffer
    _interactive_output_buffer += data


# Cleanup function for when the module is unloaded
def cleanup():
    """Cleanup function to close executor"""
    global _global_executor
    if _global_executor:
        _global_executor.close()
        _global_executor = None


# Register cleanup on exit
import atexit
atexit.register(cleanup)


def create_ubuntu_mcp_server() -> FastMCP:
    """Create and configure the secure Ubuntu MCP server"""
    mcp = FastMCP("Secure Ubuntu Controller")

    # MCP Tool Wrappers
    @mcp.tool("execute_command")
    def execute_command(
        command: str,
        working_dir: str,
        timeout: int = 25,
        interactive: int = 0,
    ) -> str:
        """
        Runs a shell command on the system.
        Args:
            command: The command to run.
            working_dir: Directory to run the command in.
            timeout: Time to wait (in seconds). Must be more than 0.
            interactive: Set to 1 if the command needs input (like asking for user name). Use 0 for normal commands.
        Returns:
            A simple result message with output or error.
        """
        try:
            if timeout <= 0:
                return "Error: timeout must be greater than 0"
            
            executor = _get_executor()
            
            # Validate working directory
            expanded_dir = os.path.expanduser(working_dir)
            if not os.path.isabs(expanded_dir):
                expanded_dir = os.path.abspath(expanded_dir)
            
            if not os.path.exists(expanded_dir):
                return f"Error: Directory does not exist: {expanded_dir}"
            
            if not os.path.isdir(expanded_dir):
                return f"Error: Path is not a directory: {expanded_dir}"
            
            # Execute command
            if interactive == 1:
                # For interactive commands, start the interactive session
                executor.start_interactive(command, working_dir=expanded_dir, 
                                        output_callback=_interactive_output_handler)
                return f"Interactive command '{command}' started in {expanded_dir}. Use send_interactive_input to send input and stop_interactive to end."
            else:
                result = executor.execute(command, timeout=timeout, working_dir=expanded_dir)
                
                if result.status == CommandStatus.COMPLETED:
                    output_text = f"Command executed successfully in {working_dir}\n"
                    output_text += f"Execution time: {result.execution_time:.2f}s\n"
                    if result.stdout:
                        output_text += f"Output:\n{result.stdout}"
                    else:
                        output_text += "No output"
                    return output_text
                else:
                    error_text = f"Command failed in {working_dir}\n"
                    error_text += f"Status: {result.status.value}\n"
                    if result.stderr:
                        error_text += f"Error: {result.stderr}"
                    elif result.stdout:
                        error_text += f"Output: {result.stdout}"
                    return error_text
                    
        except Exception as e:
            return f"Error executing command: {str(e)}"


    @mcp.tool("start_interactive")
    def start_interactive(
        command: str,
        working_dir: str,
    ) -> str:
        """
        Start an interactive command that can receive input.
        Args:
            command: The interactive command to start (e.g., 'python3', 'nc localhost 8080', 'mysql').
            working_dir: Directory to run the command in.
        Returns:
            A message indicating the interactive command has started.
        """
        try:
            executor = _get_executor()
            
            # Validate working directory
            expanded_dir = os.path.expanduser(working_dir)
            if not os.path.isabs(expanded_dir):
                expanded_dir = os.path.abspath(expanded_dir)
            
            if not os.path.exists(expanded_dir):
                return f"Error: Directory does not exist: {expanded_dir}"
            
            if not os.path.isdir(expanded_dir):
                return f"Error: Path is not a directory: {expanded_dir}"
            
            # Clear output buffer
            global _interactive_output_buffer
            _interactive_output_buffer = ""
            
            # Start interactive command
            executor.start_interactive(command, working_dir=expanded_dir, 
                                    output_callback=_interactive_output_handler)
            
            # Wait a bit for command to start and collect initial output
            time.sleep(0.5)
            
            initial_output = _interactive_output_buffer
            response = f"Interactive command '{command}' started in {expanded_dir}."
            if initial_output:
                response += f"\nInitial output:\n{initial_output}"
            
            return response
            
        except Exception as e:
            return f"Error starting interactive command: {str(e)}"


    @mcp.tool("send_interactive_input")
    def send_interactive_input(input_data: str) -> str:
        """
        Send input to the currently running interactive command.
        Args:
            input_data: The input to send to the interactive command.
        Returns:
            Any output received after sending the input, or an error message.
        """
        try:
            executor = _get_executor()
            
            if not executor.interactive_mode:
                return "Error: No interactive command is currently running. Use start_interactive first."
            
            # Clear output buffer before sending input
            global _interactive_output_buffer
            _interactive_output_buffer = ""
            
            # Send input
            executor.send_interactive_input(input_data)
            
            # Wait for output
            time.sleep(0.5)
            
            # Return collected output
            output = _interactive_output_buffer
            if output:
                return f"Input sent. Output:\n{output}"
            else:
                return "Input sent. No immediate output received."
                
        except Exception as e:
            return f"Error sending input: {str(e)}"


    @mcp.tool("stop_interactive")
    def stop_interactive() -> str:
        """
        Stop the currently running interactive command.
        Returns:
            A message indicating the interactive command has been stopped.
        """
        try:
            executor = _get_executor()
            
            if not executor.interactive_mode:
                return "No interactive command is currently running."
            
            # Stop interactive mode
            executor.stop_interactive()
            
            # Wait a bit and collect any final output
            time.sleep(0.5)
            
            global _interactive_output_buffer
            final_output = _interactive_output_buffer
            
            response = "Interactive command stopped."
            if final_output:
                response += f"\nFinal output:\n{final_output}"
            
            return response
            
        except Exception as e:
            return f"Error stopping interactive command: {str(e)}"
    return mcp



def main():
    """Main entry point"""

    print(f"Starting Secure Ubuntu MCP Server ...", file=sys.stderr)
    mcp_server = create_ubuntu_mcp_server()
    mcp_server.run(transport="http", host="0.0.0.0", port=9000, path="/mcp")


if __name__ == "__main__":
    import argparse
    import sys
    def output_handler(data):
        print(f"Interactive output: {data}", end='')
    # executor = BashExecutor(conda_env=None, use_truncate=True)
    with BashExecutor() as executor:
        print("Starting interactive Python session...")
        executor.start_interactive("nc node5.buuoj.cn 25574", output_callback=output_handler)
        
        # Send some Python commands
        time.sleep(5)  # Wait for Python to start
        # executor.send_interactive_input("print('Hello from Python!')")
        # executor.send_interactive_input("x = 42")
        # executor.send_interactive_input("print(f'The answer is {x}')")
        # executor.send_interactive_input("import sys")
        # executor.send_interactive_input("print(sys.version)")
        
        # Let it run for a bit
        time.sleep(2)
        
        # Stop interactive session
        executor.stop_interactive()
        print("\nInteractive session ended.")

    # # These commands maintain state
    # print(executor.bash_send_line("cd /tmp"))
    # print(executor.bash_send_line("pwd"))  # Will show /tmp
    # print(executor.bash_send_line("nc node5.buuoj.cn 25574"))  # Interactive!
    # # print(executor._execute_bash_command("32", "/tmp")) 
    # executor.close()
    # try:
    #     main()
    # except KeyboardInterrupt:
    #     print("\n👋 Ubuntu MCP Server stopped by user.", file=sys.stderr)
    # except Exception as e:
    #     logging.getLogger(__name__).critical(f"Server exited with a critical error: {e}", exc_info=True)
    #     sys.exit(1)