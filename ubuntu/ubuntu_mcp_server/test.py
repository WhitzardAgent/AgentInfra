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
                env=os.environ.copy()
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
                background: bool = False) -> CommandResult:
        """
        Execute a command in the bash session
        
        Args:
            command: Command to execute
            timeout: Timeout in seconds (None for no timeout)
            background: Whether to run command in background
            
        Returns:
            CommandResult with execution details
        """
        if timeout is None:
            timeout = self.timeout
        
        start_time = time.time()
        
        if background:
            return self._execute_background(command, timeout)
        else:
            return self._execute_foreground(command, timeout, start_time)
    
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
    
    def start_interactive(self, command: str, output_callback: Optional[Callable[[str], None]] = None):
        """
        Start an interactive command (like nc, python, etc.)
        
        Args:
            command: Interactive command to start
            output_callback: Function to call with output data
        """
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
    
    def get_background_processes(self) -> Dict[int, Dict[str, Any]]:
        """Get list of background processes"""
        # Execute jobs command to get current background jobs
        result = self.execute("jobs -l", timeout=5)
        jobs = {}
        
        if result.status == CommandStatus.COMPLETED:
            lines = result.stdout.split('\n')
            for line in lines:
                if line.strip():
                    # Parse job information
                    import re
                    match = re.search(r'\[(\d+)\][+-]?\s+(\d+)\s+(\w+)\s+(.+)', line)
                    if match:
                        job_id, pid, status, command = match.groups()
                        jobs[int(pid)] = {
                            'job_id': int(job_id),
                            'status': status,
                            'command': command
                        }
        
        return jobs
    
    def kill_background_process(self, pid: int) -> bool:
        """Kill a background process"""
        try:
            result = self.execute(f"kill {pid}", timeout=5)
            return result.status == CommandStatus.COMPLETED
        except:
            return False
    
    def get_working_directory(self) -> str:
        """Get current working directory"""
        result = self.execute("pwd", timeout=5)
        if result.status == CommandStatus.COMPLETED:
            return result.stdout.strip()
        return ""
    
    def change_directory(self, path: str) -> bool:
        """Change working directory"""
        result = self.execute(f"cd {path}", timeout=5)
        return result.status == CommandStatus.COMPLETED
    
    def set_environment_variable(self, key: str, value: str) -> bool:
        """Set environment variable"""
        result = self.execute(f"export {key}={value}", timeout=5)
        return result.status == CommandStatus.COMPLETED
    
    def get_environment_variable(self, key: str) -> Optional[str]:
        """Get environment variable"""
        result = self.execute(f"echo ${key}", timeout=5)
        if result.status == CommandStatus.COMPLETED:
            return result.stdout.strip()
        return None
    
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


# Example usage and test functions
def example_usage():
    """Example of how to use BashExecutor"""
    
    # Basic usage
    with BashExecutor(timeout=30) as executor:
        # Simple command
        result = executor.execute("ls -la")
        print(f"Command: {result.command}")
        print(f"Status: {result.status}")
        print(f"Output: {result.stdout}")
        print(f"Execution time: {result.execution_time:.2f}s")
        
        # Background command
        print("\n--- Background Command ---")
        bg_result = executor.execute("sleep 10", background=True)
        print(f"Background command started: {bg_result.command}")
        print(f"PID: {bg_result.pid}")
        
        # Check background processes
        bg_processes = executor.get_background_processes()
        print(f"Background processes: {bg_processes}")
        
        # Change directory
        print("\n--- Directory Operations ---")
        executor.change_directory("/tmp")
        print(f"Current directory: {executor.get_working_directory()}")
        
        # Environment variables
        print("\n--- Environment Variables ---")
        executor.set_environment_variable("TEST_VAR", "hello_world")
        test_var = executor.get_environment_variable("TEST_VAR")
        print(f"TEST_VAR: {test_var}")


def interactive_example():
    """Example of interactive command usage"""
    
    def output_handler(data):
        print(f"Interactive output: {data}", end='')
    
    with BashExecutor() as executor:
        print("Starting interactive Python session...")
        executor.start_interactive("python3", output_callback=output_handler)
        
        # Send some Python commands
        time.sleep(1)  # Wait for Python to start
        executor.send_interactive_input("print('Hello from Python!')")
        executor.send_interactive_input("x = 42")
        executor.send_interactive_input("print(f'The answer is {x}')")
        executor.send_interactive_input("import sys")
        executor.send_interactive_input("print(sys.version)")
        
        # Let it run for a bit
        time.sleep(2)
        
        # Stop interactive session
        executor.stop_interactive()
        print("\nInteractive session ended.")


if __name__ == "__main__":
    print("=== Basic Usage Example ===")
    example_usage()
    
    print("\n=== Interactive Example ===")
    interactive_example()