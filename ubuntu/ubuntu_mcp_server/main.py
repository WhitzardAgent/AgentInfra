"""
Secure Ubuntu MCP Server

A hardened Model Context Protocol server for controlling Ubuntu systems.
Provides safe, controlled access with comprehensive security protections.
"""

import json
import logging
from fastmcp import FastMCP

import subprocess
import shlex
from typing import Optional
import os
import tempfile

BLACK_LIST = {"nano", "vim", "vi"}  # Use set for O(1) lookup

class BashExecutor:
    def __init__(self, 
                 conda_base: Optional[str]="/opt/anaconda3",
                 conda_env: Optional[str]=None,
                 use_truncate: bool=False):
        self.conda_env = conda_env
        self.use_truncate = use_truncate
        self.last_bg_log = None
        self.conda_base = conda_base
        
    def _is_blacklisted(self, command: str) -> Optional[str]:
        # Use shlex to split the command safely and identify the base command
        try:
            parts = shlex.split(command)
            if not parts:
                return None
            base_cmd = parts[0]
            if base_cmd in BLACK_LIST:
                return base_cmd
            return None
        except ValueError:
            # shlex could fail on malformed command, fallback to simple check
            for banned in BLACK_LIST:
                if command.strip().startswith(banned):
                    return banned
            return None
        
    def truncate(self, text: str, n: int) -> str:
        """
        Show first n lines and last n lines of text, with omitted line count in between if any.

        Args:
        text: input multiline string.
        n: number of lines to show at start and end.

        Returns:
        A clipped string.
        """
        lines = text.splitlines()
        total = len(lines)
        if total <= 2 * n:
            return text  # No need to clip

        head = lines[:n]
        tail = lines[-n:]
        omitted_count = total - 2 * n

        return "\n".join(
            head
            + [f"... ({omitted_count} lines omitted) ..."]
            + tail
        )
    
    def _execute_bash_command(self, command: str, workding_dir:str, timeout: int = 25) -> str:
        blacklisted_cmd = self._is_blacklisted(command)
        if blacklisted_cmd:
            return (
                f"❌ Command '{blacklisted_cmd}' is not allowed in this sandboxed environment "
                "because it is an interactive tool."
            )

        if self.conda_env:
            command = (
                f"bash -c 'source \"{self.conda_base}/etc/profile.d/conda.sh\" && "
                f"conda activate {self.conda_env} && {command}'"
            )

        if timeout == 0:
            try:
                # Create a NamedTemporaryFile that is not deleted on close
                # We'll open the file separately to get a handle with line buffering
                temp_file = tempfile.NamedTemporaryFile(
                    mode="w+", encoding="utf-8", buffering=1,  # line buffered
                    delete=False,  # tempfile persists after close
                    prefix="bg_command_output_",
                    suffix=".log"
                )
                temp_file_name = temp_file.name
                temp_file.close()  # close here so Popen can open the file for writing

                # Open the temp file in append mode for subprocess to write output into
                # Use unbuffered binary mode with a file descriptor opened with os.open?
                # But simpler here to open in append mode text line buffered

                # Detach process on Unix to keep running independently
                preexec = os.setpgrp if hasattr(os, "setpgrp") else None

                # Open temp file for writing so that subprocess can write stdout and stderr there
                # Using "a" (append) is good since we closed earlier, process opens new handle
                temp_fh = open(temp_file_name, mode="a", encoding="utf-8", buffering=1)

                # Start process redirecting both stdout and stderr to the temp file handle
                process = subprocess.Popen(
                    command,
                    shell=True,
                    cwd=workding_dir,
                    stdout=temp_fh,
                    stderr=subprocess.STDOUT,
                    text=True,
                    preexec_fn=preexec,
                    executable="/bin/bash",  # to get conda shell functions
                )
                # Close temp_fh in parent so it doesn't block
                temp_fh.close()
                self.last_bg_log = (command, temp_file_name)
                return (
                    f"🚀 Command started in the background with PID {process.pid}.\n"
                    f"Output is being logged in real time to the file: {temp_file_name}"
                )
            except Exception as ex:
                return f"❌ Failed to start background command: {ex}"

        # timeout > 0 synchronous execution as before:
        try:
            completed = subprocess.run(
                command,
                shell=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=timeout,
                cwd=workding_dir,
                text=True,
                executable="/bin/bash",
            )
            output = completed.stdout.strip()
            
            if(self.use_truncate):
                output = self.truncate(text=output, n=100)

            
            if not output:
                return "✅ Command executed successfully with no output."
            return f"✅ Command output:\n{output}"
        except subprocess.TimeoutExpired:
            return f"⏰ Command timed out after {timeout} seconds: {command}"
        except subprocess.CalledProcessError as e:
            err_output = e.output.strip() if e.output else "<no output>"
            if(self.use_truncate):
                err_output = self.truncate(text=err_output, n=100)
            return f"❌ Command failed with exit code {e.returncode}.\nOutput:\n{err_output}"
        except Exception as e:
            return f"❌ Unexpected error: {e}"


def create_ubuntu_mcp_server() -> FastMCP:
    """Create and configure the secure Ubuntu MCP server"""
    mcp = FastMCP("Secure Ubuntu Controller")
    bash_executor = BashExecutor()

    def format_error(e: Exception) -> str:
        return json.dumps({"error": str(e), "type": type(e).__name__}, indent=2)

    @mcp.tool("execute_command")
    def execute_command(command: str, working_dir: str, timeout: int=25) -> str:
        """Executes a shell command on the Ubuntu system.
        Args:
            command: The shell command to execute.
            working_dir: Working directory for the command.
            timeout: Max seconds to wait; 0 runs in background.

        Returns:
            A JSON string with the command results, including stdout, stderr, and return code.
        """
        try:
            result = bash_executor._execute_bash_command(command, working_dir, timeout)
            return result # json.dumps(result, indent=2)
        except Exception as e:
            return format_error(e)
    return mcp



def main():
    """Main entry point"""

    print(f"Starting Secure Ubuntu MCP Server ...", file=sys.stderr)
    mcp_server = create_ubuntu_mcp_server()
    mcp_server.run(transport="http", host="0.0.0.0", port=9000, path="/mcp")


if __name__ == "__main__":
    import argparse
    import sys

    try:
        main()
    except KeyboardInterrupt:
        print("\n👋 Ubuntu MCP Server stopped by user.", file=sys.stderr)
    except Exception as e:
        logging.getLogger(__name__).critical(f"Server exited with a critical error: {e}", exc_info=True)
        sys.exit(1)