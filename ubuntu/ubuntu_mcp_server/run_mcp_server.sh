#!/bin/bash
# Ubuntu MCP Server launcher script for Claude Desktop
# This script activates the virtual environment and runs the server

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Activate virtual environment
source "$SCRIPT_DIR/.venv/bin/activate"

# Run the MCP server with all passed arguments
exec python3 "$SCRIPT_DIR/main.py" "$@"
