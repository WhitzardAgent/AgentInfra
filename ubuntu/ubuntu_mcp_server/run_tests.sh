#!/bin/bash

# Ubuntu MCP Server Test Suite
echo "🧪 Ubuntu MCP Server Test Suite"
echo "================================"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    if [ $2 -eq 0 ]; then
        echo -e "${GREEN}✅ $1${NC}"
    else
        echo -e "${RED}❌ $1${NC}"
        return 1
    fi
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

# Check if virtual environment exists
if [ ! -d ".venv" ]; then
    print_info "Creating virtual environment..."
    python3 -m venv .venv
fi

# Activate virtual environment
print_info "Activating virtual environment..."
source .venv/bin/activate

# Install dependencies
print_info "Installing dependencies..."
pip install -r requirements.txt > /dev/null 2>&1
print_status "Dependencies installed" $?

echo ""
echo "🔧 Running Core Tests"
echo "===================="

# Test 1: Core controller functionality
print_info "Testing core controller functionality..."
python main.py --test > /dev/null 2>&1
print_status "Core controller test" $?

# Test 2: Simple client test
print_info "Testing simple client functionality..."
python test_client.py --simple > /dev/null 2>&1
print_status "Simple client test" $?

# Test 3: Check MCP server startup
print_info "Testing MCP server startup (5 second timeout)..."
timeout 5 python main.py --policy safe > /dev/null 2>&1
if [ $? -eq 124 ]; then
    # Timeout is expected - server started successfully
    print_status "MCP server startup test" 0
else
    print_status "MCP server startup test" 1
fi

echo ""
echo "🛡️  Security Policy Tests"
echo "========================"

# Test 4: Safe policy validation
print_info "Testing safe security policy..."
python -c "
from main import create_safe_policy, UbuntuController
import asyncio

async def test_safe_policy():
    policy = create_safe_policy()
    controller = UbuntuController(policy)
    
    # Test allowed command
    try:
        result = await controller.execute_command('echo test')
        assert result['return_code'] == 0
    except Exception as e:
        raise AssertionError(f'Allowed command failed: {e}')
    
    # Test forbidden command
    try:
        await controller.execute_command('rm -rf /')
        raise AssertionError('Forbidden command was allowed')
    except PermissionError:
        pass  # Expected
    
    # Test allowed path
    import os
    home = os.path.expanduser('~')
    items = controller.list_directory(home)
    assert len(items) >= 0
    
    # Test forbidden path
    try:
        controller.list_directory('/etc/shadow')
        raise AssertionError('Forbidden path was allowed')
    except PermissionError:
        pass  # Expected
    
    print('All security tests passed')

asyncio.run(test_safe_policy())
" > /dev/null 2>&1
print_status "Safe security policy test" $?

# Test 5: Development policy validation  
print_info "Testing development security policy..."
python -c "
from main import create_development_policy, UbuntuController
import asyncio

async def test_dev_policy():
    policy = create_development_policy()
    controller = UbuntuController(policy)
    
    # Test that dev policy is more permissive
    assert policy.allow_sudo == True
    assert len(policy.allowed_paths) > 3
    
    # Test basic functionality
    result = await controller.execute_command('echo dev test')
    assert result['return_code'] == 0
    
    print('Development policy test passed')

asyncio.run(test_dev_policy())
" > /dev/null 2>&1
print_status "Development security policy test" $?

echo ""
echo "📁 File Operation Tests"
echo "======================"

# Test 6: File operations
print_info "Testing file operations..."
python -c "
from main import create_safe_policy, UbuntuController
import os
import tempfile

def test_file_ops():
    policy = create_safe_policy()
    controller = UbuntuController(policy)
    
    # Test file write/read in allowed directory
    test_file = '/tmp/mcp_test_suite.txt'
    test_content = 'Hello from test suite'
    
    # Write file
    controller.write_file(test_file, test_content)
    
    # Read file
    read_content = controller.read_file(test_file)
    assert read_content == test_content
    
    # Clean up
    os.remove(test_file)
    
    print('File operations test passed')

test_file_ops()
" > /dev/null 2>&1
print_status "File operations test" $?

echo ""
echo "📦 Package Management Tests"
echo "==========================="

# Test 7: Package search (safe operation)
print_info "Testing package search..."
python -c "
from main import create_safe_policy, UbuntuController
import asyncio

async def test_package_search():
    policy = create_safe_policy()
    controller = UbuntuController(policy)
    
    # Test package search
    result = await controller.execute_command('apt search curl | head -1')
    assert result['return_code'] == 0
    assert len(result['stdout']) > 0
    
    print('Package search test passed')

asyncio.run(test_package_search())
" > /dev/null 2>&1
print_status "Package search test" $?

echo ""
echo "📊 Summary"
echo "=========="

# Count successful tests
total_tests=7
echo "Total tests run: $total_tests"

# Show system info
print_info "System Information:"
python -c "
from main import create_safe_policy, UbuntuController

def show_system_info():
    policy = create_safe_policy()
    controller = UbuntuController(policy)
    info = controller.get_system_info()
    
    print(f\"  OS: {info['os_info'].get('PRETTY_NAME', 'Unknown')}\")
    print(f\"  User: {info['current_user']}\")
    print(f\"  Hostname: {info['hostname']}\")
    
    # Show disk usage
    total_gb = info['disk_usage']['total'] / (1024**3)
    free_gb = info['disk_usage']['free'] / (1024**3)
    print(f\"  Disk: {free_gb:.1f}GB free of {total_gb:.1f}GB total\")

show_system_info()
"

echo ""
print_info "🎉 Test suite completed!"
print_info "You can now use the Ubuntu MCP Server with:"
echo "  python main.py --policy safe    # Start with safe policy"
echo "  python main.py --policy dev     # Start with dev policy"
echo "  python main.py --test           # Run built-in tests"

# Deactivate virtual environment
deactivate 2>/dev/null || true
