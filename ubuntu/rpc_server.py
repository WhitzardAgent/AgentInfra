from xmlrpc.server import SimpleXMLRPCServer
import subprocess

def execute_bash_command(cmd):
    try:
        # Run the command in the bash shell, capture output and errors
        result = subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {'success': True, 'output': result.stdout}
    except subprocess.CalledProcessError as e:
        # Return error and output
        return {'success': False, 'output': e.stderr}

def main():
    server = SimpleXMLRPCServer(("0.0.0.0", 8000), allow_none=True)
    print("RPC Server listening on port 8000...")
    server.register_function(execute_bash_command, "execute_bash_command")
    server.serve_forever()

if __name__ == "__main__":
    main()