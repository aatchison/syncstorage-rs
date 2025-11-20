#!/usr/bin/env python3

import os
import sys
import subprocess
import time
import requests
import signal
import psutil

def setup_environment():
    """Set up environment variables for testing with Keycloak"""
    # Basic sync server settings
    os.environ["SYNC_MASTER_SECRET"] = "secret0"
    os.environ["SYNC_CORS_MAX_AGE"] = "555"
    os.environ["SYNC_CORS_ALLOWED_ORIGIN"] = "*"
    os.environ["MOZSVC_TEST_REMOTE"] = "localhost"
    
    # Database settings
    os.environ["SYNC_TOKENSERVER__DATABASE_URL"] = "mysql://root@127.0.0.1/tokenserver"
    
    # OAuth settings for Keycloak
    os.environ["KEYCLOAK_URL"] = "http://localhost:7080"
    os.environ["SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE"] = "oidc"
    os.environ["SYNC_TOKENSERVER__OIDC_ISSUER_URL"] = "http://localhost:7080/realms/sync"
    os.environ["SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL"] = "http://localhost:7080/realms/sync"
    
    # Test environment settings
    os.environ["TOKENSERVER_HOST"] = "http://localhost:8000"
    os.environ["TOKENSERVER_AUTH_METHOD"] = "oauth"

def start_server():
    """Start the syncserver"""
    print("Starting syncserver...")
    
    # Check if debug build exists
    if os.path.exists("target/debug/syncserver"):
        binary = "target/debug/syncserver"
    else:
        print("Error: syncserver binary not found. Please run 'cargo build' first.")
        return None
    
    # Start the server
    process = subprocess.Popen(
        [binary],
        env=os.environ,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for server to start
    max_attempts = 30
    for i in range(max_attempts):
        try:
            response = requests.get("http://localhost:8000/__heartbeat__", timeout=2)
            if response.status_code == 200:
                print("✅ Server started successfully!")
                return process
        except requests.exceptions.RequestException:
            pass
        
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            print(f"❌ Server failed to start:")
            print(f"STDOUT: {stdout}")
            print(f"STDERR: {stderr}")
            return None
        
        time.sleep(1)
    
    print("❌ Server failed to start within timeout")
    return None

def terminate_process(process):
    """Gracefully terminate the process and its children"""
    if process is None:
        return
    
    try:
        proc = psutil.Process(pid=process.pid)
        children = proc.children(recursive=True)
        for child in children:
            child.terminate()
        proc.terminate()
        process.wait(timeout=5)
    except (psutil.NoSuchProcess, subprocess.TimeoutExpired):
        # Force kill if graceful termination fails
        try:
            process.kill()
        except:
            pass

def run_test(test_name=None):
    """Run the authorization tests"""
    print("Running authorization tests...")
    
    cmd = [
        "python", "-m", "pytest", 
        "tools/integration_tests/tokenserver/test_authorization.py",
        "-v"
    ]
    
    if test_name:
        cmd.append(f"::{test_name}")
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    print("STDOUT:")
    print(result.stdout)
    print("\nSTDERR:")
    print(result.stderr)
    print(f"\nReturn code: {result.returncode}")
    
    return result.returncode == 0

def main():
    """Main test function"""
    print("🔧 Setting up environment for Keycloak testing...")
    setup_environment()
    
    print("🚀 Starting server...")
    server_process = start_server()
    
    if server_process is None:
        print("❌ Failed to start server")
        return 1
    
    try:
        print("🧪 Running tests...")
        # Run a specific test that should show the error status issue
        success = run_test("TestAuthorization::test_disallow_reusing_old_client_state")
        
        if success:
            print("✅ Tests passed!")
            return 0
        else:
            print("❌ Tests failed!")
            return 1
    
    finally:
        print("🛑 Stopping server...")
        terminate_process(server_process)

if __name__ == "__main__":
    sys.exit(main())