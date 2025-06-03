#!/usr/bin/env python3
"""
Validation script for Keycloak E2E test configuration.
This script validates that the make docker_run_mysql_keycloak_e2e_tests target
has all the necessary components configured correctly.
"""

import os
import sys
import yaml
import subprocess
import json

def check_file_exists(filepath, description):
    """Check if a file exists and print status."""
    if os.path.exists(filepath):
        print(f"✓ {description}: {filepath}")
        return True
    else:
        print(f"✗ {description}: {filepath} (NOT FOUND)")
        return False

def validate_docker_compose_config():
    """Validate docker-compose configuration."""
    print("Validating Docker Compose Configuration")
    print("=" * 50)
    
    # Check if docker-compose files exist
    base_file = "docker-compose.mysql.keycloak.yaml"
    e2e_file = "docker-compose.e2e.mysql.keycloak.yaml"
    
    if not check_file_exists(base_file, "Base Keycloak compose file"):
        return False
    if not check_file_exists(e2e_file, "E2E Keycloak compose file"):
        return False
    
    # Validate docker-compose config
    try:
        result = subprocess.run([
            "docker-compose", 
            "-f", base_file, 
            "-f", e2e_file, 
            "config"
        ], capture_output=True, text=True, check=True)
        
        # Parse the output to check for required services
        config = yaml.safe_load(result.stdout)
        services = config.get('services', {})
        
        required_services = ['keycloak', 'mysql-e2e-tests', 'sync-db', 'tokenserver-db', 'syncserver']
        missing_services = []
        
        for service in required_services:
            if service in services:
                print(f"✓ Service '{service}' configured")
            else:
                print(f"✗ Service '{service}' missing")
                missing_services.append(service)
        
        if missing_services:
            return False
            
        # Check Keycloak environment variables in e2e test service
        e2e_env = services.get('mysql-e2e-tests', {}).get('environment', {})
        required_keycloak_vars = [
            'SYNC_TOKENSERVER__OAUTH_PROVIDER',
            'SYNC_TOKENSERVER__KEYCLOAK_SERVER_URL',
            'SYNC_TOKENSERVER__KEYCLOAK_REALM'
        ]
        
        for var in required_keycloak_vars:
            if var in e2e_env:
                value = e2e_env[var]
                print(f"✓ Environment variable '{var}': {value}")
            else:
                print(f"✗ Environment variable '{var}' missing")
                return False
                
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Docker compose config validation failed: {e}")
        print(f"Error output: {e.stderr}")
        return False
    except Exception as e:
        print(f"✗ Error validating docker-compose config: {e}")
        return False

def validate_keycloak_realm():
    """Validate Keycloak realm configuration."""
    print("\nValidating Keycloak Realm Configuration")
    print("=" * 50)
    
    realm_file = "keycloak/realm-export.json"
    if not check_file_exists(realm_file, "Keycloak realm export"):
        return False
    
    try:
        with open(realm_file, 'r') as f:
            realm_config = json.load(f)
        
        # Check realm name
        realm_name = realm_config.get('realm')
        if realm_name == 'sync':
            print(f"✓ Realm name: {realm_name}")
        else:
            print(f"✗ Expected realm 'sync', found '{realm_name}'")
            return False
        
        # Check clients
        clients = realm_config.get('clients', [])
        client_ids = [client.get('clientId') for client in clients]
        
        expected_clients = ['confidential-client', 'public-client']
        for client_id in expected_clients:
            if client_id in client_ids:
                print(f"✓ Client '{client_id}' configured")
            else:
                print(f"✗ Client '{client_id}' missing")
                return False
        
        return True
        
    except Exception as e:
        print(f"✗ Error validating realm config: {e}")
        return False

def validate_makefile_target():
    """Validate that the Makefile target exists."""
    print("\nValidating Makefile Target")
    print("=" * 50)
    
    if not check_file_exists("Makefile", "Makefile"):
        return False
    
    try:
        with open("Makefile", 'r') as f:
            makefile_content = f.read()
        
        if "docker_run_mysql_keycloak_e2e_tests:" in makefile_content:
            print("✓ Make target 'docker_run_mysql_keycloak_e2e_tests' found")
            
            # Extract the target definition
            lines = makefile_content.split('\n')
            target_lines = []
            in_target = False
            
            for line in lines:
                if line.startswith("docker_run_mysql_keycloak_e2e_tests:"):
                    in_target = True
                    target_lines.append(line)
                elif in_target:
                    if line.startswith('\t') or line.strip() == '':
                        target_lines.append(line)
                    else:
                        break
            
            print("Target definition:")
            for line in target_lines:
                print(f"  {line}")
            
            return True
        else:
            print("✗ Make target 'docker_run_mysql_keycloak_e2e_tests' not found")
            return False
            
    except Exception as e:
        print(f"✗ Error validating Makefile: {e}")
        return False

def validate_rust_compilation():
    """Validate that Rust code compiles with Keycloak features."""
    print("\nValidating Rust Compilation")
    print("=" * 50)
    
    try:
        # Check if cargo is available
        result = subprocess.run(["cargo", "--version"], capture_output=True, text=True, check=True)
        print(f"✓ Cargo available: {result.stdout.strip()}")
        
        # Try to compile the syncserver binary with mysql feature (avoiding Python dependencies)
        print("Checking compilation...")
        result = subprocess.run([
            "cargo", "check", "--bin", "syncserver", "--no-default-features", "--features", "mysql"
        ], capture_output=True, text=True, check=True)
        
        print("✓ Rust code compiles successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"✗ Compilation failed: {e}")
        print(f"Error output: {e.stderr}")
        return False
    except Exception as e:
        print(f"✗ Error checking compilation: {e}")
        return False

def main():
    """Main validation function."""
    print("Keycloak E2E Test Configuration Validation")
    print("=" * 60)
    
    # Change to the correct directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    all_checks_passed = True
    
    # Run all validation checks
    checks = [
        validate_docker_compose_config,
        validate_keycloak_realm,
        validate_makefile_target,
        validate_rust_compilation
    ]
    
    for check in checks:
        if not check():
            all_checks_passed = False
        print()  # Add spacing between checks
    
    # Final summary
    print("=" * 60)
    if all_checks_passed:
        print("🎉 ALL CHECKS PASSED!")
        print("The make docker_run_mysql_keycloak_e2e_tests target should work correctly.")
        print("\nTo run the E2E tests (requires Docker):")
        print("  make docker_run_mysql_keycloak_e2e_tests")
        return 0
    else:
        print("❌ SOME CHECKS FAILED!")
        print("Please fix the issues above before running the E2E tests.")
        return 1

if __name__ == "__main__":
    sys.exit(main())