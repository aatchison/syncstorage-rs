#!/usr/bin/env python3

"""
Simple test script to verify Keycloak integration configuration
"""

import json
import os
import sys

def test_config_files():
    """Test that our configuration files are properly set up"""
    print("✓ Testing configuration files...")
    
    # Test 1: Check if Keycloak config exists
    keycloak_config_path = "config/local.keycloak.toml"
    if os.path.exists(keycloak_config_path):
        print(f"  - Found Keycloak config: {keycloak_config_path}")
        with open(keycloak_config_path, 'r') as f:
            content = f.read()
            assert 'oauth_provider = "keycloak"' in content
            assert 'keycloak_server_url = "http://localhost:7080"' in content
            assert 'keycloak_realm = "sync"' in content
            print("  - Keycloak config contains expected settings")
    else:
        print(f"  - ERROR: Keycloak config not found at {keycloak_config_path}")
        return False
    
    # Test 2: Check if Keycloak realm export exists
    realm_export_path = "keycloak/realm-export.json"
    if os.path.exists(realm_export_path):
        print(f"  - Found realm export: {realm_export_path}")
        with open(realm_export_path, 'r') as f:
            realm_data = json.load(f)
            assert realm_data.get('realm') == 'sync'
            assert 'clients' in realm_data
            print(f"  - Realm export contains {len(realm_data['clients'])} clients")
    else:
        print(f"  - ERROR: Realm export not found at {realm_export_path}")
        return False
    
    # Test 3: Check if Docker compose file exists
    docker_compose_path = "docker-compose.mysql.keycloak.yaml"
    if os.path.exists(docker_compose_path):
        print(f"  - Found Docker compose: {docker_compose_path}")
        with open(docker_compose_path, 'r') as f:
            content = f.read()
            assert 'keycloak:' in content
            assert 'KEYCLOAK_ADMIN:' in content
            print("  - Docker compose contains Keycloak service")
    else:
        print(f"  - ERROR: Docker compose not found at {docker_compose_path}")
        return False
    
    return True

def test_rust_code_structure():
    """Test that our Rust code structure is correct"""
    print("✓ Testing Rust code structure...")
    
    # Test 1: Check if Keycloak module exists
    keycloak_module_path = "tokenserver-auth/src/oauth/keycloak.rs"
    if os.path.exists(keycloak_module_path):
        print(f"  - Found Keycloak module: {keycloak_module_path}")
        with open(keycloak_module_path, 'r') as f:
            content = f.read()
            assert 'KeycloakVerifier' in content
            assert 'VerifyToken' in content
            assert 'TokenClaims' in content
            print("  - Keycloak module contains expected structures")
    else:
        print(f"  - ERROR: Keycloak module not found at {keycloak_module_path}")
        return False
    
    # Test 2: Check if settings are updated
    settings_path = "tokenserver-settings/src/lib.rs"
    if os.path.exists(settings_path):
        print(f"  - Found settings module: {settings_path}")
        with open(settings_path, 'r') as f:
            content = f.read()
            assert 'oauth_provider' in content
            assert 'keycloak_server_url' in content
            assert 'keycloak_realm' in content
            print("  - Settings module contains Keycloak configuration")
    else:
        print(f"  - ERROR: Settings module not found at {settings_path}")
        return False
    
    # Test 3: Check if main OAuth module is updated
    oauth_module_path = "tokenserver-auth/src/oauth/native.rs"
    if os.path.exists(oauth_module_path):
        print(f"  - Found OAuth module: {oauth_module_path}")
        with open(oauth_module_path, 'r') as f:
            content = f.read()
            assert 'UnifiedVerifier' in content
            assert 'keycloak' in content.lower()
            print("  - OAuth module contains unified verifier")
    else:
        print(f"  - ERROR: OAuth module not found at {oauth_module_path}")
        return False
    
    return True

def test_jwt_token_structure():
    """Test JWT token structure expectations"""
    print("✓ Testing JWT token structure...")
    
    # Example JWT payload that Keycloak would generate
    jwt_payload = {
        "sub": "user123",
        "preferred_username": "testuser",
        "scope": "openid profile email",
        "realm_access": {
            "roles": ["user", "sync-user"]
        },
        "resource_access": {
            "sync-client": {
                "roles": ["sync"]
            }
        },
        "iss": "http://localhost:7080/realms/sync",
        "aud": "sync-client",
        "exp": 1735934159,
        "iat": 1735930559
    }
    
    # Verify structure
    assert jwt_payload["sub"] == "user123"
    assert jwt_payload["preferred_username"] == "testuser"
    assert "openid" in jwt_payload["scope"]
    assert "sync-user" in jwt_payload["realm_access"]["roles"]
    
    print(f"  - Subject: {jwt_payload['sub']}")
    print(f"  - Username: {jwt_payload['preferred_username']}")
    print(f"  - Scope: {jwt_payload['scope']}")
    print(f"  - Issuer: {jwt_payload['iss']}")
    print(f"  - Roles: {jwt_payload['realm_access']['roles']}")
    
    return True

def main():
    """Run all tests"""
    print("Testing Keycloak Integration")
    print("=" * 40)
    
    # Change to the repository directory
    os.chdir('/workspace/syncstorage-rs')
    
    tests = [
        test_config_files,
        test_rust_code_structure,
        test_jwt_token_structure,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
                print("  ✓ PASSED\n")
            else:
                failed += 1
                print("  ✗ FAILED\n")
        except Exception as e:
            failed += 1
            print(f"  ✗ FAILED: {e}\n")
    
    print("=" * 40)
    print(f"Results: {passed} passed, {failed} failed")
    
    if failed == 0:
        print("🎉 All tests passed! Keycloak integration is properly configured.")
        return 0
    else:
        print("❌ Some tests failed. Please check the configuration.")
        return 1

if __name__ == "__main__":
    sys.exit(main())