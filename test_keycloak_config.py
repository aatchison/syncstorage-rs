#!/usr/bin/env python3
"""
Test script to validate Keycloak realm configuration.
This script checks that the realm export JSON is valid and contains
the necessary configuration for OAuth integration.
"""

import json
import sys
import re

def test_realm_config():
    """Test the Keycloak realm configuration."""
    print("Testing Keycloak Realm Configuration")
    print("=" * 40)
    
    try:
        # Load and parse the realm configuration
        with open('keycloak/realm-export.json', 'r') as f:
            realm_config = json.load(f)
        
        print("✓ Realm JSON is valid")
        
        # Check realm name
        realm_name = realm_config.get('realm')
        assert realm_name == 'sync', f"Expected realm 'sync', got '{realm_name}'"
        print(f"✓ Realm name: {realm_name}")
        
        # Check that frontendUrl is not malformed
        attributes = realm_config.get('attributes', {})
        frontend_url = attributes.get('frontendUrl', '')
        
        # Should be empty or a valid URL
        if frontend_url:
            # Basic URL validation - should start with http:// or https://
            url_pattern = re.compile(r'^https?://')
            assert url_pattern.match(frontend_url), f"frontendUrl should be a valid URL or empty, got '{frontend_url}'"
            print(f"✓ frontendUrl is valid: {frontend_url}")
        else:
            print("✓ frontendUrl is empty (will use default)")
        
        # Check clients exist
        clients = realm_config.get('clients', [])
        client_ids = [client.get('clientId') for client in clients]
        
        required_clients = ['confidential-client', 'public-client']
        for client_id in required_clients:
            assert client_id in client_ids, f"Required client '{client_id}' not found"
            print(f"✓ Client '{client_id}' exists")
        
        # Check client configurations
        for client in clients:
            client_id = client.get('clientId')
            if client_id in required_clients:
                # Check that redirect URIs are properly formatted
                redirect_uris = client.get('redirectUris', [])
                for uri in redirect_uris:
                    if uri and not uri.startswith(('http://', 'https://', '*')):
                        raise AssertionError(f"Invalid redirect URI in client '{client_id}': {uri}")
                
                print(f"✓ Client '{client_id}' redirect URIs are valid")
        
        # Check that realm is enabled
        enabled = realm_config.get('enabled', False)
        assert enabled, "Realm should be enabled"
        print("✓ Realm is enabled")
        
        print("\n🎉 All Keycloak configuration tests passed!")
        return True
        
    except FileNotFoundError:
        print("✗ Realm export file not found: keycloak/realm-export.json")
        return False
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON in realm export: {e}")
        return False
    except AssertionError as e:
        print(f"✗ Configuration validation failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

if __name__ == "__main__":
    success = test_realm_config()
    sys.exit(0 if success else 1)