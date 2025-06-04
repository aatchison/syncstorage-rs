#!/usr/bin/env python3

import requests
import json
import os

def test_keycloak_token():
    """Test getting a token from Keycloak"""
    
    # Use the same URL as in the tests
    keycloak_base_url = os.environ.get('KEYCLOAK_URL', 'http://keycloak:7080')
    token_url = f"{keycloak_base_url}/realms/sync/protocol/openid-connect/token"
    
    print(f"Testing Keycloak token endpoint: {token_url}")
    
    # Use the same credentials as in the test
    data = {
        'grant_type': 'client_credentials',
        'client_id': 'confidential-client',
        'scope': 'openid https://identity.mozilla.com/apps/oldsync',
        'client_secret': 'YcdeiCc742lOk17poGhWT51GTAWMnQMr'
    }
    
    try:
        print("Making request to Keycloak...")
        response = requests.post(token_url, data=data, timeout=10)
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        print(f"Response text: {response.text}")
        
        if response.status_code == 200:
            token_data = response.json()
            access_token = token_data.get('access_token')
            print(f"Successfully got access token: {access_token[:50] if access_token else 'None'}...")
            
            # Try to decode the JWT to see its contents
            if access_token:
                import base64
                # JWT has 3 parts separated by dots
                parts = access_token.split('.')
                if len(parts) >= 2:
                    # Decode the payload (second part)
                    payload = parts[1]
                    # Add padding if needed
                    payload += '=' * (4 - len(payload) % 4)
                    try:
                        decoded = base64.b64decode(payload)
                        payload_json = json.loads(decoded)
                        print(f"JWT payload: {json.dumps(payload_json, indent=2)}")
                    except Exception as e:
                        print(f"Could not decode JWT payload: {e}")
            
            return access_token
        else:
            print(f"Failed to get token: {response.status_code} - {response.text}")
            return None
            
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_keycloak_connectivity():
    """Test basic connectivity to Keycloak"""
    keycloak_base_url = os.environ.get('KEYCLOAK_URL', 'http://keycloak:7080')
    
    print(f"Testing connectivity to: {keycloak_base_url}")
    
    try:
        # Test basic connectivity
        response = requests.get(f"{keycloak_base_url}/realms/sync", timeout=5)
        print(f"Realm endpoint status: {response.status_code}")
        if response.status_code == 200:
            print("✓ Keycloak realm is accessible")
        else:
            print("✗ Keycloak realm not accessible")
            
        # Test OpenID configuration
        config_url = f"{keycloak_base_url}/realms/sync/.well-known/openid_configuration"
        response = requests.get(config_url, timeout=5)
        print(f"OpenID config status: {response.status_code}")
        if response.status_code == 200:
            print("✓ OpenID configuration accessible")
            config = response.json()
            print(f"Token endpoint: {config.get('token_endpoint')}")
        else:
            print("✗ OpenID configuration not accessible")
            
    except Exception as e:
        print(f"Connectivity error: {e}")

if __name__ == "__main__":
    print("=== Keycloak Debug Test ===")
    test_keycloak_connectivity()
    print("\n=== Token Test ===")
    test_keycloak_token()