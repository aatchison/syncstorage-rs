#!/usr/bin/env python3

import requests
import json
import jwt
import sys

def get_keycloak_token():
    """Get a JWT token from Keycloak"""
    token_url = "http://keycloak:7080/realms/sync/protocol/openid-connect/token"
    confidential_client_secret = "YcdeiCc742lOk17poGhWT51GTAWMnQMr"
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': 'confidential-client',
        'scope': 'openid https://identity.mozilla.com/apps/oldsync',
        'client_secret': confidential_client_secret
    }
    
    print(f"Getting token from: {token_url}")
    response = requests.post(token_url, data=data, timeout=10)
    print(f"Response status: {response.status_code}")
    
    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get('access_token')
        print(f"Got token: {access_token[:50]}...")
        return access_token
    else:
        print(f"Failed to get token: {response.text}")
        return None

def get_keycloak_jwks():
    """Get JWKs from Keycloak"""
    jwks_url = "http://keycloak:7080/realms/sync/protocol/openid-connect/certs"
    print(f"Getting JWKs from: {jwks_url}")
    
    response = requests.get(jwks_url, timeout=10)
    print(f"JWKs response status: {response.status_code}")
    
    if response.status_code == 200:
        jwks = response.json()
        print(f"Got {len(jwks.get('keys', []))} JWK keys")
        return jwks
    else:
        print(f"Failed to get JWKs: {response.text}")
        return None

def decode_jwt_token(token):
    """Decode JWT token without verification to see claims"""
    try:
        # Decode without verification to see the claims
        decoded = jwt.decode(token, options={"verify_signature": False})
        print("JWT Claims:")
        print(json.dumps(decoded, indent=2))
        return decoded
    except Exception as e:
        print(f"Failed to decode JWT: {e}")
        return None

def test_syncserver_endpoint(token):
    """Test the syncserver endpoint with the JWT token"""
    url = "http://syncserver:8000/1.0/sync/1.5?duration=12"
    headers = {
        'Authorization': f'Bearer {token}',
        'X-KeyID': '0000000001234-qqo',
        'Accept': 'application/json'
    }
    
    print(f"Testing syncserver endpoint: {url}")
    print(f"Headers: {headers}")
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        print(f"Syncserver response status: {response.status_code}")
        print(f"Syncserver response: {response.text}")
        return response
    except Exception as e:
        print(f"Failed to call syncserver: {e}")
        return None

def main():
    print("=== JWT Token Verification Debug ===")
    
    # Get token from Keycloak
    token = get_keycloak_token()
    if not token:
        print("Failed to get token from Keycloak")
        sys.exit(1)
    
    # Get JWKs from Keycloak
    jwks = get_keycloak_jwks()
    if not jwks:
        print("Failed to get JWKs from Keycloak")
        sys.exit(1)
    
    # Decode the JWT token to see claims
    claims = decode_jwt_token(token)
    if not claims:
        print("Failed to decode JWT token")
        sys.exit(1)
    
    # Test the syncserver endpoint
    response = test_syncserver_endpoint(token)
    
    print("=== Debug Complete ===")

if __name__ == "__main__":
    main()