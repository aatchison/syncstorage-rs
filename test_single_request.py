#!/usr/bin/env python3

import requests
import json
import time

def get_keycloak_token():
    """Get a JWT token from Keycloak"""
    token_url = "http://localhost:7080/realms/sync/protocol/openid-connect/token"
    confidential_client_secret = "YcdeiCc742lOk17poGhWT51GTAWMnQMr"
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': 'confidential-client',
        'scope': 'openid https://identity.mozilla.com/apps/oldsync',
        'client_secret': confidential_client_secret
    }
    
    print(f"Getting token from: {token_url}")
    response = requests.post(token_url, data=data, timeout=10)
    print(f"Token response status: {response.status_code}")
    
    if response.status_code == 200:
        token = response.json().get('access_token')
        print(f"Got token: {token[:50]}...")
        return token
    else:
        print(f"Failed to get token: {response.text}")
        return None

def test_syncserver_with_token(token):
    """Test the syncserver with the JWT token"""
    url = "http://localhost:8000/1.0/sync/1.5?duration=12"
    headers = {
        'Authorization': f'Bearer {token}',
        'X-KeyID': '1234-aaaa',
        'Accept': 'application/json'
    }
    
    print(f"Making request to: {url}")
    print(f"Headers: {headers}")
    
    response = requests.get(url, headers=headers, timeout=10)
    print(f"Syncserver response status: {response.status_code}")
    print(f"Syncserver response: {response.text}")
    
    return response

if __name__ == "__main__":
    print("=== Testing Keycloak JWT with Syncserver ===")
    
    # Get token from Keycloak
    token = get_keycloak_token()
    if not token:
        print("Failed to get token, exiting")
        exit(1)
    
    # Test syncserver with token
    print("\n=== Testing Syncserver ===")
    response = test_syncserver_with_token(token)
    
    print(f"\nFinal result: {response.status_code}")