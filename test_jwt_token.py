#!/usr/bin/env python3

import os
import sys
import requests
import json
import base64

# Test JWT token generation
def test_jwt_token():
    # Get token from Keycloak
    keycloak_url = "http://localhost:7080"
    token_url = f"{keycloak_url}/realms/sync/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': 'sync-service',
        'client_secret': 'sync-service-secret'
    }
    
    try:
        response = requests.post(token_url, data=data)
        response.raise_for_status()
        token_data = response.json()
        access_token = token_data['access_token']
        
        print(f"Got access token: {access_token[:50]}...")
        
        # Decode JWT to see the payload
        parts = access_token.split('.')
        if len(parts) >= 2:
            # Decode the payload (second part)
            payload = parts[1]
            # Add padding if needed
            payload += '=' * (4 - len(payload) % 4)
            decoded = base64.b64decode(payload)
            payload_json = json.loads(decoded)
            
            print(f"JWT payload:")
            print(json.dumps(payload_json, indent=2))
            
            print(f"Subject: {payload_json.get('sub')}")
            print(f"Email: {payload_json.get('email')}")
            
        return access_token
        
    except Exception as e:
        print(f"Error getting token: {e}")
        return None

if __name__ == "__main__":
    test_jwt_token()