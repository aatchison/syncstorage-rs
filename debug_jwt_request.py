#!/usr/bin/env python3

import requests
import json
import os

def get_keycloak_token():
    """Get a JWT token from Keycloak using client credentials flow"""
    token_url = "http://keycloak:7080/realms/sync/protocol/openid-connect/token"
    
    data = {
        'grant_type': 'client_credentials',
        'client_id': 'confidential-client',
        'client_secret': 'confidential-client-secret',
        'scope': 'openid email'
    }
    
    response = requests.post(token_url, data=data)
    if response.status_code == 200:
        return response.json()['access_token']
    else:
        print(f"Failed to get token: {response.status_code} {response.text}")
        return None

def test_syncserver_request():
    """Make a request to syncserver with Keycloak JWT token"""
    token = get_keycloak_token()
    if not token:
        return
    
    print(f"Got token: {token[:50]}...")
    
    # Make a request to syncserver tokenserver endpoint
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }
    
    # Try to get a sync token
    url = "http://syncserver:8000/1.0/sync/1.5"
    
    print(f"Making request to: {url}")
    print(f"Headers: {headers}")
    
    try:
        response = requests.get(url, headers=headers)
        print(f"Response status: {response.status_code}")
        print(f"Response headers: {dict(response.headers)}")
        print(f"Response body: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")

if __name__ == "__main__":
    test_syncserver_request()