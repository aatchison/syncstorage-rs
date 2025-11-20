#!/usr/bin/env python3
import requests
import json
import jwt

# Get token from Keycloak
response = requests.post(
    'http://keycloak:7080/realms/sync/protocol/openid-connect/token',
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
    data={
        'grant_type': 'client_credentials',
        'client_id': 'sync-client',
        'client_secret': 'YcdeiCc742lOk17poGhWT51GTAWMnQMr'
    }
)

if response.status_code == 200:
    data = response.json()
    token = data['access_token']
    print(f'Token: {token[:50]}...')
    
    # Decode JWT to see claims
    try:
        decoded = jwt.decode(token, options={'verify_signature': False})
        print('JWT Claims:')
        print(json.dumps(decoded, indent=2))
    except Exception as e:
        print(f'Error decoding JWT: {e}')
        
    # Test request to syncserver
    print('\nTesting request to syncserver...')
    try:
        sync_response = requests.get(
            'http://syncserver:8000/1.0/sync/1.5',
            headers={'Authorization': f'Bearer {token}'},
            timeout=5
        )
        print(f'Response status: {sync_response.status_code}')
        print(f'Response headers: {dict(sync_response.headers)}')
        print(f'Response body: {sync_response.text[:500]}')
    except Exception as e:
        print(f'Error making request: {e}')
else:
    print(f'Error getting token: {response.status_code} {response.text}')