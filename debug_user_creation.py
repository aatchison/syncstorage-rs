#!/usr/bin/env python3

import requests
import jwt
import json

# Get JWT token from Keycloak
response = requests.post(
    'http://localhost:7080/realms/sync/protocol/openid-connect/token',
    headers={'Content-Type': 'application/x-www-form-urlencoded'},
    data={
        'grant_type': 'client_credentials',
        'client_id': 'confidential-client',
        'client_secret': 'YcdeiCc742lOk17poGhWT51GTAWMnQMr'
    }
)

if response.status_code == 200:
    data = response.json()
    token = data['access_token']
    
    # Decode token without verification to see claims
    decoded = jwt.decode(token, options={'verify_signature': False})
    
    fxa_uid = decoded.get('sub')
    fxa_email_domain = 'localhost'  # From syncserver settings
    expected_email = f"{fxa_uid}@{fxa_email_domain}"
    
    print(f"JWT Subject (fxa_uid): {fxa_uid}")
    print(f"Expected email format: {expected_email}")
    print(f"This is the email format that should be used in _add_user() calls")
else:
    print(f'Error getting token: {response.status_code} {response.text}')