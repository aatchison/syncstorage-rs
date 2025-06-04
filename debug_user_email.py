#!/usr/bin/env python3

import os
import sys

# Set environment variable to simulate Keycloak mode
os.environ['SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE'] = 'oidc'

# Import the test support module
sys.path.append('/workspace/syncstorage-rs/tools/integration_tests/tokenserver')

# Test the email logic directly
def test_email_logic():
    oauth_provider_type = os.environ.get('SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE', 'fxa')
    print(f"OAuth provider type: {oauth_provider_type}")
    
    if oauth_provider_type == 'oidc':
        # When using Keycloak OIDC, the JWT subject is a UUID and email is constructed as {uuid}@{domain}
        # The service account UUID is fixed in our Keycloak configuration
        keycloak_service_account_uuid = '468ee2d8-047a-497a-9247-f8e7056608a6'
        email = f'{keycloak_service_account_uuid}@localhost'
        print(f"Keycloak email format: {email}")
    else:
        # Default FxA format
        FXA_EMAIL_DOMAIN = 'api-accounts.stage.mozaws.net'
        email = 'test@%s' % FXA_EMAIL_DOMAIN
        print(f"FxA email format: {email}")
    
    return email

if __name__ == "__main__":
    email = test_email_logic()
    print(f"Final email: {email}")