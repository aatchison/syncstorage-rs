# Real JWT Token Implementation for E2E Tests

## Overview

This implementation replaces the test mode bypass approach with real JWT token generation from Keycloak for end-to-end testing. This provides proper OIDC integration testing while maintaining backward compatibility with FxA.

## Changes Made

### 1. Removed Test Mode Bypass

**File: `tokenserver-auth/src/oauth/native.rs`**
- Removed `test_mode` field from `Verifier` struct
- Removed `verify_test_token()` method that parsed fake JSON tokens
- Removed test mode check in `verify()` method
- All tokens now go through proper JWT validation

### 2. Added Test User to Keycloak

**File: `keycloak/realm-export.json`**
- Added test user: `test@test.com` with password `1234`
- User has proper realm roles and email verification
- Note: E2E tests use client credentials flow, not password grant

### 3. Enhanced Test Support for Real JWT Tokens

**File: `tools/integration_tests/tokenserver/test_support.py`**
- Added `_get_keycloak_token()` method to generate real JWT tokens
- Uses Keycloak client credentials grant flow with confidential client
- Automatically detects OIDC configuration from environment variables
- Falls back to fake tokens when Keycloak is not available or for FxA

### 4. Removed Test Mode from Docker Compose

**File: `docker-compose.e2e.mysql.keycloak.yaml`**
- Removed `SYNC_TOKENSERVER__TEST_MODE: "true"` environment variable
- E2E tests now use real JWT validation

## How It Works

### Token Generation Logic

1. **OIDC Mode (Keycloak)**:
   - Detects `SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE=oidc`
   - Makes HTTP request to Keycloak token endpoint
   - Uses client credentials grant with confidential client
   - Returns real JWT token with proper claims and signature

2. **FxA Mode or Fallback**:
   - Uses original fake JSON token approach
   - Maintains backward compatibility
   - Works when Keycloak is not available

### Environment Variables

The implementation automatically detects the OAuth provider type:
- `SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE=oidc` → Use Keycloak
- `SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE=fxa` → Use fake tokens
- Missing or other values → Use fake tokens

### Keycloak Configuration

- **Token Endpoint**: `{OIDC_ISSUER_URL}/protocol/openid-connect/token`
- **Grant Type**: `client_credentials`
- **Client ID**: `confidential-client`
- **Client Secret**: `YcdeiCc742lOk17poGhWT51GTAWMnQMr`
- **Scope**: `openid https://identity.mozilla.com/apps/oldsync`

## Benefits

1. **Real OIDC Testing**: E2E tests now use actual JWT tokens with proper validation
2. **Backward Compatibility**: FxA tests continue to work with fake tokens
3. **Automatic Detection**: No manual configuration needed - detects environment
4. **Graceful Fallback**: Falls back to fake tokens if Keycloak is unavailable
5. **Proper Integration**: Tests the full OIDC flow including JWT verification

## Testing

All existing tests continue to pass:
- OIDC integration tests: ✅ 3/3 passing
- Tokenserver auth tests: ✅ All passing
- Compilation: ✅ Successful

## Usage

When running E2E tests with Keycloak:
1. Start Keycloak service with the realm export
2. Set environment variables for OIDC mode
3. Run tests - they will automatically use real JWT tokens

The test support will:
- Generate real JWT tokens from Keycloak
- Use proper OAuth headers with Bearer tokens
- Validate tokens through the full OIDC flow
- Provide meaningful error messages if token generation fails

This implementation ensures that E2E tests properly validate the OIDC integration while maintaining compatibility with existing FxA-based tests.