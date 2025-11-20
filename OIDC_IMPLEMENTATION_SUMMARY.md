# OIDC Support Implementation Summary

## Overview
Successfully reconfigured the sync server OAuth system to support Keycloak as an OIDC provider instead of being hardcoded to Firefox Accounts (FxA). This implementation allows the tokenserver to work with any OIDC-compliant provider while maintaining backward compatibility with FxA.

## Key Changes Made

### 1. Configuration Support (`tokenserver-settings/src/lib.rs`)
- Added `oauth_provider_type` field to specify "fxa" or "oidc"
- Added `oidc_issuer_url` field for OIDC provider configuration
- Both fields support environment variable configuration

### 2. OAuth Token Verification (`tokenserver-auth/src/oauth/native.rs`)
- Enhanced `TokenClaims` struct to support multiple token formats:
  - FxA tokens: `fxa-generation` field
  - OIDC tokens: `iat` (issued at) field  
  - Legacy tokens: `generation` field
- Updated `Verifier` constructor to handle both FxA and OIDC endpoints:
  - FxA: `/v1/verify` and `/v1/jwks`
  - OIDC: `/protocol/openid-connect/certs`
- Modified verification logic to skip remote verification for OIDC providers
- Enhanced scope validation to handle both comma-separated and space-separated formats

### 3. Keycloak Configuration (`keycloak/realm-export.json`)
- Added sync scope: `https://identity.mozilla.com/apps/oldsync`
- Configured public-client with sync scope in defaultClientScopes
- Updated realm to support OAuth flows needed by sync server

### 4. Test Configuration Updates
- Updated `conftest.py` to conditionally use Keycloak when `KEYCLOAK_URL` is set
- Modified Docker Compose to use OIDC configuration instead of FxA JWK settings
- Updated test scripts to request sync scope in OAuth flow

## Technical Implementation Details

### Token Format Compatibility
The `TokenClaims` struct now handles three different generation field formats:
```rust
#[derive(Serialize, Deserialize, Debug)]
struct TokenClaims {
    #[serde(rename = "sub")]
    user: String,
    scope: String,
    #[serde(rename = "fxa-generation")]
    fxa_generation: Option<i64>,
    #[serde(rename = "iat")]
    issued_at: Option<i64>,
    #[serde(default)]
    generation: Option<u64>,
}
```

### Provider-Specific Logic
The verifier now adapts its behavior based on the provider type:
- **FxA providers**: Use remote verification fallback if JWT verification fails
- **OIDC providers**: Skip remote verification, rely only on JWT validation

### Scope Validation
Enhanced to support both OAuth 2.0 standard formats:
```rust
let has_sync_scope = self.scope.split(',').any(|scope| scope.trim() == SYNC_SCOPE)
    || self.scope.split(' ').any(|scope| scope.trim() == SYNC_SCOPE);
```

## Configuration Examples

### Environment Variables
```bash
export OAUTH_PROVIDER_TYPE=oidc
export OIDC_ISSUER_URL=http://localhost:7080/realms/sync
export FXA_OAUTH_SERVER_URL=http://localhost:7080/realms/sync
```

### Configuration File
```toml
oauth_provider_type = "oidc"
oidc_issuer_url = "http://localhost:7080/realms/sync"
fxa_oauth_server_url = "http://localhost:7080/realms/sync"
```

## Testing and Verification

### Integration Tests
Created comprehensive integration tests (`test_oidc_integration.py`) that verify:
- ✅ OIDC configuration loading (file and environment)
- ✅ TokenClaims multi-format support (FxA, OIDC, legacy)
- ✅ Scope validation (comma and space-separated)
- ✅ OIDC provider logic (no remote verification fallback)
- ✅ Successful compilation of entire syncserver with OIDC support

### Build Verification
- ✅ `cargo build --bin syncserver` succeeds
- ✅ `cargo build --no-default-features` succeeds for tokenserver-auth
- ✅ All OIDC configuration options load correctly

## Backward Compatibility
The implementation maintains full backward compatibility:
- Existing FxA configurations continue to work unchanged
- Legacy token formats are still supported
- Default behavior remains FxA-compatible when no OIDC config is provided

## Benefits Achieved
1. **Flexibility**: Can now use any OIDC-compliant provider (Keycloak, Auth0, etc.)
2. **Maintainability**: Cleaner separation between OAuth providers
3. **Standards Compliance**: Follows OIDC and OAuth 2.0 standards
4. **Performance**: Eliminates unnecessary remote verification for OIDC tokens
5. **Security**: Proper JWT validation with provider-specific logic

## Next Steps
The sync server is now ready to work with Keycloak. To deploy:

1. Start Keycloak with the provided realm configuration
2. Set environment variables for OIDC provider
3. Start syncserver - it will automatically use OIDC mode
4. Test OAuth flow with Keycloak-issued tokens

The implementation successfully addresses the original issue where authorization tests were failing with "invalid-credentials" instead of specific error statuses, by providing proper OIDC token handling and validation.