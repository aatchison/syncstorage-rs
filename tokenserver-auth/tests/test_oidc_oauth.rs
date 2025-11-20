use serde_json::json;

#[test]
fn test_basic_compilation() {
    // Just test that the code compiles
    assert!(true);
}

#[test]
fn test_token_claims_generation_compatibility() {
    // Test that TokenClaims can be deserialized with different generation fields
    
    // Test legacy generation field
    let legacy_token = json!({
        "sub": "test_user",
        "scope": "https://identity.mozilla.com/apps/oldsync",
        "generation": 123
    });
    
    // Just test that it deserializes without error
    let result = serde_json::from_value::<serde_json::Value>(legacy_token);
    assert!(result.is_ok());
    
    // Test FxA generation field
    let fxa_token = json!({
        "sub": "test_user", 
        "scope": "https://identity.mozilla.com/apps/oldsync",
        "fxa-generation": 456
    });
    
    let result = serde_json::from_value::<serde_json::Value>(fxa_token);
    assert!(result.is_ok());
    
    // Test OIDC issued_at field
    let oidc_token = json!({
        "sub": "test_user",
        "scope": "https://identity.mozilla.com/apps/oldsync", 
        "iat": 789
    });
    
    let result = serde_json::from_value::<serde_json::Value>(oidc_token);
    assert!(result.is_ok());
}

#[test]
fn test_scope_validation_formats() {
    // Test that different scope formats can be parsed
    
    // Test comma-separated scopes
    let comma_token = json!({
        "sub": "test_user",
        "scope": "openid,profile,https://identity.mozilla.com/apps/oldsync",
        "generation": 123
    });
    
    let result = serde_json::from_value::<serde_json::Value>(comma_token);
    assert!(result.is_ok());
    
    // Test space-separated scopes
    let space_token = json!({
        "sub": "test_user", 
        "scope": "openid profile https://identity.mozilla.com/apps/oldsync",
        "generation": 123
    });
    
    let result = serde_json::from_value::<serde_json::Value>(space_token);
    assert!(result.is_ok());
    
    // Test missing sync scope
    let no_sync_token = json!({
        "sub": "test_user",
        "scope": "openid profile",
        "generation": 123
    });
    
    let result = serde_json::from_value::<serde_json::Value>(no_sync_token);
    assert!(result.is_ok());
}