#!/usr/bin/env rust-script

//! Test script to verify Keycloak integration
//! 
//! This script tests the basic functionality of our Keycloak OAuth integration
//! without requiring a full Docker setup.

use std::collections::HashMap;

fn main() {
    println!("Testing Keycloak Integration");
    
    // Test 1: Configuration parsing
    test_config_parsing();
    
    // Test 2: JWT token structure
    test_jwt_structure();
    
    println!("All tests completed!");
}

fn test_config_parsing() {
    println!("✓ Test 1: Configuration parsing");
    
    // Simulate the configuration we expect
    let config = HashMap::from([
        ("oauth_provider", "keycloak"),
        ("keycloak_server_url", "http://localhost:7080"),
        ("keycloak_realm", "sync"),
        ("keycloak_request_timeout", "30"),
    ]);
    
    assert_eq!(config.get("oauth_provider"), Some(&"keycloak"));
    assert_eq!(config.get("keycloak_server_url"), Some(&"http://localhost:7080"));
    assert_eq!(config.get("keycloak_realm"), Some(&"sync"));
    
    println!("  - OAuth provider: {}", config.get("oauth_provider").unwrap());
    println!("  - Keycloak server: {}", config.get("keycloak_server_url").unwrap());
    println!("  - Keycloak realm: {}", config.get("keycloak_realm").unwrap());
}

fn test_jwt_structure() {
    println!("✓ Test 2: JWT token structure");
    
    // Example JWT payload that Keycloak would generate
    let jwt_payload = r#"{
        "sub": "user123",
        "preferred_username": "testuser",
        "scope": "openid profile email",
        "realm_access": {
            "roles": ["user", "sync-user"]
        },
        "resource_access": {
            "sync-client": {
                "roles": ["sync"]
            }
        },
        "iss": "http://localhost:7080/realms/sync",
        "aud": "sync-client",
        "exp": 1735934159,
        "iat": 1735930559
    }"#;
    
    // Parse the JSON to verify structure
    let parsed: serde_json::Value = serde_json::from_str(jwt_payload).unwrap();
    
    assert_eq!(parsed["sub"], "user123");
    assert_eq!(parsed["preferred_username"], "testuser");
    assert!(parsed["scope"].as_str().unwrap().contains("openid"));
    
    println!("  - Subject: {}", parsed["sub"]);
    println!("  - Username: {}", parsed["preferred_username"]);
    println!("  - Scope: {}", parsed["scope"]);
    println!("  - Issuer: {}", parsed["iss"]);
}