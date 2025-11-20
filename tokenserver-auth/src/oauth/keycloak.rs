#[cfg(feature = "keycloak")]
use super::VerifyOutput;
#[cfg(feature = "keycloak")]
pub use crate::crypto::JWTVerifier;
#[cfg(feature = "keycloak")]
use crate::crypto::OAuthVerifyError;
#[cfg(feature = "keycloak")]
use crate::VerifyToken;
#[cfg(feature = "keycloak")]
use async_trait::async_trait;
#[cfg(feature = "keycloak")]
use reqwest::Url;
#[cfg(feature = "keycloak")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "keycloak")]
use std::{borrow::Cow, time::Duration};
#[cfg(feature = "keycloak")]
use syncserver_common::Metrics;
#[cfg(feature = "keycloak")]
use tokenserver_common::TokenserverError;
#[cfg(feature = "keycloak")]
use tokenserver_settings::Settings;

#[cfg(feature = "keycloak")]
const SYNC_SCOPE: &str = "https://identity.mozilla.com/apps/oldsync";

#[cfg(feature = "keycloak")]
#[derive(Serialize, Deserialize, Debug)]
struct TokenClaims {
    #[serde(rename = "sub")]
    user: String,
    #[serde(rename = "preferred_username")]
    username: Option<String>,
    email: Option<String>,
    scope: Option<String>,
    #[serde(rename = "fxa-generation")]
    generation: Option<i64>,
    // Keycloak specific fields
    #[serde(rename = "realm_access")]
    realm_access: Option<RealmAccess>,
    #[serde(rename = "resource_access")]
    resource_access: Option<serde_json::Value>,
}

#[cfg(feature = "keycloak")]
#[derive(Serialize, Deserialize, Debug)]
struct RealmAccess {
    roles: Vec<String>,
}

#[cfg(feature = "keycloak")]
impl TokenClaims {
    fn validate(self) -> Result<VerifyOutput, TokenserverError> {
        // For Keycloak, we'll be more flexible with scope validation
        // We can check for specific roles or scopes as needed
        if let Some(scope) = &self.scope {
            if !scope.split(' ').any(|s| s == "openid" || s == "email") {
                return Err(TokenserverError::invalid_credentials(
                    "Unauthorized - missing required scope".to_string(),
                ));
            }
        }
        
        Ok(self.into())
    }
}

#[cfg(feature = "keycloak")]
impl From<TokenClaims> for VerifyOutput {
    fn from(value: TokenClaims) -> Self {
        // For Keycloak, we'll use the subject as the user ID
        // In a real implementation, you might want to map this differently
        Self {
            fxa_uid: value.user,
            generation: value.generation,
        }
    }
}

/// The Keycloak verifier used to verify OAuth tokens.
#[cfg(feature = "keycloak")]
#[derive(Clone)]
pub struct KeycloakVerifier<J> {
    jwks_url: Url,
    jwk_verifiers: Vec<J>,
    http_client: reqwest::Client,
    realm: String,
}

#[cfg(feature = "keycloak")]
impl<J> KeycloakVerifier<J>
where
    J: JWTVerifier,
{
    pub fn new(settings: &Settings, jwk_verifiers: Vec<J>) -> Result<Self, TokenserverError> {
        let base_url = Url::parse(&settings.keycloak_server_url)
            .map_err(|_| TokenserverError::internal_error())?;
        
        let jwks_path = format!("realms/{}/protocol/openid-connect/certs", settings.keycloak_realm);
        let jwks_url = base_url
            .join(&jwks_path)
            .map_err(|_| TokenserverError::internal_error())?;
        
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(settings.keycloak_request_timeout))
            .use_rustls_tls()
            .build()
            .map_err(|_| TokenserverError::internal_error())?;

        Ok(Self {
            jwks_url,
            jwk_verifiers,
            http_client,
            realm: settings.keycloak_realm.clone(),
        })
    }

    async fn get_remote_jwks(&self) -> Result<Vec<J>, TokenserverError> {
        #[derive(Deserialize)]
        struct KeysResponse<K> {
            keys: Vec<K>,
        }
        self.http_client
            .get(self.jwks_url.clone())
            .send()
            .await
            .map_err(internal_err_with_ctx)?
            .json::<KeysResponse<J::Key>>()
            .await
            .map_err(internal_err_with_ctx)?
            .keys
            .into_iter()
            .map(|key| key.try_into().map_err(internal_err_with_ctx))
            .collect()
    }

    fn verify_jwt_locally(
        &self,
        verifiers: &[Cow<'_, J>],
        token: &str,
    ) -> Result<TokenClaims, OAuthVerifyError> {
        if verifiers.is_empty() {
            return Err(OAuthVerifyError::InvalidKey);
        }

        verifiers
            .iter()
            .find_map(|verifier| {
                match verifier.verify::<TokenClaims>(token) {
                    // If it's an invalid signature, it means our key was well formatted,
                    // but the signature was incorrect. Lets try another key if we have any
                    Err(OAuthVerifyError::InvalidSignature) => None,
                    res => Some(res),
                }
            })
            // If there is nothing, it means all of our keys were well formatted, but none of them
            // were able to verify the signature, lets return a TrustError
            .ok_or(OAuthVerifyError::TrustError)?
    }
}

#[cfg(feature = "keycloak")]
#[async_trait]
impl<J> VerifyToken for KeycloakVerifier<J>
where
    J: JWTVerifier,
{
    type Output = VerifyOutput;

    /// Verifies a Keycloak OAuth token. Returns `VerifyOutput` for valid tokens and a `TokenserverError`
    /// for invalid tokens.
    ///
    /// The verifier will first attempt to verify the token using Keycloak's public keys, which were
    /// provided as environment variables.
    ///
    /// If Keycloak's public keys were not supplied, then the verifier will query Keycloak's 
    /// `/realms/{realm}/protocol/openid-connect/certs` endpoint to get the latest public keys.
    async fn verify(
        &self,
        token: String,
        metrics: &Metrics,
    ) -> Result<VerifyOutput, TokenserverError> {
        let mut verifiers = self
            .jwk_verifiers
            .iter()
            .map(Cow::Borrowed)
            .collect::<Vec<_>>();
        
        if self.jwk_verifiers.is_empty() {
            verifiers = self
                .get_remote_jwks()
                .await
                .unwrap_or_else(|e| {
                    slog_scope::warn!("Error requesting remote jwks from Keycloak: {}", e);
                    vec![]
                })
                .into_iter()
                .map(Cow::Owned)
                .collect();
        }

        let claims = match self.verify_jwt_locally(&verifiers, &token) {
            Ok(res) => res,
            Err(e) => {
                if e.is_reportable_err() {
                    metrics.incr(e.metric_label())
                }
                return Err(unauthorized_err_with_ctx(e));
            }
        };
        
        claims.validate()
    }
}

#[cfg(feature = "keycloak")]
fn unauthorized_err_with_ctx<E: std::fmt::Display>(err: E) -> TokenserverError {
    TokenserverError {
        context: err.to_string(),
        ..TokenserverError::invalid_credentials("Unauthorized".to_string())
    }
}

#[cfg(feature = "keycloak")]
fn internal_err_with_ctx<E: std::fmt::Display>(err: E) -> TokenserverError {
    TokenserverError {
        context: err.to_string(),
        ..TokenserverError::internal_error()
    }
}

#[cfg(all(test, feature = "keycloak"))]
mod tests {
    use crate::crypto::{JWTVerifierImpl, OAuthVerifyError};
    use serde_json::json;
    use super::*;

    #[derive(Deserialize)]
    struct MockJWK {}

    macro_rules! mock_jwk_verifier {
        ($im:expr) => {
            mock_jwk_verifier!(_token, $im);
        };
        ($token:ident, $im:expr) => {
            #[derive(Clone, Debug)]
            struct MockJWTVerifier {}
            impl TryFrom<MockJWK> for MockJWTVerifier {
                type Error = OAuthVerifyError;
                fn try_from(_value: MockJWK) -> Result<Self, Self::Error> {
                    Ok(Self {})
                }
            }

            impl JWTVerifier for MockJWTVerifier {
                type Key = MockJWK;
                fn verify<T: ::serde::de::DeserializeOwned>(
                    &self,
                    $token: &str,
                ) -> Result<T, OAuthVerifyError> {
                    $im
                }
            }
        };
    }

    #[tokio::test]
    async fn test_keycloak_token_validation() -> Result<(), TokenserverError> {
        let token_claims = TokenClaims {
            user: "keycloak_user_id".to_string(),
            username: Some("testuser".to_string()),
            email: Some("test@example.com".to_string()),
            scope: Some("openid email".to_string()),
            generation: Some(1),
            realm_access: None,
            resource_access: None,
        };
        
        mock_jwk_verifier!(token, Ok(serde_json::from_str(token).unwrap()));
        
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let settings = Settings {
            keycloak_server_url: "http://localhost:7080".to_string(),
            keycloak_realm: "sync".to_string(),
            keycloak_request_timeout: 10,
            ..Settings::default()
        };
        
        let verifier: KeycloakVerifier<MockJWTVerifier> = KeycloakVerifier::new(&settings, jwk_verifiers)?;
        
        let res = verifier
            .verify(
                serde_json::to_string(&token_claims).unwrap(),
                &Default::default(),
            )
            .await?;
            
        assert_eq!(res.fxa_uid, "keycloak_user_id");
        assert_eq!(res.generation.unwrap(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_keycloak_missing_scope_fails() -> Result<(), TokenserverError> {
        let token_claims = TokenClaims {
            user: "keycloak_user_id".to_string(),
            username: Some("testuser".to_string()),
            email: Some("test@example.com".to_string()),
            scope: Some("profile".to_string()), // Missing required scopes
            generation: Some(1),
            realm_access: None,
            resource_access: None,
        };
        
        mock_jwk_verifier!(token, Ok(serde_json::from_str(token).unwrap()));
        
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let settings = Settings {
            keycloak_server_url: "http://localhost:7080".to_string(),
            keycloak_realm: "sync".to_string(),
            keycloak_request_timeout: 10,
            ..Settings::default()
        };
        
        let verifier: KeycloakVerifier<MockJWTVerifier> = KeycloakVerifier::new(&settings, jwk_verifiers)?;
        
        let err = verifier
            .verify(
                serde_json::to_string(&token_claims).unwrap(),
                &Default::default(),
            )
            .await
            .unwrap_err();
            
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert!(err.description.contains("Unauthorized"));
        Ok(())
    }
}