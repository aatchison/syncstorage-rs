use super::VerifyOutput;
use crate::VerifyToken;
pub use crate::crypto::JWTVerifier;
use crate::crypto::JWTVerifyError;
use async_trait::async_trait;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{borrow::Cow, time::Duration};
use syncserver_common::Metrics;
use tokenserver_common::TokenserverError;
use tokenserver_settings::{OAuthProvider, Settings};

const SYNC_SCOPE: &str = "https://identity.mozilla.com/apps/oldsync";

#[derive(Serialize, Deserialize, Debug)]
struct TokenClaims {
    #[serde(rename = "sub")]
    user: String,
    scope: String,
    #[serde(rename = "fxa-generation")]
    fxa_generation: Option<i64>,
    /// The OIDC "issued at" claim. Only used as the generation for OIDC providers.
    #[serde(rename = "iat")]
    issued_at: Option<i64>,
    /// A plain "generation" claim, kept for compatibility with test tokens.
    #[serde(default)]
    generation: Option<u64>,
}

impl TokenClaims {
    /// Returns the generation, preferring the FxA-specific claim. For OIDC providers, which
    /// have no generation concept, the "iat" claim is used next. FxA tokens never use "iat",
    /// since it is in seconds while FxA generations are in milliseconds.
    fn get_generation(&self, oidc: bool) -> Option<i64> {
        self.fxa_generation
            .or(if oidc { self.issued_at } else { None })
            .or(self.generation.map(|g| g as i64))
    }

    fn validate(self, oidc: bool) -> Result<VerifyOutput, TokenserverError> {
        // FxA uses comma-separated scopes; OIDC providers use space-separated scopes.
        let has_sync_scope = self
            .scope
            .split([',', ' '])
            .any(|scope| scope.trim() == SYNC_SCOPE);
        if !has_sync_scope {
            return Err(TokenserverError::invalid_credentials(
                "Unauthorized".to_string(),
            ));
        }
        let generation = self.get_generation(oidc);
        Ok(VerifyOutput {
            fxa_uid: self.user,
            generation,
        })
    }
}

/// The verifier used to verify OAuth tokens.
#[derive(Clone)]
pub struct Verifier<J> {
    verify_url: Url,
    jwks_url: Url,
    jwk_verifiers: Vec<J>,
    http_client: reqwest::Client,
    /// True when `oauth_provider` is "oidc".
    oidc: bool,
}

impl<J> Verifier<J>
where
    J: JWTVerifier,
{
    pub fn new(settings: &Settings, jwk_verifiers: Vec<J>) -> Result<Self, TokenserverError> {
        let oidc = settings.oauth_provider == OAuthProvider::Oidc;
        let (verify_url, jwks_url) = if oidc {
            // For OIDC providers like Keycloak
            let issuer = settings.oidc_issuer_url.as_ref().ok_or_else(|| {
                internal_err_with_ctx("oauth_provider is \"oidc\" but oidc_issuer_url is not set")
            })?;
            // Make sure the issuer path ends in "/" so that `join` appends to it instead of
            // replacing its last segment (e.g. ".../realms/sync").
            let issuer = if issuer.ends_with('/') {
                issuer.to_owned()
            } else {
                format!("{}/", issuer)
            };
            let base_url = Url::parse(&issuer).map_err(|_| TokenserverError::internal_error())?;

            // OIDC has no verify endpoint; only local JWT verification is used, so this URL
            // is a placeholder that is never requested.
            let verify_url = base_url.clone();
            let jwks_url = base_url
                .join("protocol/openid-connect/certs")
                .map_err(|_| TokenserverError::internal_error())?;

            (verify_url, jwks_url)
        } else {
            let base_url = Url::parse(&settings.fxa_oauth_server_url)
                .map_err(|_| TokenserverError::internal_error())?;
            let verify_url = base_url
                .join("v1/verify")
                .map_err(|_| TokenserverError::internal_error())?;
            let jwks_url = base_url
                .join("v1/jwks")
                .map_err(|_| TokenserverError::internal_error())?;

            (verify_url, jwks_url)
        };
        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(settings.fxa_oauth_request_timeout))
            .use_rustls_tls()
            .build()
            .map_err(|_| TokenserverError::internal_error())?;

        Ok(Self {
            verify_url,
            jwks_url,
            jwk_verifiers,
            http_client,
            oidc,
        })
    }

    async fn remote_verify_token(&self, token: &str) -> Result<TokenClaims, TokenserverError> {
        #[derive(Serialize)]
        struct VerifyRequest<'a> {
            token: &'a str,
        }

        #[derive(Serialize, Deserialize)]
        struct VerifyResponse {
            user: String,
            scope: Vec<String>,
            generation: Option<i64>,
        }

        impl From<VerifyResponse> for TokenClaims {
            fn from(value: VerifyResponse) -> Self {
                Self {
                    user: value.user,
                    scope: value.scope.join(","),
                    fxa_generation: value.generation,
                    issued_at: None,
                    generation: None,
                }
            }
        }

        Ok(self
            .http_client
            .post(self.verify_url.clone())
            .json(&VerifyRequest { token })
            .send()
            .await
            .map_err(unauthorized_err_with_ctx)
            .and_then(|res| {
                if !res.status().is_success() {
                    Err(unauthorized_err_with_ctx(format!(
                        "Got verify status code: {}",
                        res.status()
                    )))
                } else {
                    Ok(res)
                }
            })?
            .json::<VerifyResponse>()
            .await
            .map_err(unauthorized_err_with_ctx)?
            .into())
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
    ) -> Result<TokenClaims, JWTVerifyError> {
        if verifiers.is_empty() {
            return Err(JWTVerifyError::InvalidKey);
        }

        verifiers
            .iter()
            .find_map(|verifier| {
                match verifier.verify::<TokenClaims>(token) {
                    // If it's an invalid signature, it means our key was well formatted,
                    // but the signature was incorrect. Lets try another key if we have any
                    Err(JWTVerifyError::InvalidSignature) => None,
                    res => Some(res),
                }
            })
            // If there is nothing, it means all of our keys were well formatted, but none of them
            // were able to verify the signature, lets erturn a TrustError
            .ok_or(JWTVerifyError::TrustError)?
    }
}

#[async_trait]
impl<J> VerifyToken for Verifier<J>
where
    J: JWTVerifier,
{
    type Output = VerifyOutput;

    /// Verifies an OAuth token. Returns `VerifyOutput` for valid tokens and a `TokenserverError`
    /// for invalid tokens.
    ///
    /// The verifier will first attempt to verify the token using FxA's public keys, which were
    /// provided as environment variables.
    ///
    /// If FxA's public keys were not supplied, then the verifier will query FxA's /v1/jwks
    /// endpoint to get the latest public keys.
    ///
    /// If verifying the tokens fails because the keys are
    /// invalid, or because the keys were valid but the tokens have changed their structure, then
    /// the verifier will fallback to hitting fxa's /v1/verify endpoint to verify instead. All
    /// other failures will be recorded as invalid credentials and will returns a generic "Unauthorized" message
    /// to the user
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
                    slog_scope::warn!("Error requesting remote jwks: {}", e);
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
                match e {
                    JWTVerifyError::DecodingError | JWTVerifyError::InvalidKey => {
                        // OIDC providers have no remote verify endpoint to fall back to
                        if self.oidc {
                            return Err(unauthorized_err_with_ctx(e));
                        }
                        self.remote_verify_token(&token).await?
                    }
                    e => return Err(unauthorized_err_with_ctx(e)),
                }
            }
        };
        claims.validate(self.oidc)
    }
}

fn unauthorized_err_with_ctx<E: std::fmt::Display>(err: E) -> TokenserverError {
    TokenserverError {
        context: err.to_string(),
        ..TokenserverError::invalid_credentials("Unauthorized".to_string())
    }
}

fn internal_err_with_ctx<E: std::fmt::Display>(err: E) -> TokenserverError {
    TokenserverError {
        context: err.to_string(),
        ..TokenserverError::internal_error()
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{JWTVerifierImpl, JWTVerifyError};
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
                type Error = JWTVerifyError;
                fn try_from(_value: MockJWK) -> Result<Self, Self::Error> {
                    Ok(Self {})
                }
            }

            impl JWTVerifier for MockJWTVerifier {
                type Key = MockJWK;
                fn verify<T: ::serde::de::DeserializeOwned>(
                    &self,
                    $token: &str,
                ) -> Result<T, JWTVerifyError> {
                    $im
                }
            }
        };
    }

    #[tokio::test]
    async fn test_no_keys_in_verifier_fallsback_to_fxa() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new();
        let mock_jwks = server.mock("GET", "/v1/jwks").with_status(500).create();

        let body = json!({
            "user": "fxa_id",
            "scope": [SYNC_SCOPE],
            "generation": 123
        });
        let mock_verify = server
            .mock("POST", "/v1/verify")
            .with_header("content-type", "application/json")
            .with_status(200)
            .with_body(body.to_string())
            .create();

        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Default::default()
        };
        let verifer: Verifier<JWTVerifierImpl> = Verifier::new(&settings, vec![])?;
        let res = verifer
            .verify("a token fxa will validate".to_string(), &Default::default())
            .await?;
        mock_jwks.expect(1);
        mock_verify.expect(1);
        assert_eq!(res.generation.unwrap(), 123);
        assert_eq!(res.fxa_uid, "fxa_id");
        Ok(())
    }

    #[tokio::test]
    async fn test_expired_signature_fails() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new();
        let mock = server.mock("POST", "/v1/verify").create();
        mock_jwk_verifier!(Err(JWTVerifyError::InvalidSignature));

        let jwk_verifiers = vec![MockJWTVerifier {}];
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };

        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers)?;

        let err = verifier
            .verify("An expired token".to_string(), &Default::default())
            .await
            .unwrap_err();
        // We also make sure we didn't try to hit the server
        mock.expect(0);
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");

        Ok(())
    }

    #[tokio::test]
    async fn test_verifier_attempts_all_keys_if_invalid_signature() -> Result<(), TokenserverError>
    {
        let mut server = mockito::Server::new();
        let mock = server.mock("POST", "/v1/verify").create();
        #[derive(Debug, Clone)]
        struct MockJWTVerifier {
            id: u8,
        }

        impl TryFrom<MockJWK> for MockJWTVerifier {
            type Error = JWTVerifyError;
            fn try_from(_value: MockJWK) -> Result<Self, Self::Error> {
                Ok(Self { id: 0 })
            }
        }

        impl JWTVerifier for MockJWTVerifier {
            type Key = MockJWK;
            fn verify<T: serde::de::DeserializeOwned>(
                &self,
                token: &str,
            ) -> Result<T, JWTVerifyError> {
                if self.id == 0 {
                    Err(JWTVerifyError::InvalidSignature)
                } else {
                    Ok(serde_json::from_str(token).unwrap())
                }
            }
        }

        let jwk_verifiers = vec![MockJWTVerifier { id: 0 }, MockJWTVerifier { id: 1 }];
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers).unwrap();

        let token_claims = TokenClaims {
            user: "fxa_id".to_string(),
            scope: SYNC_SCOPE.to_string(),
            fxa_generation: Some(124),
            issued_at: None,
            generation: None,
        };

        let res = verifier
            .verify(
                serde_json::to_string(&token_claims).unwrap(),
                &Default::default(),
            )
            .await?;
        assert_eq!(res.fxa_uid, "fxa_id");
        assert_eq!(res.generation.unwrap(), 124);
        mock.expect(0); // We shouldn't have hit the server
        Ok(())
    }

    #[tokio::test]
    async fn test_verifier_all_signature_failures_fails() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new();
        let mock_verify = server.mock("POST", "/v1/verify").create();
        mock_jwk_verifier!(Err(JWTVerifyError::InvalidSignature));

        let jwk_verifiers = vec![MockJWTVerifier {}, MockJWTVerifier {}];
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers).unwrap();
        let err = verifier
            .verify(
                "a token with an invalid signature".to_string(),
                &Default::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");

        mock_verify.expect(0);
        Ok(())
    }

    #[tokio::test]
    async fn test_verifier_fallsback_if_decode_error() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new();
        let body = json!({
            "user": "fxa_id",
            "scope": [SYNC_SCOPE],
            "generation": 123
        });
        let mock_verify = server
            .mock("POST", "/v1/verify")
            .with_header("content-type", "application/json")
            .with_status(200)
            .with_body(body.to_string())
            .create();

        mock_jwk_verifier!(Err(JWTVerifyError::DecodingError));

        let jwk_verifiers = vec![MockJWTVerifier {}];
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers).unwrap();

        let res = verifier
            .verify(
                "invalid token that can't be decoded".to_string(),
                &Default::default(),
            )
            .await?;
        assert_eq!(res.fxa_uid, "fxa_id");
        assert_eq!(res.generation.unwrap(), 123);
        mock_verify.expect(1); // We would have have hit the server
        Ok(())
    }

    #[tokio::test]
    async fn test_no_sync_scope_fails() -> Result<(), TokenserverError> {
        let server = mockito::Server::new();
        let token_claims = TokenClaims {
            user: "fxa_id".to_string(),
            scope: "some other scope".to_string(),
            fxa_generation: Some(124),
            issued_at: None,
            generation: None,
        };
        mock_jwk_verifier!(token, Ok(serde_json::from_str(token).unwrap()));
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers).unwrap();
        let err = verifier
            .verify(
                serde_json::to_string(&token_claims).unwrap(),
                &Default::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");

        Ok(())
    }

    #[tokio::test]
    async fn test_fxa_rejects_token_no_matter_the_body() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new();
        let body = json!({
            "user": "fxa_id",
            "scope": [SYNC_SCOPE],
            "generation": 123
        });
        let mock_verify = server
            .mock("POST", "/v1/verify")
            .with_header("content-type", "application/json")
            .with_status(401)
            // Even though the body is fine, if FxA returns a none-200, we automatically
            // return a credential error
            .with_body(body.to_string())
            .create();
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };

        mock_jwk_verifier!(Err(JWTVerifyError::DecodingError));
        let jwk_verifiers = vec![];

        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers).unwrap();

        let err = verifier
            .verify(
                "A token that we will ask FxA about".to_string(),
                &Default::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");
        mock_verify.expect(1);

        Ok(())
    }

    #[tokio::test]
    async fn test_fxa_accepts_token_but_bad_body() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new();
        let body = json!({
            "bad_key": "foo",
            "scope": [SYNC_SCOPE],
            "bad_genreation": 123
        });
        let mock_verify = server
            .mock("POST", "/v1/verify")
            .with_header("content-type", "application/json")
            .with_status(200)
            // Even though the body is valid json, it doesn't match our expectation so we'll error
            // out
            .with_body(body.to_string())
            .create();
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };

        mock_jwk_verifier!(Err(JWTVerifyError::DecodingError));
        let jwk_verifiers = vec![];

        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers).unwrap();

        let err = verifier
            .verify(
                "A token that we will ask FxA about".to_string(),
                &Default::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");
        mock_verify.expect(1);

        Ok(())
    }

    fn oidc_settings() -> Settings {
        Settings {
            oauth_provider: OAuthProvider::Oidc,
            // Nothing listens here; these tests must not make any requests
            oidc_issuer_url: Some("http://127.0.0.1:1/realms/sync".to_owned()),
            ..Settings::default()
        }
    }

    #[test]
    fn test_oidc_jwks_url_keeps_realm_path() -> Result<(), TokenserverError> {
        mock_jwk_verifier!(Err(JWTVerifyError::InvalidSignature));
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&oidc_settings(), vec![])?;
        assert_eq!(
            verifier.jwks_url.as_str(),
            "http://127.0.0.1:1/realms/sync/protocol/openid-connect/certs"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_does_not_fall_back_to_remote_verify() -> Result<(), TokenserverError> {
        mock_jwk_verifier!(Err(JWTVerifyError::DecodingError));
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&oidc_settings(), jwk_verifiers)?;
        let err = verifier
            .verify(
                "invalid token that can't be decoded".to_string(),
                &Default::default(),
            )
            .await
            .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_uses_iat_as_generation() -> Result<(), TokenserverError> {
        let token_claims = TokenClaims {
            user: "keycloak_user_id".to_string(),
            scope: format!("openid {}", SYNC_SCOPE),
            fxa_generation: None,
            issued_at: Some(1_700_000_000),
            generation: None,
        };
        mock_jwk_verifier!(token, Ok(serde_json::from_str(token).unwrap()));
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&oidc_settings(), jwk_verifiers)?;
        let res = verifier
            .verify(
                serde_json::to_string(&token_claims).unwrap(),
                &Default::default(),
            )
            .await?;
        assert_eq!(res.fxa_uid, "keycloak_user_id");
        assert_eq!(res.generation, Some(1_700_000_000));
        Ok(())
    }

    #[tokio::test]
    async fn test_fxa_ignores_iat_as_generation() -> Result<(), TokenserverError> {
        let server = mockito::Server::new();
        let token_claims = TokenClaims {
            user: "fxa_id".to_string(),
            scope: SYNC_SCOPE.to_string(),
            fxa_generation: None,
            issued_at: Some(1_700_000_000),
            generation: None,
        };
        mock_jwk_verifier!(token, Ok(serde_json::from_str(token).unwrap()));
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let settings = Settings {
            fxa_oauth_server_url: server.url(),
            ..Settings::default()
        };
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers)?;
        let res = verifier
            .verify(
                serde_json::to_string(&token_claims).unwrap(),
                &Default::default(),
            )
            .await?;
        assert_eq!(res.fxa_uid, "fxa_id");
        assert_eq!(res.generation, None);
        Ok(())
    }
}
