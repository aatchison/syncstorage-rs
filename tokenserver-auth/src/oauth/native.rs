use super::VerifyOutput;
use crate::VerifyToken;
pub use crate::crypto::JWTVerifier;
use crate::crypto::JWTVerifyError;
use async_trait::async_trait;
use reqwest::Url;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    borrow::Cow,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use syncserver_common::Metrics;
use tokenserver_common::TokenserverError;
use tokenserver_settings::{OAuthProvider, Settings};

const SYNC_SCOPE: &str = "https://identity.mozilla.com/apps/oldsync";
/// How far in the future an OIDC token's `nbf` may be, in seconds: the leeway jsonwebtoken
/// allows on `exp` by default
const OIDC_NBF_LEEWAY: i64 = 60;

#[derive(Serialize, Deserialize, Debug)]
struct TokenClaims {
    #[serde(rename = "sub")]
    user: String,
    scope: String,
    #[serde(rename = "fxa-generation")]
    generation: Option<i64>,
}

impl TokenClaims {
    fn validate(self) -> Result<VerifyOutput, TokenserverError> {
        if !self.scope.split(',').any(|scope| scope == SYNC_SCOPE) {
            return Err(TokenserverError::invalid_credentials(
                "Unauthorized".to_string(),
            ));
        }
        Ok(self.into())
    }
}

impl From<TokenClaims> for VerifyOutput {
    fn from(value: TokenClaims) -> Self {
        Self {
            fxa_uid: value.user,
            generation: value.generation,
        }
    }
}

/// The claims of an access token from an OIDC provider (`oauth_provider` "oidc").
#[derive(Serialize, Deserialize, Debug)]
struct OidcTokenClaims {
    #[serde(rename = "sub")]
    user: String,
    /// Space-separated, unlike FxA's comma-separated scopes
    scope: String,
    /// OIDC providers have no FxA generation, but a provider can send one in the same claim
    /// as FxA (for example Keycloak with a user attribute mapper). It is never derived from
    /// other claims such as `iat`.
    #[serde(rename = "fxa-generation")]
    generation: Option<i64>,
    iss: String,
    aud: Audience,
    /// The client the token was issued to. Keycloak always sets it on access tokens.
    azp: Option<String>,
    /// Not before, in seconds since the epoch. jsonwebtoken doesn't check it by default.
    nbf: Option<i64>,
}

/// The `aud` claim: one audience or a list of them (RFC 7519, section 4.1.3)
#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, audience: &str) -> bool {
        match self {
            Audience::One(aud) => aud == audience,
            Audience::Many(auds) => auds.iter().any(|aud| aud == audience),
        }
    }
}

/// The issuer and audience an OIDC access token must name (RFC 9068, section 4), and the
/// clients it may be issued to
#[derive(Clone)]
struct OidcExpected {
    issuer: String,
    audience: String,
    allowed_clients: Vec<String>,
}

impl OidcTokenClaims {
    fn validate(self, expected: &OidcExpected) -> Result<VerifyOutput, TokenserverError> {
        if !self.scope.split(' ').any(|scope| scope == SYNC_SCOPE) {
            return Err(TokenserverError::invalid_credentials(
                "Unauthorized".to_string(),
            ));
        }
        // The subject becomes the user's fxa_uid
        if self.user.is_empty() {
            return Err(unauthorized_err_with_ctx("Empty OIDC token subject"));
        }
        if self.iss.trim_end_matches('/') != expected.issuer.trim_end_matches('/') {
            return Err(unauthorized_err_with_ctx("Unexpected OIDC token issuer"));
        }
        if !self.aud.contains(&expected.audience) {
            return Err(unauthorized_err_with_ctx("Unexpected OIDC token audience"));
        }
        if !self
            .azp
            .is_some_and(|azp| expected.allowed_clients.contains(&azp))
        {
            return Err(unauthorized_err_with_ctx("Unexpected OIDC token client"));
        }
        if let Some(nbf) = self.nbf {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(internal_err_with_ctx)?
                .as_secs() as i64;
            if nbf > now + OIDC_NBF_LEEWAY {
                return Err(unauthorized_err_with_ctx("OIDC token is not yet valid"));
            }
        }
        Ok(VerifyOutput {
            fxa_uid: self.user,
            generation: self.generation,
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
    /// Set when `oauth_provider` is "oidc"
    oidc: Option<OidcExpected>,
}

impl<J> Verifier<J>
where
    J: JWTVerifier,
{
    pub fn new(settings: &Settings, jwk_verifiers: Vec<J>) -> Result<Self, TokenserverError> {
        let (verify_url, jwks_url, oidc) = if settings.oauth_provider == OAuthProvider::Oidc {
            let issuer = settings.oidc_issuer_url.as_ref().ok_or_else(|| {
                internal_err_with_ctx("oauth_provider is \"oidc\" but oidc_issuer_url is not set")
            })?;
            let audience = settings
                .oidc_audience
                .as_ref()
                .filter(|audience| !audience.is_empty())
                .ok_or_else(|| {
                    internal_err_with_ctx("oauth_provider is \"oidc\" but oidc_audience is not set")
                })?;
            if settings.oidc_allowed_clients.is_empty()
                || settings.oidc_allowed_clients.iter().any(String::is_empty)
            {
                return Err(internal_err_with_ctx(
                    "oauth_provider is \"oidc\" but oidc_allowed_clients is not set",
                ));
            }
            // Make sure the issuer path ends in "/" so that `join` appends to it instead of
            // replacing its last segment (e.g. ".../realms/sync").
            let base_url = Url::parse(&format!("{}/", issuer.trim_end_matches('/')))
                .map_err(internal_err_with_ctx)?;
            let jwks_url = base_url
                .join("protocol/openid-connect/certs")
                .map_err(internal_err_with_ctx)?;
            let expected = OidcExpected {
                issuer: issuer.to_owned(),
                audience: audience.to_owned(),
                allowed_clients: settings.oidc_allowed_clients.clone(),
            };
            // OIDC providers have no verify endpoint, so this URL is never requested
            (base_url, jwks_url, Some(expected))
        } else {
            let base_url = Url::parse(&settings.fxa_oauth_server_url)
                .map_err(|_| TokenserverError::internal_error())?;
            let verify_url = base_url
                .join("v1/verify")
                .map_err(|_| TokenserverError::internal_error())?;
            let jwks_url = base_url
                .join("v1/jwks")
                .map_err(|_| TokenserverError::internal_error())?;
            (verify_url, jwks_url, None)
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
                    generation: value.generation,
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

    fn verify_jwt_locally<T: DeserializeOwned>(
        &self,
        verifiers: &[Cow<'_, J>],
        token: &str,
    ) -> Result<T, JWTVerifyError> {
        if verifiers.is_empty() {
            return Err(JWTVerifyError::InvalidKey);
        }

        verifiers
            .iter()
            .find_map(|verifier| {
                match verifier.verify::<T>(token) {
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
            verifiers = match self.get_remote_jwks().await {
                Ok(keys) => keys,
                Err(e) => {
                    slog_scope::warn!("Error requesting remote jwks: {}", e);
                    if self.oidc.is_some() {
                        // With no remote verify to fall back to, the token can't be checked:
                        // the provider is unavailable, not the credentials invalid
                        return Err(TokenserverError {
                            context: e.context,
                            ..TokenserverError::resource_unavailable()
                        });
                    }
                    vec![]
                }
            }
            .into_iter()
            .map(Cow::Owned)
            .collect();
        }

        if let Some(expected) = &self.oidc {
            // OIDC providers have no remote verify endpoint to fall back to
            return self
                .verify_jwt_locally::<OidcTokenClaims>(&verifiers, &token)
                .map_err(|e| {
                    if e.is_reportable_err() {
                        metrics.incr(e.metric_label())
                    }
                    unauthorized_err_with_ctx(e)
                })?
                .validate(expected);
        }

        let claims = match self.verify_jwt_locally(&verifiers, &token) {
            Ok(res) => res,
            Err(e) => {
                if e.is_reportable_err() {
                    metrics.incr(e.metric_label())
                }
                match e {
                    JWTVerifyError::DecodingError | JWTVerifyError::InvalidKey => {
                        self.remote_verify_token(&token).await?
                    }
                    e => return Err(unauthorized_err_with_ctx(e)),
                }
            }
        };
        claims.validate()
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
    use crate::test_utils::test_jwk;
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
        let mut server = mockito::Server::new_async().await;
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
        let mut server = mockito::Server::new_async().await;
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
        let mut server = mockito::Server::new_async().await;
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
            generation: Some(124),
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
        let mut server = mockito::Server::new_async().await;
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
        let mut server = mockito::Server::new_async().await;
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
        let server = mockito::Server::new_async().await;
        let token_claims = TokenClaims {
            user: "fxa_id".to_string(),
            scope: "some other scope".to_string(),
            generation: Some(124),
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
        let mut server = mockito::Server::new_async().await;
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
        let mut server = mockito::Server::new_async().await;
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

    const OIDC_ISSUER: &str = "http://127.0.0.1:1/realms/sync";

    fn oidc_settings() -> Settings {
        Settings {
            oauth_provider: OAuthProvider::Oidc,
            // Nothing listens here; these tests must not make any requests
            oidc_issuer_url: Some(OIDC_ISSUER.to_owned()),
            oidc_audience: Some("tokenserver".to_owned()),
            oidc_allowed_clients: vec!["thunderbird".to_owned(), "tokenserver-tests".to_owned()],
            ..Settings::default()
        }
    }

    /// Verifies `claims` (serialized as the token) with an OIDC verifier whose mock JWT
    /// verifier accepts any signature.
    async fn verify_oidc_claims(
        claims: serde_json::Value,
    ) -> Result<VerifyOutput, TokenserverError> {
        mock_jwk_verifier!(
            token,
            serde_json::from_str(token).map_err(|_| JWTVerifyError::DecodingError)
        );
        let verifier: Verifier<MockJWTVerifier> =
            Verifier::new(&oidc_settings(), vec![MockJWTVerifier {}])?;
        verifier
            .verify(claims.to_string(), &Default::default())
            .await
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

    #[test]
    fn test_oidc_requires_issuer_and_audience() {
        mock_jwk_verifier!(Err(JWTVerifyError::InvalidSignature));
        let settings = Settings {
            oidc_issuer_url: None,
            ..oidc_settings()
        };
        assert!(Verifier::<MockJWTVerifier>::new(&settings, vec![]).is_err());
        for oidc_audience in [None, Some(String::new())] {
            let settings = Settings {
                oidc_audience,
                ..oidc_settings()
            };
            assert!(Verifier::<MockJWTVerifier>::new(&settings, vec![]).is_err());
        }
        for oidc_allowed_clients in [vec![], vec![String::new()]] {
            let settings = Settings {
                oidc_allowed_clients,
                ..oidc_settings()
            };
            assert!(Verifier::<MockJWTVerifier>::new(&settings, vec![]).is_err());
        }
    }

    #[tokio::test]
    async fn test_oidc_checks_client() -> Result<(), TokenserverError> {
        let claims = |azp: Option<&str>| {
            let mut claims = json!({
                "sub": "keycloak_user_id",
                "scope": format!("openid {SYNC_SCOPE}"),
                "iss": OIDC_ISSUER,
                "aud": "tokenserver",
            });
            if let Some(azp) = azp {
                claims["azp"] = json!(azp);
            }
            claims
        };

        for azp in ["thunderbird", "tokenserver-tests"] {
            verify_oidc_claims(claims(Some(azp))).await?;
        }
        for azp in [Some("public-client"), Some(""), None] {
            let err = verify_oidc_claims(claims(azp)).await.unwrap_err();
            assert_eq!(err.status, "invalid-credentials");
            assert_eq!(err.http_status, 401);
            assert_eq!(err.description, "Unauthorized");
            assert_eq!(err.context, "Unexpected OIDC token client");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_checks_issuer_and_audience() -> Result<(), TokenserverError> {
        let claims = |iss: serde_json::Value, aud: serde_json::Value| {
            let mut claims = json!({
                "sub": "keycloak_user_id",
                "azp": "thunderbird",
                "scope": format!("openid {SYNC_SCOPE}"),
            });
            if !iss.is_null() {
                claims["iss"] = iss;
            }
            if !aud.is_null() {
                claims["aud"] = aud;
            }
            claims
        };

        // `aud` can be a single audience or a list
        verify_oidc_claims(claims(json!(OIDC_ISSUER), json!("tokenserver"))).await?;
        verify_oidc_claims(claims(
            json!(format!("{OIDC_ISSUER}/")),
            json!(["account", "tokenserver"]),
        ))
        .await?;

        for (iss, aud) in [
            (
                json!("http://127.0.0.1:1/realms/other"),
                json!("tokenserver"),
            ),
            (json!(null), json!("tokenserver")),
            (json!(OIDC_ISSUER), json!("account")),
            (json!(OIDC_ISSUER), json!(["account", "broker"])),
            (json!(OIDC_ISSUER), json!(null)),
        ] {
            let err = verify_oidc_claims(claims(iss, aud)).await.unwrap_err();
            assert_eq!(err.status, "invalid-credentials");
            assert_eq!(err.http_status, 401);
            assert_eq!(err.description, "Unauthorized");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_does_not_fall_back_to_remote_verify() -> Result<(), TokenserverError> {
        // A remote verify would POST to the issuer
        let mut server = mockito::Server::new_async().await;
        let mock_verify = server
            .mock("POST", mockito::Matcher::Any)
            .expect(0)
            .create_async()
            .await;
        let settings = Settings {
            oidc_issuer_url: Some(format!("{}/realms/sync", server.url())),
            ..oidc_settings()
        };
        mock_jwk_verifier!(Err(JWTVerifyError::DecodingError));
        let jwk_verifiers = vec![MockJWTVerifier {}];
        let verifier: Verifier<MockJWTVerifier> = Verifier::new(&settings, jwk_verifiers)?;
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
        assert_eq!(err.context, JWTVerifyError::DecodingError.to_string());
        mock_verify.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_with_jwt_verifier() -> Result<(), TokenserverError> {
        use crate::test_utils::{OTHER_PRIVATE_KEY_PEM, TEST_PRIVATE_KEY_PEM};
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let token = |typ: &str, exp: i64, private_key_pem: &[u8]| {
            let header = Header {
                typ: Some(typ.to_owned()),
                ..Header::new(Algorithm::RS256)
            };
            let claims = json!({
                "sub": "keycloak_user_id",
                "azp": "thunderbird",
                "scope": format!("openid {SYNC_SCOPE}"),
                "iss": OIDC_ISSUER,
                "aud": ["account", "tokenserver"],
                "exp": exp,
            });
            let key = EncodingKey::from_rsa_pem(private_key_pem).unwrap();
            encode(&header, &claims, &key).unwrap()
        };
        let jwk_verifiers = vec![JWTVerifierImpl::try_from(test_jwk()).unwrap()];
        let verifier: Verifier<JWTVerifierImpl> = Verifier::new(&oidc_settings(), jwk_verifiers)?;

        let res = verifier
            .verify(
                token("at+jwt", now + 300, TEST_PRIVATE_KEY_PEM),
                &Default::default(),
            )
            .await?;
        assert_eq!(res.fxa_uid, "keycloak_user_id");
        assert_eq!(res.generation, None);

        for (token, context) in [
            // Not an RFC 9068 access token, e.g. an ID token
            (
                token("JWT", now + 300, TEST_PRIVATE_KEY_PEM),
                JWTVerifyError::TrustError,
            ),
            (
                token("at+jwt", now - 3600, TEST_PRIVATE_KEY_PEM),
                JWTVerifyError::ExpiredSignature,
            ),
            // Every key fails on the signature
            (
                token("at+jwt", now + 300, OTHER_PRIVATE_KEY_PEM),
                JWTVerifyError::TrustError,
            ),
        ] {
            let err = verifier
                .verify(token, &Default::default())
                .await
                .unwrap_err();
            assert_eq!(err.status, "invalid-credentials");
            assert_eq!(err.http_status, 401);
            assert_eq!(err.description, "Unauthorized");
            assert_eq!(err.context, context.to_string());
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_jwks_fetch_failure_is_unavailable() -> Result<(), TokenserverError> {
        let mut server = mockito::Server::new_async().await;
        let issuer = format!("{}/realms/sync", server.url());
        let certs_path = "/realms/sync/protocol/openid-connect/certs";

        // The JWKS endpoint fails, or nothing listens at the issuer
        let mock_jwks = server
            .mock("GET", certs_path)
            .with_status(500)
            .expect(1)
            .create_async()
            .await;
        for issuer in [issuer.as_str(), OIDC_ISSUER] {
            let settings = Settings {
                oidc_issuer_url: Some(issuer.to_owned()),
                ..oidc_settings()
            };
            let verifier: Verifier<JWTVerifierImpl> = Verifier::new(&settings, vec![])?;
            let err = verifier
                .verify("a token".to_string(), &Default::default())
                .await
                .unwrap_err();
            assert_eq!(err.http_status, 503);
            assert_eq!(err.description, "Resource is not available");
        }
        mock_jwks.assert_async().await;

        // Keys that were fetched but don't verify the token still mean bad credentials
        let mock_jwks = server
            .mock("GET", certs_path)
            .with_header("content-type", "application/json")
            .with_body(json!({ "keys": [test_jwk()] }).to_string())
            .expect(1)
            .create_async()
            .await;
        let settings = Settings {
            oidc_issuer_url: Some(issuer),
            ..oidc_settings()
        };
        let verifier: Verifier<JWTVerifierImpl> = Verifier::new(&settings, vec![])?;
        let err = verifier
            .verify("a token".to_string(), &Default::default())
            .await
            .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        mock_jwks.assert_async().await;
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_checks_nbf() -> Result<(), TokenserverError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let claims = |nbf: Option<i64>| {
            let mut claims = json!({
                "sub": "keycloak_user_id",
                "azp": "thunderbird",
                "scope": format!("openid {SYNC_SCOPE}"),
                "iss": OIDC_ISSUER,
                "aud": "tokenserver",
            });
            if let Some(nbf) = nbf {
                claims["nbf"] = json!(nbf);
            }
            claims
        };

        // No nbf, a past one, or one within the leeway
        for nbf in [None, Some(now - 3600), Some(now), Some(now + 30)] {
            verify_oidc_claims(claims(nbf)).await?;
        }
        for nbf in [now + 120, now + 3600] {
            let err = verify_oidc_claims(claims(Some(nbf))).await.unwrap_err();
            assert_eq!(err.status, "invalid-credentials");
            assert_eq!(err.http_status, 401);
            assert_eq!(err.description, "Unauthorized");
            assert_eq!(err.context, "OIDC token is not yet valid");
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_rejects_empty_subject() {
        let err = verify_oidc_claims(json!({
            "sub": "",
            "azp": "thunderbird",
            "scope": format!("openid {SYNC_SCOPE}"),
            "iss": OIDC_ISSUER,
            "aud": "tokenserver",
        }))
        .await
        .unwrap_err();
        assert_eq!(err.status, "invalid-credentials");
        assert_eq!(err.http_status, 401);
        assert_eq!(err.description, "Unauthorized");
        assert_eq!(err.context, "Empty OIDC token subject");
    }

    #[tokio::test]
    async fn test_oidc_generation_comes_only_from_fxa_generation() -> Result<(), TokenserverError> {
        let res = verify_oidc_claims(json!({
            "sub": "keycloak_user_id",
            "azp": "thunderbird",
            "scope": format!("openid {SYNC_SCOPE}"),
            "fxa-generation": 1234,
            "iat": 1_700_000_000,
            "iss": OIDC_ISSUER,
            "aud": "tokenserver",
        }))
        .await?;
        assert_eq!(res.fxa_uid, "keycloak_user_id");
        assert_eq!(res.generation, Some(1234));

        // Without the claim there is no generation; `iat` and `generation` don't stand in
        let res = verify_oidc_claims(json!({
            "sub": "keycloak_user_id",
            "azp": "thunderbird",
            "scope": format!("openid {SYNC_SCOPE}"),
            "iat": 1_700_000_000,
            "generation": 1234,
            "iss": OIDC_ISSUER,
            "aud": "tokenserver",
        }))
        .await?;
        assert_eq!(res.generation, None);
        Ok(())
    }

    #[tokio::test]
    async fn test_oidc_requires_sync_scope() {
        for scope in [
            Some("openid email".to_owned()),
            // OIDC scopes are space-separated
            Some(format!("openid,{SYNC_SCOPE}")),
            None,
        ] {
            let mut claims = json!({
                "sub": "keycloak_user_id",
                "azp": "thunderbird",
                "iss": OIDC_ISSUER,
                "aud": "tokenserver",
            });
            if let Some(scope) = scope {
                claims["scope"] = json!(scope);
            }
            let err = verify_oidc_claims(claims).await.unwrap_err();
            assert_eq!(err.status, "invalid-credentials");
            assert_eq!(err.http_status, 401);
            assert_eq!(err.description, "Unauthorized");
        }
    }
}
