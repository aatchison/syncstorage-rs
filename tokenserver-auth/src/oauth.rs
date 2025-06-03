use serde::{Deserialize, Serialize};

#[cfg(not(feature = "py"))]
use async_trait::async_trait;
#[cfg(not(feature = "py"))]
use syncserver_common::Metrics;
#[cfg(not(feature = "py"))]
use tokenserver_common::TokenserverError;
#[cfg(not(feature = "py"))]
use tokenserver_settings::Settings;
#[cfg(not(feature = "py"))]
use crate::VerifyToken;

#[cfg(not(feature = "py"))]
mod native;
#[cfg(feature = "py")]
mod py;
#[cfg(feature = "keycloak")]
mod keycloak;

#[cfg(feature = "py")]
pub type Verifier = py::Verifier;

#[cfg(not(feature = "py"))]
pub type Verifier<J> = native::Verifier<J>;

#[cfg(feature = "keycloak")]
pub type KeycloakVerifier<J> = keycloak::KeycloakVerifier<J>;

/// Unified OAuth verifier that can handle both FxA and Keycloak
#[cfg(not(feature = "py"))]
#[derive(Clone)]
pub enum UnifiedVerifier<J> {
    Fxa(native::Verifier<J>),
    #[cfg(feature = "keycloak")]
    Keycloak(keycloak::KeycloakVerifier<J>),
}

#[cfg(not(feature = "py"))]
impl<J> UnifiedVerifier<J>
where
    J: crate::crypto::JWTVerifier,
{
    pub fn new(settings: &Settings, jwk_verifiers: Vec<J>) -> Result<Self, TokenserverError> {
        match settings.oauth_provider.as_str() {
            #[cfg(feature = "keycloak")]
            "keycloak" => Ok(UnifiedVerifier::Keycloak(
                keycloak::KeycloakVerifier::new(settings, jwk_verifiers)?
            )),
            #[cfg(not(feature = "keycloak"))]
            "keycloak" => Err(TokenserverError::internal_error()),
            "fxa" | _ => Ok(UnifiedVerifier::Fxa(
                native::Verifier::new(settings, jwk_verifiers)?
            )),
        }
    }
}

#[cfg(not(feature = "py"))]
#[async_trait]
impl<J> VerifyToken for UnifiedVerifier<J>
where
    J: crate::crypto::JWTVerifier,
{
    type Output = VerifyOutput;

    async fn verify(
        &self,
        token: String,
        metrics: &Metrics,
    ) -> Result<VerifyOutput, TokenserverError> {
        match self {
            UnifiedVerifier::Fxa(verifier) => verifier.verify(token, metrics).await,
            #[cfg(feature = "keycloak")]
            UnifiedVerifier::Keycloak(verifier) => verifier.verify(token, metrics).await,
        }
    }
}

/// The information extracted from a valid OAuth token.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyOutput {
    #[serde(rename = "user")]
    pub fxa_uid: String,
    pub generation: Option<i64>,
}
