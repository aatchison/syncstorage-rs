use serde::{Deserialize, Serialize};

mod native;

pub type Verifier<J> = native::Verifier<J>;

/// The information extracted from a valid OAuth token.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct VerifyOutput {
    #[serde(rename = "user")]
    pub fxa_uid: String,
    pub generation: Option<i64>,
}
