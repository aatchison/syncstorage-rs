#[macro_use]
extern crate slog_scope;

use config::{Config, ConfigError, Environment, File};
use regex::Regex;
use serde::{Deserialize, Deserializer};
use syncserver_common::{
    X_LAST_MODIFIED, X_VERIFY_CODE, X_WEAVE_BYTES, X_WEAVE_NEXT_OFFSET, X_WEAVE_RECORDS,
    X_WEAVE_TIMESTAMP, X_WEAVE_TOTAL_BYTES, X_WEAVE_TOTAL_RECORDS,
};
use syncstorage_settings::Settings as SyncstorageSettings;
use tokenserver_settings::{OAuthProvider, Settings as TokenserverSettings};
use url::Url;

pub const COLLECTION_ID_REGEX: &str = r"[a-zA-Z0-9._-]{1,32}";
static PREFIX: &str = "sync";

#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// TCP port the server binds to. Default: 8000.
    pub port: u16,
    /// Host address the server binds to. Default: "127.0.0.1". Use "0.0.0.0"
    /// inside containers so the port is reachable from the host.
    pub host: String,
    /// Keep-alive header value (seconds)
    pub actix_keep_alive: Option<u32>,
    /// The master secret, from which are derived
    /// the signing secret and token secret
    /// that are used during Hawk authentication.
    pub master_secret: Secrets,

    /// Emit human-readable logs instead of mozlog JSON. Default: false.
    /// Production environments should leave this off (JSON is preferred).
    pub human_logs: bool,

    /// Hostname of the StatsD/metrics sink. Default: "localhost".
    pub statsd_host: Option<String>,
    /// Port of the StatsD/metrics sink. Default: 8125.
    pub statsd_port: u16,
    /// Whether to  include the hostname in metrics, which increases cardinality significantly in
    /// prod.
    pub include_hostname_tag: bool,

    /// Environment of Sync application (Stage, Prod, Dev, etc).
    pub environment: String,

    /// Cors Settings
    pub cors_allowed_origin: Option<String>,
    pub cors_max_age: Option<usize>,
    pub cors_allowed_methods: Option<Vec<String>>,
    pub cors_allowed_headers: Option<Vec<String>>,

    /// The maximum number of blocking threads that can be used by the worker.
    /// Note, we don't want "Option" here because we use this as part of the
    /// metric periodic reporter. The default value is 512.
    pub worker_max_blocking_threads: usize,

    // TOOD: Eventually, the below settings will be enabled or disabled via Cargo features
    pub syncstorage: SyncstorageSettings,
    pub tokenserver: TokenserverSettings,
}

impl Settings {
    /// Load the settings from the config file if supplied, then the environment.
    pub fn with_env_and_config_file(filename: Option<&str>) -> Result<Self, ConfigError> {
        let mut builder = Config::builder();

        // Merge the config file if supplied
        if let Some(config_filename) = filename {
            builder = builder.add_source(File::with_name(config_filename));
        }

        // Merge the environment overrides
        // While the prefix is currently case insensitive, it's traditional that
        // environment vars be UPPERCASE, this ensures that will continue should
        // Environment ever change their policy about case insensitivity.
        // This will accept environment variables specified as
        // `SYNC_FOO__BAR_VALUE="gorp"` as `foo.bar_value = "gorp"`
        builder = builder.add_source(
            Environment::with_prefix(&PREFIX.to_uppercase())
                .separator("__")
                .prefix_separator("_")
                // Allow specific Vec<String> settings to be provided
                // via a comma-separated env var. `with_list_parse_key`
                // restricts list-splitting to the named key so
                // ordinary string settings that happen to contain
                // commas are untouched.
                .list_separator(",")
                .with_list_parse_key("syncstorage.gcs_payload_offload_collections")
                .with_list_parse_key("tokenserver.oidc_allowed_clients")
                .try_parsing(true),
        );
        let settings: Config = builder.build()?;

        let mut s: Settings = settings.try_deserialize::<Self>().map_err(|e| match e {
            ConfigError::Message(v) => {
                println!("Bad configuration: {v:?}");
                println!("Please set in config file or use environment variable.");
                println!(
                    "For example to set `database_url` use env var `{}_DATABASE_URL`\n",
                    PREFIX.to_uppercase()
                );
                error!("Configuration error: Value undefined {v:?}");
                ConfigError::NotFound(v)
            }
            e => {
                error!("Configuration error: Other: {e:?}");
                e
            }
        })?;
        s.normalize()?;
        s.validate()?;
        Ok(s)
    }

    /// Adjust values if required
    pub fn normalize(&mut self) -> Result<(), ConfigError> {
        self.syncstorage.normalize();

        if self.worker_max_blocking_threads != 0 {
            return Ok(());
        }

        // Db backends w/ blocking calls block via actix-threadpool: grow its
        // size to accommodate the full number of connections
        let total_db_pool_size = {
            let syncstorage_pool_max_size =
                if self.syncstorage.uses_spanner() || !self.syncstorage.enabled {
                    0
                } else {
                    self.syncstorage.database_pool_max_size
                };

            let tokenserver_pool_max_size = if self.tokenserver.enabled {
                self.tokenserver.database_pool_max_size
            } else {
                0
            };

            syncstorage_pool_max_size + tokenserver_pool_max_size
        };

        let fxa_threads = if self.tokenserver.enabled
            && self.tokenserver.fxa_oauth_primary_jwk.is_none()
            && self.tokenserver.fxa_oauth_secondary_jwk.is_none()
        {
            self.tokenserver
                .additional_blocking_threads_for_fxa_requests
                .ok_or_else(|| {
                    println!(
                        "If the Tokenserver OAuth JWK is not cached, additional blocking \
                                        threads must be used to handle the requests to FxA."
                    );

                    let setting_name = "tokenserver.additional_blocking_threads_for_fxa_requests";
                    ConfigError::NotFound(String::from(setting_name))
                })?
        } else {
            0
        };
        self.worker_max_blocking_threads =
            (total_db_pool_size + fxa_threads).max(num_cpus::get() as u32 * 5) as usize;

        Ok(())
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        // Fail fast if an enabled service has no DATABASE_URL configured,
        // rather than silently falling back to a default connection string.
        if self.syncstorage.enabled && self.syncstorage.database_url.is_empty() {
            return Err(ConfigError::Message(
                "SYNC_SYNCSTORAGE__DATABASE_URL must be set".to_owned(),
            ));
        }
        if self.tokenserver.enabled && self.tokenserver.database_url.is_empty() {
            return Err(ConfigError::Message(
                "SYNC_TOKENSERVER__DATABASE_URL must be set".to_owned(),
            ));
        }

        // overriding limits must be > 0 and validate names while we're at it
        let coll_regex = Regex::new(&format!("^{}$", COLLECTION_ID_REGEX)).unwrap();
        for (name, overrides) in &self.syncstorage.limits.collections {
            if !coll_regex.is_match(name) {
                return Err(ConfigError::Message(format!(
                    "Invalid SYNC_SYNCSTORAGE__LIMITS__COLLECTIONS: \
                         Invalid collection name format for \"{name}\""
                )));
            }
            for (field, value) in [
                (
                    "max_record_payload_bytes",
                    overrides.max_record_payload_bytes,
                ),
                ("max_post_bytes", overrides.max_post_bytes),
                ("max_request_bytes", overrides.max_request_bytes),
            ] {
                if value == Some(0) {
                    return Err(ConfigError::Message(format!(
                        "Invalid SYNC_SYNCSTORAGE__LIMITS__COLLECTIONS: \
                         \"{name}\" {field} must be greater than 0"
                    )));
                }
            }
        }

        // GCS payload off-load is only wired up for the Spanner backend. On
        // mysql/postgres the payload_link column does not exist, so an
        // off-loaded write would upload to GCS, clear the inline payload, then
        // persist a row with no link and lose the payload. Refuse to boot when
        // it's configured against a non-Spanner backend.
        if self.syncstorage.enabled
            && !self.syncstorage.uses_spanner()
            && (self.syncstorage.gcs_payload_bucket.is_some()
                || !self.syncstorage.gcs_payload_offload_collections.is_empty())
        {
            return Err(ConfigError::Message(
                "GCS payload off-load (SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET / \
                 SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS) is only \
                 supported on the Spanner backend"
                    .to_owned(),
            ));
        }

        // The prefix for the offload gcs object name cannot be empty.
        if self.syncstorage.enabled && self.syncstorage.gcs_payload_prefix.is_empty() {
            return Err(ConfigError::Message(
                "SYNC_SYNCSTORAGE__GCS_PAYLOAD_PREFIX must not be empty".to_owned(),
            ));
        }

        if let Some(init_node_url) = &self.tokenserver.init_node_url {
            let url = Url::parse(init_node_url).map_err(|e| {
                ConfigError::Message(format!("Invalid SYNC_TOKENSERVER__INIT_NODE_URL: {e}"))
            })?;
            if !["http", "https"].contains(&url.scheme()) {
                return Err(ConfigError::Message(
                    "Invalid SYNC_TOKENSERVER__INIT_NODE_URL: \
                     requires an \"https\"/\"http\" scheme"
                        .to_owned(),
                ));
            }
        }

        // An OIDC provider has no FxA fallback, so its issuer and audience must be set.
        if self.tokenserver.enabled && self.tokenserver.oauth_provider == OAuthProvider::Oidc {
            let issuer = self.tokenserver.oidc_issuer_url.as_deref().ok_or_else(|| {
                ConfigError::Message(
                    "SYNC_TOKENSERVER__OIDC_ISSUER_URL must be set when \
                     SYNC_TOKENSERVER__OAUTH_PROVIDER is \"oidc\""
                        .to_owned(),
                )
            })?;
            let url = Url::parse(issuer).map_err(|e| {
                ConfigError::Message(format!("Invalid SYNC_TOKENSERVER__OIDC_ISSUER_URL: {e}"))
            })?;
            if !["http", "https"].contains(&url.scheme()) {
                return Err(ConfigError::Message(
                    "Invalid SYNC_TOKENSERVER__OIDC_ISSUER_URL: \
                     requires an \"https\"/\"http\" scheme"
                        .to_owned(),
                ));
            }
            if self
                .tokenserver
                .oidc_audience
                .as_deref()
                .is_none_or(str::is_empty)
            {
                return Err(ConfigError::Message(
                    "SYNC_TOKENSERVER__OIDC_AUDIENCE must be set when \
                     SYNC_TOKENSERVER__OAUTH_PROVIDER is \"oidc\""
                        .to_owned(),
                ));
            }
            if self.tokenserver.oidc_allowed_clients.is_empty()
                || self
                    .tokenserver
                    .oidc_allowed_clients
                    .iter()
                    .any(String::is_empty)
            {
                return Err(ConfigError::Message(
                    "SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS must be set, with no empty \
                     client IDs, when SYNC_TOKENSERVER__OAUTH_PROVIDER is \"oidc\""
                        .to_owned(),
                ));
            }
            // The FxA webhook would act on OIDC users, and the FxA JWKs would replace the
            // provider's keys.
            if self.tokenserver.fxa_webhook_enabled {
                return Err(ConfigError::Message(
                    "SYNC_TOKENSERVER__FXA_WEBHOOK_ENABLED must not be set when \
                     SYNC_TOKENSERVER__OAUTH_PROVIDER is \"oidc\""
                        .to_owned(),
                ));
            }
            if self.tokenserver.fxa_oauth_primary_jwk.is_some()
                || self.tokenserver.fxa_oauth_secondary_jwk.is_some()
            {
                return Err(ConfigError::Message(
                    "SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK and \
                     SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK must not be set when \
                     SYNC_TOKENSERVER__OAUTH_PROVIDER is \"oidc\""
                        .to_owned(),
                ));
            }
        } else if self.tokenserver.enabled
            && (self.tokenserver.oidc_issuer_url.is_some()
                || self.tokenserver.oidc_audience.is_some()
                || !self.tokenserver.oidc_allowed_clients.is_empty())
        {
            // Otherwise a missing oauth_provider would silently verify tokens against FxA.
            return Err(ConfigError::Message(
                "SYNC_TOKENSERVER__OIDC_ISSUER_URL, SYNC_TOKENSERVER__OIDC_AUDIENCE and \
                 SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS require \
                 SYNC_TOKENSERVER__OAUTH_PROVIDER to be \"oidc\""
                    .to_owned(),
            ));
        }
        Ok(())
    }

    #[cfg(debug_assertions)]
    pub fn test_settings() -> Self {
        let mut settings =
            Self::with_env_and_config_file(None).expect("Could not get Settings in test_settings");
        settings.port = 8000;
        settings.syncstorage.database_pool_max_size = 1;
        settings.syncstorage.database_use_test_transactions = true;
        settings.syncstorage.database_pool_connection_max_idle = Some(300);
        settings.syncstorage.database_pool_connection_lifespan = Some(300);
        settings
    }

    pub fn banner(&self) -> String {
        let quota = if self.syncstorage.enable_quota {
            format!(
                "Quota: {} bytes ({}enforced)",
                self.syncstorage.limits.max_quota_limit,
                if !self.syncstorage.enforce_quota {
                    "un"
                } else {
                    ""
                }
            )
        } else {
            "No quota".to_owned()
        };
        let db = Url::parse(&self.syncstorage.database_url)
            .map(|url| url.scheme().to_owned())
            .unwrap_or_else(|_| "<invalid db>".to_owned());
        let parallelism = format!(
            "available_parallelism: {:?} num_cpus: {} num_cpus (phys): {}",
            std::thread::available_parallelism(),
            num_cpus::get(),
            num_cpus::get_physical()
        );
        format!(
            "http://{}:{} ({db}) ({parallelism}) {quota}",
            self.host, self.port
        )
    }
}

impl Default for Settings {
    fn default() -> Settings {
        Settings {
            port: 8000,
            host: "127.0.0.1".to_string(),
            actix_keep_alive: None,
            master_secret: Secrets::default(),
            statsd_host: Some("localhost".to_owned()),
            statsd_port: 8125,
            include_hostname_tag: false,
            environment: "dev".to_owned(),
            human_logs: false,
            cors_allowed_origin: Some("*".to_owned()),
            cors_allowed_methods: Some(
                ["DELETE", "GET", "POST", "PUT"]
                    .into_iter()
                    .map(String::from)
                    .collect(),
            ),
            cors_allowed_headers: Some(
                [
                    "Authorization",
                    "Content-Type",
                    "X-Confirm-Delete",
                    "User-Agent",
                    X_LAST_MODIFIED,
                    X_WEAVE_TIMESTAMP,
                    X_WEAVE_NEXT_OFFSET,
                    X_WEAVE_RECORDS,
                    X_WEAVE_BYTES,
                    X_WEAVE_TOTAL_RECORDS,
                    X_WEAVE_TOTAL_BYTES,
                    X_VERIFY_CODE,
                    "TEST_IDLES",
                ]
                .into_iter()
                .map(String::from)
                .collect(),
            ),
            cors_max_age: Some(1728000),
            worker_max_blocking_threads: 512,
            syncstorage: SyncstorageSettings::default(),
            tokenserver: TokenserverSettings::default(),
        }
    }
}

/// Secrets used during Hawk authentication.
#[derive(Clone, Debug)]
pub struct Secrets {
    /// The master secret in byte array form.
    ///
    /// The signing secret and token secret are derived from this.
    pub master_secret: Vec<u8>,

    /// The signing secret used during Hawk authentication.
    pub signing_secret: [u8; 32],
}

impl Secrets {
    /// Decode the master secret to a byte array
    /// and derive the signing secret from it.
    pub fn new(master_secret: &str) -> Result<Self, String> {
        let master_secret = master_secret.as_bytes().to_vec();
        let signing_secret = syncserver_common::hkdf_expand_32(
            b"services.mozilla.com/tokenlib/v1/signing",
            None,
            &master_secret,
        )?;
        Ok(Self {
            master_secret,
            signing_secret,
        })
    }
}

impl Default for Secrets {
    /// Create a (useless) default `Secrets` instance.
    fn default() -> Self {
        Self {
            master_secret: vec![],
            signing_secret: [0u8; 32],
        }
    }
}

impl<'d> Deserialize<'d> for Secrets {
    /// Deserialize the master secret and signing secret byte arrays
    /// from a single master secret string.
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'d>,
    {
        let master_secret: String = Deserialize::deserialize(deserializer)?;
        Secrets::new(&master_secret)
            .map_err(|e| serde::de::Error::custom(format!("error: {:?}", e)))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // A syncstorage DATABASE_URL is required to pass validation, since
    // syncstorage is enabled by default. Tests that exercise unrelated config
    // must supply one explicitly so they don't depend on the ambient env.
    const TEST_SYNCSTORAGE_DATABASE_URL: &str = "mysql://root@127.0.0.1/syncstorage";
    const TEST_TOKENSERVER_DATABASE_URL: &str = "mysql://root@127.0.0.1/tokenserver";

    #[test]
    fn test_environment_variable_prefix() {
        // Setting an environment variable with the correct prefix correctly sets the setting
        // (note that the default value for the settings.tokenserver.enabled setting is false)
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                (
                    "SYNC_TOKENSERVER__DATABASE_URL",
                    Some(TEST_TOKENSERVER_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__ENABLED", Some("true")),
            ],
            || {
                let settings = Settings::with_env_and_config_file(None).unwrap();
                assert!(settings.tokenserver.enabled);
            },
        );

        // Setting an environment variable with the incorrect prefix does not set the setting
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__ENABLED", None),
                ("SYNC__TOKENSERVER__ENABLED", Some("true")),
            ],
            || {
                let settings = Settings::with_env_and_config_file(None).unwrap();
                assert!(!settings.tokenserver.enabled);
            },
        );
    }

    #[test]
    fn test_missing_syncstorage_database_url_fails_fast() {
        // syncstorage is enabled by default, so an unset DATABASE_URL must
        // produce an error rather than fall back to a default value.
        temp_env::with_vars(
            [
                ("SYNC_SYNCSTORAGE__DATABASE_URL", None::<&str>),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
            ],
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("an unset syncstorage DATABASE_URL should fail validation");
                assert!(err.to_string().contains("SYNC_SYNCSTORAGE__DATABASE_URL"));
            },
        );
    }

    #[test]
    fn test_missing_tokenserver_database_url_fails_fast_when_enabled() {
        // An enabled Tokenserver with no DATABASE_URL must fail fast.
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", Some("true")),
            ],
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("an unset tokenserver DATABASE_URL should fail when enabled");
                assert!(err.to_string().contains("SYNC_TOKENSERVER__DATABASE_URL"));
            },
        );
    }

    #[test]
    fn test_collection_limits_override_validates() {
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
                (
                    "SYNC_SYNCSTORAGE__LIMITS__COLLECTIONS",
                    Some(
                        r#"{"newtab-images":{"max_record_payload_bytes":20971520,"max_post_bytes":26214400,"max_request_bytes":26218496}}"#,
                    ),
                ),
            ],
            || {
                let settings = Settings::with_env_and_config_file(None)
                    .expect("a collection limits override should validate");
                let entry = settings
                    .syncstorage
                    .limits
                    .collections
                    .get("newtab-images")
                    .expect("override present");
                assert_eq!(entry.max_record_payload_bytes, Some(20_971_520));
                assert_eq!(entry.max_post_bytes, Some(26_214_400));
                assert_eq!(entry.max_request_bytes, Some(26_218_496));
            },
        );
    }

    #[test]
    fn test_zero_collection_override_fails() {
        for (field, json) in [
            (
                "max_record_payload_bytes",
                r#"{"tabs":{"max_record_payload_bytes":0}}"#,
            ),
            ("max_post_bytes", r#"{"tabs":{"max_post_bytes":0}}"#),
            ("max_request_bytes", r#"{"tabs":{"max_request_bytes":0}}"#),
        ] {
            temp_env::with_vars(
                [
                    (
                        "SYNC_SYNCSTORAGE__DATABASE_URL",
                        Some(TEST_SYNCSTORAGE_DATABASE_URL),
                    ),
                    ("SYNC_TOKENSERVER__DATABASE_URL", None),
                    ("SYNC_TOKENSERVER__ENABLED", None),
                    ("SYNC_SYNCSTORAGE__LIMITS__COLLECTIONS", Some(json)),
                ],
                || {
                    let err = Settings::with_env_and_config_file(None)
                        .expect_err("a zero override should fail");
                    let msg = err.to_string();
                    assert!(msg.contains(field), "error {msg:?} should mention {field}");
                    assert!(msg.contains("must be greater than 0"));
                },
            );
        }
    }

    #[test]
    fn test_gcs_offload_bucket_on_non_spanner_fails() {
        // The default test DATABASE_URL is mysql, which has no payload_link
        // column, so a configured off-load bucket must fail validation.
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
                (
                    "SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET",
                    Some("sync-payloads"),
                ),
            ],
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("an off-load bucket on a non-spanner backend should fail");
                assert!(err.to_string().contains("Spanner backend"));
            },
        );
    }

    #[test]
    fn test_gcs_offload_collections_on_non_spanner_fails() {
        // Opting collections into off-load without a bucket must also fail on
        // a non-spanner backend.
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
                (
                    "SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS",
                    Some("tabs,history"),
                ),
            ],
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("off-load collections on a non-spanner backend should fail");
                assert!(err.to_string().contains("Spanner backend"));
            },
        );
    }

    #[test]
    fn test_empty_gcs_payload_prefix_fails() {
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
                ("SYNC_SYNCSTORAGE__GCS_PAYLOAD_PREFIX", Some("")),
            ],
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("an empty payload prefix should fail validation");
                assert!(err.to_string().contains("GCS_PAYLOAD_PREFIX"));
            },
        );
    }

    #[test]
    fn test_default_gcs_payload_prefix_validates() {
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
                ("SYNC_SYNCSTORAGE__GCS_PAYLOAD_PREFIX", None),
            ],
            || {
                let settings = Settings::with_env_and_config_file(None)
                    .expect("the default payload prefix should validate");
                assert!(!settings.syncstorage.gcs_payload_prefix.is_empty());
            },
        );
    }

    #[test]
    fn test_gcs_offload_on_spanner_validates() {
        // The same off-load config validates against a spanner DATABASE_URL.
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some("spanner://projects/test/instances/test/databases/test"),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", None),
                (
                    "SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET",
                    Some("sync-payloads"),
                ),
                (
                    "SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS",
                    Some("tabs,history"),
                ),
            ],
            || {
                let settings = Settings::with_env_and_config_file(None)
                    .expect("off-load config should validate on spanner");
                assert_eq!(
                    settings.syncstorage.gcs_payload_bucket.as_deref(),
                    Some("sync-payloads")
                );
                assert_eq!(
                    settings.syncstorage.gcs_payload_offload_collections,
                    vec!["tabs".to_owned(), "history".to_owned()]
                );
            },
        );
    }

    #[test]
    fn test_oidc_provider_requires_issuer_and_audience() {
        let vars = |issuer: Option<&'static str>, audience: Option<&'static str>| {
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                (
                    "SYNC_TOKENSERVER__DATABASE_URL",
                    Some(TEST_TOKENSERVER_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__ENABLED", Some("true")),
                ("SYNC_TOKENSERVER__OAUTH_PROVIDER", Some("oidc")),
                ("SYNC_TOKENSERVER__OIDC_ISSUER_URL", issuer),
                ("SYNC_TOKENSERVER__OIDC_AUDIENCE", audience),
                (
                    "SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS",
                    Some("thunderbird"),
                ),
            ]
        };
        temp_env::with_vars(vars(None, Some("syncserver")), || {
            let err = Settings::with_env_and_config_file(None)
                .expect_err("an OIDC provider with no issuer should fail validation");
            assert!(
                err.to_string()
                    .contains("SYNC_TOKENSERVER__OIDC_ISSUER_URL")
            );
        });
        temp_env::with_vars(
            vars(Some("keycloak/realms/sync"), Some("syncserver")),
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("an OIDC issuer that isn't a URL should fail validation");
                assert!(
                    err.to_string()
                        .contains("SYNC_TOKENSERVER__OIDC_ISSUER_URL")
                );
            },
        );
        temp_env::with_vars(vars(Some("http://keycloak:7080/realms/sync"), None), || {
            let err = Settings::with_env_and_config_file(None)
                .expect_err("an OIDC provider with no audience should fail validation");
            assert!(err.to_string().contains("SYNC_TOKENSERVER__OIDC_AUDIENCE"));
        });
        temp_env::with_vars(
            vars(Some("http://keycloak:7080/realms/sync"), Some("syncserver")),
            || {
                let settings = Settings::with_env_and_config_file(None)
                    .expect("an OIDC provider with an issuer and audience should validate");
                assert_eq!(settings.tokenserver.oauth_provider, OAuthProvider::Oidc);
            },
        );
    }

    #[test]
    fn test_unknown_oauth_provider_fails() {
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__OAUTH_PROVIDER", Some("keycloak")),
            ],
            || {
                Settings::with_env_and_config_file(None)
                    .expect_err("an unknown oauth_provider should not fall back to FxA");
            },
        );
    }

    /// Env for an enabled Tokenserver with the given OIDC settings and no FxA webhook or JWKs,
    /// plus `extra`
    fn oidc_vars(
        provider: Option<&'static str>,
        issuer: Option<&'static str>,
        audience: Option<&'static str>,
        allowed_clients: Option<&'static str>,
        extra: &[(&'static str, Option<&'static str>)],
    ) -> Vec<(&'static str, Option<&'static str>)> {
        let mut vars = vec![
            (
                "SYNC_SYNCSTORAGE__DATABASE_URL",
                Some(TEST_SYNCSTORAGE_DATABASE_URL),
            ),
            (
                "SYNC_TOKENSERVER__DATABASE_URL",
                Some(TEST_TOKENSERVER_DATABASE_URL),
            ),
            ("SYNC_TOKENSERVER__ENABLED", Some("true")),
            ("SYNC_TOKENSERVER__OAUTH_PROVIDER", provider),
            ("SYNC_TOKENSERVER__OIDC_ISSUER_URL", issuer),
            ("SYNC_TOKENSERVER__OIDC_AUDIENCE", audience),
            ("SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS", allowed_clients),
            ("SYNC_TOKENSERVER__FXA_WEBHOOK_ENABLED", None),
            ("SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__KTY", None),
            ("SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__N", None),
            ("SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__E", None),
            ("SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__KTY", None),
            ("SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__N", None),
            ("SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__E", None),
        ];
        vars.extend_from_slice(extra);
        vars
    }

    const OIDC_TEST_ISSUER: &str = "http://keycloak:7080/realms/sync";

    #[test]
    fn test_oidc_provider_rejects_fxa_webhook() {
        temp_env::with_vars(
            oidc_vars(
                Some("oidc"),
                Some(OIDC_TEST_ISSUER),
                Some("tokenserver"),
                Some("thunderbird"),
                &[("SYNC_TOKENSERVER__FXA_WEBHOOK_ENABLED", Some("true"))],
            ),
            || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("an OIDC provider with the FxA webhook should fail validation");
                assert!(
                    err.to_string()
                        .contains("SYNC_TOKENSERVER__FXA_WEBHOOK_ENABLED")
                );
            },
        );
    }

    #[test]
    fn test_oidc_provider_rejects_fxa_jwks() {
        for [kty, n, e] in [
            [
                "SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__KTY",
                "SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__N",
                "SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK__E",
            ],
            [
                "SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__KTY",
                "SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__N",
                "SYNC_TOKENSERVER__FXA_OAUTH_SECONDARY_JWK__E",
            ],
        ] {
            temp_env::with_vars(
                oidc_vars(
                    Some("oidc"),
                    Some(OIDC_TEST_ISSUER),
                    Some("tokenserver"),
                    Some("thunderbird"),
                    &[(kty, Some("RSA")), (n, Some("AQAB")), (e, Some("AQAB"))],
                ),
                || {
                    let err = Settings::with_env_and_config_file(None)
                        .expect_err("an OIDC provider with an FxA JWK should fail validation");
                    assert!(
                        err.to_string()
                            .contains("SYNC_TOKENSERVER__FXA_OAUTH_PRIMARY_JWK")
                    );
                },
            );
        }
    }

    #[test]
    fn test_oidc_provider_requires_allowed_clients() {
        for allowed_clients in [None, Some(""), Some("thunderbird,")] {
            let vars = oidc_vars(
                Some("oidc"),
                Some(OIDC_TEST_ISSUER),
                Some("tokenserver"),
                allowed_clients,
                &[],
            );
            temp_env::with_vars(vars, || {
                let err = Settings::with_env_and_config_file(None).expect_err(
                    "an OIDC provider with no or empty allowed clients should fail validation",
                );
                assert!(
                    err.to_string()
                        .contains("SYNC_TOKENSERVER__OIDC_ALLOWED_CLIENTS")
                );
            });
        }
        let vars = oidc_vars(
            Some("oidc"),
            Some(OIDC_TEST_ISSUER),
            Some("tokenserver"),
            Some("thunderbird,tokenserver-tests"),
            &[],
        );
        temp_env::with_vars(vars, || {
            let settings = Settings::with_env_and_config_file(None)
                .expect("an OIDC provider with allowed clients should validate");
            assert_eq!(
                settings.tokenserver.oidc_allowed_clients,
                vec!["thunderbird".to_owned(), "tokenserver-tests".to_owned()]
            );
        });
    }

    #[test]
    fn test_oidc_settings_require_oidc_provider() {
        for (provider, issuer, audience, allowed_clients) in [
            (None, Some(OIDC_TEST_ISSUER), None, None),
            (Some("fxa"), None, Some("tokenserver"), None),
            (
                Some("fxa"),
                Some(OIDC_TEST_ISSUER),
                Some("tokenserver"),
                None,
            ),
            (None, None, None, Some("thunderbird")),
            (Some("fxa"), None, None, Some("thunderbird")),
        ] {
            let vars = oidc_vars(provider, issuer, audience, allowed_clients, &[]);
            temp_env::with_vars(vars, || {
                let err = Settings::with_env_and_config_file(None)
                    .expect_err("OIDC settings without the OIDC provider should fail validation");
                assert!(
                    err.to_string()
                        .contains("require SYNC_TOKENSERVER__OAUTH_PROVIDER")
                );
            });
        }
        // FxA mode without OIDC settings is unaffected
        temp_env::with_vars(oidc_vars(None, None, None, None, &[]), || {
            let settings = Settings::with_env_and_config_file(None)
                .expect("FxA mode without OIDC settings should validate");
            assert_eq!(settings.tokenserver.oauth_provider, OAuthProvider::Fxa);
        });
    }

    #[test]
    fn test_disabled_tokenserver_does_not_require_database_url() {
        // A disabled Tokenserver should not require a DATABASE_URL.
        temp_env::with_vars(
            [
                (
                    "SYNC_SYNCSTORAGE__DATABASE_URL",
                    Some(TEST_SYNCSTORAGE_DATABASE_URL),
                ),
                ("SYNC_TOKENSERVER__DATABASE_URL", None),
                ("SYNC_TOKENSERVER__ENABLED", Some("false")),
            ],
            || {
                let settings = Settings::with_env_and_config_file(None)
                    .expect("a disabled tokenserver should not require a DATABASE_URL");
                assert!(!settings.tokenserver.enabled);
                assert!(settings.tokenserver.database_url.is_empty());
            },
        );
    }

    #[test]
    fn test_collection_deletion_confirmation_setting_values() {
        assert!(
            !Settings::default()
                .syncstorage
                .require_collection_delete_confirmation
        );
        assert!(
            Settings::default()
                .cors_allowed_headers
                .unwrap()
                .contains(&"X-Confirm-Delete".to_owned())
        );
        for (value, expected) in [
            (None, Some(false)),
            (Some("false"), Some(false)),
            (Some("true"), Some(true)),
            (Some("invalid"), None),
        ] {
            temp_env::with_vars(
                [
                    (
                        "SYNC_SYNCSTORAGE__DATABASE_URL",
                        Some(TEST_SYNCSTORAGE_DATABASE_URL),
                    ),
                    ("SYNC_SYNCSTORAGE__ENABLED", Some("true")),
                    ("SYNC_TOKENSERVER__ENABLED", Some("false")),
                    ("SYNC_SYNCSTORAGE__GCS_PAYLOAD_BUCKET", None),
                    ("SYNC_SYNCSTORAGE__GCS_PAYLOAD_OFFLOAD_COLLECTIONS", None),
                    ("SYNC_SYNCSTORAGE__GCS_PAYLOAD_PREFIX", None),
                    (
                        "SYNC_SYNCSTORAGE__REQUIRE_COLLECTION_DELETE_CONFIRMATION",
                        value,
                    ),
                ],
                || {
                    let result = Settings::with_env_and_config_file(None);
                    match expected {
                        Some(expected) => assert_eq!(
                            result
                                .unwrap()
                                .syncstorage
                                .require_collection_delete_confirmation,
                            expected
                        ),
                        None => assert!(result.is_err(), "invalid Boolean must fail startup"),
                    }
                },
            );
        }
    }
}
