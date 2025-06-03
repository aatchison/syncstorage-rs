use syncserver_settings::Settings;
use std::env;

fn main() {
    // Test OIDC configuration
    env::set_var("SYNC_TOKENSERVER__OAUTH_PROVIDER_TYPE", "oidc");
    env::set_var("SYNC_TOKENSERVER__OIDC_ISSUER_URL", "http://localhost:7080/realms/sync");
    env::set_var("SYNC_TOKENSERVER__FXA_OAUTH_SERVER_URL", "http://localhost:7080/realms/sync");
    
    match Settings::with_env_and_config_file(None) {
        Ok(settings) => {
            println!("✅ Settings loaded successfully!");
            println!("OAuth provider type: {:?}", settings.tokenserver.oauth_provider_type);
            println!("OIDC issuer URL: {:?}", settings.tokenserver.oidc_issuer_url);
            println!("FxA OAuth server URL: {}", settings.tokenserver.fxa_oauth_server_url);
        }
        Err(e) => {
            println!("❌ Failed to load settings: {}", e);
        }
    }
}