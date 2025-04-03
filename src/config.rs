use std::path::PathBuf;

use anyhow::Result;
use config::{Config, ConfigError, File};
use serde::{Deserialize, Serialize};

use crate::work_dir;

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub upstream_addr: String,
    pub mints: Vec<String>,
    pub cost: u64,
    pub min_lock_time: u64,
    pub work_dir: PathBuf,
    pub secret_key: Option<String>,
    pub payout_payment_request: String,
    pub payout_interval: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:6188".to_string(),
            upstream_addr: "127.0.0.1:8085".to_string(),
            mints: vec!["https://nofees.testnut.cashu.space".to_string()],
            cost: 1,
            min_lock_time: 300, // 5 minutes default lock time
            work_dir: work_dir().expect("Could not find work dir"),
            secret_key: None,
            payout_payment_request: "lnbc...".to_string(), // Placeholder, must be replaced in actual config
            payout_interval: 900,                          // Default 900 seconds (15 minutes)
        }
    }
}

impl ProxyConfig {
    pub fn new() -> Result<Self, ConfigError> {
        let config_dir = crate::work_dir().map_err(|_| {
            ConfigError::Message("Failed to determine configuration directory".to_string())
        })?;

        let config_path = config_dir.join("config.toml");

        let s = Config::builder();

        // Start with defaults
        let mut builder = s.add_source(config::Config::try_from(&ProxyConfig::default())?);

        // Add configuration from file if it exists
        if config_path.exists() {
            builder = builder.add_source(File::from(config_path));
        }

        // Build the config
        let config = builder.build()?;

        // Deserialize the config into our ProxyConfig struct
        config.try_deserialize()
    }
}
