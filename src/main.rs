use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use bip39::Mnemonic;
use cashu_proxy::config::ProxyConfig;
use cashu_proxy::{work_dir, CashuProxy};
use pingora_core::prelude::*;
use pingora_proxy::http_proxy_service;
use tracing_subscriber::EnvFilter;

fn load_or_generate_mnemonic() -> anyhow::Result<Mnemonic> {
    let mnemonic_path = work_dir()?.join("mnemonic.txt");

    if Path::new(&mnemonic_path).exists() {
        // Load existing mnemonic
        let mut file = File::open(&mnemonic_path)?;
        let mut mnemonic_str = String::new();
        file.read_to_string(&mut mnemonic_str)?;

        let mnemonic = Mnemonic::parse(mnemonic_str.trim())?;
        tracing::info!("Loaded existing mnemonic");
        Ok(mnemonic)
    } else {
        // Generate new mnemonic
        let mnemonic = Mnemonic::generate(12)?;

        // Save to file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&mnemonic_path)?;

        file.write_all(mnemonic.to_string().as_bytes())?;
        tracing::info!("Generated and saved new mnemonic");
        Ok(mnemonic)
    }
}

/// Read the current derivation index from file, or create with default value of 0
fn get_derivation_index() -> anyhow::Result<u32> {
    let index_path = work_dir()?.join("derivation_index.txt");

    if Path::new(&index_path).exists() {
        // Load existing index
        let mut file = File::open(&index_path)?;
        let mut index_str = String::new();
        file.read_to_string(&mut index_str)?;

        let index = u32::from_str(index_str.trim())?;
        tracing::info!("Loaded derivation index: {}", index);
        Ok(index)
    } else {
        // Start with index 0
        let index = 0;

        // Save to file
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .open(&index_path)?;

        file.write_all(index.to_string().as_bytes())?;
        tracing::info!("Initialized new derivation index: {}", index);
        Ok(index)
    }
}

/// Increment and save the derivation index
fn increment_derivation_index(current_index: u32) -> anyhow::Result<u32> {
    let index_path = work_dir()?.join("derivation_index.txt");
    let new_index = current_index + 1;

    // Save to file
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&index_path)?;

    file.write_all(new_index.to_string().as_bytes())?;
    tracing::info!("Incremented derivation index to: {}", new_index);
    Ok(new_index)
}

fn main() {
    let default_filter = "debug";

    let sqlx_filter = "sqlx=warn";
    let hyper_filter = "hyper=warn";
    let h2_filter = "h2=warn";
    let tower_http = "tower_http=warn";

    let env_filter = EnvFilter::new(format!(
        "{},{},{},{},{}",
        default_filter, sqlx_filter, hyper_filter, h2_filter, tower_http
    ));

    tracing_subscriber::fmt().with_env_filter(env_filter).init();

    let mut server = Server::new(Some(Opt::default())).unwrap();
    server.bootstrap();

    // Load or generate mnemonic
    let mnemonic = load_or_generate_mnemonic().unwrap_or_else(|e| {
        tracing::error!("Failed to load or generate mnemonic: {}", e);
        std::process::exit(1);
    });

    // Get the current derivation index
    let derivation_index = get_derivation_index().unwrap_or_else(|e| {
        tracing::error!("Failed to load derivation index: {}", e);
        std::process::exit(1);
    });

    // Load configuration
    let config = ProxyConfig::new().unwrap_or_else(|e| {
        tracing::warn!("Failed to load config: {}, using defaults", e);
        ProxyConfig::default()
    });

    let cashu_proxy = match tokio::runtime::Runtime::new().unwrap().block_on(async {
        // Pass None for spending conditions to let the CashuProxy create them
        let proxy = CashuProxy::new(&config, mnemonic, derivation_index, None).await?;

        Ok::<_, anyhow::Error>(proxy)
    }) {
        Ok(proxy) => proxy,
        Err(e) => {
            tracing::error!("Failed to initialize CashuProxy: {}", e);
            std::process::exit(1);
        }
    };

    // Create a Tokio runtime for the main thread
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Spawn task for periodic payouts
    let payout_interval_secs = config.payout_interval;
    let proxy_clone = cashu_proxy.clone();

    assert!(config.min_lock_time > payout_interval_secs);

    rt.spawn(async move {
        let mut interval =
            tokio::time::interval(tokio::time::Duration::from_secs(payout_interval_secs));

        loop {
            interval.tick().await;
            tracing::info!("Running scheduled payout");

            let current_index = get_derivation_index().unwrap_or(derivation_index);
            match proxy_clone
                .pay_out(|| increment_derivation_index(current_index))
                .await
            {
                Ok(_) => tracing::info!("Scheduled payout completed successfully"),
                Err(e) => tracing::error!("Scheduled payout failed: {}", e),
            }
        }
    });

    let cashu_proxy_clone = cashu_proxy.clone();

    rt.spawn(async move { cashu_proxy_clone.start_keys_server().await });

    let mut lb = http_proxy_service(&server.configuration, cashu_proxy);
    lb.add_tcp(&config.listen_addr);

    server.add_service(lb);
    server.run_forever();
}
