use bip39::Mnemonic;
use cashu_proxy::config::ProxyConfig;
use cashu_proxy::CashuProxy;
use pingora_core::prelude::*;
use pingora_proxy::http_proxy_service;
use tracing_subscriber::EnvFilter;

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
    // Set load balancer
    let mnemonic = Mnemonic::generate(12).unwrap();

    // Load configuration
    let config = ProxyConfig::new().unwrap_or_else(|e| {
        tracing::warn!("Failed to load config: {}, using defaults", e);
        ProxyConfig::default()
    });

    let cashu_proxy = match tokio::runtime::Runtime::new().unwrap().block_on(async {
        // Pass None for spending conditions to let the CashuProxy create them
        CashuProxy::new(&config, mnemonic, None).await
    }) {
        Ok(proxy) => proxy,
        Err(e) => {
            tracing::error!("Failed to initialize CashuProxy: {}", e);
            std::process::exit(1);
        }
    };

    // Spawn task here

    let mut lb = http_proxy_service(&server.configuration, cashu_proxy);
    lb.add_tcp(&config.listen_addr);

    server.add_service(lb);
    server.run_forever();
}
