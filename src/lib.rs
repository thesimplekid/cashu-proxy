use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use axum::extract::State;
use axum::response::Json;
use axum::routing::get;
use axum::Router;
use bip39::Mnemonic;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::SECP256K1;
use bitcoin::Network;
use bloomfilter::Bloom;
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::nuts::{
    Conditions, CurrencyUnit, PaymentRequest, PaymentRequestBuilder, PaymentRequestPayload,
    PublicKey, SecretKey, SigFlag, SpendingConditions, Token, TransportType,
};
use cdk::wallet::types::WalletKey;
use cdk::wallet::{MultiMintWallet, SendOptions};
use cdk::Amount;
use db::ProofWithKey;
use nostr_sdk::nips::nip19::Nip19Profile;
use nostr_sdk::{Client as NostrClient, EventBuilder, FromBech32, Keys};
use pingora_core::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};
use serde_json;
use tokio::sync::{Mutex, RwLock};

pub mod config;
mod db;

#[derive(Clone)]
pub struct CashuProxy {
    allowed_mints: Vec<MintUrl>,
    spending_conditions: Arc<RwLock<SpendingConditions>>,
    cost: Amount,
    min_lock_time: u64,
    wallet: MultiMintWallet,
    upstream_addr: (String, u16),
    signing_key: Arc<RwLock<SecretKey>>,
    payout_payment_request: PaymentRequest,
    bloom: Arc<Mutex<Bloom<PublicKey>>>,
    db: db::Db,
    seed: Mnemonic,
    internal_keys_port: u16,
}

impl CashuProxy {
    pub async fn new(
        config: &config::ProxyConfig,
        mnemonic: Mnemonic,
        derivation_index: u32,
        spending_conditions: Option<SpendingConditions>,
    ) -> anyhow::Result<Self> {
        let db_path = &config.work_dir;
        let wallet_db = db_path.join("cdk_wallet.redb");

        let localstore = cdk_redb::WalletRedbDatabase::new(&wallet_db).unwrap();

        let wallet = MultiMintWallet::new(
            Arc::new(localstore),
            Arc::new(mnemonic.to_seed_normalized("")),
            vec![],
        );
        for w in config.mints.iter() {
            let w_clone = w.clone();
            let wallet_clone = wallet.clone();
            wallet_clone
                .create_and_add_wallet(&w_clone, CurrencyUnit::Sat, None)
                .await
                .unwrap();
        }

        let allowed_mints = config
            .mints
            .iter()
            .flat_map(|p| MintUrl::from_str(p))
            .collect();

        // Derive the secret key from the mnemonic using the derivation index
        let seed = mnemonic.to_seed_normalized("");

        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;

        // Use custom derivation path with the provided index: m/0'/0'/index'
        let path = format!("m/0'/0'/{}'", derivation_index);
        let derivation_path = DerivationPath::from_str(&path)?;

        let derived_xpriv = xpriv.derive_priv(SECP256K1, &derivation_path)?;
        let secret_key: SecretKey = derived_xpriv.private_key.into();

        tracing::info!(
            "Using derived secret key with public key: {} (index: {})",
            secret_key.public_key(),
            derivation_index
        );

        // Use provided spending conditions or create from config
        let spending_conditions = spending_conditions.unwrap_or_else(|| {
            // Always use P2PKConditions
            SpendingConditions::P2PKConditions {
                data: secret_key.public_key(),
                conditions: None,
            }
        });

        // Parse the upstream address
        let parts: Vec<&str> = config.upstream_addr.split(':').collect();
        let host = parts[0].to_string();
        let port = parts[1].parse::<u16>().unwrap_or(8085);
        let upstream_addr = (host, port);

        let num_items = 100000;
        let fp_rate = 0.001;

        let bloom = Bloom::new_for_fp_rate(num_items, fp_rate).unwrap();

        let proxy_db_path = config.work_dir.join("proxy_db.redb");

        let proxy_db = db::Db::new(&proxy_db_path)?;

        Ok(Self {
            wallet,
            spending_conditions: Arc::new(RwLock::new(spending_conditions)),
            allowed_mints,
            cost: config.cost.into(),
            min_lock_time: config.min_lock_time,
            upstream_addr,
            signing_key: Arc::new(RwLock::new(secret_key)),
            payout_payment_request: PaymentRequest::from_str(&config.payout_payment_request)?,
            bloom: Arc::new(Mutex::new(bloom)),
            db: proxy_db,
            seed: mnemonic,
            internal_keys_port: 8787, // Default internal port for keys API
        })
    }

    pub fn get_x_cashu(&self, session: &mut Session) -> Option<String> {
        match session
            .req_header()
            .headers
            .get("X-Cashu")
            .map(|v| v.to_str())
        {
            None => None,
            Some(v) => match v {
                Ok(v) => Some(v.to_string()),
                Err(_) => None,
            },
        }
    }

    pub async fn verify_x_cashu(&self, token: &str) -> anyhow::Result<()> {
        tracing::debug!("Verifying X-Cashu token");

        // Parse the token
        let token = match Token::from_str(token) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Invalid token format: {}", e);
                bail!("Invalid token format: {}", e);
            }
        };

        // Get the mint URL
        let mint = match token.mint_url() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Failed to extract mint URL from token: {}", e);
                bail!("Invalid token: missing or invalid mint URL: {}", e);
            }
        };

        let unit = token.unit().unwrap_or_default();

        if unit != CurrencyUnit::Sat {
            tracing::warn!("Token unit {} expected sat.", unit);
            bail!("Unit {} is not sat", unit);
        }

        let token_value = token.value()?;
        if token_value < self.cost {
            tracing::warn!(
                "Token value {} is less then cost {}.",
                token_value,
                self.cost
            );
            bail!(
                "Token value {} is less then cost {}.",
                token_value,
                self.cost
            );
        }

        // Check if the mint is allowed
        if !self.allowed_mints.contains(&mint) {
            tracing::warn!("Token from disallowed mint: {}", mint);
            bail!("Mint not allowed: {}", mint);
        }
        tracing::debug!("Token from allowed mint: {}", mint);

        // Get the wallet for this mint
        let wallet = match self
            .wallet
            .get_wallet(&WalletKey::new(mint.clone(), unit.clone()))
            .await
        {
            Some(w) => w,
            None => {
                tracing::error!("Failed to get wallet for mint: {}", mint);
                bail!("Internal error: wallet not found for mint: {}", mint);
            }
        };

        assert_eq!(unit, wallet.unit);
        assert_eq!(mint, wallet.mint_url);

        // Create spending conditions with locktime
        let pubkey = match self.spending_conditions.read().await.pubkeys() {
            Some(keys) if !keys.is_empty() => keys[0],
            _ => {
                tracing::error!("No pubkey available for spending conditions");
                bail!("Configuration error: no pubkey available for spending conditions");
            }
        };

        let conditions = SpendingConditions::new_p2pk(
            pubkey,
            Some(Conditions {
                locktime: Some(unix_time() + self.min_lock_time - 3600),
                ..Default::default()
            }),
        );

        if let Err(err) = wallet.verify_token_dleq(&token).await {
            tracing::warn!("Token did not have valid dleq: {}", err);
            bail!("Token did not have valid dleq: {}", err);
        }

        // Verify the token
        if let Err(e) = wallet.verify_token_p2pk(&token, conditions) {
            tracing::warn!("Token verification failed: {}", e);
            bail!("Token verification failed: {}", e);
        }

        tracing::debug!("Token verified successfully");

        let proofs = token.proofs();
        let proof_count = proofs.len();

        // Extract public keys from proofs
        let ys: Vec<PublicKey> = proofs.iter().flat_map(|p| p.y()).collect();

        assert_eq!(proof_count, ys.len());

        {
            let mut bloom = self.bloom.lock().await;

            for y in ys.iter() {
                if bloom.check(y) {
                    tracing::warn!("Received already seen token");
                    bail!("Payment rejected: one or more proofs have already been spent");
                }
            }

            for y in ys.iter() {
                bloom.set(y);
            }
        }

        let mint_url = token.mint_url()?.to_string();

        let secret_key = self.signing_key.read().await.clone();

        let proofs_with_key = proofs
            .into_iter()
            .map(|p| ProofWithKey {
                proof: p,
                secret_key: secret_key.clone(),
                mint_url: mint_url.clone(),
            })
            .collect::<Vec<ProofWithKey>>();

        assert_eq!(proof_count, proofs_with_key.len());

        self.db.add_proofs(proofs_with_key)?;

        tracing::info!(
            "Successfully verified and processed token with {} proofs from {}",
            proof_count,
            mint
        );
        Ok(())
    }

    pub async fn pay_out<F>(&self, increment_index: F) -> anyhow::Result<()>
    where
        F: FnOnce() -> anyhow::Result<u32>,
    {
        match increment_index() {
            Ok(new_index) => {
                tracing::info!("Incremented derivation index to: {}", new_index);
                // Update the signing key and spending conditions with the new index
                if let Err(e) = self.update_keys_with_index(new_index).await {
                    tracing::error!("Failed to update keys with new index: {}", e);
                } else {
                    tracing::info!("Successfully updated signing key and spending conditions with new index: {}", new_index);
                    // Clear the bloom filter after payout
                    let mut bloom = self.bloom.lock().await;
                    *bloom = Bloom::new_for_fp_rate(100000, 0.001).unwrap();
                    tracing::info!("Reset bloom filter after payout");
                }
            }
            Err(e) => {
                tracing::error!("Failed to increment derivation index: {}", e);
            }
        }

        let proofs = self.db.get_all_proofs()?;

        for (mint_url, proofs_with_key) in proofs {
            let wallet = self
                .wallet
                .get_wallet(&WalletKey::new(mint_url.parse()?, CurrencyUnit::Sat))
                .await
                .expect("Wallet created");

            let (proofs, singing_keys, claimed_ys) = proofs_with_key.into_iter().fold(
                (Vec::new(), Vec::new(), Vec::new()),
                |(mut proofs, mut keys, mut claimed_ys), p| {
                    if !keys.contains(&p.secret_key) {
                        keys.push(p.secret_key);
                    }

                    if let Ok(y) = p.proof.y() {
                        claimed_ys.push(y);
                    }

                    proofs.push(p.proof);

                    (proofs, keys, claimed_ys)
                },
            );

            println!("{:?}", singing_keys);

            assert_eq!(proofs.len(), claimed_ys.len());

            let amount_rec = wallet
                .receive_proofs(proofs, SplitTarget::default(), &singing_keys, &[])
                .await?;

            if let Err(err) = self.db.remove_proofs_by_ys(&claimed_ys) {
                tracing::error!("Could not remove ys from db {}", err);
            };

            let send = wallet
                .prepare_send(amount_rec, SendOptions::default())
                .await?;

            // Use the configured payment request for payouts
            let proofs = wallet.send(send, None).await?.proofs();

            // We prefer nostr transport if it is available to hide ip.
            let transport = self
                .payout_payment_request
                .transports
                .iter()
                .find(|t| t._type == TransportType::Nostr)
                .ok_or(anyhow!("Nostr transport not defined"))?;

            let keys = Keys::generate();
            let client = NostrClient::new(keys.clone());
            let nprofile = Nip19Profile::from_bech32(&transport.target)?;

            tracing::debug!("Relays: {:?}", nprofile.relays);

            let payload = PaymentRequestPayload {
                id: self.payout_payment_request.payment_id.clone(),
                memo: None,
                mint: wallet.mint_url.clone(),
                unit: wallet.unit.clone(),
                proofs,
            };

            let rumor = EventBuilder::new(
                nostr_sdk::Kind::from_u16(14),
                serde_json::to_string(&payload)?,
            );

            let relays = nprofile.relays;

            for relay in relays.iter() {
                client.add_write_relay(relay).await?;
            }

            client.connect().await;

            let gift_wrap = client
                .gift_wrap_to(
                    relays,
                    &nprofile.public_key,
                    rumor.build(keys.public_key),
                    None,
                )
                .await?;

            tracing::info!(
                "Published event {} successfully to {}",
                gift_wrap.val,
                gift_wrap
                    .success
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );

            if !gift_wrap.failed.is_empty() {
                tracing::warn!(
                    "Could not publish to {}",
                    gift_wrap
                        .failed
                        .keys()
                        .map(|relay| relay.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }

        Ok(())
    }

    pub async fn update_keys_with_index(&self, derivation_index: u32) -> anyhow::Result<()> {
        // Note: We don't have access to the original mnemonic here, but we can use the wallet's seed
        // to derive our new keys in exactly the same way CashuProxy::new() does
        let seed = self.seed.to_seed_normalized("");

        // Use the same derivation logic as in CashuProxy::new()
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed)?;

        // Use custom derivation path with the provided index: m/0'/0'/index'
        let path = format!("m/0'/0'/{}'", derivation_index);
        let derivation_path = DerivationPath::from_str(&path)?;

        let derived_xpriv = xpriv.derive_priv(SECP256K1, &derivation_path)?;
        let new_secret_key: SecretKey = derived_xpriv.private_key.into();

        tracing::info!(
            "Updating to derived secret key with public key: {} (index: {})",
            new_secret_key.public_key(),
            derivation_index
        );

        // Update the signing key
        let mut current_key = self.signing_key.write().await;

        // Create and update the spending conditions
        let new_spending_conditions = SpendingConditions::P2PKConditions {
            data: new_secret_key.public_key(),
            conditions: None,
        };

        // Update the spending conditions
        let mut spending_conditions = self.spending_conditions.write().await;

        // Store the key pair in the database for history
        let keypair = db::KeyPair {
            derivation_index,
            public_key: current_key.public_key(),
            secret_key: current_key.clone().into(),
        };

        if let Err(e) = self.db.add_keypair(keypair) {
            tracing::error!("Failed to store key pair in database: {}", e);
        } else {
            tracing::info!(
                "Stored key pair with index {} in database",
                derivation_index
            );
        }

        *spending_conditions = new_spending_conditions;
        *current_key = new_secret_key.clone();

        Ok(())
    }

    pub async fn start_keys_server(&self) -> anyhow::Result<()> {
        let db_clone = self.db.clone();

        // Set up the Axum app with our keys handler
        let app = Router::new()
            .route("/api/v1/keys", get(keys_handler))
            .with_state(db_clone);

        // Bind to localhost only since this is internal
        let addr = SocketAddr::from(([127, 0, 0, 1], self.internal_keys_port));

        let listener = tokio::net::TcpListener::bind(addr).await?;

        tracing::info!("Starting internal keys API server at {}", addr);
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("Keys server error: {}", e);
        }

        Ok(())
    }

    pub fn get_internal_keys_url(&self) -> String {
        format!("http://127.0.0.1:{}/api/v1/keys", self.internal_keys_port)
    }
}

#[async_trait]
impl ProxyHttp for CashuProxy {
    type CTX = ();

    fn new_ctx(&self) {}

    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        // Check if this is a request to the keys endpoint
        let req_header = session.req_header();
        if req_header.uri.path() == "/api/v1/keys" {
            return Ok(Box::new(HttpPeer::new(
                (self.upstream_addr.0.as_str(), self.internal_keys_port),
                false,
                "".to_string(),
            )));
        }

        // Set SNI
        let peer = Box::new(HttpPeer::new(
            (self.upstream_addr.0.as_str(), self.upstream_addr.1),
            false,
            "".to_string(),
        ));
        Ok(peer)
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        _upstream_request: &mut RequestHeader,
        _ctx: &mut Self::CTX,
    ) -> Result<()>
    where
        Self::CTX: Send + Sync,
    {
        Ok(())
    }

    async fn request_filter(&self, session: &mut Session, _ctx: &mut Self::CTX) -> Result<bool>
    where
        Self::CTX: Send + Sync,
    {
        tracing::debug!("Checking filter");
        let req_header = session.req_header();
        if req_header.uri.path() == "/api/v1/keys" {
            return Ok(false);
        }

        let filter = match self.get_x_cashu(session) {
            Some(x_cashu) => match self.verify_x_cashu(&x_cashu).await {
                Ok(()) => false,
                Err(_) => true,
            },

            None => true,
        };

        if filter {
            tracing::debug!("Payment required");
            // rate limited, return 429
            let mut header = ResponseHeader::build(402, None).unwrap();

            let payment_builder = PaymentRequestBuilder::default()
                .unit(CurrencyUnit::Sat)
                .amount(self.cost)
                .p2pk(
                    self.spending_conditions
                        .read()
                        .await
                        .pubkeys()
                        .expect("Pubkeys defined"),
                    Some(SigFlag::SigInputs),
                    Some(unix_time() + self.min_lock_time),
                    None,
                )
                .mints(self.allowed_mints.clone());

            let payment_request = payment_builder.build();

            header
                .insert_header("X-Cashu", payment_request.to_string())
                .unwrap();
            session.set_keepalive(None);
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }

        Ok(false)
    }
}

pub fn work_dir() -> anyhow::Result<PathBuf> {
    let home_dir = home::home_dir().ok_or(anyhow!("Unknown home dir"))?;
    let dir = home_dir.join(".cashu-proxy");

    std::fs::create_dir_all(&dir)?;

    Ok(dir)
}

/// Seconds since unix epoch
pub fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// The Axum handler for the /api/v1/keys endpoint
async fn keys_handler(State(db): State<db::Db>) -> Json<BTreeMap<String, String>> {
    println!("Keys re");
    match db.get_all_keypairs() {
        Ok(keypairs) => {
            let mut key_map = BTreeMap::new();
            for kp in keypairs {
                key_map.insert(kp.public_key.to_string(), kp.secret_key.to_string());
            }
            Json(key_map)
        }
        Err(err) => {
            tracing::error!("Failed to retrieve key pairs: {}", err);
            Json(BTreeMap::new()) // Return empty map on error
        }
    }
}
