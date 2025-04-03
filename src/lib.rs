use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use bip39::Mnemonic;
use cdk::amount::SplitTarget;
use cdk::mint_url::MintUrl;
use cdk::nuts::{
    Conditions, CurrencyUnit, PaymentRequest, PaymentRequestBuilder, PaymentRequestPayload,
    PublicKey, SecretKey, SigFlag, SpendingConditions, State, Token, TransportType,
};
use cdk::types::ProofInfo;
use cdk::wallet::types::WalletKey;
use cdk::wallet::{MultiMintWallet, SendOptions};
use cdk::Amount;
use db::Db;
use nostr_sdk::nips::nip19::Nip19Profile;
use nostr_sdk::{Client as NostrClient, EventBuilder, FromBech32, Keys};
use pingora_core::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

pub mod config;
mod db;

#[derive(Clone)]
pub struct CashuProxy {
    allowed_mints: Vec<MintUrl>,
    spending_conditions: SpendingConditions,
    cost: Amount,
    min_lock_time: u64,
    wallet: MultiMintWallet,
    upstream_addr: (String, u16),
    signing_key: SecretKey,
    payout_payment_request: PaymentRequest,
    proxy_db: Arc<Db>,
}

impl CashuProxy {
    pub async fn new(
        config: &config::ProxyConfig,
        mnemonic: Mnemonic,
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

        // Get secret key from config, error if not provided
        let secret_key = match &config.secret_key {
            Some(key_str) => match SecretKey::from_str(key_str) {
                Ok(key) => key,
                Err(_) => bail!("Invalid secret key format in configuration"),
            },
            None => {
                bail!("Secret key not provided in configuration");
            }
        };

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

        let proxy_db_path = config.work_dir.join("proxy_db.redb");

        let proxy_db = Arc::new(Db::new(&proxy_db_path)?);

        Ok(Self {
            wallet,
            spending_conditions,
            allowed_mints,
            cost: config.cost.into(),
            min_lock_time: config.min_lock_time,
            upstream_addr,
            signing_key: secret_key,
            payout_payment_request: PaymentRequest::from_str(&config.payout_payment_request)?,
            proxy_db,
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
        let pubkey = match self.spending_conditions.pubkeys() {
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

        // Check if proofs have been spent before
        match self.proxy_db.update_proofs_states(&ys, State::Spent).await {
            Ok(states) => {
                if states.contains(&Some(State::Spent)) {
                    tracing::warn!("Double-spend attempt detected");
                    bail!("Payment rejected: one or more proofs have already been spent");
                }
                tracing::debug!("All proofs are valid and unspent");
            }
            Err(err) => {
                let err_msg = err.to_string();
                if err_msg.contains("Double-spend") || err_msg.contains("already been spent") {
                    tracing::warn!("Double-spend attempt: {}", err_msg);
                    bail!("Payment rejected: {}", err_msg);
                } else {
                    tracing::error!("Database error during proof verification: {}", err_msg);
                    bail!("Internal error: failed to verify proofs: {}", err_msg);
                }
            }
        }

        // Create ProofInfo objects for wallet storage
        let proofs_info: Vec<ProofInfo> = proofs
            .into_iter()
            .flat_map(|p| ProofInfo::new(p, mint.clone(), State::Unspent, unit.clone()))
            .collect();

        assert_eq!(proof_count, proofs_info.len());

        // Update the wallet with the new proofs
        if let Err(e) = wallet.localstore.update_proofs(proofs_info, vec![]).await {
            tracing::error!("Failed to update wallet with proofs: {}", e);
            bail!("Internal error: failed to update wallet: {}", e);
        }

        tracing::info!(
            "Successfully verified and processed token with {} proofs from {}",
            proof_count,
            mint
        );
        Ok(())
    }

    pub async fn pay_out(&self) -> anyhow::Result<()> {
        for wallet in self.wallet.get_wallets().await {
            let balance = wallet.total_balance().await?;

            if balance > Amount::ZERO {
                let proofs = wallet.get_unspent_proofs().await?;

                let amount_rec = wallet
                    .receive_proofs(
                        proofs,
                        SplitTarget::default(),
                        &[self.signing_key.clone()],
                        &[],
                    )
                    .await?;

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

                tracing::info!("Paid out {} to payment request", balance);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl ProxyHttp for CashuProxy {
    type CTX = ();

    fn new_ctx(&self) {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
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
                    self.spending_conditions.pubkeys().expect("Pubkeys defined"),
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
