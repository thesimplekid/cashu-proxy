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
    SecretKey, SigFlag, SpendingConditions, State, Token, TransportType,
};
use cdk::types::ProofInfo;
use cdk::wallet::types::WalletKey;
use cdk::wallet::{MultiMintWallet, SendOptions};
use cdk::Amount;
use nostr_sdk::nips::nip19::Nip19Profile;
use nostr_sdk::{Client as NostrClient, EventBuilder, FromBech32, Keys};
use pingora_core::prelude::*;
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::{ProxyHttp, Session};

pub mod config;

pub struct CashuProxy {
    allowed_mints: Vec<MintUrl>,
    spending_conditions: SpendingConditions,
    cost: Amount,
    min_lock_time: u64,
    wallet: MultiMintWallet,
    upstream_addr: (String, u16),
    signing_key: SecretKey,
    payout_payment_request: PaymentRequest,
}

impl CashuProxy {
    pub async fn new(
        config: &config::ProxyConfig,
        mnemonic: Mnemonic,
        spending_conditions: Option<SpendingConditions>,
    ) -> anyhow::Result<Self> {
        let db_path = config.get_db_path();
        let localstore = cdk_redb::WalletRedbDatabase::new(&db_path).unwrap();

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

        Ok(Self {
            wallet,
            spending_conditions,
            allowed_mints,
            cost: config.cost.into(),
            min_lock_time: config.min_lock_time.unwrap_or(86400),
            upstream_addr,
            signing_key: secret_key,
            payout_payment_request: PaymentRequest::from_str(&config.payout_payment_request)?,
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
        tracing::debug!("Verifying header");
        let token = Token::from_str(token)?;
        let mint = token.mint_url()?;

        if !self.allowed_mints.contains(&mint) {
            bail!("Mint not allowed");
        }

        let wallet = self
            .wallet
            .get_wallet(&WalletKey::new(mint, CurrencyUnit::Sat))
            .await
            .unwrap();

        let conditions = SpendingConditions::new_p2pk(
            self.spending_conditions
                .pubkeys()
                .expect("Pubkey required")
                .first()
                .expect("One pubkey required")
                .clone(),
            Some(Conditions {
                locktime: Some(unix_time() + self.min_lock_time - 3600),
                ..Default::default()
            }),
        );

        wallet.verify_token_p2pk(&token, conditions)?;

        let mint_url = wallet.mint_url;
        let unit = wallet.unit;

        let proofs_info: Vec<ProofInfo> = token
            .proofs()
            .into_iter()
            .flat_map(|p| ProofInfo::new(p, mint_url.clone(), State::Unspent, unit.clone()))
            .collect();

        wallet.localstore.update_proofs(proofs_info, vec![]).await?;

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

                println!("{:?}", nprofile.relays);

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

                println!(
                    "Published event {} succufully to {}",
                    gift_wrap.val,
                    gift_wrap
                        .success
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                );

                if !gift_wrap.failed.is_empty() {
                    println!(
                        "Could not publish to {:?}",
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
                Ok(()) => {
                    self.pay_out().await.unwrap();
                    false
                }
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
