use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use cdk::nuts::{Proof, PublicKey, SecretKey};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

// Key is the y-value of the proof, value is the serialized ProofWithKey
const PROOFS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("proofs");

// Key is the derivation index, value is the serialized KeyPair
const KEYPAIRS_TABLE: TableDefinition<u32, &str> = TableDefinition::new("keypairs");

#[derive(Clone)]
pub struct Db {
    inner: Arc<Database>,
}

impl Db {
    pub fn new(path: &PathBuf) -> Result<Self> {
        let db = Arc::new(Database::create(path)?);

        let write_txn = db.begin_write()?;
        {
            let _proofs_table = write_txn.open_table(PROOFS_TABLE)?;
            let _keypairs_table = write_txn.open_table(KEYPAIRS_TABLE)?;
        }

        write_txn.commit()?;

        Ok(Self { inner: db })
    }

    pub fn add_proofs(&self, proofs: Vec<ProofWithKey>) -> Result<()> {
        if proofs.is_empty() {
            tracing::warn!("No proofs provided to update_proofs_states");
            return Ok(());
        }

        let write_txn = self.inner.begin_write()?;

        {
            let mut table = write_txn.open_table(PROOFS_TABLE)?;

            for proof in proofs.iter() {
                // Use the y-value of the proof as the key
                let y_value = proof.proof.y()?.to_string();
                table.insert(y_value.as_str(), serde_json::to_string(proof)?.as_str())?;
            }
        }

        write_txn.commit()?;
        Ok(())
    }

    pub fn get_all_proofs(&self) -> Result<HashMap<String, Vec<ProofWithKey>>> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(PROOFS_TABLE)?;

        let mut result: HashMap<String, Vec<ProofWithKey>> = HashMap::new();

        for entry_result in table.iter()? {
            let (_, value_handle) = entry_result?;
            let value = value_handle.value().to_string();
            let proof_with_key: ProofWithKey = serde_json::from_str(&value)?;

            // Group by mint_url
            result
                .entry(proof_with_key.mint_url.clone())
                .or_insert_with(Vec::new)
                .push(proof_with_key);
        }

        Ok(result)
    }

    /// Remove proofs with the specified y-values from the database
    pub fn remove_proofs_by_ys(&self, ys: &[PublicKey]) -> Result<()> {
        if ys.is_empty() {
            return Ok(());
        }

        let write_txn = self.inner.begin_write()?;

        {
            let mut table = write_txn.open_table(PROOFS_TABLE)?;

            for y in ys {
                table.remove(y.to_string().as_str())?;
                tracing::debug!("Removed proof with y-value: {}", y);
            }
        }

        write_txn.commit()?;
        Ok(())
    }

    /// Get proofs with the specified y-values from the database
    pub fn get_proofs_by_ys(&self, ys: &[PublicKey]) -> Result<HashMap<String, Vec<ProofWithKey>>> {
        let mut result = HashMap::<String, Vec<ProofWithKey>>::new();

        if ys.is_empty() {
           return Ok(result);
        }

        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(PROOFS_TABLE)?;

        for y in ys.iter() {
            let entry = table.get(y.to_hex().as_str())?;
            
            if let Some(value) = entry {
                let proof_with_key: ProofWithKey = serde_json::from_str(&value.value().to_string())?;  
                
                result
                    .entry(proof_with_key.mint_url.clone())
                    .or_insert_with(Vec::new)
                    .push(proof_with_key);
            }
        }

        Ok(result)
    }

    /// Store a key pair in the database
    pub fn add_keypair(&self, keypair: KeyPair) -> Result<()> {
        let write_txn = self.inner.begin_write()?;

        {
            let mut table = write_txn.open_table(KEYPAIRS_TABLE)?;

            // Use the derivation index as the key
            table.insert(
                keypair.derivation_index,
                serde_json::to_string(&keypair)?.as_str(),
            )?;
            tracing::debug!(
                "Stored key pair with derivation index: {}",
                keypair.derivation_index
            );
        }

        write_txn.commit()?;
        Ok(())
    }

    /// Get all stored key pairs
    pub fn get_all_keypairs(&self) -> Result<Vec<KeyPair>> {
        let read_txn = self.inner.begin_read()?;
        let table = read_txn.open_table(KEYPAIRS_TABLE)?;

        let mut keypairs = vec![];

        for entry_result in table.iter()? {
            let (_, value_handle) = entry_result?;
            let value = value_handle.value().to_string();
            let keypair: KeyPair = serde_json::from_str(&value)?;
            keypairs.push(keypair);
        }

        Ok(keypairs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofWithKey {
    pub proof: Proof,
    pub mint_url: String,
    pub secret_key: SecretKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyPair {
    pub derivation_index: u32,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}
