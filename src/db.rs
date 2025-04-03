use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{bail, Result};
use cdk::nuts::{PublicKey, State};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const SEEN_YS_TABLE: TableDefinition<[u8; 33], bool> = TableDefinition::new("seen_ys");

#[derive(Clone)]
pub struct Db {
    inner: Arc<Database>,
}

impl Db {
    pub fn new(path: &PathBuf) -> Result<Self> {
        let db = Arc::new(Database::create(path)?);

        let write_txn = db.begin_write()?;
        {
            let _table = write_txn.open_table(SEEN_YS_TABLE)?;
        }

        write_txn.commit()?;

        Ok(Self { inner: db })
    }

    pub async fn update_proofs_states(
        &self,
        ys: &[PublicKey],
        proofs_state: State,
    ) -> Result<Vec<Option<State>>> {
        if ys.is_empty() {
            tracing::warn!("No proofs provided to update_proofs_states");
            return Ok(Vec::new());
        }

        tracing::debug!("Updating state for {} proofs to {:?}", ys.len(), proofs_state);
        
        let write_txn = match self.inner.begin_write() {
            Ok(txn) => txn,
            Err(e) => {
                tracing::error!("Failed to begin database transaction: {}", e);
                bail!("Database error: failed to begin transaction: {}", e)
            }
        };

        let mut states = Vec::with_capacity(ys.len());
        {
            let table = match write_txn.open_table(SEEN_YS_TABLE) {
                Ok(table) => table,
                Err(e) => {
                    write_txn.abort()?;
                    tracing::error!("Failed to open table: {}", e);
                    bail!("Database error: failed to open table: {}", e)
                }
            };
            
            // First collect current states
            for y in ys {
                let y_bytes = y.to_bytes();
                let current_state = match table.get(y_bytes) {
                    Ok(Some(spent)) => {
                        let is_spent = spent.value();
                        if is_spent {
                            tracing::debug!("Proof {} is already spent", y);
                            Some(State::Spent)
                        } else {
                            tracing::debug!("Proof {} is unspent", y);
                            Some(State::Unspent)
                        }
                    }
                    Ok(None) => {
                        tracing::debug!("Proof {} is new", y);
                        None
                    }
                    Err(e) => {
                        write_txn.abort()?;
                        tracing::error!("Database error when checking proof {}: {}", y, e);
                        bail!("Database error when checking proof: {}", e)
                    }
                };
                states.push(current_state);
            }
        }

        // Check if any proofs are spent
        if states.contains(&Some(State::Spent)) {
            tracing::warn!("Attempted to use already spent proof");
            write_txn.abort()?;
            bail!("Double-spend attempt: one or more proofs have already been spent")
        }

        {
            let mut table = match write_txn.open_table(SEEN_YS_TABLE) {
                Ok(table) => table,
                Err(e) => {
                    write_txn.abort()?;
                    tracing::error!("Failed to open table for writing: {}", e);
                    bail!("Database error: failed to open table for writing: {}", e)
                }
            };
            
            // If no proofs are spent, proceed with update
            let is_spent = matches!(proofs_state, State::Spent);
            for y in ys {
                let y_bytes = y.to_bytes();
                if let Err(e) = table.insert(y_bytes, is_spent) {
                    write_txn.abort()?;
                    tracing::error!("Failed to update proof {}: {}", y, e);
                    bail!("Database error: failed to update proof state: {}", e)
                }
                tracing::debug!("Updated proof {} to {}", y, if is_spent { "spent" } else { "unspent" });
            }
        }
        
        if let Err(e) = write_txn.commit() {
            tracing::error!("Failed to commit transaction: {}", e);
            bail!("Database error: failed to commit transaction: {}", e)
        }
        
        tracing::info!("Successfully updated {} proofs to {:?}", ys.len(), proofs_state);
        Ok(states)
    }
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct SearchCount {
    pub all_time_search_count: u64,
}
