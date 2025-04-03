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
        let write_txn = self.inner.begin_write()?;

        let mut states = Vec::with_capacity(ys.len());
        {
            let table = write_txn.open_table(SEEN_YS_TABLE)?;
            {
                // First collect current states
                for y in ys {
                    let current_state = match table.get(y.to_bytes())? {
                        Some(spent) => {
                            if spent.value() {
                                Some(State::Spent)
                            } else {
                                Some(State::Unspent)
                            }
                        }
                        None => None,
                    };
                    states.push(current_state);
                }
            }
        }

        // Check if any proofs are spent
        if states.contains(&Some(State::Spent)) {
            write_txn.abort()?;
            bail!("Y has already been seen")
        }

        {
            let mut table = write_txn.open_table(SEEN_YS_TABLE)?;
            {
                // If no proofs are spent, proceed with update
                let is_spent = matches!(proofs_state, State::Spent);
                for y in ys {
                    table.insert(y.to_bytes(), is_spent)?;
                }
            }
        }
        write_txn.commit()?;

        Ok(states)
    }
}

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize)]
pub struct SearchCount {
    pub all_time_search_count: u64,
}
